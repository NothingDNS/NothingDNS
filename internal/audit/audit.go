package audit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sanitizeLogField removes newlines and control characters that could
// inject false entries into structured log files.
func sanitizeLogField(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

// sanitizeLogToken escapes a single-token field of the space-separated
// key=value line: spaces, control bytes and backslashes become RFC 1035 style
// \DDD / \\ escapes (newline and CR keep their \n / \r form, NUL is
// dropped). A query name is attacker-chosen and is not escaped by the wire
// decoder, so a label such as "x client=6.6.6.6" forged fields (F642).
func sanitizeLogToken(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == 0x7f || c == '\\' {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == 0:
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\\':
			b.WriteString(`\\`)
		case c <= ' ' || c == 0x7f:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// QueryAuditEntry represents a single query audit log entry.
type QueryAuditEntry struct {
	RequestID string // Unique correlation ID for end-to-end tracing
	Timestamp string
	ClientIP  string
	QueryName string
	QueryType string
	Rcode     string
	Latency   time.Duration
	CacheHit  bool
	Upstream  string
}

// AXFRAuditEntry represents an AXFR (full zone transfer) audit log entry.
type AXFRAuditEntry struct {
	RequestID   string
	Timestamp   string
	ClientIP    string
	Zone        string
	Action      string // "request", "completed", "failed"
	RecordCount int
	Latency     time.Duration
}

// IXFRAuditEntry represents an IXFR (incremental zone transfer) audit log entry.
type IXFRAuditEntry struct {
	RequestID   string
	Timestamp   string
	ClientIP    string
	Zone        string
	Action      string // "request", "completed", "failed"
	RecordCount int
	Latency     time.Duration
}

// NOTIFYAuditEntry represents a NOTIFY (zone update notification) audit log entry.
type NOTIFYAuditEntry struct {
	RequestID string
	Timestamp string
	ClientIP  string // the notifying server
	Zone      string
	Action    string // "received", "accepted", "rejected"
}

// UpdateAuditEntry represents a DDNS UPDATE (RFC 2136) audit log entry.
type UpdateAuditEntry struct {
	RequestID string
	Timestamp string
	ClientIP  string
	Zone      string
	Action    string // "request", "success", "failure"
	Rcode     string
	Added     int
	Deleted   int
}

// ReloadAuditEntry represents a configuration reload audit log entry.
type ReloadAuditEntry struct {
	Timestamp string
	Action    string // "start", "complete", "failed"
	Zones     int    // number of zones reloaded
	Error     string
}

// AuditLogger writes structured audit logs for security-sensitive operations.
type AuditLogger struct {
	mu     sync.Mutex
	output io.Writer
	file   *os.File
	// enabled is atomic so every Log* entry point can fast-path out of a
	// disabled logger without formatting the line or taking the global
	// mutex. Close() flips it concurrently with in-flight Log* calls.
	enabled atomic.Bool
	lastErr error

	// Async writer: audit logging must never block the DNS request path.
	// Log* enqueue formatted lines onto a bounded channel that a single
	// background goroutine drains, coalescing queued lines into one write to the
	// output. A synchronous write under a global mutex (the previous design)
	// meant a full disk or a stalled network volume would hold the lock and
	// stall ALL resolution.
	lines     chan string
	syncReq   chan chan struct{}
	done      chan struct{}
	wg        sync.WaitGroup
	dropped   atomic.Uint64
	closeOnce sync.Once
}

// auditQueueSize bounds the in-memory backlog of pending audit lines. When full
// (writer can't keep up with the disk), new lines are dropped rather than
// blocking the request path — a dropped audit line is preferable to stalled DNS.
const auditQueueSize = 8192

// NewAuditLogger creates a new audit logger.
// If queryLogFile is non-empty, opens the file for append.
// Otherwise uses stdout.
func NewAuditLogger(queryLog bool, queryLogFile string) (*AuditLogger, error) {
	if !queryLog {
		return &AuditLogger{}, nil // enabled zero value is false
	}

	var output io.Writer = os.Stdout
	var file *os.File

	if queryLogFile != "" {
		f, err := os.OpenFile(queryLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("opening query log file %s: %w", queryLogFile, err)
		}
		if err := f.Chmod(0600); err != nil {
			f.Close()
			return nil, fmt.Errorf("securing query log file %s: %w", queryLogFile, err)
		}
		file = f
		output = f
	}

	return newAuditLogger(output, file), nil
}

// newAuditLogger builds an enabled logger over output and starts its background
// writer. output is captured before the goroutine starts, so it must be set
// here (not swapped afterward).
func newAuditLogger(output io.Writer, file *os.File) *AuditLogger {
	al := &AuditLogger{
		output:  output,
		file:    file,
		lines:   make(chan string, auditQueueSize),
		syncReq: make(chan chan struct{}),
		done:    make(chan struct{}),
	}
	al.enabled.Store(true)
	al.wg.Add(1)
	go al.run()
	return al
}

// Sync blocks until every line queued before the call has been written and
// flushed. Intended for tests and graceful checkpoints; the request path never
// calls it.
func (a *AuditLogger) Sync() {
	if !a.enabled.Load() || a.syncReq == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case a.syncReq <- ack:
		<-ack
	case <-a.done:
	}
}

// run is the single background writer. It drains queued lines to a buffered
// writer, flushing periodically so entries reach disk promptly, and drains +
// flushes on shutdown.
func (a *AuditLogger) run() {
	defer a.wg.Done()
	var sb strings.Builder

	// writeBatch coalesces the triggering line plus every other line currently
	// queued into a single write, cutting syscalls under load. a.output is read
	// only here (on a channel event), so a test that swaps a.output before its
	// first Log is safe via the channel's happens-before edge.
	writeBatch := func(first string) {
		sb.Reset()
		if first != "" {
			sb.WriteString(first)
			sb.WriteByte('\n')
		}
		for drained := false; !drained; {
			select {
			case line := <-a.lines:
				sb.WriteString(line)
				sb.WriteByte('\n')
			default:
				drained = true
			}
		}
		if sb.Len() == 0 {
			return
		}
		if _, err := io.WriteString(a.output, sb.String()); err != nil {
			a.setErr(err)
		}
	}

	for {
		select {
		case line := <-a.lines:
			writeBatch(line)
		case ack := <-a.syncReq:
			writeBatch("") // drain + write everything queued before the Sync
			close(ack)
		case <-a.done:
			writeBatch("") // final drain before exit
			return
		}
	}
}

func (a *AuditLogger) setErr(err error) {
	a.mu.Lock()
	a.lastErr = err
	a.mu.Unlock()
}

// LogQuery writes a query audit entry.
func (a *AuditLogger) LogQuery(entry QueryAuditEntry) {
	if !a.enabled.Load() {
		return // fast path: skip formatting and the global mutex
	}
	a.writeLine(formatQueryAuditLine(entry))
}

// LogAXFR writes an AXFR audit entry.
func (a *AuditLogger) LogAXFR(entry AXFRAuditEntry) {
	if !a.enabled.Load() {
		return
	}
	a.writeLine(formatAXFRAuditLine(entry))
}

// LogIXFR writes an IXFR audit entry.
func (a *AuditLogger) LogIXFR(entry IXFRAuditEntry) {
	if !a.enabled.Load() {
		return
	}
	a.writeLine(formatIXFRAuditLine(entry))
}

// LogNOTIFY writes a NOTIFY audit entry.
func (a *AuditLogger) LogNOTIFY(entry NOTIFYAuditEntry) {
	if !a.enabled.Load() {
		return
	}
	a.writeLine(formatNOTIFYAuditLine(entry))
}

// LogUpdate writes a DDNS UPDATE audit entry.
func (a *AuditLogger) LogUpdate(entry UpdateAuditEntry) {
	if !a.enabled.Load() {
		return
	}
	a.writeLine(formatUpdateAuditLine(entry))
}

// LogReload writes a config reload audit entry.
func (a *AuditLogger) LogReload(entry ReloadAuditEntry) {
	if !a.enabled.Load() {
		return
	}
	a.writeLine(formatReloadAuditLine(entry))
}

// writeLine enqueues a formatted line for the background writer. It NEVER
// blocks the caller (the DNS request path): if the queue is full or the logger
// is shutting down, the line is dropped and counted. a.lines is never closed
// (shutdown is signalled via a.done), so the non-blocking send cannot panic.
func (a *AuditLogger) writeLine(line string) {
	if !a.enabled.Load() {
		return
	}
	select {
	case a.lines <- line:
	case <-a.done:
		// shutting down — drop
	default:
		a.dropped.Add(1)
	}
}

// Dropped returns the number of audit lines dropped because the queue was full.
func (a *AuditLogger) Dropped() uint64 {
	return a.dropped.Load()
}

// LastError returns the most recent write or close error observed by the logger.
func (a *AuditLogger) LastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// Close closes the audit logger and flushes any buffered output.
//
// Without locking, Close raced with concurrent Log* callers: the
// file.Close() ran while another goroutine was holding nothing and
// calling a.output.Write on the same *os.File. Take a.mu so the
// final close happens-after every in-flight write, and flip
// a.enabled to false so subsequent Log* calls fast-path out
// instead of trying to write into a closed descriptor.
//
// Idempotent: re-entry observes enabled=false and a.file==nil and
// returns cleanly.
func (a *AuditLogger) Close() {
	a.closeOnce.Do(func() {
		a.enabled.Store(false)
		if a.done != nil {
			close(a.done) // signal the writer to drain + flush + exit
			a.wg.Wait()   // wait for all queued lines to reach the file
		}
		a.mu.Lock()
		if a.file != nil {
			if err := a.file.Close(); err != nil {
				a.lastErr = err
			}
			a.file = nil
		}
		a.mu.Unlock()
	})
}

func formatQueryAuditLine(e QueryAuditEntry) string {
	cacheHit := "miss"
	if e.CacheHit {
		cacheHit = "hit"
	}
	upstream := "-"
	if e.Upstream != "" {
		upstream = e.Upstream
	}
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s query=%s type=%s rcode=%s latency=%s cache=%s upstream=%s",
		e.Timestamp,
		reqID,
		sanitizeLogToken(e.ClientIP),
		sanitizeLogToken(e.QueryName),
		sanitizeLogToken(e.QueryType),
		e.Rcode,
		e.Latency.Round(time.Microsecond),
		cacheHit,
		upstream,
	)
}

func formatAXFRAuditLine(e AXFRAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s records=%d latency=%s",
		e.Timestamp,
		reqID,
		sanitizeLogToken(e.ClientIP),
		sanitizeLogToken(e.Zone),
		e.Action,
		e.RecordCount,
		e.Latency.Round(time.Millisecond),
	)
}

func formatIXFRAuditLine(e IXFRAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s records=%d latency=%s",
		e.Timestamp,
		reqID,
		sanitizeLogToken(e.ClientIP),
		sanitizeLogToken(e.Zone),
		e.Action,
		e.RecordCount,
		e.Latency.Round(time.Millisecond),
	)
}

func formatNOTIFYAuditLine(e NOTIFYAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s",
		e.Timestamp,
		reqID,
		sanitizeLogToken(e.ClientIP),
		sanitizeLogToken(e.Zone),
		e.Action,
	)
}

func formatUpdateAuditLine(e UpdateAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s rcode=%s added=%d deleted=%d",
		e.Timestamp,
		reqID,
		sanitizeLogToken(e.ClientIP),
		sanitizeLogToken(e.Zone),
		e.Action,
		e.Rcode,
		e.Added,
		e.Deleted,
	)
}

func formatReloadAuditLine(e ReloadAuditEntry) string {
	errStr := ""
	if e.Error != "" {
		errStr = " error=" + sanitizeLogField(e.Error)
	}
	return fmt.Sprintf("%s action=reload.%s zones=%d%s",
		e.Timestamp,
		e.Action,
		e.Zones,
		errStr,
	)
}
