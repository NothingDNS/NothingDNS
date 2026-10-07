package protocol

import (
	"runtime/debug"
	"testing"
	"unsafe"
)

func f592Wire(t testing.TB, id uint16, name string) []byte {
	t.Helper()
	q, err := NewQuery(id, name, TypeA)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// TestReleaseOfNonPooledMessageIsNoOp (F592): Release must only recycle
// Messages obtained from UnpackMessage/AcquireMessage. A hand-built Message
// sharing section slices with a live pooled Message must neither zero the
// shared entries nor hand the shared backing array to the next pool user.
func TestReleaseOfNonPooledMessageIsNoOp(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	live, err := UnpackMessage(f592Wire(t, 0x1111, "live.example."))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()
	liveArr := unsafe.SliceData(live.Questions)
	liveRR := &ResourceRecord{Name: live.Questions[0].Name, Type: TypeA, Class: ClassIN, TTL: 60, Data: &RDataA{Address: [4]byte{192, 0, 2, 1}}}
	live.Answers = append(live.Answers, liveRR)

	// reply()-style response aliasing the live query's slices.
	reply := &Message{Questions: live.Questions, Answers: live.Answers}
	reply.Header.Flags.QR = true
	reply.Release()
	reply.Release()

	if live.Questions[0] == nil || live.Questions[0].Name == nil || live.Questions[0].Name.String() != "live.example." {
		t.Fatalf("Release of a hand-built reply corrupted the live query's question: %v", live.Questions[0])
	}
	if live.Answers[0] != liveRR || liveRR.TTL != 60 || liveRR.Data == nil {
		t.Fatalf("Release of a hand-built reply zeroed a shared answer record: %+v", liveRR)
	}

	// Other non-pooled constructors: NewMessage, NewQuery, Copy.
	nm := NewMessage(Header{ID: 1})
	nq, err := NewQuery(2, "nq.example.", TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	cp := live.Copy()
	foreign := map[*Message]bool{reply: true, nm: true, nq: true, cp: true}
	for m := range foreign {
		m.Release()
	}
	if nq.Questions[0] == nil || nq.Questions[0].Name.String() != "nq.example." {
		t.Fatal("Release of a NewQuery message zeroed its question")
	}
	if cp.Answers[0] == nil || cp.Answers[0].TTL != 60 {
		t.Fatal("Release of a Copy zeroed its records")
	}

	for i := 0; i < 8; i++ {
		got := AcquireMessage()
		if foreign[got] {
			t.Fatalf("AcquireMessage returned a never-pooled *Message (%p)", got)
		}
		if unsafe.SliceData(got.Questions[:cap(got.Questions)]) == liveArr {
			t.Fatal("AcquireMessage returned a Questions backing array still owned by a live Message")
		}
		u, err := UnpackMessage(f592Wire(t, uint16(i), "next.example."))
		if err != nil {
			t.Fatal(err)
		}
		if foreign[u] || unsafe.SliceData(u.Questions) == liveArr {
			t.Fatal("UnpackMessage reused a never-pooled Message or a live backing array")
		}
	}
}

// TestPooledMessageStillRecycled guards the pooled path after F592: a
// Message from UnpackMessage/AcquireMessage is still returned to the pool by
// Release (and only once — F103).
func TestPooledMessageStillRecycled(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	wire := f592Wire(t, 7, "pooled.example.")

	reused := false
	for i := 0; i < 200 && !reused; i++ {
		m, err := UnpackMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		m.Release()
		m2, err := UnpackMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		reused = m2 == m
		m2.Release()
	}
	if !reused {
		t.Fatal("a Released UnpackMessage result was never handed out again; pooled path no longer recycles")
	}

	a := AcquireMessage()
	a.Release()
	a.Release() // F103: second Release stays a no-op
	b, c := AcquireMessage(), AcquireMessage()
	if b == c {
		t.Fatal("double Release of an acquired Message put it into the pool twice")
	}
}
