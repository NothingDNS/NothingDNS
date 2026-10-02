package config

import "testing"

// TestRound036TransferJournalDirParsed pins the AGENTS.md silent-ignore
// contract for transfer.journal_dir: the field is declared on
// TransferConfig (yaml "journal_dir"), consumed by
// cmd/nothingdns/transfer_manager.go when set, so unmarshalToConfig must
// read it. It previously read only allow_list and require_tsig in the
// transfer branch, so an operator's journal_dir was silently dropped and
// the IXFR journal silently stayed on the storage.data_dir default —
// with no unknown-key warning, because warnUnknownNestedKeys derives
// known keys from struct yaml tags and journal_dir IS a declared tag.
func TestRound036TransferJournalDirParsed(t *testing.T) {
	cfg, err := UnmarshalYAML("transfer:\n  journal_dir: /custom/journals\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML failed: %v", err)
	}
	if cfg.Transfer.JournalDir != "/custom/journals" {
		t.Fatalf("transfer.journal_dir not parsed: JournalDir=%q, want %q",
			cfg.Transfer.JournalDir, "/custom/journals")
	}
}

// TestRound036TransferSectionStillWired is the control: the sibling keys of
// the transfer section must keep parsing, so a future regression in the
// section's reader is attributable rather than masked.
func TestRound036TransferSectionStillWired(t *testing.T) {
	cfg, err := UnmarshalYAML("transfer:\n  allow_list:\n    - 10.0.0.1\n  require_tsig: true\n  journal_dir: /j\n")
	if err != nil {
		t.Fatalf("UnmarshalYAML failed: %v", err)
	}
	if len(cfg.Transfer.AllowList) != 1 || cfg.Transfer.AllowList[0] != "10.0.0.1" {
		t.Fatalf("allow_list not parsed: %v", cfg.Transfer.AllowList)
	}
	if !cfg.Transfer.RequireTSIG {
		t.Fatal("require_tsig not parsed")
	}
	if cfg.Transfer.JournalDir != "/j" {
		t.Fatalf("journal_dir not parsed alongside siblings: %q", cfg.Transfer.JournalDir)
	}
}
