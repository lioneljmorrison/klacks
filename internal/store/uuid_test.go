package store

import "testing"

func TestParseUUID(t *testing.T) {
	want := UUID{0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00}
	for _, s := range []string{
		"123e4567-e89b-12d3-a456-426614174000",
		"123E4567-E89B-12D3-A456-426614174000",
	} {
		got, err := ParseUUID(s)
		if err != nil || got != want {
			t.Errorf("ParseUUID(%q) = %x, %v; want %x", s, got, err, want)
		}
	}
	for _, s := range []string{
		"",
		"123e4567e89b12d3a456426614174000",      // no hyphens
		"123e4567-e89b-12d3-a456-42661417400",   // short
		"123e4567-e89b-12d3-a456-4266141740000", // long
		"123e456-7e89b-12d3-a456-426614174000",  // hyphen misplaced
		"123e4567-e89b-12d3-a456-42661417400g",  // not hex
		"{123e4567-e89b-12d3-a456-426614174000}",
	} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("ParseUUID(%q) succeeded; want error", s)
		}
	}
}

func TestFormatUUID(t *testing.T) {
	const s = "123e4567-e89b-12d3-a456-426614174000"
	u, err := ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatUUID(u); got != s {
		t.Errorf("FormatUUID = %q; want %q", got, s)
	}
}
