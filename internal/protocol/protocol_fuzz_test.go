package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to the frame decoder (S-35). It must
// never panic, and anything it accepts must be a valid frame that survives
// an encode/decode round trip unchanged, so what the server acts on is
// exactly what the bytes said.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"type":"subscribe","room_id":"33333333-3333-3333-3333-333333333333"}`,
		`{"v":1,"type":"resume","room_id":"33333333-3333-3333-3333-333333333333","last_seen_seq":7}`,
		`{"v":1,"type":"publish","room_id":"33333333-3333-3333-3333-333333333333","message_id":"44444444-4444-4444-4444-444444444444","device_id":"22222222-2222-2222-2222-222222222222","header":"aGRy","ciphertext":"Y3Q="}`,
		`{"v":1,"type":"ack","room_id":"33333333-3333-3333-3333-333333333333","seq":3}`,
		`{"v":2,"type":"ack"}`,
		`{"v":1,"type":"deliver"}`,
		`{"v":1,"type":"publish","ciphertext":"!!"}`,
		`{"v":1,"type":"resume","room_id":"33333333-3333-3333-3333-333333333333","last_seen_seq":-1}`,
		`[]`, `null`, ``, `{"v":1e999}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Decode(b)
		if err != nil {
			return
		}
		if err := validate(fr); err != nil {
			t.Fatalf("Decode accepted an invalid frame: %v", err)
		}
		enc, err := Encode(fr)
		if err != nil {
			t.Fatalf("re-encode %T: %v", fr, err)
		}
		again, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode of re-encoded %s: %v", enc, err)
		}
		// The canonical encoding is a fixed point. (Comparing encodings,
		// not structs, treats an empty and an absent byte field alike:
		// both mean "none".)
		enc2, err := Encode(again)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("round trip changed the frame:\n %s\n %s", enc, enc2)
		}
		if reflect.TypeOf(fr) != reflect.TypeOf(again) {
			t.Fatalf("round trip changed the frame type: %T -> %T", fr, again)
		}
	})
}
