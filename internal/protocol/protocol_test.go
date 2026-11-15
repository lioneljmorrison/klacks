package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
)

const (
	roomStr   = "11111111-1111-1111-1111-111111111111"
	msgStr    = "22222222-2222-2222-2222-222222222222"
	deviceStr = "33333333-3333-3333-3333-333333333333"
	senderStr = "44444444-4444-4444-4444-444444444444"
)

func mustID(t *testing.T, s string) UUID {
	t.Helper()
	u, err := store.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return UUID(u)
}

func TestDecodeClientFrames(t *testing.T) {
	room, msg, device := mustID(t, roomStr), mustID(t, msgStr), mustID(t, deviceStr)
	for _, tc := range []struct {
		in   string
		want Frame
	}{
		{
			`{"v":1,"type":"subscribe","room_id":"` + roomStr + `"}`,
			&Subscribe{Envelope{1, TypeSubscribe}, room},
		},
		{
			`{"v":1,"type":"resume","room_id":"` + roomStr + `","last_seen_seq":0}`,
			&Resume{Envelope{1, TypeResume}, room, 0},
		},
		{
			`{"v":1,"type":"resume","room_id":"` + roomStr + `","last_seen_seq":41}`,
			&Resume{Envelope{1, TypeResume}, room, 41},
		},
		{
			`{"v":1,"type":"publish","room_id":"` + roomStr + `","message_id":"` + msgStr +
				`","device_id":"` + deviceStr + `","header":"aGRy","ciphertext":"Y3Q="}`,
			&Publish{Envelope{1, TypePublish}, room, msg, device, []byte("hdr"), []byte("ct")},
		},
		{
			// header is optional
			`{"v":1,"type":"publish","room_id":"` + roomStr + `","message_id":"` + msgStr +
				`","device_id":"` + deviceStr + `","ciphertext":"Y3Q="}`,
			&Publish{Envelope{1, TypePublish}, room, msg, device, nil, []byte("ct")},
		},
		{
			`{"v":1,"type":"ack","room_id":"` + roomStr + `","seq":7}`,
			&Ack{Envelope{1, TypeAck}, room, 7},
		},
		{
			// unknown fields are ignored
			`{"v":1,"type":"ack","room_id":"` + roomStr + `","seq":7,"future":true}`,
			&Ack{Envelope{1, TypeAck}, room, 7},
		},
	} {
		got, err := Decode([]byte(tc.in))
		if err != nil {
			t.Errorf("Decode(%s): %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Decode(%s) = %#v; want %#v", tc.in, got, tc.want)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	pub := func(fields string) string {
		return `{"v":1,"type":"publish"` + fields + `}`
	}
	okPub := `,"room_id":"` + roomStr + `","message_id":"` + msgStr + `","device_id":"` + deviceStr + `"`
	zero := "00000000-0000-0000-0000-000000000000"
	for _, tc := range []struct {
		in   string
		want error
	}{
		{``, ErrBadFrame},
		{`not json`, ErrBadFrame},
		{`[]`, ErrBadFrame},
		{`{"v":1,"type":"ack","room_id":"` + roomStr + `","seq":1} trailing`, ErrBadFrame},
		{`{"type":"ack","room_id":"` + roomStr + `","seq":1}`, ErrUnsupportedVersion},
		{`{"v":2,"type":"ack","room_id":"` + roomStr + `","seq":1}`, ErrUnsupportedVersion},
		{`{"v":1,"type":"nope"}`, ErrUnknownType},
		{`{"v":1}`, ErrUnknownType},
		// server-to-client frames are not accepted from clients
		{`{"v":1,"type":"deliver","room_id":"` + roomStr + `","seq":1}`, ErrUnknownType},
		{`{"v":1,"type":"error","code":"internal"}`, ErrUnknownType},
		{`{"v":1,"type":"subscribe"}`, ErrBadFrame},
		{`{"v":1,"type":"subscribe","room_id":"` + zero + `"}`, ErrBadFrame},
		{`{"v":1,"type":"subscribe","room_id":"x"}`, ErrBadFrame},
		{`{"v":1,"type":"subscribe","room_id":12345678901234567890123456789012}`, ErrBadFrame},
		{`{"v":1,"type":"resume","room_id":"` + roomStr + `","last_seen_seq":-1}`, ErrBadFrame},
		{`{"v":1,"type":"ack","room_id":"` + roomStr + `","seq":0}`, ErrBadFrame},
		{`{"v":1,"type":"ack","room_id":"` + roomStr + `","seq":"1"}`, ErrBadFrame},
		{pub(okPub), ErrBadFrame}, // no ciphertext
		{pub(okPub + `,"ciphertext":""`), ErrBadFrame},
		{pub(okPub + `,"ciphertext":"!!"`), ErrBadFrame},
		{pub(`,"room_id":"` + roomStr + `","device_id":"` + deviceStr + `","ciphertext":"Y3Q="`), ErrBadFrame},
		{pub(`,"room_id":"` + roomStr + `","message_id":"` + msgStr + `","ciphertext":"Y3Q="`), ErrBadFrame},
	} {
		_, err := Decode([]byte(tc.in))
		if !errors.Is(err, tc.want) {
			t.Errorf("Decode(%s) err = %v; want %v", tc.in, err, tc.want)
		}
	}
}

func TestEncodeDeliver(t *testing.T) {
	b, err := Encode(&Deliver{
		RoomID:     mustID(t, roomStr),
		Seq:        9,
		MessageID:  mustID(t, msgStr),
		SenderID:   mustID(t, senderStr),
		DeviceID:   mustID(t, deviceStr),
		Header:     []byte("hdr"),
		Ciphertext: []byte("ct"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"type":"deliver","room_id":"` + roomStr + `","seq":9,"message_id":"` + msgStr +
		`","sender_id":"` + senderStr + `","device_id":"` + deviceStr + `","header":"aGRy","ciphertext":"Y3Q="}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestEncodeError(t *testing.T) {
	b, err := Encode(&Error{Code: CodeBadFrame, Message: "bad frame"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"v":1,"type":"error","code":"bad_frame","message":"bad frame"}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	b, err = Encode(&Error{Code: CodeNotMember, Message: "x", RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr)})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"v":1,"type":"error","code":"not_member","message":"x","room_id":"` + roomStr +
		`","message_id":"` + msgStr + `"}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := &Publish{RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
		Header: []byte{0, 1, 2}, Ciphertext: []byte{0xff, 0xfe}}
	b, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	in.Envelope = Envelope{Version, TypePublish}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("got %#v; want %#v", got, in)
	}
}

// A publish carrying the largest payload core accepts must fit in
// MaxFrameSize, so the transport's read limit never drops a legal frame.
func TestMaxFrameSizeFitsMaxPayload(t *testing.T) {
	for _, split := range []int{0, 1, 2, core.MaxPayloadSize / 2, core.MaxPayloadSize - 1, core.MaxPayloadSize} {
		b, err := Encode(&Publish{
			RoomID: mustID(t, roomStr), MessageID: mustID(t, msgStr), DeviceID: mustID(t, deviceStr),
			Header:     bytes.Repeat([]byte{0xff}, split),
			Ciphertext: bytes.Repeat([]byte{0xff}, core.MaxPayloadSize-split),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > MaxFrameSize {
			t.Errorf("split %d: frame is %d bytes > MaxFrameSize %d", split, len(b), MaxFrameSize)
		}
	}
}

func TestErrorFor(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("decode: %w", ErrBadFrame), CodeBadFrame},
		{ErrUnsupportedVersion, CodeUnsupportedVersion},
		{ErrUnknownType, CodeUnknownType},
		{fmt.Errorf("post: %w", core.ErrPayloadTooLarge), CodePayloadTooLarge},
		{fmt.Errorf("post: %w", core.ErrNotMember), CodeNotMember},
		{core.ErrForbidden, CodeForbidden},
		{core.ErrRoomNotFound, CodeRoomNotFound},
		{core.ErrInvalidArgument, CodeInvalidArgument},
		{errors.New("pg: connection refused at 10.0.0.5"), CodeInternal},
		{fmt.Errorf("post message: %w", context.DeadlineExceeded), CodeUnavailable},
		{fmt.Errorf("post message: scylla: %w", gocql.ErrTimeoutNoResponse), CodeUnavailable},
	} {
		got := ErrorFor(tc.err)
		if got.Code != tc.code {
			t.Errorf("ErrorFor(%v).Code = %q; want %q", tc.err, got.Code, tc.code)
		}
		if got.Message == "" {
			t.Errorf("ErrorFor(%v).Message is empty", tc.err)
		}
	}
	// A decode error tells the client what was wrong with its frame.
	_, err := Decode([]byte(`{"v":1,"type":"subscribe"}`))
	if got := ErrorFor(err); !strings.Contains(got.Message, "room_id is required") {
		t.Errorf("bad_frame message = %q; want the reason", got.Message)
	}
	// An outage names no store detail either.
	if got := ErrorFor(fmt.Errorf("pg 10.0.0.5: %w", context.DeadlineExceeded)); strings.Contains(got.Message, "10.0.0.5") {
		t.Errorf("unavailable error leaked: %q", got.Message)
	}
	// Internal details never reach the client.
	if got := ErrorFor(errors.New("pg: connection refused at 10.0.0.5")); strings.Contains(got.Message, "10.0.0.5") {
		t.Errorf("internal error leaked: %q", got.Message)
	}
}

func TestUUIDJSON(t *testing.T) {
	b, err := json.Marshal(mustID(t, roomStr))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"`+roomStr+`"` {
		t.Errorf("got %s", b)
	}
}

// docs/protocol.md states the size limits; keep it in step.
func TestDocLimits(t *testing.T) {
	doc, err := os.ReadFile("../../docs/protocol.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{MaxFrameSize, core.MaxPayloadSize} {
		if s := commas(n); !strings.Contains(string(doc), s) {
			t.Errorf("docs/protocol.md does not mention %s", s)
		}
	}
}

func commas(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
