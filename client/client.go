package client

// The transport: the prekey REST endpoints and the WebSocket messaging
// path, wired to the crypto. This is a reference client — small, blocking,
// and explicit about its states — not a production SDK.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// Client is one device's reference client: its keys, its sessions, and its
// connection to one klacks server (dev identity auth).
type Client struct {
	base   string // REST base URL, http(s)://…
	user   [16]byte
	device [16]byte
	httpc  *http.Client

	// Keys: the identity, the signed prekey, and the private halves of the
	// one-time prekeys, keyed by id. Only the public halves ever leave.
	id       IdentityKey
	spk      SignedPrekey
	opkNext  int64
	opkPrivs map[int64]OneTimePrekey

	// Sessions and per-room receive bookkeeping.
	mu       sync.Mutex
	sessions map[sessionKey]*session
	rooms    map[[16]byte]*roomState
	// pending holds messages that arrived before the session's first
	// message (publishes can commit out of send order): they decrypt once
	// the prekey message establishes the session.
	pending map[sessionKey][]deliver

	// fallbacks are receive-only sessions demoted (or never promoted) by
	// the initiation tie-break, kept while the messages sent over them
	// arrive; fallbackOrder tracks insertion for per-peer eviction.
	fallbacks     map[fallbackKey]*session
	fallbackOrder []fallbackKey

	// Sender keys (S-27, S-28): this device's sending chain per room, the
	// installed chains of each peer sender device per room, and the group
	// messages stashed per sender device while their distribution is in
	// flight.
	skOwn     map[[16]byte]*SenderChain
	skPeers   map[skRef]*SenderKeys
	skPending map[skRef][]deliver

	// roomPeers (S-29) is this device's membership view per room, in
	// devices: every other member device it distributes to, seeded by
	// Distribute and Rotate, updated by removals and the members frame.
	// The view is what rotation redistributes to.
	roomPeers map[[16]byte][]Peer

	// beforePublish, when set, runs after Send seals each envelope and
	// before it is published (SetBeforePublish).
	beforePublish func() error

	// The WebSocket connection and its read loop. readStarted marks a
	// successful Dial: only then does a read loop exist to close
	// readerDone, so Close waits on it only then.
	conn        *websocket.Conn
	readCtx     context.Context
	readCancel  context.CancelFunc
	readerDone  chan struct{} // closed when the read loop exits
	readStarted bool
	log         *slog.Logger

	// Inbox receives one event per delivered message, decrypted or with
	// the reason it was rejected. Errs receives transport-level problems
	// (error frames, read failures). Both close when the client closes.
	Inbox chan Received
	Errs  chan error

	closeOnce sync.Once
	done      chan struct{}
}

// Received is one delivered message, decrypted when it could be.
type Received struct {
	Room         [16]byte
	Seq          int64
	Sender       [16]byte
	SenderDevice [16]byte
	MessageID    [16]byte
	Plaintext    []byte
	// Err is set when the message was rejected: undecryptable, out of
	// order, or otherwise tampered. The client does not deliver
	// plaintext it could not verify.
	Err error
}

// roomState is one room's receive bookkeeping: the seq ordering the server
// promises (per room, gap-free, from 1) is verified here, independently of
// the AEAD — this is how tampering with a stored seq is caught (S-25).
type roomState struct {
	// baseline: the first delivered seq this connection saw; the gap
	// check starts from the second.
	started bool
	lastSeq int64
	// messageID per delivered seq, for duplicate detection.
	seen map[int64][16]byte
	// known message ids at any seq: a repeated id at a different seq is
	// tampering (a row copied across the room's stream).
	ids map[[16]byte]int64
	// removed (S-29): this device was removed from the room. Everything
	// the room still sends the connection — it stays subscribed until the
	// server notices — is dropped unread: distributions must not install,
	// or the removed member could re-enter a chain it no longer holds.
	removed bool
}

// NewClient builds a client for a device, generating fresh key material
// including an initial batch of one-time prekeys.
func NewClient(base string, user, device [16]byte) (*Client, error) {
	id, err := NewIdentity()
	if err != nil {
		return nil, err
	}
	spk, err := NewSignedPrekey(1)
	if err != nil {
		return nil, err
	}
	opks, err := NewOneTimePrekeys(1, 10)
	if err != nil {
		return nil, err
	}
	return newClientWithKeys(base, user, device, id, spk, opks)
}

// NewClientWithKeys builds a client from stored key material, as a device
// restoring its state would.
func NewClientWithKeys(base string, user, device [16]byte, id IdentityKey, spk SignedPrekey, opks []OneTimePrekey) (*Client, error) {
	return newClientWithKeys(base, user, device, id, spk, opks)
}

func newClientWithKeys(base string, user, device [16]byte, id IdentityKey, spk SignedPrekey, opks []OneTimePrekey) (*Client, error) {
	if spk.ID < 1 {
		return nil, errors.New("client: signed prekey id must be >= 1")
	}
	c := &Client{
		base:       strings.TrimSuffix(base, "/"),
		user:       user,
		device:     device,
		id:         id,
		spk:        spk,
		opkNext:    1,
		opkPrivs:   make(map[int64]OneTimePrekey, len(opks)),
		sessions:   make(map[sessionKey]*session),
		rooms:      make(map[[16]byte]*roomState),
		pending:    make(map[sessionKey][]deliver),
		fallbacks:  make(map[fallbackKey]*session),
		skOwn:      make(map[[16]byte]*SenderChain),
		skPeers:    make(map[skRef]*SenderKeys),
		skPending:  make(map[skRef][]deliver),
		roomPeers:  make(map[[16]byte][]Peer),
		httpc:      &http.Client{},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Inbox:      make(chan Received, 1024),
		Errs:       make(chan error, 64),
		done:       make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	if err := c.AddOneTimePrekeys(opks); err != nil {
		return nil, err
	}
	return c, nil
}

// AddOneTimePrekeys generates n fresh one-time prekeys, adds their private
// halves locally, and returns the whole key pairs.
func (c *Client) AddOneTimePrekeys(opks []OneTimePrekey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.opkNext
	for _, p := range opks {
		if p.ID < next {
			return fmt.Errorf("client: one-time prekey id %d below next %d", p.ID, next)
		}
		next = p.ID + 1
		c.opkPrivs[p.ID] = p
	}
	c.opkNext = next
	return nil
}

// OneTimePrekeysHeld reports how many one-time prekey private halves the
// client still holds.
func (c *Client) OneTimePrekeysHeld() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.opkPrivs)
}

// HeldOneTimePrekeys returns copies of the one-time prekey pairs the client
// still holds, for callers that persist key material (the keyfile sync in
// cmd/testchat). The client keeps a private's half after the server has
// deleted the public one only until an initiation consumes it; what is
// held here is exactly what a restart must carry forward.
func (c *Client) HeldOneTimePrekeys() []OneTimePrekey {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]OneTimePrekey, 0, len(c.opkPrivs))
	for _, p := range c.opkPrivs {
		out = append(out, p)
	}
	return out
}

// NewOneTimePrekeys generates n keys locally and returns them for upload.
func (c *Client) NewOneTimePrekeys(n int) ([]OneTimePrekey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	from := c.opkNext
	opks, err := NewOneTimePrekeys(int(from), n)
	if err != nil {
		return nil, err
	}
	c.opkNext = from + int64(n)
	for _, p := range opks {
		c.opkPrivs[p.ID] = p
	}
	return opks, nil
}

// identity headers, the dev auth this reference client speaks.
func (c *Client) authHeaders(req *http.Request) {
	req.Header.Set("X-Klacks-User", format(c.user))
	req.Header.Set("X-Klacks-Device", format(c.device))
}

// rest does one JSON REST call with dev auth headers.
func (c *Client) rest(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	c.authHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	return nil
}

// registerBundleUpload is the device's full bundle for PUT /v1/device/bundle.
type registerBundleUpload struct {
	IdentityKey           []byte       `json:"identity_key"`
	IdentityDHKey         []byte       `json:"identity_dh_key"`
	SignedPrekeyID        int64        `json:"signed_prekey_id"`
	SignedPrekey          []byte       `json:"signed_prekey"`
	SignedPrekeySignature []byte       `json:"signed_prekey_signature"`
	OneTimePrekeys        []wirePrekey `json:"one_time_prekeys"`
}

// Register uploads this device's bundle with its one-time prekeys.
func (c *Client) Register(ctx context.Context) error {
	dhPub, err := c.id.DHPublic()
	if err != nil {
		return err
	}
	sig := c.id.SignBundleKeys(dhPub, c.spk.Pub)
	c.mu.Lock()
	wire := make([]wirePrekey, 0, len(c.opkPrivs))
	for id, p := range c.opkPrivs {
		wire = append(wire, wirePrekey{ID: id, Key: p.Pub[:]})
	}
	c.mu.Unlock()
	return c.rest(ctx, http.MethodPut, "/v1/device/bundle", &registerBundleUpload{
		IdentityKey:           c.id.EdPublic(),
		IdentityDHKey:         dhPub[:],
		SignedPrekeyID:        c.spk.ID,
		SignedPrekey:          c.spk.Pub[:],
		SignedPrekeySignature: sig,
		OneTimePrekeys:        wire,
	}, nil)
}

// Replenish uploads n fresh one-time prekeys.
func (c *Client) Replenish(ctx context.Context, n int) error {
	opks, err := c.NewOneTimePrekeys(n)
	if err != nil {
		return err
	}
	wire := make([]wirePrekey, len(opks))
	for i, p := range opks {
		wire[i] = wirePrekey{ID: p.ID, Key: p.Pub[:]}
	}
	return c.rest(ctx, http.MethodPost, "/v1/device/prekeys", &struct {
		OneTimePrekeys []wirePrekey `json:"one_time_prekeys"`
	}{wire}, nil)
}

// fetchBundle gets (user, device)'s bundle, consuming one of its one-time
// prekeys server-side (S-23).
func (c *Client) fetchBundle(ctx context.Context, user, device [16]byte) (Bundle, error) {
	var w wireBundle
	if err := c.rest(ctx, http.MethodGet,
		"/v1/users/"+format(user)+"/devices/"+format(device)+"/bundle", nil, &w); err != nil {
		return Bundle{}, err
	}
	return w.bundle(), nil
}

// FetchBundle is the exported form.
func (c *Client) FetchBundle(ctx context.Context, user, device [16]byte) (Bundle, error) {
	return c.fetchBundle(ctx, user, device)
}

// ListDevices returns user's registered device UUIDs.
func (c *Client) ListDevices(ctx context.Context, user [16]byte) ([][16]byte, error) {
	var devs []struct {
		DeviceID string `json:"device_id"`
	}
	if err := c.rest(ctx, http.MethodGet, "/v1/users/"+format(user)+"/devices", nil, &devs); err != nil {
		return nil, err
	}
	out := make([][16]byte, 0, len(devs))
	for _, d := range devs {
		u, err := parseUUID(d.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("list devices: %w", err)
		}
		out = append(out, u)
	}
	return out, nil
}
