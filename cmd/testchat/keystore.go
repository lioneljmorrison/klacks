package main

// The device's persisted state in ~/.klacks-testchat: its keys
// (<user>-<device>.json) and its ratchet sessions
// (<user>-<device>.sessions.json). The same -user name is the same device
// with the same keys and sessions on every run, so what peers seal over
// those sessions decrypts after a restart — the reference client's
// NewClientWithKeys and RestoreState are the "a device restoring its
// state" path this uses.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/lioneljmorrison/klacks/client"
)

// keyState is one device's secret material on disk. Only the identity's
// Ed25519 seed is stored for the identity: the client derives both the
// signing key and its X25519 (Montgomery) form from it, deterministically.
// The prekeys store their public halves too, so no derivation is needed
// beyond NewIdentityFromSeed. Registered records that the server accepted
// this bundle: later runs skip re-registering, because a wholesale
// re-upload would resurrect one-time prekeys peers have already consumed.
type keyState struct {
	IdentitySeed   string       `json:"identity_seed"`
	SignedPrekey   wirePrekey   `json:"signed_prekey"`
	OneTimePrekeys []wirePrekey `json:"one_time_prekeys"`
	Registered     bool         `json:"registered"`
}

// wirePrekey is one X25519 key pair, hex-encoded.
type wirePrekey struct {
	ID   int64  `json:"id"`
	Priv string `json:"priv"`
	Pub  string `json:"pub"`
}

// keyFilePath is where this device's keys live: one file per identity.
func keyFilePath(user, device [16]byte) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".klacks-testchat")
	return filepath.Join(dir, uuidString(user)+"-"+uuidString(device)+".json"), nil
}

// loadKeys reads the persisted key state, or nil when there is none. The
// path is built from this device's own identity, never user input.
func loadKeys(path string) (*keyState, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the path is derived from the device identity, not user input
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ks keyState
	if err := json.Unmarshal(b, &ks); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &ks, nil
}

// saveKeys writes the key state with owner-only permissions.
func saveKeys(path string, ks *keyState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'))
}

// writeFileAtomic writes data owner-only via a temporary file and a
// rename, so a crash mid-write leaves the previous file intact.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// sessionsPath is where the device's client state (sessions, room
// positions, stashes, sender keys) is saved, next to its key file:
// <user>-<device>.sessions.json. The name predates S-42's wider snapshot;
// the client still reads the older sessions-only format.
func sessionsPath(keyPath string) string {
	return strings.TrimSuffix(keyPath, ".json") + ".sessions.json"
}

// restoreSessions loads the saved client state into c; none saved (a first
// run, or -fresh) is not an error.
func restoreSessions(c *client.Client, keyPath string) error {
	b, err := os.ReadFile(sessionsPath(keyPath)) //nolint:gosec // derived from the device identity, not user input
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return c.RestoreState(b)
}

// saveState writes the device's state: the key file (with the one-time
// prekeys still held) and the session snapshot. It runs before every
// publish (the client's BeforePublish hook), after every delivery and at
// shutdown. Before every publish is the part that matters for safety: a
// send chain step that reached the wire but not the disk would come back
// after a restart and seal the next message under the same key and nonce.
//
// Sessions are written first. A one-time prekey leaves the key file once an
// initiation consumed it; were the key file written first, a crash between
// the two writes would lose that prekey's private half with the session it
// built unsaved, and the initiation's redelivery could never be answered.
// The other way round, a crash leaves only an unneeded private half behind.
// The pool is read before the sessions, so it never misses a prekey a saved
// session has not consumed yet.
func (a *app) saveState() error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	syncKeysFromClient(a.keys, a.c)
	b, err := a.c.MarshalState()
	if err != nil {
		return fmt.Errorf("save sessions: %w", err)
	}
	if err := writeFileAtomic(sessionsPath(a.keyPath), b); err != nil {
		return fmt.Errorf("save sessions: %w", err)
	}
	if err := saveKeys(a.keyPath, a.keys); err != nil {
		return fmt.Errorf("save keys: %w", err)
	}
	return nil
}

// saveRegistered records that the server holds this device's bundle and
// saves the state. The pump may be saving concurrently, so the flag is set
// under saveMu like every other write to the key state.
func (a *app) saveRegistered() error {
	a.saveMu.Lock()
	a.keys.Registered = true
	a.saveMu.Unlock()
	return a.saveState()
}

// clientFromKeys builds the reference client from persisted material.
func clientFromKeys(base string, user, device [16]byte, ks *keyState) (*client.Client, error) {
	seed, err := hex.DecodeString(ks.IdentitySeed)
	if err != nil || len(seed) != 32 {
		return nil, errors.New("keyfile: bad identity seed")
	}
	id, err := client.NewIdentityFromSeed(seed)
	if err != nil {
		return nil, err
	}
	spk, err := prekeyFromWire(ks.SignedPrekey)
	if err != nil {
		return nil, fmt.Errorf("keyfile: signed prekey: %w", err)
	}
	opks := make([]client.OneTimePrekey, 0, len(ks.OneTimePrekeys))
	for _, w := range ks.OneTimePrekeys {
		p, err := prekeyFromWire(w)
		if err != nil {
			return nil, fmt.Errorf("keyfile: one-time prekey %d: %w", w.ID, err)
		}
		// SignedPrekey and OneTimePrekey share one layout.
		opks = append(opks, client.OneTimePrekey(p))
	}
	return client.NewClientWithKeys(base, user, device, id, spk, opks)
}

// prekeyFromWire decodes one hex key pair. The public half must match the
// private one's X25519 form — a corrupted or hand-edited keyfile must not
// register quietly.
func prekeyFromWire(w wirePrekey) (client.SignedPrekey, error) {
	priv, err := hex.DecodeString(w.Priv)
	if err != nil || len(priv) != 32 {
		return client.SignedPrekey{}, errors.New("bad private half")
	}
	pub, err := hex.DecodeString(w.Pub)
	if err != nil || len(pub) != 32 {
		return client.SignedPrekey{}, errors.New("bad public half")
	}
	var priv32, pub32 [32]byte
	copy(priv32[:], priv)
	copy(pub32[:], pub)
	derived, err := curve25519.X25519(priv32[:], curve25519.Basepoint)
	if err != nil {
		return client.SignedPrekey{}, err
	}
	if string(derived) != string(pub) {
		return client.SignedPrekey{}, errors.New("public half does not match the private one")
	}
	return client.SignedPrekey{ID: w.ID, Priv: priv32, Pub: pub32}, nil
}

// freshKeys generates a whole new device key set for saving.
func freshKeys() (*keyState, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	spk, err := newKeyPair()
	if err != nil {
		return nil, err
	}
	ks := &keyState{
		IdentitySeed: hex.EncodeToString(seed),
		SignedPrekey: wirePrekey{ID: 1, Priv: hex.EncodeToString(spk.priv[:]), Pub: hex.EncodeToString(spk.pub[:])},
	}
	for id := int64(1); id <= 10; id++ {
		p, err := newKeyPair()
		if err != nil {
			return nil, err
		}
		ks.OneTimePrekeys = append(ks.OneTimePrekeys, wirePrekey{
			ID: id, Priv: hex.EncodeToString(p.priv[:]), Pub: hex.EncodeToString(p.pub[:]),
		})
	}
	return ks, nil
}

// syncKeysFromClient writes back the client's current pool: the identity
// seed and signed prekey are unchanged, but initiations consume one-time
// prekeys while the session runs, and a restart must carry exactly what is
// left.
func syncKeysFromClient(ks *keyState, c *client.Client) {
	held := c.HeldOneTimePrekeys()
	out := make([]wirePrekey, 0, len(held))
	for _, p := range held {
		out = append(out, wirePrekey{ID: p.ID, Priv: hex.EncodeToString(p.Priv[:]), Pub: hex.EncodeToString(p.Pub[:])})
	}
	// Ascending by id: the client validates a restored pool in order, and
	// the held pool comes out of a map.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	ks.OneTimePrekeys = out
}

type keyPair struct {
	priv [32]byte
	pub  [32]byte
}

func newKeyPair() (keyPair, error) {
	var p keyPair
	if _, err := rand.Read(p.priv[:]); err != nil {
		return p, err
	}
	pub, err := curve25519.X25519(p.priv[:], curve25519.Basepoint)
	if err != nil {
		return p, err
	}
	copy(p.pub[:], pub)
	return p, nil
}
