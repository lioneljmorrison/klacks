package httpapi

// Prekey bundle endpoints (S-22) over the device store. The server validates
// shapes only — sizes, ids, counts; it never sees private key material and
// never verifies signatures. Identity comes from the authenticator (JWT, or
// the dev stub in env dev): a client registers only its own (user, device),
// but may fetch any user's bundle, which is what session initiation needs.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/lioneljmorrison/klacks/internal/auth"
	"github.com/lioneljmorrison/klacks/internal/store"
)

// maxBundleBody caps a bundle upload body: a full batch of
// store.MaxPrekeysPerUpload 32-byte keys base64-encoded stays far below it.
const maxBundleBody = 512 << 10

// DeviceStore is the device/prekey API the Devices handlers serve.
// *store.Devices implements it.
type DeviceStore interface {
	UploadBundle(ctx context.Context, user, device store.UUID, b store.Bundle, prekeys []store.OneTimePrekey) error
	AddOneTimePrekeys(ctx context.Context, user, device store.UUID, prekeys []store.OneTimePrekey) error
	Bundle(ctx context.Context, user, device store.UUID) (store.Bundle, store.Taken, error)
	ListDevices(ctx context.Context, user store.UUID) ([]store.Device, error)
}

// Devices serves the prekey bundle endpoints. A nil authenticator is not
// allowed: build Devices only when there is one.
type Devices struct {
	auth  auth.Authenticator
	store DeviceStore
	log   *slog.Logger
}

// NewDevices returns the prekey bundle handlers. Nil log discards.
func NewDevices(a auth.Authenticator, store DeviceStore, log *slog.Logger) *Devices {
	if log == nil {
		log = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &Devices{auth: a, store: store, log: log}
}

// discardWriter absorbs a nil logger's output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Register adds the endpoints to mux.
func (d *Devices) Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/device/bundle", d.upload)
	mux.HandleFunc("POST /v1/device/prekeys", d.replenish)
	mux.HandleFunc("GET /v1/users/{user}/devices/{device}/bundle", d.fetchBundle)
	mux.HandleFunc("GET /v1/users/{user}/devices", d.list)
}

// uploadRequest is one bundle upload: the full bundle plus the initial batch
// of one-time prekeys. Keys are base64.
type uploadRequest struct {
	IdentityKey     []byte          `json:"identity_key"`
	IdentityDHKey   []byte          `json:"identity_dh_key"`
	SignedPrekeyID  int64           `json:"signed_prekey_id"`
	SignedPrekey    []byte          `json:"signed_prekey"`
	SignedPrekeySig []byte          `json:"signed_prekey_signature"`
	OneTimePrekeys  []oneTimePrekey `json:"one_time_prekeys"`
}

type oneTimePrekey struct {
	ID  int64  `json:"id"`
	Key []byte `json:"key"`
}

// bundleResponse is a fetched bundle. OneTimePrekey is omitted when the
// device has none left.
type bundleResponse struct {
	UserID                  string         `json:"user_id"`
	DeviceID                string         `json:"device_id"`
	IdentityKey             []byte         `json:"identity_key"`
	IdentityDHKey           []byte         `json:"identity_dh_key"`
	SignedPrekeyID          int64          `json:"signed_prekey_id"`
	SignedPrekey            []byte         `json:"signed_prekey"`
	SignedPrekeySig         []byte         `json:"signed_prekey_signature"`
	OneTimePrekey           *oneTimePrekey `json:"one_time_prekey,omitempty"`
	OneTimePrekeysRemaining int            `json:"one_time_prekeys_remaining"`
}

// upload registers or replaces the authenticated device's bundle.
func (d *Devices) upload(w http.ResponseWriter, r *http.Request) {
	id, ok := d.identity(w, r)
	if !ok {
		return
	}
	var req uploadRequest
	if !decode(w, r, &req) {
		return
	}
	prekeys := make([]store.OneTimePrekey, len(req.OneTimePrekeys))
	for i, p := range req.OneTimePrekeys {
		prekeys[i] = store.OneTimePrekey{ID: p.ID, Key: p.Key}
	}
	b := store.Bundle{
		IdentityKey:     req.IdentityKey,
		IdentityDHKey:   req.IdentityDHKey,
		SignedPrekeyID:  req.SignedPrekeyID,
		SignedPrekey:    req.SignedPrekey,
		SignedPrekeySig: req.SignedPrekeySig,
	}
	if err := d.store.UploadBundle(r.Context(), id.UserID, id.DeviceID, b, prekeys); err != nil {
		d.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// replenish adds one-time prekeys to the authenticated device's bundle.
func (d *Devices) replenish(w http.ResponseWriter, r *http.Request) {
	id, ok := d.identity(w, r)
	if !ok {
		return
	}
	var req uploadRequest // the same shape; only one_time_prekeys is read
	if !decode(w, r, &req) {
		return
	}
	prekeys := make([]store.OneTimePrekey, len(req.OneTimePrekeys))
	for i, p := range req.OneTimePrekeys {
		prekeys[i] = store.OneTimePrekey{ID: p.ID, Key: p.Key}
	}
	if err := d.store.AddOneTimePrekeys(r.Context(), id.UserID, id.DeviceID, prekeys); err != nil {
		d.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// fetchBundle returns a user's device bundle and consumes one of its
// one-time prekeys (S-23): the consumed key is deleted server-side, so
// concurrent fetchers never receive the same one.
func (d *Devices) fetchBundle(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.identity(w, r); !ok {
		return
	}
	user, device, ok := pathIDs(w, r)
	if !ok {
		return
	}
	b, taken, err := d.store.Bundle(r.Context(), user, device)
	if err != nil {
		d.writeError(w, err)
		return
	}
	resp := bundleResponse{
		UserID:                  store.FormatUUID(user),
		DeviceID:                store.FormatUUID(device),
		IdentityKey:             b.IdentityKey,
		IdentityDHKey:           b.IdentityDHKey,
		SignedPrekeyID:          b.SignedPrekeyID,
		SignedPrekey:            b.SignedPrekey,
		SignedPrekeySig:         b.SignedPrekeySig,
		OneTimePrekeysRemaining: taken.Remaining,
	}
	if taken.ID != 0 {
		resp.OneTimePrekey = &oneTimePrekey{ID: taken.ID, Key: taken.Key}
	}
	writeJSON(w, http.StatusOK, resp)
}

// list returns a user's registered devices.
func (d *Devices) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.identity(w, r); !ok {
		return
	}
	user, err := store.ParseUUID(r.PathValue("user"))
	if err != nil || user == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "user is not a UUID"})
		return
	}
	devs, err := d.store.ListDevices(r.Context(), user)
	if err != nil {
		d.writeError(w, err)
		return
	}
	type deviceInfo struct {
		DeviceID string `json:"device_id"`
		LastSeen string `json:"last_seen,omitempty"`
	}
	out := make([]deviceInfo, 0, len(devs))
	for _, dev := range devs {
		info := deviceInfo{DeviceID: store.FormatUUID(dev.DeviceID)}
		if dev.LastSeen != nil {
			info.LastSeen = dev.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

// identity authenticates the request and writes the error when it fails.
func (d *Devices) identity(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	id, err := d.auth.Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Code: "unauthenticated", Message: "identity headers required"})
			return auth.Identity{}, false
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
		return auth.Identity{}, false
	}
	return id, true
}

// pathIDs parses the {user} and {device} path values.
func pathIDs(w http.ResponseWriter, r *http.Request) (user, device store.UUID, ok bool) {
	user, err := store.ParseUUID(r.PathValue("user"))
	if err != nil || user == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "user is not a UUID"})
		return user, device, false
	}
	device, err = store.ParseUUID(r.PathValue("device"))
	if err != nil || device == (store.UUID{}) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "device is not a UUID"})
		return user, device, false
	}
	return user, device, true
}

// decode reads and unmarshals a bounded JSON body.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBundleBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_argument", Message: "invalid JSON body"})
		return false
	}
	return true
}

// errorResponse is the REST error body. Code values are stable; message is
// for people and may change.
type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError maps a store error to its REST status. Unexpected errors are
// logged, not sent.
func (d *Devices) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidBundle):
		writeJSON(w, http.StatusBadRequest, errorResponse{Code: "invalid_bundle", Message: err.Error()})
	case errors.Is(err, store.ErrDeviceNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{Code: "device_not_found", Message: "device not found"})
	default:
		d.log.Error("devices: request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Code: "internal", Message: "internal error"})
	}
}
