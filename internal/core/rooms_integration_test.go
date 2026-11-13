//go:build integration

package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lioneljmorrison/klacks/internal/core"
	"github.com/lioneljmorrison/klacks/internal/store"
	"github.com/lioneljmorrison/klacks/internal/testutil/dbtest"
)

func id(b byte) store.UUID { return store.UUID{15: b} }

var (
	owner = id(0xb1)
	alice = id(0xb2)
	bob   = id(0xb3)
)

// removals records MemberRemoved events.
type removals []core.MemberRemoved

func (r *removals) hook(_ context.Context, e core.MemberRemoved) { *r = append(*r, e) }

func newService(t *testing.T, onRemoved func(context.Context, core.MemberRemoved)) *core.Service {
	t.Helper()
	return core.New(store.NewRooms(dbtest.MigratedPostgres(t), 10*time.Second), nil, nil, onRemoved)
}

func TestCreateRoomKinds(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	for _, k := range []core.Kind{core.KindDM, core.KindGroup, core.KindSpace} {
		if _, err := svc.CreateRoom(ctx, k, owner); err != nil {
			t.Errorf("kind %q: %v", k, err)
		}
	}
	if _, err := svc.CreateRoom(ctx, "channel", owner); !errors.Is(err, core.ErrInvalidArgument) {
		t.Errorf("unknown kind: err = %v, want ErrInvalidArgument", err)
	}
}

func TestMembershipLifecycle(t *testing.T) {
	var got removals
	svc := newService(t, got.hook)
	ctx := context.Background()
	room, err := svc.CreateRoom(ctx, core.KindGroup, owner)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.AddMember(ctx, room, owner, alice, core.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, room, owner, alice, core.RoleAdmin); !errors.Is(err, core.ErrAlreadyMember) {
		t.Fatalf("re-add: err = %v, want ErrAlreadyMember", err)
	}
	if err := svc.AddMember(ctx, room, owner, bob, "superuser"); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("unknown role: err = %v, want ErrInvalidArgument", err)
	}
	if err := svc.AddMember(ctx, id(0xee), owner, bob, core.RoleMember); !errors.Is(err, core.ErrRoomNotFound) {
		t.Fatalf("missing room: err = %v, want ErrRoomNotFound", err)
	}

	if err := svc.RemoveMember(ctx, room, owner, alice); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (core.MemberRemoved{Room: room, User: alice, Actor: owner}) {
		t.Fatalf("events = %+v, want one removal of alice by owner", got)
	}
	if err := svc.RemoveMember(ctx, room, owner, alice); !errors.Is(err, core.ErrMemberNotFound) {
		t.Fatalf("remove twice: err = %v, want ErrMemberNotFound", err)
	}
	if len(got) != 1 {
		t.Fatalf("failed removal emitted an event: %+v", got)
	}
	// Removed members can be added back.
	if err := svc.AddMember(ctx, room, owner, alice, core.RoleMember); err != nil {
		t.Fatal(err)
	}
}

// TestMembershipAuthorization checks that AddMember and RemoveMember enforce
// the authorizer against roles read from the database, including for a
// removed member. The full role matrix is in TestAuthorize.
func TestMembershipAuthorization(t *testing.T) {
	var got removals
	svc := newService(t, got.hook)
	ctx := context.Background()
	admin, member, gone, outsider := id(0xc1), id(0xc2), id(0xc3), id(0xc4)
	room, err := svc.CreateRoom(ctx, core.KindGroup, owner)
	if err != nil {
		t.Fatal(err)
	}
	for user, role := range map[store.UUID]core.Role{admin: core.RoleAdmin, member: core.RoleMember, gone: core.RoleMember} {
		if err := svc.AddMember(ctx, room, owner, user, role); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.RemoveMember(ctx, room, gone, gone); err != nil {
		t.Fatalf("member leaving: %v", err)
	}

	tests := []struct {
		name string
		do   func() error
		want error
	}{
		{"admin adds member", func() error { return svc.AddMember(ctx, room, admin, alice, core.RoleMember) }, nil},
		{"admin adds admin", func() error { return svc.AddMember(ctx, room, admin, bob, core.RoleAdmin) }, core.ErrForbidden},
		{"member adds member", func() error { return svc.AddMember(ctx, room, member, bob, core.RoleMember) }, core.ErrForbidden},
		{"outsider adds member", func() error { return svc.AddMember(ctx, room, outsider, bob, core.RoleMember) }, core.ErrNotMember},
		{"removed member adds member", func() error { return svc.AddMember(ctx, room, gone, bob, core.RoleMember) }, core.ErrNotMember},
		{"removed member removes member", func() error { return svc.RemoveMember(ctx, room, gone, member) }, core.ErrNotMember},
		{"member removes member", func() error { return svc.RemoveMember(ctx, room, member, alice) }, core.ErrForbidden},
		{"admin removes owner", func() error { return svc.RemoveMember(ctx, room, admin, owner) }, core.ErrForbidden},
		{"admin removes non-member", func() error { return svc.RemoveMember(ctx, room, admin, outsider) }, core.ErrMemberNotFound},
		{"admin removes member", func() error { return svc.RemoveMember(ctx, room, admin, alice) }, nil},
		{"owner removes admin", func() error { return svc.RemoveMember(ctx, room, owner, admin) }, nil},
	}
	for _, tt := range tests {
		err := tt.do()
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
	want := []core.MemberRemoved{
		{Room: room, User: gone, Actor: gone},
		{Room: room, User: alice, Actor: admin},
		{Room: room, User: admin, Actor: owner},
	}
	if len(got) != len(want) {
		t.Fatalf("events = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %+v, want %+v", got, want)
		}
	}
}
