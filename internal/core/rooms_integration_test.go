//go:build integration

package core_test

import (
	"context"
	"errors"
	"testing"

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
	return core.New(store.NewRooms(dbtest.MigratedPostgres(t)), onRemoved)
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

	if err := svc.AddMember(ctx, room, alice, core.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, room, alice, core.RoleAdmin); !errors.Is(err, core.ErrAlreadyMember) {
		t.Fatalf("re-add: err = %v, want ErrAlreadyMember", err)
	}
	if err := svc.AddMember(ctx, room, bob, "superuser"); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("unknown role: err = %v, want ErrInvalidArgument", err)
	}
	if err := svc.AddMember(ctx, id(0xee), bob, core.RoleMember); !errors.Is(err, core.ErrRoomNotFound) {
		t.Fatalf("missing room: err = %v, want ErrRoomNotFound", err)
	}

	if err := svc.RemoveMember(ctx, room, alice); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (core.MemberRemoved{Room: room, User: alice}) {
		t.Fatalf("events = %+v, want one removal of alice", got)
	}
	if err := svc.RemoveMember(ctx, room, alice); !errors.Is(err, core.ErrNotMember) {
		t.Fatalf("remove twice: err = %v, want ErrNotMember", err)
	}
	if len(got) != 1 {
		t.Fatalf("failed removal emitted an event: %+v", got)
	}
	// Removed members can be added back.
	if err := svc.AddMember(ctx, room, alice, core.RoleMember); err != nil {
		t.Fatal(err)
	}
}
