package core

import (
	"errors"
	"testing"
)

func TestAuthorize(t *testing.T) {
	const none Role = "" // not a member
	tests := []struct {
		name string
		req  request
		want error
	}{
		// Post and read: any member.
		{"owner posts", request{actor: RoleOwner, action: actPost}, nil},
		{"admin posts", request{actor: RoleAdmin, action: actPost}, nil},
		{"member posts", request{actor: RoleMember, action: actPost}, nil},
		{"non-member posts", request{actor: none, action: actPost}, ErrNotMember},
		{"member reads", request{actor: RoleMember, action: actRead}, nil},
		{"non-member reads", request{actor: none, action: actRead}, ErrNotMember},

		// Add: owner adds any role; admin adds members only.
		{"owner adds owner", request{actor: RoleOwner, action: actAdd, target: RoleOwner}, nil},
		{"owner adds admin", request{actor: RoleOwner, action: actAdd, target: RoleAdmin}, nil},
		{"owner adds member", request{actor: RoleOwner, action: actAdd, target: RoleMember}, nil},
		{"admin adds owner", request{actor: RoleAdmin, action: actAdd, target: RoleOwner}, ErrForbidden},
		{"admin adds admin", request{actor: RoleAdmin, action: actAdd, target: RoleAdmin}, ErrForbidden},
		{"admin adds member", request{actor: RoleAdmin, action: actAdd, target: RoleMember}, nil},
		{"member adds member", request{actor: RoleMember, action: actAdd, target: RoleMember}, ErrForbidden},
		{"non-member adds member", request{actor: none, action: actAdd, target: RoleMember}, ErrNotMember},

		// Remove: owner removes anyone; admin removes members; anyone leaves.
		{"owner removes owner", request{actor: RoleOwner, action: actRemove, target: RoleOwner}, nil},
		{"owner removes admin", request{actor: RoleOwner, action: actRemove, target: RoleAdmin}, nil},
		{"owner removes member", request{actor: RoleOwner, action: actRemove, target: RoleMember}, nil},
		{"admin removes owner", request{actor: RoleAdmin, action: actRemove, target: RoleOwner}, ErrForbidden},
		{"admin removes admin", request{actor: RoleAdmin, action: actRemove, target: RoleAdmin}, ErrForbidden},
		{"admin removes member", request{actor: RoleAdmin, action: actRemove, target: RoleMember}, nil},
		{"member removes member", request{actor: RoleMember, action: actRemove, target: RoleMember}, ErrForbidden},
		{"member leaves", request{actor: RoleMember, action: actRemove, target: RoleMember, self: true}, nil},
		{"admin leaves", request{actor: RoleAdmin, action: actRemove, target: RoleAdmin, self: true}, nil},
		{"owner leaves", request{actor: RoleOwner, action: actRemove, target: RoleOwner, self: true}, nil},
		{"non-member removes member", request{actor: none, action: actRemove, target: RoleMember}, ErrNotMember},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorize(tt.req)
			if tt.want == nil && got != nil || tt.want != nil && !errors.Is(got, tt.want) {
				t.Fatalf("authorize(%+v) = %v, want %v", tt.req, got, tt.want)
			}
		})
	}
}
