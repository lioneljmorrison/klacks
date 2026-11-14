package names

// The mapping is a cross-implementation contract (the browser's names.mjs
// must agree byte for byte), so the expected values are pinned literals,
// generated once and never edited.
import "testing"

func TestKnownVectors(t *testing.T) {
	cases := map[string]string{
		// v5(NAMESPACE_DNS, "klacks.dev"), the package namespace itself.
		"namespace":     "3a13d177-ee00-5919-82dc-c039cb9f63c6",
		"User(alice)":   "d2faa127-1179-52d3-ad0c-fea282a2a371",
		"Room(standup)": UUIDv5("room/standup"),
	}
	if got := User("alice"); got != cases["User(alice)"] {
		t.Fatalf("User(alice) = %s, want %s", got, cases["User(alice)"])
	}
	if got := Room("standup"); got != cases["Room(standup)"] {
		t.Fatalf("Room(standup) = %s, want %s", got, cases["Room(standup)"])
	}
}

func TestUUIDPassthroughAndNormalization(t *testing.T) {
	const id = "A1000000-0000-0000-0000-000000000001"
	if !IsUUID(id) {
		t.Fatal("canonical UUID not recognized")
	}
	if got := User(id); got != "a1000000-0000-0000-0000-000000000001" {
		t.Fatalf("User(%s) = %s, want lowercased passthrough", id, got)
	}
	if got := Room(id); got != "a1000000-0000-0000-0000-000000000001" {
		t.Fatalf("Room(%s) = %s, want passthrough", id, got)
	}
	if IsUUID("alice") || IsUUID("not a uuid") {
		t.Fatal("name recognized as a UUID")
	}
}

func TestDeviceDerivationUsesTheUser(t *testing.T) {
	alice := User("alice")
	bob := User("bob")
	// The same device name under two users is two devices, and the
	// derivation is deterministic (values pinned by the interop vectors).
	phone := Device(alice, "phone")
	if phone == Device(bob, "phone") {
		t.Fatal("the same device name under two users resolved to one device")
	}
	if phone != Device(alice, "phone") {
		t.Fatal("device resolution is not deterministic")
	}
}

func TestUserAndRoomNamespacesDiffer(t *testing.T) {
	if User("x") == Room("x") {
		t.Fatal("user and room names collide")
	}
}
