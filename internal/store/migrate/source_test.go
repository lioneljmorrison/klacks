package migrate

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadSource(t *testing.T) {
	fsys := fstest.MapFS{
		".keep":                 {},
		"000002_b.up.cql":       {Data: []byte("x")},
		"000001_a.up.cql":       {Data: []byte("x")},
		"000001_a.down.cql":     {Data: []byte("x")},
		"000010_no_down.up.cql": {Data: []byte("x")},
		"000002_b.down.cql":     {Data: []byte("x")},
	}
	migs, err := readSource(fsys, "cql")
	if err != nil {
		t.Fatal(err)
	}
	var got []uint
	for _, m := range migs {
		got = append(got, m.Version)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 10 {
		t.Fatalf("versions = %v", got)
	}
	if migs[2].Down != "" || migs[0].Down != "000001_a.down.cql" {
		t.Fatalf("down files wrong: %+v", migs)
	}
}

func TestReadSourceEmpty(t *testing.T) {
	migs, err := readSource(fstest.MapFS{".keep": {}}, "sql")
	if err != nil || len(migs) != 0 {
		t.Fatalf("migs=%v err=%v", migs, err)
	}
}

func TestReadSourceRejects(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"bad name":      {"create_rooms.sql": {}},
		"wrong ext":     {"000001_a.up.sql": {}},
		"zero version":  {"000000_a.up.cql": {}},
		"missing up":    {"000001_a.down.cql": {}},
		"name mismatch": {"000001_a.up.cql": {}, "000001_b.down.cql": {}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readSource(fsys, "cql"); err == nil || !strings.Contains(err.Error(), "migrate") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
