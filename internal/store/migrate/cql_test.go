package migrate

import (
	"slices"
	"testing"
)

func TestSplitCQL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "  \n ", nil},
		{"single no semicolon", "CREATE TABLE t (a int PRIMARY KEY)", []string{"CREATE TABLE t (a int PRIMARY KEY)"}},
		{"two", "CREATE TABLE a (x int PRIMARY KEY);\nCREATE TABLE b (y int PRIMARY KEY);\n",
			[]string{"CREATE TABLE a (x int PRIMARY KEY)", "CREATE TABLE b (y int PRIMARY KEY)"}},
		{"line comments", "-- header; with semicolon\nCREATE TABLE a (x int PRIMARY KEY); // trailing; note\n",
			[]string{"CREATE TABLE a (x int PRIMARY KEY)"}},
		{"block comment", "/* a; b */ SELECT 1; /* unterminated ;", []string{"SELECT 1"}},
		{"string with semicolon and escaped quote", "INSERT INTO t (s) VALUES ('a;b''c'); SELECT 2",
			[]string{"INSERT INTO t (s) VALUES ('a;b''c')", "SELECT 2"}},
		{"quoted identifier", `CREATE TABLE "we;ird" (x int PRIMARY KEY);`, []string{`CREATE TABLE "we;ird" (x int PRIMARY KEY)`}},
		{"dollar string", "CREATE FUNCTION f() RETURNS int LANGUAGE lua AS $$ return 1; $$;",
			[]string{"CREATE FUNCTION f() RETURNS int LANGUAGE lua AS $$ return 1; $$"}},
		{"comment markers inside string", "INSERT INTO t (s) VALUES ('-- not a comment /* no */');",
			[]string{"INSERT INTO t (s) VALUES ('-- not a comment /* no */')"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := splitCQL(c.in); !slices.Equal(got, c.want) {
				t.Fatalf("splitCQL(%q)\n got  %q\n want %q", c.in, got, c.want)
			}
		})
	}
}
