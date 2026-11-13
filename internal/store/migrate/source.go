package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
)

// migration is one versioned up/down pair.
type migration struct {
	Version uint
	Name    string
	Up      string // file path, empty if missing
	Down    string // file path, empty if missing
}

var fileRE = regexp.MustCompile(`^([0-9]+)_([A-Za-z0-9_]+)\.(up|down)\.([a-z]+)$`)

// readSource lists the migrations with extension ext ("sql" or "cql") at the
// root of fsys, sorted by version. Dotfiles (such as .keep) are ignored; any
// other file must follow the naming scheme.
func readSource(fsys fs.FS, ext string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: read source: %w", err)
	}
	byVersion := map[uint]*migration{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name[0] == '.' {
			continue
		}
		m := fileRE.FindStringSubmatch(name)
		if m == nil || m[4] != ext {
			return nil, fmt.Errorf("migrate: %s: want NNNNNN_name.up.%s or NNNNNN_name.down.%s", name, ext, ext)
		}
		v, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("migrate: %s: version must be a positive integer", name)
		}
		mig := byVersion[uint(v)]
		if mig == nil {
			mig = &migration{Version: uint(v), Name: m[2]}
			byVersion[uint(v)] = mig
		}
		if mig.Name != m[2] {
			return nil, fmt.Errorf("migrate: version %d has two names: %q and %q", v, mig.Name, m[2])
		}
		if m[3] == "up" {
			mig.Up = name
		} else {
			mig.Down = name
		}
	}
	out := make([]migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" {
			return nil, fmt.Errorf("migrate: version %d (%s) has no .up.%s file", m.Version, m.Name, ext)
		}
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b migration) int { return int(a.Version) - int(b.Version) })
	return out, nil
}
