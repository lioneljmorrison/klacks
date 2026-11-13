package migrate

import "strings"

// splitCQL splits a CQL script into statements on top-level semicolons.
// Comments (--, //, /* */) are dropped; semicolons inside 'strings',
// "quoted identifiers" and $$dollar strings$$ are kept.
func splitCQL(script string) []string {
	var (
		out []string
		cur strings.Builder
	)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		rest := script[i:]
		switch {
		case strings.HasPrefix(rest, "--"), strings.HasPrefix(rest, "//"):
			if j := strings.IndexByte(rest, '\n'); j >= 0 {
				i += j // keep the newline as whitespace
				cur.WriteByte('\n')
			} else {
				i = len(script)
			}
		case strings.HasPrefix(rest, "/*"):
			if j := strings.Index(rest[2:], "*/"); j >= 0 {
				i += j + 3
			} else {
				i = len(script)
			}
			cur.WriteByte(' ')
		case strings.HasPrefix(rest, "$$"):
			end := strings.Index(rest[2:], "$$")
			if end < 0 {
				cur.WriteString(rest)
				i = len(script)
				break
			}
			cur.WriteString(rest[:end+4])
			i += end + 3
		case c == '\'' || c == '"':
			j := 1
			for j < len(rest) {
				if rest[j] == c {
					if j+1 < len(rest) && rest[j+1] == c { // doubled quote escape
						j += 2
						continue
					}
					break
				}
				j++
			}
			end := min(j+1, len(rest))
			cur.WriteString(rest[:end])
			i += end - 1
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}
