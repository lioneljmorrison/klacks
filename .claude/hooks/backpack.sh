#!/usr/bin/env bash
# Backpack session-start hook: prints "where are we" for this project.
#
# Copy it into any project. It reads the workspace and URL, and the optional
# "repo" (to narrow "Next" to one repository), from the project's
# .backpack.json and the token from BACKPACK_TOKEN. It never fails a session:
# without .backpack.json it prints nothing, and on any other problem it says
# so in one line. When Backpack refuses the request it prints Backpack's own
# reason. It always exits 0.

config="${CLAUDE_PROJECT_DIR:-$PWD}/.backpack.json"
[ -f "$config" ] || exit 0

field() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$config" | head -n 1; }
workspace=$(field workspace)
url=$(field url)
repo=$(field repo)

# A 2xx answer is printed as it is. A 4xx refusal is Backpack saying why (a
# joined workspace, an unknown repo, a bad token), so its reason is printed.
# Anything else, or no answer, is "unreachable".
reason() {
	body=$1
	case $body in
	'{'*) # {"error":"..."}: the message, its first line, quotes unescaped
		msg=$(printf '%s' "$body" | sed -n 's/^.*"error"[[:space:]]*:[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*$/\1/p' |
			sed 's/\\n.*$//; s/\\"/"/g; s/\\\\/\\/g' | head -n 1) ;;
	*) msg=$(printf '%s\n' "$body" | head -n 1) ;;
	esac
	printf 'Backpack: %s\n' "${msg:-refused the request (HTTP $2)}"
}

if [ -n "$BACKPACK_TOKEN" ] && [ -n "$workspace" ] && [ -n "$url" ] &&
	answer=$(curl -sS --max-time 3 -w '\n%{http_code}' \
		-H "Authorization: Bearer $BACKPACK_TOKEN" \
		-H "Accept: text/plain" \
		"${url%/}/v1/workspaces/$workspace/status${repo:+?repo=$repo}" 2>/dev/null); then
	code=${answer##*$'\n'}
	body=${answer%$'\n'*}
	body=$(printf '%s' "$body")
	case $code in
	2??) printf '%s\n' "$body" ;;
	4??) reason "$body" "$code" ;;
	*) echo "Backpack unreachable — orientation skipped" ;;
	esac
else
	echo "Backpack unreachable — orientation skipped"
fi
exit 0
