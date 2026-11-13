# klacks

A self-hosted, embeddable messaging core in Go with Signal-protocol
end-to-end encryption. The design lives in
"Secure Messaging Core — Implementation Plan.md".

## Working rules

- **Don't guess.** If something is unclear or unknown, research it (the
  code, the implementation plan, primary sources such as the Signal specs)
  and ask rather than assuming. Crypto especially: never fill gaps from memory.
- **YAGNI.** Build only what the current story needs. The simple solution is
  usually the right one; no speculative abstractions, options or layers.
- **TDD.** Write a failing test first, run it and see it fail, then write
  the code that makes it pass, then refactor.
- **Testing.** Verify with Bash (`go build ./...`, `go vet ./...`,
  `go test ./...`, `-race` where concurrency is involved) and, for anything
  in a browser, the Playwright MCP tools. Don't claim something works
  without having run it.

## Branches and releases

- `dev` is the working branch. Task branches start from `dev`, and their PRs
  target `dev`.
- `main` is the release branch. Only `dev` merges into `main`, through a PR,
  and releases (git tags + `gh release create`) are cut from `main`.
- Never commit directly to `main`, and never force-push.

## How this project tracks

Delivery is in Backpack, workspace `klacks` (see `.backpack.json`),
through the `backpack` MCP tools. There is no tracking document, and tracking
is never committed. `actions` lists rarer actions; run rarer changes through
`batch`.

- **Orientation.** The session hook shows "where are we"; trust it.
  Call `where_are_we` only if the hook didn't. `whats_next` gives the next
  story, `get_story` its detail. Pass `.backpack.json`'s `repo`, if any,
  to `whats_next`, `add_story` and `add_bug_fix`.
- **Record each move as it happens** with `set_status`: `in_progress` with the
  task branch, `in_review` with the PR link, `merged` with the merge
  commit. `merge_branch` moves `dev`'s stories to `main`; `cut_release` records a
  release (you create the git tag).
- **While in progress,** keep `update_story` activity current.
- **Log as you go** with `log`: decisions with their reason. Entries are never
  edited; fix one with a `correction`. Stuck or unneeded: `on_hold` or
  `closed`, with a reason.
- **Upstream changed.** Check each marked story against the plan; update its
  plan, or `mark_reviewed` with a reason.
- **Search first,** before `add_story` or `add_idea`. New work goes in with
  `add_story` and its `reasoning`, waits as proposed for a person (a bug with a
  clear fix: `add_bug_fix`), then `add_dependency`. Break an `add_idea`
  into proposed stories and any phase, then `refine_idea` it.
- **Many changes** go in one `batch`; read each answer.
