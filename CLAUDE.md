# klacks

A self-hosted, embeddable messaging core in Go with Signal-protocol
end-to-end encryption. The design lives in
"Secure Messaging Core — Implementation Plan.md".

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
