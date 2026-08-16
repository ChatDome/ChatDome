# Issue tracker: GitHub

Issues, specs, and executable tickets for this repository live in
`ChatDome/ChatDome` GitHub Issues. Use the `gh` CLI for all operations.

## Prerequisites

Before changing GitHub state, verify authentication:

```text
gh auth status
```

If `gh` is unavailable or authentication fails, stop and ask the user to
install or authenticate GitHub CLI.

## Conventions

- Create an issue with `gh issue create`.
- Read an issue and its comments with `gh issue view <number> --comments`.
- List issues with `gh issue list`, using label and state filters as needed.
- Add a comment with `gh issue comment <number>`.
- Apply or remove labels with `gh issue edit <number>`.
- Close an issue with `gh issue close <number>`.
- Use `--body-file` for multiline bodies.
- Infer the repository from `git remote -v` when running inside this clone.
- Confirm the intended mutation before creating, editing, commenting on, assigning, or closing an issue.

## Pull requests as a triage surface

**PRs as a request surface: no.**

Pull requests are not included in routine triage discovery. An explicitly
named pull request may still be inspected when the user requests it.

## Publishing and fetching

When a skill says “publish to the issue tracker”, create a GitHub Issue.

When a skill says “fetch the relevant ticket”, read the complete Issue body,
comments, labels, state, author, and relationships.

## Wayfinding operations

- A map is one Issue labelled `wayfinder:map`.
- Decision and investigation tickets are child Issues of the map.
- Use GitHub sub-issue and blocking relationships when available.
- A ticket is ready when it is open, unassigned, and all blockers are closed.
- Claim a ticket by assigning it to the developer performing the work.
- Resolve a ticket by posting its result, closing it, and linking the result
  from the map’s Decisions-so-far section.
