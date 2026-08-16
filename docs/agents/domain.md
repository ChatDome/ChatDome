# Domain Docs

ChatDome uses a single domain context. Formal engineering documentation
lives in the adjacent `../ChatDome-docs` repository.

## Read before exploring

Read only the documents relevant to the current task:

- `../ChatDome-docs/CONTEXT.md`, when present, for domain terminology.
- `../ChatDome-docs/docs/00-governance/` for documentation and coding rules.
- `../ChatDome-docs/docs/02-system-design/` for system-level architecture.
- `../ChatDome-docs/docs/03-module-specs/` for module contracts and behavior.
- `../ChatDome-docs/docs/05-decision-log/` for applicable ADRs.

If `CONTEXT.md` does not exist, proceed silently. Create it only when the
first stable domain term is recorded.

## Write locations

- Domain glossary: `../ChatDome-docs/CONTEXT.md`
- System design: `../ChatDome-docs/docs/02-system-design/`
- Module specifications: `../ChatDome-docs/docs/03-module-specs/`
- Implementation plans: `../ChatDome-docs/docs/04-implementation-plans/`
- ADRs: `../ChatDome-docs/docs/05-decision-log/`
- Agent workflow configuration: `docs/agents/` in the ChatDome code repository

Do not create `CONTEXT.md`, `CONTEXT-MAP.md`, or `docs/adr/` in the
ChatDome code repository.

New long-form documents must follow
`../ChatDome-docs/docs/00-governance/documentation-standards.md` and update
the index and revision history in `../ChatDome-docs/README.md`.

## Use the glossary vocabulary

Use domain terms exactly as defined in `../ChatDome-docs/CONTEXT.md`.
Do not replace established terms with synonyms.

If a required concept is missing, record it through the `domain-modeling`
workflow instead of inventing competing terminology.

## Flag ADR conflicts

If proposed work conflicts with an existing decision under
`../ChatDome-docs/docs/05-decision-log/`, identify the ADR explicitly before
continuing.
