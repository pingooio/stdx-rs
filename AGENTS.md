When working in this repository, read and follow the stdx project skill at
`skills/stdx/SKILL.md`. It covers how to use stdx crates (import from git,
never crates.io), the full crate catalog, and the zero-external-dependency
policy.

## Contributor guidelines

### Writing and updating code

Always document code but without necessarily explaining the internals of the
functions, instead, explain what the user can expect, and the situations where
it can returns an error / panic (if it applies).

When modifying code, always verify that the documentation / comments / README /
examples are up-to-date.

When creating a new library named `mylib` (for example), don't use the usual
`mylib/src/lib.rs` architecture, but instead use `mylib/mylib.rs` and update
the `[lib]` field in `Cargo.toml`.

When adding a workspace member to the root Cargo.toml, ensure that the
workspace members are alphabetically ordered.
