# Release notes

This file is optional. The `release-gh` and `release-coach` skills read it, if
it exists, to pick up release gotchas before cutting a release. If it does not
exist, they ignore it and default to `CHANGELOG.md` at the repo root - the
normal case for every repo.

## This repo's gotcha

The real changelog is `_template/CHANGELOG.md`. The root `CHANGELOG.md` is a
blank Keep a Changelog stub that ships to every downstream project scaffolded
from this template, so this library's own history has to live under
`_template/` to keep the two from colliding. Releases must write their
`[Unreleased]` entries in `_template/CHANGELOG.md`, not the root stub.

## Using this file in other repos

Add a `RELEASE.md` at a repo's root any time a release skill needs a note it
would not find on its own - most commonly, a real changelog that lives somewhere
other than `CHANGELOG.md` at the root. State the real path plainly in the file;
the release skills read it and resolve the changelog from it. The file is
plain Markdown and can carry any release-related notes, not just the changelog
path. When a repo draws its changelog from the root `CHANGELOG.md`, leave the
file out entirely and the default is used.