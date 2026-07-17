# Contributing
Thank you for your interest in contributing to this project.
By contributing to this project you agree to the [Developer Certificate of Origin](https://developercertificate.org/).

## Contributions

* Provide feedback and report potential bugs
* Suggest enhancements to the project
* Perform tests and increase test coverage
* Fix a [Bug](https://github.com/united-security-providers/coraza-envoy-go-filter/issues?q=is%3Aopen+is%3Aissue+label%3Abug) or implement an [Enhancement](https://github.com/united-security-providers/coraza-envoy-go-filter/issues?q=%3Aopen+is%3Aissue+label%3Aenhancement)


## Reporting an Issue

* Check existing [Issues](https://github.com/united-security-providers/coraza-envoy-go-filter/issues) (open and closed) to ensure it was not already reported.
* Provide a detailed description and a reproducible test case in a new [Issue](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/new).
  Be sure to include as much relevant information as possible, a **code sample** or an **test case** demonstrating the fault helps us to reproduce your problem.

[TODO] Information regarding security policy


## Patches

Did you write a patch that fixes a bug?

* Open a new GitHub pull request which includes your changes.
* Please include a description which clearly describes the change. Include the relevant issue number if applicable.

## Commit messages

Use a Conventional-Commit-style prefix and keep the subject imperative and short:

```
<type>: <subject, imperative mood, <= 50 chars, no trailing period>

<body wrapped at 80 chars explaining what and why, not how>
```

* **Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `style`, `ci`.
* Present tense — "add", not "added".
* Explain *what* and *why* in the body; leave *how* to the diff.
* No watermarks or co-author trailers.
* Reference the relevant issue or PR when applicable.

## Branch naming

Name branches `<type>/<short-name>`, using the same types as commits — for example `feat/response-body-block`, `fix/encodedata-nil-err`, `chore/bump-envoy`, `ci/align-workflows`.

## Working in parallel (worktrees)

Run more than one change at a time with `git worktree` rather than extra clones or juggling branches in a single checkout:

* Give each change its own worktree **and** branch: `git worktree add ../<name> -b <type>/<name>`.
* Never let two writers share one branch — two commits racing on the same branch stomp each other, one landing on top of the other's in-progress edits.
* Keep one logical change per branch and PR; don't mix unrelated edits in a single commit.
* Read-only exploration needs none of this.

## Questions

Do you have questions about the source code? Ask any question about how to use Coraza in the community [Discussions](https://github.com/united-security-providers/coraza-envoy-go-filter/discussions/categories/q-a).
