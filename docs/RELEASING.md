# Releasing TgCryptoRust

Work directly on `master` for this repository. Keep the package version in
`Cargo.toml`, `pyproject.toml`, `Cargo.lock`, and `uv.lock` consistent. Update
`CHANGELOG.md`, the README, and the Python, security, audit, and performance
guides when their claims or commands change.

## Before tagging

1. Resolve dependency PRs and inspect their semantics. Updating an action SHA
   must not silently change the compiler version used by the MSRV job.
2. Run Rustfmt, Clippy, the core hardware/software tests, and the Rust 1.89 check.
   Build/install a wheel and run the Python suite; verify typing files are in
   wheels and the source distribution. Validate workflow YAML with Actionlint.
3. Commit to `master`, push it, and check the GitHub CI run for that exact commit.
   A previous green run does not validate a newer commit.
4. Check that the intended version tag does not already exist. Create an
   annotated `v<version>` tag on the reviewed commit and push it without force.

The standard entry point is the **Publish to PyPI** workflow (`pypi.yml`),
triggered by a `v*` tag push. Manual dispatch is available for controlled retries.
The GitHub-only **Release** workflow is reusable and can also be dispatched
manually; it does not replace the top-level PyPI publishing step.

## Pipeline

1. Verify tag/version/commit consistency.
2. Run the reusable CI suite: format and lint, Rust 1.89 MSRV, Rust tests on
   Linux/macOS/Windows, forced software AES, and Python 3.9–3.14 wheel tests.
3. Build the native OS wheel matrix, Linux ARM wheels, and source distribution
   from the same reviewed source. Required builds must succeed before publication.
4. Publish the GitHub release with its artifacts.
5. Publish that artifact set to PyPI using trusted publishing from the top-level
   `pypi.yml` job and the existing `pypi` GitHub environment.

GitHub's default workflow token does not generally start another workflow from
events it creates. The pipeline therefore invokes its reusable workflows
explicitly, rather than depending on a bot-created release event to start PyPI
publishing. Trusted publishing stays outside reusable workflows.

## Verify and recover

Inspect all jobs in the run, including the final GitHub and PyPI publication
jobs. Check the GitHub release asset set and the PyPI version/file list. A pushed
tag, queued run, built wheel, or existing release page alone does not establish
that every job completed successfully.

If a build fails before publication, fix the cause on `master` and retry the
appropriate workflow at an explicit reviewed ref. Do not silently move an
existing version tag or mix artifacts from different source commits. If the
fix requires changing a published distribution, increment the version: PyPI
does not permit replacing an existing distribution file.

Environment approvals and trusted-publisher configuration are GitHub/PyPI
settings. Complete any configured approval in GitHub; do not paste tokens into
chat, source, release notes, or logs. Preserve TLS and artifact verification.
