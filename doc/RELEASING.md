# Release Process

This document is the authoritative checklist for cutting a jwtauth release. Execute phases in order. Do not skip gates.

---

## Phase 1 — Pre-Flight Gate

**Gate: all items must pass before proceeding.**

- [ ] All issues in the release milestone are closed (`gh issue list --milestone vX.Y.Z`)
- [ ] CI is green on `dev` — verify 5 consecutive passing runs on the Actions tab
- [ ] Run the full test suite locally with race detection: `./run-ci-locally.sh`
- [ ] Audit pending ADR fixes: read the ADR files listed in the roadmap memory; confirm any blocking items are resolved or explicitly deferred with a filed issue

---

## Phase 2 — Documentation Audit

Audit each document against the implementation. Fix everything before committing.

### README.md

- [ ] Spec counts match actual test output (`go test -v ./pkg/... | grep "Will run"`)
  - Total (unit + integration), per-suite counts, alloc numbers if cited
- [ ] Go version badge matches `go.mod` `go` directive
- [ ] API stability banner is current — remove or update "planned" items that have shipped

### CHANGELOG.md

- [ ] A `## [Unreleased]` section exists at the top with all changes since the last release
- [ ] Every merged PR since the last release has a CHANGELOG entry
- [ ] Entries that belong to the new release are NOT in the previous version's section
- [ ] The previous release section is `## [vX.Y.Z] — YYYY-MM-DD` (not `## [Unreleased — vX.Y.Z]`)
- [ ] **Missing entries check**: cross-reference `git log vPREV..dev --oneline` against CHANGELOG; write entries for anything absent

### UPGRADING.md

- [ ] A `## vPREV.x → vX.Y.Z` section exists
- [ ] Every breaking change has a "Before/After" code block and a required action
- [ ] Every behavioral change callers must know about is documented (even if not breaking)

### ARCHITECTURE.md

- [ ] New ADRs are in the Architecture Decision Records table
- [ ] `Last Updated` date and `Version` field match the new release
- [ ] Metrics section: count matches `PrometheusMetrics` registered metrics

### Example modules

- [ ] `go mod tidy -diff` produces no output in each example directory:
  ```
  for d in examples/*/; do echo "=== $d ==="; (cd "$d" && go mod tidy -diff); done
  ```

**Commit all Phase 2 fixes to `dev` before proceeding.**

---

## Phase 3 — Performance Gate

Run benchmark suite on both the previous release tag and current `dev`. Compare with `benchstat`.

```bash
# Baseline (previous release)
git worktree add /tmp/jwtauth-baseline vPREV
cd /tmp/jwtauth-baseline
go test -run='^$' -bench=. -benchmem -count=3 ./pkg/... > /tmp/bench-baseline.txt
cd -
git worktree remove /tmp/jwtauth-baseline

# Candidate (dev)
go test -run='^$' -bench=. -benchmem -count=3 ./pkg/... > /tmp/bench-candidate.txt

# Compare
benchstat /tmp/bench-baseline.txt /tmp/bench-candidate.txt
```

**Gate:**
- `< 15%` regression on any operation → soft gate: document the regression in the release notes and proceed
- `≥ 15%` regression on any operation → hard stop: file a bug, identify root cause, resolve before proceeding

Save both raw files and a written report to `doc/benchmarks/`:
- `doc/benchmarks/vX.Y.Z.txt` — candidate raw output
- `doc/benchmarks/vPREV.txt` — baseline raw output (if not already present)
- `doc/benchmarks/vX.Y.Z-report.md` — written report with verdict, geomean table, and notable operations

Commit the benchmark data to `dev`.

---

## Phase 4 — Release Branch

### Check for main divergence

```bash
git log --oneline origin/main
```

If any commits landed on `main` since the previous release tag (squash-merges from hotfixes, etc.), merge `origin/main` into the release branch locally and resolve conflicts before opening the PR — **never use GitHub's conflict resolution UI** for this repo (it gets stuck on merge commits).

### Cut the branch

```bash
git checkout dev && git pull origin dev
git checkout -b release/vX.Y.Z
git push -u origin release/vX.Y.Z
```

### Open the PR

```bash
gh pr create --base main --title "release: vX.Y.Z" --body "..."
```

PR body must include:
- Summary of all changes (Fixed / Added / Changed / Chore / Documentation)
- Release checklist (mirror Phase 1–3 items as checked checkboxes)
- Post-merge steps reminder: tag → push tag → GitHub Release → Discussions

**Resolve any conflicts** (see Conflict Resolution section below), then wait for CI to pass.

---

## Phase 5 — Tag and Publish

After the PR is merged:

```bash
# Get the merge commit SHA
git fetch origin main
git log --oneline origin/main -1

# Create annotated tag on the merge commit
git tag -a vX.Y.Z <SHA> -m "Release vX.Y.Z"
git push origin vX.Y.Z

# Create GitHub Release (from the pushed tag — do NOT pass --target)
gh release create vX.Y.Z \
  --title "vX.Y.Z — <short description>" \
  --notes "..."
```

Release notes structure:
1. One-sentence summary of the release theme
2. `## What's Changed` — Fixed / Added / Chore / Documentation sections
3. `## Upgrading` — brief upgrade note with link to UPGRADING.md section
4. `## Performance` — one-line verdict with link to benchmark report
5. `**Full Changelog**: https://github.com/aetomala/jwtauth/compare/vPREV...vX.Y.Z`

### Post Discussions announcement

```bash
gh api graphql -f query='{ repository(owner:"aetomala",name:"jwtauth") { id } }' --jq '.data.repository.id'
# → use the returned ID as $REPO_ID below

gh api graphql -f query='mutation(...) { createDiscussion(...) { discussion { url } } }' \
  -f repoId="$REPO_ID" \
  -f catId="DIC_kwDOQmTk584C7HmI" \   # Announcements category
  -f title="vX.Y.Z released — <description>" \
  -f body="..."
```

Announcement body structure:
- Lead: one sentence on what shipped and the theme
- Key changes: 3–5 bullets covering the most impactful items
- Upgrade note: one sentence + link to UPGRADING.md
- Performance: one sentence + link to benchmark report
- Release link

---

## Phase 6 — Post-Release Cleanup

```bash
# Close the milestone
gh api --method PATCH repos/aetomala/jwtauth/milestones/<NUMBER> -f state=closed

# Merge main back into dev (keeps histories in sync; avoids future conflicts)
git checkout dev && git pull origin dev
git merge --no-ff origin/main -m "chore: merge main (vX.Y.Z) back into dev"
git push origin dev
```

Then:
- [ ] Open v(X.Y+1).0 milestone on GitHub if it does not exist
- [ ] Update `jwtauth.md` project context file: bump "Latest release" and "Active" lines
- [ ] Update the `session_v*_release_handoff.md` memory file to reflect completion
- [ ] Delete the `release/vX.Y.Z` branch: `gh pr view --json headRefName | ...` or manually in GitHub

---

## Conflict Resolution

When a release branch conflicts with `main` due to squash-merge divergence (the standard pattern for this repo):

1. Merge `origin/main` into the release branch locally: `git merge --no-commit --no-ff origin/main`
2. For each conflict, take `--ours` (the release branch version): `git checkout --ours <file>`
3. Verify no conflict markers remain: `grep -r "<<<<<<" .`
4. Commit and push: `git add <files> && git commit -m "chore: merge main into release/vX.Y.Z; resolve squash-merge conflicts"`

**Never use `--theirs` on code files in a release merge** — `main` holds the previous release; `dev`/release holds all new work.

---

## Quick Reference — Key IDs

| Resource | Value |
|----------|-------|
| Announcements category ID | `DIC_kwDOQmTk584C7HmI` |
| v0.7.0 milestone number | TBD |

---

## Benchmark regression thresholds

| Regression | Action |
|------------|--------|
| < 15% on any operation | Soft gate — document in release notes and proceed |
| ≥ 15% on any operation | Hard stop — file bug, resolve before release |

Applies per-operation. Always use `benchstat` with `-count=3` minimum; `-count=6` for statistical confidence intervals.
