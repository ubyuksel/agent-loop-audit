# Release gates for 0.1.0

The repository remains PRIVATE throughout preparation. Tests do not authorize
visibility changes, tags/releases, PyPI uploads or any other publication.

- [ ] Confirm legal rights-holder explicitly; review provenance; adopt standard
  MIT LICENSE with year 2026 only after owner approval. Then replace pending
  metadata/private classifier; independently update license assertions.
- [ ] Verify an approved private reporting route. GitHub's feature applies to
  public repositories; the private endpoint currently returns 404. SECURITY.md
  documents a pending procedure, not an available route. This is a blocker:
  separately authorized publication transition and enablement/verification, or
  an approved alternative, is required.
- [ ] Review all tracked source/docs/examples and synthetic fixtures.
- [ ] Rebuild wheel/sdist after input changes; inspect exact members, metadata,
  dependency absence, source parity and wheel RECORD hashes.
- [ ] Verify clean-checkout builds and isolated wheel/sdist installation,
  console/module entry points and exact synthetic JSON with network blocked.
- [ ] Regenerate/validate docs/UPLOAD_MANIFEST.json and dist/SHA256SUMS.txt;
  record reviewer-test and full-candidate hashes separately.
- [ ] Run full tests and fresh independent QA, with explicit capability skips.
- [ ] Trusted offline scan: candidate tree, all reachable Git history/refs and
  extracted artifacts. Record commands/version/digests; classify checksum false
  positives individually. Stop on actual sensitive findings.
- [ ] Commit reviewed changes, scan final history, normal-push only this private
  repository and run manual CI for that commit under owner authority.
  Baseline 39936840882 passed all 12 cells at
  5391ec4c17df4d951602699d28e74bf9e3b75cde; it cannot validate later changes.
  Require 12/12 final-commit jobs and inspect capability skips.
- [ ] Complete independent Q4 review and exact-byte final gate report.
- [ ] Obtain separate explicit owner approval for any publication.

Local evidence stays ignored. Never infer scanner PASS from text search, matrix
PASS from local tests, or reporting availability from a policy file.
