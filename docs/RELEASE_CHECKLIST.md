# Release checklist

The owner authorized the v0.1.0 GitHub release. The repository is public and
private vulnerability reporting is enabled. This does not authorize PyPI or
changes to another repository. Do not bypass any failed security/license gate.

Before each release:

- Verify clean Git state, exact remote/branch, MIT ownership and enabled private
  reporting API plus the visible public reporting link.
- Review source/docs and synthetic-only fixtures; exclude real logs, private
  reports, planning, evidence, credentials and environments from uploads.
- Rebuild wheel/sdist from a clean checkout. Check archive members, dependency
  absence, full MIT text, source parity and wheel RECORD hashes/sizes.
- Verify isolated offline wheel/sdist installation, console/module entry points,
  expected synthetic JSON and unchanged inputs with network/process guards.
- Regenerate docs/UPLOAD_MANIFEST.json and dist/SHA256SUMS.txt; record reviewer
  test hash separately. Checksums establish integrity, not signer authenticity.
- Run full tests and independent affected QA. Keep OS-capability skips explicit.
- Scan source, all reachable Git history/refs and extracted archive content with
  a trusted offline scanner. Recompute checksum false positives individually;
  stop on sensitive or unclassified findings. Never upload raw scanner reports.
- Commit necessary changes, rescan final history, normal-push and verify all 12
  OS/Python CI cells pass for that exact commit. Inspect skips, not just job status.
- Check the intended tag/release do not already exist. Create an annotated tag
  for the tested commit; never move or overwrite an existing published tag.
- Publish accurate notes, verified wheel/sdist and SHA256SUMS.txt only after all
  gates pass. Verify anonymous release/download access and downloaded hashes.

Release notes must link the final CI run and disclose token-accounting, format,
filesystem and build-reproducibility limits. No usage statistics, token savings
or OpenAI endorsement may be invented. No force push or PyPI publication.
