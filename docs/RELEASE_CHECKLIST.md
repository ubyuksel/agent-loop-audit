# Private candidate gates

- Local source tests, adversarial independent QA and installed console/module
  offline smoke must pass against recorded bytes.
- Wheel/sdist paths and metadata must match an explicit allowlist, with no raw
  data, .planning, evidence, reports, caches or environment files.
- Record source/build/archive SHA256; recheck after any relevant change.
- Review authored-code, fixtures and build/action provenance; owner confirms the
  actual copyright holder and adopts final MIT license. Pending in this candidate.
- Owner configures a real private security reporting channel. Pending.
- Trusted offline scanner covers working tree, all reachable refs/commits and
  archive contents; manual review of scanner blind spots. Tool absent: pending,
  never equate a text search or empty history with a clean secrets scan.
- Execute all12 OS/Python matrix cells. Missing cells and capability skips remain
  pending, independently of local installation success.
- Review CI permissions/action pins/trigger costs before a separately authorized
  private remote/CI run. This task creates no remote or workflow run.
- Explicit scoped owner approval is required for any public visibility, tag,
  release, upload, package publication or application. None is authorized here.
