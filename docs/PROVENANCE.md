# Source and provenance register

Original implementation and synthetic unittest corpus authored for this isolated
project. No upstream source implementation was copied or vendored. No real user
rollout, account data or credentials were used. MIT/license release review remains
a manual gate. LICENSE is explicitly pending owner/rightsholder approval; the
candidate makes no MIT grant and uses LicenseRef-Private-Candidate-Pending.

Protocol shape references, pinned by the supplied plan to OpenAI Codex commit
`4610b573e59b211bf9430cf6ffb97cfb84623090` (2026-10-23):

- [History serialization](https://github.com/openai/codex/blob/4610b573e59b211bf9430cf6ffb97cfb84623090/codex-rs/history/src/rollout_payload.rs): envelope discriminator, payload and sibling metadata.
- [Protocol models](https://github.com/openai/codex/blob/4610b573e59b211bf9430cf6ffb97cfb84623090/codex-rs/protocol/src/models.rs): separate function/custom requests and text/content-item results.
- [Protocol events](https://github.com/openai/codex/blob/4610b573e59b211bf9430cf6ffb97cfb84623090/codex-rs/protocol/src/protocol.rs): exec, patch and MCP outcomes.
- [History definitions](https://github.com/openai/codex/blob/4610b573e59b211bf9430cf6ffb97cfb84623090/codex-rs/history/src/lib.rs): planning reference; types can be re-exported from other modules.

The first three pinned files were fetched read-only during P1 development.
No downloaded code was saved in this repository. Development source retrieval
is distinct from application audit/tests, which use no network. Frozen planning
references remain in ignored `.planning/` with bytes verified against the ZIP.

All seven tracked JSONL files (six fixtures and one example) are invented.
The example and retry fixture intentionally have identical bytes. Test canaries,
paths and identifiers are generated synthetic values, not redacted incidents.
No third-party implementation is vendored. Build tools/actions are not runtime
dependencies and are not bundled in the wheel. Project ownership must still be
confirmed explicitly by the owner; development history is not legal approval.

## P4 build and action provenance (2026-10-23)

Public PyPI JSON metadata was retrieved read-only, then free build-only packages
installed into the ignored project venv: build1.6.1, setuptools84.2.1, wheel0.48.0,
packaging26.3, pyproject_hooks1.3.3, colorama0.4.6. First three project metadata
license expressions are MIT; transitive license metadata is reviewed below in
candidate evidence. None is bundled as a runtime dependency or vendored source.
Installed metadata: packaging uses Apache-2.0 OR BSD-2-Clause; pyproject_hooks MIT;
colorama has a BSD License classifier (license-expression metadata unspecified).
Its installed license SHA256 is cac35c02686e5d04a5a7140bfb3b36e73aed496656e891102e428886d7930318.
Sources: https://pypi.org/pypi/build/json , https://pypi.org/pypi/setuptools/json ,
https://pypi.org/pypi/wheel/json . Build version pins are separate from runtime.

GitHub official release/tag-ref API metadata resolved current upstream tags to
commit objects: actions/checkout v7.0.1 =
3d3c42e5aac5ba805825da76410c181273ba90b1; actions/setup-python v7.1.0 =
6d4fd22b20465ccc0f7354476588e8df7c9ca0e0. Read-only endpoints were
https://api.github.com/repos/actions/checkout/releases/latest and corresponding
/git/ref/tags/v7.0.1; setup-python equivalent /releases/latest and
/git/ref/tags/v7.1.0. These pins were subsequently executed successfully in
[baseline CI run 39936840882](https://github.com/ubyuksel/agent-loop-audit/actions/runs/39936840882)
at commit `5391ec4c17df4d951602699d28e74bf9e3b75cde`, all 12 matrix jobs.

Owning-package maintenance: P1's __init__ version and AGENTS authority note were
updated for the owner's latest continuation/QA permission; P3's expected example
was regenerated for version0.1.0. No parsing, identity, accounting or rule semantics
changed. Final Q4 reviews the resulting exact candidate. No personal maintainer
identity, public URL or security contact was invented.
