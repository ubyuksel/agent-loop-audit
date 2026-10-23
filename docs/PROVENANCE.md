# P1 source and provenance register

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

Competitor gate: supplied research dated 2026-10-23 is current on the P1 date;
the >30-day refresh gate is not triggered. No competitor was installed or run.
The plan's nearest comparator pin is agent-call-graph
`a4326ca1391e9e7e2cfebe94dd905c6565434b34`; its stated native Codex gap remains
a planning hypothesis, not a newly measured market or exclusivity claim.

Distribution name is provisional; registry name, dependency/license provenance,
history, installed wheel and full platform validation remain later release gates.

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
/git/ref/tags/v7.1.0. No workflow has been pushed or executed.

Owning-package maintenance: P1's __init__ version and AGENTS authority note were
updated for the owner's latest continuation/QA permission; P3's expected example
was regenerated for version0.1.0. No parsing, identity, accounting or rule semantics
changed. Final Q4 reviews the resulting exact candidate. No personal maintainer
identity, public URL or security contact was invented.
