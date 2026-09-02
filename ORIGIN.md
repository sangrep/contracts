# Origin and provenance

This repository is the canonical standalone home for Sangrep's language-neutral contract work.
The initial evidence and citation modules were developed before this repository was established and
were admitted only after a file-by-file authorship, license, and byte-provenance review. Public
history describes the component itself; source-control locations and operational records are not
part of the public artifact.

All implementation, schema, test, tool, and documentation source in this repository is original
Sangrep Contracts work unless an entry in
[`provenance/public-source-origin-v1.json`](provenance/public-source-origin-v1.json) says otherwise.
There are currently no third-party source files. Development dependencies are not bundled into the
runtime package.

Generated Python wire types, schema-bound rules, and vector manifests identify their generators and
are checked for drift. Conformance inputs use synthetic domains and data. The development trust
registry contains only public verification material from an accepted receipt; no signing secret is
stored here.

The repository is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
