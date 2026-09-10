# BuildBox SBOM tools

A [BuildBox](https://github.com/TrustedObjects/BuildBox) tool generating the
SBOM of a target, in **SPDX 2.3** and **CycloneDX 1.6**, for Cyber Resilience
Act compliance.

## Why it is short

A BuildBox target already declares every component of a delivery, each pinned
to an exact revision: the package list *is* a SBOM skeleton. This tool formats
it, and expands the packages which themselves contain many components.

## Installation

In your `.bbx/packages`, add a `buildbox_sbom_tools` package file:

```bash
SRC_PROTO=git
SRC_URI=https://github.com/TrustedObjects/BuildBox-sbom-tools.git
SRC_REVISION="master"
SRC_BUILD=prebuilt
```

Then list it in the target tools file (`.bbx/tools.<TARGET>`):

```
buildbox_sbom_tools
```

BuildBox puts the tool `bin/` on the `PATH`, so `bbx-sbom` is available to the
target scripts, with no build step.

## Usage

The SBOM has to be generated **after the build**: what a package really
contains is only known once it is built. The natural place is the target
delivery script, `DIST` in the target profile:

```bash
#!/bin/bash
set -e

bbx-sbom
```

```
Usage: bbx-sbom [OPTIONS]

  -o, --output DIR      Where to write the documents (default: $BB_TARGET_DIR/sbom)
  --name NAME           Product name (default: the project name)
  --product-version V   Product version (default: the profile revision)
  --format FORMAT       'spdx', 'cyclonedx' or 'both' (default: both)
```

Output, in `$BB_TARGET_DIR/sbom/` unless told otherwise:

| File | Content |
|---|---|
| `<product>-<target>.spdx.json` | SPDX 2.3 document |
| `<product>-<target>.cdx.json` | CycloneDX 1.6 document |
| `components.jsonl` | the collected components, one JSON per line |
| `exclusions.jsonl` | the packages left out, and why |

## Package fields

These fields go in the package files of `.bbx/packages/`, next to the `SRC_*`
ones. All are optional: without any of them a package is reported with what
BuildBox knows, which is already its name, its version, its origin and its
exact revision.

| Field | Role |
|---|---|
| `SBOM_SCOPE` | `shipped` (default), `build` or `excluded`, see below |
| `SBOM_EXCLUDE_REASON` | why the package is excluded. **Required** when `SBOM_SCOPE=excluded` |
| `SBOM_PLUGIN` | plugin expanding the package content, see [Plugins](#plugins) |
| `SBOM_NAME` | component name, when the BuildBox package name is not the upstream one |
| `SBOM_VERSION` | version, when the revision is not the upstream version |
| `SBOM_LICENSE` | SPDX licence expression, for example `Apache-2.0` or `MIT OR GPL-2.0-only` |
| `SBOM_SUPPLIER` | who publishes the component |
| `SBOM_CPE` | CPE 2.3 identifier, for vulnerability matching |
| `SBOM_PURL` | package URL, when the one built from the Git origin is not right |

> **Attention:** a package file is sourced by the shell, so **a value holding
> spaces must be quoted**: `SBOM_SUPPLIER="Upstream Corp"`.
> `SBOM_EXCLUDE_REASON` almost always needs it.

A licence which is not a plain SPDX expression is reported as `NOASSERTION`
rather than passed off as a licence: a wrong licence in a SBOM is worse than an
admitted gap. The tool counts the components without a licence and says so at
the end of the run.

### Scopes

| `SBOM_SCOPE` | Meaning | In the documents |
|---|---|---|
| `shipped` | part of the delivered product | yes, CycloneDX scope `required`, SPDX `CONTAINS` |
| `build` | needed to build, not shipped | yes, CycloneDX scope `optional`, SPDX `BUILD_DEPENDENCY_OF` |
| `excluded` | out of the SBOM entirely | no, listed in `exclusions.jsonl` with its reason |

A build time component is **not** an excluded one. Declaring a toolchain as
`build` keeps the record complete, which is what an audit expects, while
`excluded` is for what must not appear at all. An exclusion is never silent: it
lands in `exclusions.jsonl`, and a missing reason is warned about.

## Expanding a package

A package may contain many components: a firmware built from a distribution, a
container image, a bundle of third party sources. Expanding it is delegated,
and there is a **single contract** for that, resolved in this order:

| Order | Source | For |
|---|---|---|
| 1 | `.bbx-sbom/collect`, executable, in the package sources | sources we own |
| 2 | the plugin named by `SBOM_PLUGIN` | sources we do not own |
| 3 | nothing | the package is the single component it is |

The package itself is always reported, even when it expands: what BuildBox
pinned is part of the record.

### Collector contract

A collector is an executable writing **one JSON object per line** on stdout,
one line per component. Nothing else goes on stdout. It runs with the BuildBox
environment set, and with the package sources as working directory for a
`.bbx-sbom/collect`, so a useful collector fits in ten lines.

| Field | Required | Content |
|---|---|---|
| `name` | yes | component name |
| `version` | | version |
| `license` | | SPDX expression |
| `supplier` | | who publishes it |
| `purl` | | package URL |
| `cpe` | | CPE 2.3 identifier |
| `source` | | where the code comes from |
| `revision` | | exact revision, a commit for instance |
| `scope` | | `shipped` (default) or `build` |

The tool fills in what a collector leaves out: which BuildBox package the
component came from, and which collector found it. Components are merged on
name, version and purl, the first occurrence winning, so a component found
twice appears once and a document does not change between two runs on the same
tree.

This line oriented format is deliberately not SPDX nor CycloneDX: collectors
are shell scripts, and SBOM specifications keep moving. Writing the documents
is the tool's job, and only the tool has to follow the specifications.

### Plugins

A plugin is `plugins/<name>/collect` in this repository, an executable
following the collector contract. It is given:

| Variable | Content |
|---|---|
| `SBOM_PACKAGE` | the BuildBox package name |
| `SBOM_PACKAGE_SRC_DIR` | its sources directory in the target |

No plugin is provided yet.

## Not in scope: vulnerabilities

This tool does not check CVEs. A SBOM is a build artefact, immutable once the
product is built, while a vulnerability report is dated and changes without any
rebuild. The two are kept apart on purpose: generate the SBOM at delivery time,
and run a vulnerability scan against the stored documents whenever needed,
including on past deliveries.

## License

Copyright Trusted Objects.

GNU General Public License v2. See [LICENSE](LICENSE) for details.
