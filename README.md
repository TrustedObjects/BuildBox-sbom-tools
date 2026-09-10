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
| `SBOM_SOURCE` | source URL to publish instead of `SRC_URI`, see [Sources which must not be published](#sources-which-must-not-be-published) |
| `SBOM_TYPE` | component type: `library` (default), `application`, `firmware`, `operating-system`, `device` |

> **Attention:** a package file is sourced by the shell, so **a value holding
> spaces must be quoted**: `SBOM_SUPPLIER="Upstream Corp"`.
> `SBOM_EXCLUDE_REASON` almost always needs it.

A licence which is not a plain SPDX expression is reported as `NOASSERTION`
rather than passed off as a licence: a wrong licence in a SBOM is worse than an
admitted gap. The tool counts the components without a licence and says so at
the end of the run.

That check is a shape check, not a lookup: it rejects what cannot be an SPDX
expression, and does not tell a real identifier from a plausible looking one,
so `Proprietary-TO` goes through untouched. Checking against the SPDX licence
list would mean shipping that list and keeping it current, which is not done
here.

Free text such as `Apache Software License`, which apt and pip hand out, is
**not lost**: each format carries it its own way, so nothing is thrown away and
nothing is passed off as an SPDX expression.

| Licence | SPDX | CycloneDX |
|---|---|---|
| an expression, `MIT`, `GPL-2.0-only OR MIT` | `licenseDeclared` | `licenses[].expression` |
| free text, `Apache Software License` | `NOASSERTION` plus `licenseComments` | `licenses[].license.name` |
| none | `NOASSERTION` | absent |

### Sources which must not be published

`SRC_URI` is what BuildBox clones from, and it is reported as the download
location of the component. On an internal Git or HTTP server, that address has
no place in a document meant to leave the company. `SBOM_SOURCE` replaces it:

```bash
SBOM_SOURCE=https://example.com/
```

The component is then reported with that URL as its source, and its purl is
built **without** the `vcs_url` qualifier, because a URL which is not the
repository must not be presented as one. Nothing else changes: the exact
revision is still reported, in the component `revision` field, in the SPDX
`sourceInfo` and in the CycloneDX component, so the build stays traceable
internally from the same document.

It is a per-package field on purpose, and it is worth checking when a package
is added to a target: the tool cannot tell an internal host from a public one.

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
| `type` | | `library` (default), `application`, `firmware`, `operating-system`, `device` |

Any other field is kept as it is in `components.jsonl`, unused by the documents
but part of the audit trail: a collector can record there where each component
was found, in which container image for instance.

A collector which fails, or which finds nothing, is reported: its output is
read before being taken in, so that its exit code is not swallowed. A silently
empty expansion is the worst outcome for a compliance document.

The tool fills in what a collector leaves out: which BuildBox package the
component came from, and which collector found it. Components are merged on
name, version and purl, the first occurrence winning, so a component found
twice appears once and a document does not change between two runs on the same
tree.

This line oriented format is deliberately not SPDX nor CycloneDX: collectors
are shell scripts, and SBOM specifications keep moving. Writing the documents
is the tool's job, and only the tool has to follow the specifications.

### Writing a collector

Three things learnt the hard way, worth knowing before writing one:

- **Do not redo heavy work.** When the data already comes from an extraction
  step of its own, read what that step produced instead of running it again.
  The SBOM and the other deliverables then always describe the same thing, and
  the collector fails with a clear message when the step has not run.
- **Emit a simple text format where `jq` is missing.** A collector gathering
  its data inside a virtual machine or a container may not have `jq` there.
  Write tab separated lines, and convert them in the collector, on the BuildBox
  side, where `jq` is available.
- **Parse tab separated lines with `jq`, not with `read`.** A tab is IFS
  whitespace, so the shell collapses consecutive tabs: one empty field shifts
  every following one, silently.

### Plugins

A plugin is `plugins/<name>/collect` in this repository, an executable
following the collector contract. It is given:

| Variable | Content |
|---|---|
| `SBOM_PACKAGE` | the BuildBox package name |
| `SBOM_PACKAGE_SRC_DIR` | its sources directory in the target |

#### `openwrt`

Lists the components of an OpenWrt firmware. Declare it in the package file of
your OpenWrt sources:

```bash
SBOM_PLUGIN=openwrt
```

> **This collector requires `CONFIG_JSON_CYCLONEDX_SBOM=y` in the OpenWrt
> configuration of the firmware.** It is off by default in OpenWrt, unless
> building as a buildbot. Add it to the configuration your build applies, the
> `config-*` file the build script copies over `.config`, not to `.config`
> itself, which the build overwrites.

OpenWrt knows its own content far better than any parsing of the build tree
would: with that option set, it writes a CycloneDX document next to the image,
cross referencing the image manifest with `tmp/.packageinfo`, and it already
handles what is easy to get wrong, the kernel and the ABI suffixed package
names (`libfoo1` for `libfoo`). The plugin reads that document, so it follows
OpenWrt upstream for free.

Without the option, the plugin does not fail: it falls back to the image
manifest, which gives names and versions but **no licence and no CPE**, and it
says so on every run. A SBOM without licences does not answer a CRA
requirement, so treat that fallback as a warning to act on, not as a mode of
operation.

The `.config` is deliberately not read. It says what was *selected*, host tools
and build dependencies included, while the manifest says what really ended up
in the firmware. Only the latter is defensible in a compliance document.

Several licences on one package are joined with `AND`: for compliance, having
to satisfy them all is the safe reading of an ambiguous `PKG_LICENSE`.

## Not in scope: vulnerabilities

This tool does not check CVEs. A SBOM is a build artefact, immutable once the
product is built, while a vulnerability report is dated and changes without any
rebuild. The two are kept apart on purpose: generate the SBOM at delivery time,
and run a vulnerability scan against the stored documents whenever needed,
including on past deliveries.

## License

Copyright Trusted Objects.

GNU General Public License v2. See [LICENSE](LICENSE) for details.
