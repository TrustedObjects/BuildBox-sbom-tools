# BuildBox SBOM tools - SPDX writer
# Copyright (C) 2026 Trusted Objects

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.

## SPDX 2.3, JSON serialisation.
##
## What is not known is written NOASSERTION rather than guessed: an SBOM
## claiming a licence it did not read is worse than one admitting the gap.

## @param Document name
## @param Product name
## @param Product version
## @param Tool version
## @stdin Component lines
## @print SPDX 2.3 JSON document
function sbom_write_spdx {
	local doc_name="${1}"
	local product="${2}"
	local product_version="${3}"
	local tool_version="${4}"
	local created
	created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	local namespace="https://trusted-objects.com/spdxdocs/${doc_name}-$(uuidgen)"

	jq -s \
		--arg doc_name "${doc_name}" \
		--arg product "${product}" \
		--arg product_version "${product_version}" \
		--arg tool "${SBOM_TOOL_NAME} ${tool_version}" \
		--arg created "${created}" \
		--arg namespace "${namespace}" \
		"${SBOM_JQ_LICENCE_HELPERS}"'
		# SPDX identifiers must be unique and stable inside the document
		def spdxid($i): "SPDXRef-Package-" + ($i + 1 | tostring);
		def licence($c):
			if is_spdx_expression($c.license) then $c.license else "NOASSERTION" end;
		def supplier($c):
			if ($c.supplier // "") == "" then "NOASSERTION"
			else "Organization: " + $c.supplier end;
		def download($c):
			if ($c.source // "") == "" then "NOASSERTION" else $c.source end;

		. as $components
		| {
			spdxVersion: "SPDX-2.3",
			dataLicense: "CC0-1.0",
			SPDXID: "SPDXRef-DOCUMENT",
			name: $doc_name,
			documentNamespace: $namespace,
			creationInfo: {
				created: $created,
				creators: [ "Tool: " + $tool ]
			},
			packages: (
				[ {
					SPDXID: "SPDXRef-Product",
					name: $product,
					versionInfo: (if $product_version == "" then "NOASSERTION" else $product_version end),
					downloadLocation: "NOASSERTION",
					filesAnalyzed: false,
					licenseConcluded: "NOASSERTION",
					licenseDeclared: "NOASSERTION",
					supplier: "Organization: Trusted Objects",
					copyrightText: "NOASSERTION"
				} ]
				+ [ $components | to_entries[] | .key as $i | .value as $c | {
					SPDXID: spdxid($i),
					name: $c.name,
					versionInfo: (if ($c.version // "") == "" then "NOASSERTION" else $c.version end),
					downloadLocation: download($c),
					filesAnalyzed: false,
					licenseConcluded: "NOASSERTION",
					licenseDeclared: licence($c),
					supplier: supplier($c),
					copyrightText: "NOASSERTION"
				}
				+ (if ($c.purl // "") == "" then {} else {
					externalRefs: [ {
						referenceCategory: "PACKAGE-MANAGER",
						referenceType: "purl",
						referenceLocator: $c.purl
					} ]
				} end)
				+ (if ($c.revision // "") == "" then {} else {
					sourceInfo: ("Built from revision " + $c.revision)
				} end)
				# Free text licence: kept as a comment, the field itself
				# only ever holding a valid expression
				+ (if (($c.license // "") != "") and (is_spdx_expression($c.license) | not)
				   then { licenseComments: ("Declared licence, not an SPDX expression: " + $c.license) }
				   else {} end)
				+ (if ($c.scope // "shipped") == "build" then {
					comment: "Build time component, not shipped in the product"
				} else {} end)
				]
			),
			relationships: (
				[ {
					spdxElementId: "SPDXRef-DOCUMENT",
					relatedSpdxElement: "SPDXRef-Product",
					relationshipType: "DESCRIBES"
				} ]
				+ [ $components | to_entries[] | .key as $i | .value as $c | {
					spdxElementId: "SPDXRef-Product",
					relatedSpdxElement: spdxid($i),
					relationshipType: (
						if ($c.scope // "shipped") == "build"
						then "BUILD_DEPENDENCY_OF" else "CONTAINS" end
					)
				} ]
			)
		}
	'
}
