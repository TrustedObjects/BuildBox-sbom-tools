# BuildBox SBOM tools - CycloneDX writer
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

## CycloneDX 1.6, JSON serialisation.
##
## CycloneDX has no build time scope: 'required' is what ships, 'optional'
## carries what the build needed, and the comment says so, so that a reader is
## never left guessing.

## @param Product name
## @param Product version
## @param Tool version
## @param Product type, a CycloneDX classification: 'firmware' by default
## @stdin Component lines
## @print CycloneDX 1.6 JSON document
function sbom_write_cyclonedx {
	local product="${1}"
	local product_version="${2}"
	local tool_version="${3}"
	local product_type="${4:-firmware}"
	local created
	created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	local serial="urn:uuid:$(uuidgen)"

	jq -s \
		--arg product "${product}" \
		--arg product_version "${product_version}" \
		--arg tool_name "${SBOM_TOOL_NAME}" \
		--arg tool_version "${tool_version}" \
		--arg created "${created}" \
		--arg serial "${serial}" \
		--arg product_type "${product_type}" \
		"${SBOM_JQ_LICENCE_HELPERS}"'
		def ref($c; $i):
			if ($c.purl // "") != "" then $c.purl
			else "component-" + ($i + 1 | tostring) end;

		. as $components
		| {
			bomFormat: "CycloneDX",
			specVersion: "1.6",
			serialNumber: $serial,
			version: 1,
			metadata: {
				timestamp: $created,
				tools: {
					components: [ {
						type: "application",
						name: $tool_name,
						version: $tool_version
					} ]
				},
				component: {
					type: $product_type,
					"bom-ref": "product",
					name: $product,
					version: (if $product_version == "" then "unknown" else $product_version end),
					supplier: { name: "Trusted Objects" }
				}
			},
			components: [ $components | to_entries[] | .key as $i | .value as $c | {
				type: ($c.type // "library"),
				"bom-ref": ref($c; $i),
				name: $c.name,
				version: (if ($c.version // "") == "" then "unknown" else $c.version end),
				scope: (if ($c.scope // "shipped") == "build" then "optional" else "required" end)
			}
			+ (if ($c.purl // "") == "" then {} else { purl: $c.purl } end)
			+ (if ($c.cpe // "") == "" then {} else { cpe: $c.cpe } end)
			+ (if ($c.supplier // "") == "" then {} else { supplier: { name: $c.supplier } } end)
			+ (if ($c.license // "") == "" then {}
			   elif is_spdx_expression($c.license) then {
				licenses: [ { expression: $c.license } ]
			   } else {
				# CycloneDX takes a licence name, so free text survives
				licenses: [ { license: { name: $c.license } } ]
			   } end)
			+ (if ($c.source // "") == "" then {} else {
				externalReferences: [ { type: "vcs", url: $c.source } ]
			} end)
			+ (if ($c.scope // "shipped") == "build" then {
				description: "Build time component, not shipped in the product"
			} else {} end)
			# Where the component was found, one property per place: the
			# images of a product do not hold the same packages even when
			# built on the same distribution
			+ (if (($c.contexts // []) | length) == 0 then {} else {
				properties: [ $c.contexts[] | {
					name: "bbx-sbom:found-in",
					value: .
				} ]
			} end)
			],
			dependencies: [ {
				ref: "product",
				dependsOn: [ $components | to_entries[]
					| select((.value.scope // "shipped") != "build")
					| ref(.value; .key) ]
			} ]
		}
	'
}
