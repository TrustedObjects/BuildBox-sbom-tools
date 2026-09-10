# BuildBox SBOM tools - component collection
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

## A BuildBox package is one component, and may contain many more: a firmware
## built from a distribution, a container image, a bundle of third party
## sources. Expanding it is delegated, and there is a single contract for that,
## resolved in this order:
##
## 1. the executable '.bbx-sbom/collect' in the package sources, which the
##    package owns and which knows its own content,
## 2. the plugin named by SBOM_PLUGIN in the package file, for sources we do
##    not own, such as an OpenWrt tree,
## 3. nothing, and the package is reported as the single component it is.
##
## All three write component lines on stdout, so they are interchangeable and a
## third party collector is a ten line script.

## Resolved version of a package: what was really cloned beats what was asked
## for, an unpinned branch being useless in a SBOM.
## @param Package name
## @param Package source directory
## @print Version, empty when nothing is known
function sbom_package_version () (
	local pkg_name="${1}"
	local src_dir="${2}"
	local declared
	declared=$(bb_get_package_revision "${pkg_name}")
	if [ -n "${src_dir}" ] && [ -d "${src_dir}/.git" ]; then
		local described
		described=$(git -C "${src_dir}" describe --tags --always --dirty 2> /dev/null)
		if [ -n "${described}" ]; then
			echo "${described}"
			return 0
		fi
	fi
	if [ -n "${declared}" ]; then
		echo "${declared}"
		return 0
	fi
	echo "${SRC_REVISION}"
)

## Exact commit of a package, when it comes from Git: this is what makes the
## document reproducible, a branch name does not.
## @param Package source directory
## @print Commit hash, empty when not a Git source
function sbom_package_commit () (
	local src_dir="${1}"
	if [ -z "${src_dir}" ] || [ ! -d "${src_dir}/.git" ]; then
		return 0
	fi
	git -C "${src_dir}" rev-parse HEAD 2> /dev/null
)

## Package URL of a package, built from what BuildBox knows. 'generic' is the
## honest type here: BuildBox packages are not npm nor pypi entries, and the
## VCS qualifier carries what identifies the code.
## @param Component name
## @param Version
## @param Source URI
## @param Commit
## @print purl, empty when there is not enough to build one
function sbom_purl {
	local name="${1}"
	local version="${2}"
	local uri="${3}"
	local commit="${4}"
	if [ -z "${name}" ]; then
		return 0
	fi
	local purl="pkg:generic/${name}"
	if [ -n "${version}" ]; then
		purl="${purl}@${version}"
	fi
	if [ -n "${uri}" ]; then
		purl="${purl}?vcs_url=${uri}"
		if [ -n "${commit}" ]; then
			purl="${purl}%40${commit}"
		fi
	fi
	echo "${purl}"
}

## Collect one BuildBox package, delegating to its collector when it has one.
## The package fields are already loaded by the caller.
## @param Package name
## @env `SBOM_PLUGINS_DIR`: where the plugins live
## @print Component lines
function sbom_collect_package {
	local pkg_name="${1}"
	local scope="${SBOM_SCOPE:-shipped}"

	case "${scope}" in
		shipped|build) ;;
		excluded)
			# Reported apart, never silently dropped
			sbom_emit \
				name "${SBOM_NAME:-${pkg_name}}" \
				buildbox_package "${pkg_name}" \
				scope excluded \
				reason "${SBOM_EXCLUDE_REASON}" \
				> "${SBOM_EXCLUSIONS_FILE}.tmp"
			cat "${SBOM_EXCLUSIONS_FILE}.tmp" >> "${SBOM_EXCLUSIONS_FILE}"
			rm -f "${SBOM_EXCLUSIONS_FILE}.tmp"
			if [ -z "${SBOM_EXCLUDE_REASON}" ]; then
				sbom_warn "package '${pkg_name}' is excluded without SBOM_EXCLUDE_REASON"
			fi
			return 0
			;;
		*)
			sbom_warn "package '${pkg_name}' declares an unknown SBOM_SCOPE '${scope}', taken as shipped"
			scope="shipped"
			;;
	esac

	local src_dir
	src_dir=$(bb_get_package_src_dir "${pkg_name}" 2> /dev/null)
	local name="${SBOM_NAME:-$(basename "$(bb_get_package_name_no_revision "${pkg_name}")")}"
	local version="${SBOM_VERSION:-$(sbom_package_version "${pkg_name}" "${src_dir}")}"
	local commit
	commit=$(sbom_package_commit "${src_dir}")
	# The licence is passed on as it is: the writers know how to carry a name
	# which is not an SPDX expression without losing it
	local licence="${SBOM_LICENSE}"
	# SBOM_SOURCE replaces SRC_URI in the document, for a package whose source
	# server has no place in it: an internal one, typically. The purl then
	# carries no vcs_url qualifier, because a URL which is not the repository
	# must not be presented as one; the exact revision is reported all the
	# same, in its own field.
	local source_uri="${SRC_URI}"
	local purl_uri="${SRC_URI}"
	if [ -n "${SBOM_SOURCE}" ]; then
		source_uri="${SBOM_SOURCE}"
		purl_uri=""
	fi
	local purl="${SBOM_PURL:-$(sbom_purl "${name}" "${version}" "${purl_uri}" "${commit}")}"

	# The package itself, always reported: even when it expands into many
	# components, what BuildBox pinned is part of the record
	sbom_emit \
		name "${name}" \
		version "${version}" \
		license "${licence}" \
		supplier "${SBOM_SUPPLIER}" \
		purl "${purl}" \
		cpe "${SBOM_CPE}" \
		source "${source_uri}" \
		revision "${commit}" \
		scope "${scope}" \
		type "${SBOM_TYPE}" \
		origin buildbox \
		buildbox_package "${pkg_name}"

	# Then whatever it contains
	local collector="${src_dir}/.bbx-sbom/collect"
	if [ -n "${src_dir}" ] && [ -x "${collector}" ]; then
		sbom_run_collector "${pkg_name}" "pkg-script" "${src_dir}" \
			"${collector}"
		return $?
	fi
	if [ -n "${SBOM_PLUGIN}" ]; then
		local plugin="${SBOM_PLUGINS_DIR}/${SBOM_PLUGIN}/collect"
		if [ ! -x "${plugin}" ]; then
			sbom_warn "package '${pkg_name}' asks for the unknown SBOM plugin '${SBOM_PLUGIN}'"
			return 0
		fi
		SBOM_PACKAGE="${pkg_name}" SBOM_PACKAGE_SRC_DIR="${src_dir}" \
			sbom_run_collector "${pkg_name}" "${SBOM_PLUGIN}" "${src_dir}" \
				"${plugin}"
		return $?
	fi
	return 0
}

## Run a collector and take in its components.
## The output is collected before being emitted, so that a collector failing
## is seen: in a pipeline its exit code would be hidden by the next stage, and
## a silently empty expansion is the worst outcome for a compliance document.
## @param Package name
## @param Collector name, for the origin field
## @param Working directory
## @param Collector path
## @print Component lines
## @return 0 on success, 1 when the collector failed
function sbom_run_collector {
	local pkg_name="${1}"
	local origin="${2}"
	local work_dir="${3}"
	local collector="${4}"
	sbom_log "\t  ${origin} collector" >&2
	local out
	out=$(mktemp)
	local ret=0
	( cd "${work_dir}" > /dev/null 2>&1 || cd .; "${collector}" ) > "${out}" || ret=$?
	if [ ${ret} -ne 0 ]; then
		sbom_warn "the ${origin} collector of '${pkg_name}' failed (exit ${ret}), its content is missing from the SBOM"
		rm -f "${out}"
		return 1
	fi
	# A collector writing nothing is worth saying: it may be a silent failure
	if [ ! -s "${out}" ]; then
		sbom_warn "the ${origin} collector of '${pkg_name}' found no component"
	else
		sbom_tag_children "${pkg_name}" "${origin}" < "${out}"
	fi
	rm -f "${out}"
	return 0
}

## Complete the lines a collector produced with what it cannot know: which
## BuildBox package they came from, and which collector found them. A collector
## setting those fields itself is left alone.
## @param BuildBox package name
## @param Collector name
## @stdin Component lines
## @print Component lines
function sbom_tag_children {
	jq -c --arg pkg "${1}" --arg origin "${2}" '
		. as $c
		| $c
		| .buildbox_package = ($c.buildbox_package // $pkg)
		| .origin = ($c.origin // $origin)
		| .scope = ($c.scope // "shipped")
	'
}
