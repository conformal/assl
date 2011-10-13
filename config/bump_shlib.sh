#!/bin/sh
#
# Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# Bumps shared library version:
#   - Bumps shared lib version according to specified level (major or minor)
#   - Updates all necessary package control files with new shlib version
#   - Automatically stages changes in git since a major bump involves
#     adding and removing files for debian packaging

LIBRARY=assl
SCRIPT=$(basename $0)
HEADER=../${LIBRARY}.h
VER_PREFIX=$(echo $LIBRARY | tr '[:lower:]' '[:upper:]')
SHLIB_FILE=../shlib_version
DEB_CONTROL=debian/control
DEB_PACKAGE_BASE=lib$LIBRARY
PORT_CATEGORY=security
PORT_NAME=${LIBRARY}
PORT_MAKEFILE=openbsd/${PORT_CATEGORY}/${PORT_NAME}/Makefile

# verify params
if [ $# -lt 1 ]; then
	echo "usage: $SCRIPT {major | minor}"
	exit 1
fi

# verify valid type
RTYPE="$1"
if [ "$RTYPE" != "major" -a "$RTYPE" != "minor" ]; then
	echo "$SCRIPT: error: type must be major or minor"
	exit 1
fi

CUR_DIR=$(pwd)
cd "$(dirname $0)"

# verify header exists
if [ ! -f "$HEADER" ]; then
	echo "$SCRIPT: error: $HEADER does not exist" 1>&2
	exit 1
fi

# verify shlib version file exists
if [ ! -f "$SHLIB_FILE" ]; then
	echo "$SCRIPT: error: $SHLIB_FILE does not exist" 1>&2
	exit 1
fi

# verify port makefile exists
if [ ! -f "$PORT_MAKEFILE" ]; then
	echo "$SCRIPT: error: $PORT_MAKEFILE does not exist" 1>&2
	exit 1
fi

# verify debian control exists
if [ ! -f "$DEB_CONTROL" ]; then
	echo "$SCRIPT: error: $DEB_CONTROL does not exist" 1>&2
	exit 1
fi

# verify git is available
if ! type git >/dev/null 2>&1; then
	echo -n "$SCRIPT: error: Unable to find 'git' in the system path."
	exit 1
fi

# get project version
PAT_PREFIX="(^#define[[:space:]]+${VER_PREFIX}_VERSION"
PAT_SUFFIX='[[:space:]]+)[0-9]+$'
PMAJOR=$(egrep "${PAT_PREFIX}_MAJOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
PMINOR=$(egrep "${PAT_PREFIX}_MINOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
PPATCH=$(egrep "${PAT_PREFIX}_PATCH${PAT_SUFFIX}" $HEADER | awk '{print $3}')
if [ -z "$PMAJOR" -o -z "$PMINOR" -o -z "$PPATCH" ]; then
	echo "$SCRIPT: error: unable to get version from $HEADER" 1>&2
	exit 1
fi

# get shlib version
. $SHLIB_FILE
if [ -z "$major" -o -z "$minor" ]; then
	echo "$SCRIPT: error: unable to get version from $SHLIB_FILE" 1>&2
	exit 1
fi
SHLIB_MAJOR_OLD=$major
SHLIB_MAJOR=$major
SHLIB_MINOR=$minor

# bump shlib version according to type
if [ "$RTYPE" = "major" ]; then
	SHLIB_MAJOR=$(expr $SHLIB_MAJOR + 1)
	SHLIB_MINOR=0
elif [ "$RTYPE" = "minor" ]; then
	SHLIB_MINOR=$(expr $SHLIB_MINOR + 1)
fi
SHLIB_VER="${SHLIB_MAJOR}.${SHLIB_MINOR}"

# modify debian files if major bump
if [ "$RTYPE" = "major" ]; then
	DEB_PACKAGE="${DEB_PACKAGE_BASE}${SHLIB_MAJOR_OLD}"
	DEB_INSTALL="debian/${DEB_PACKAGE}.install"
	DEB_SHLIB="debian/${DEB_PACKAGE}.shlibs"
	DEB_PACKAGE_NEW="${DEB_PACKAGE_BASE}${SHLIB_MAJOR}"
	DEB_INSTALL_NEW="debian/${DEB_PACKAGE_NEW}.install"
	DEB_SHLIB_NEW="debian/${DEB_PACKAGE_NEW}.shlibs"

	# verify debian install file exists
	if [ ! -f "$DEB_INSTALL" ]; then
		echo "$SCRIPT: error: $DEB_INSTALL does not exist" 1>&2
		exit 1
	fi

	# verify debian shlibs file exists
	if [ ! -f "$DEB_SHLIB" ]; then
		echo "$SCRIPT: error: $DEB_SHLIB does not exist" 1>&2
		exit 1
	fi

	# modify debian control with new major
	sed -E "
	    s/$DEB_PACKAGE/${DEB_PACKAGE_NEW}/;
	" <"$DEB_CONTROL" >"${DEB_CONTROL}.tmp"

	# update debian install file
	cp "$DEB_INSTALL" "$DEB_INSTALL_NEW.tmp"

	# update debian shlibs file
	# the next released package which contains the new shlib major
	# will be at least one patch level higher
	PPATCH=$(expr $PPATCH + 1)
	echo -n "$DEB_PACKAGE_BASE $SHLIB_MAJOR $DEB_PACKAGE_NEW (>= " \
	    >"${DEB_SHLIB_NEW}.tmp"
	echo    "$PMAJOR.$PMINOR.$PPATCH)" \
	    >>"${DEB_SHLIB_NEW}.tmp"
fi

# update shlib file with new shlib version
echo "major=$SHLIB_MAJOR" >"${SHLIB_FILE}.tmp"
echo "minor=$SHLIB_MINOR" >>"${SHLIB_FILE}.tmp"

# modify OpenBSD package files with new shlib version
SHLIB_PAT="(SHARED_LIBS=[[:space:]]+.*${LIBRARY}[[:space:]]+)[0-9]+\.[0-9]+(.*)"
sed -E "
    s/${SHLIB_PAT}/\1${SHLIB_VER}\2/;
" <"$PORT_MAKEFILE" >"${PORT_MAKEFILE}.tmp"

# apply changes
if [ "$RTYPE" = "major" ]; then
	mv "${DEB_CONTROL}.tmp" "$DEB_CONTROL"
	mv "${DEB_INSTALL_NEW}.tmp" "$DEB_INSTALL_NEW"
	mv "${DEB_SHLIB_NEW}.tmp" "$DEB_SHLIB_NEW"
	git rm "$DEB_INSTALL"
	git rm "$DEB_SHLIB"
	git add "$DEB_CONTROL"
	git add "$DEB_INSTALL_NEW"
	git add "$DEB_SHLIB_NEW"
fi
mv "${SHLIB_FILE}.tmp" "$SHLIB_FILE"
mv "${PORT_MAKEFILE}.tmp" "$PORT_MAKEFILE"
git add "$SHLIB_FILE"
git add "$PORT_MAKEFILE"

echo "All files have been prepared and added to the git staging area."
echo "Use the following commands to review the changes for accuracy:"
echo "  git status"
echo "  git diff --cached"
