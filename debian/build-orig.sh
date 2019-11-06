#!/bin/bash

PACKAGENAME_DEBIAN="c-icap-module-squidclamav"
PACKAGENAME_ORIGINAL="squidclamav"

GIT_URL="git://github.com/darold/${PACKAGENAME_ORIGINAL}.git"

if [ ! -z "${GIT_URL}" ]
then
    USE_GIT_URL="${GIT_URL}"
else
    echo "Error: unable to detect GIT_URL variable"
    exit 1
fi

STARTPATH="$(pwd)"
SQUIDCLAMAVTMP="$(mktemp -d)/"

pushd "${SQUIDCLAMAVTMP}/"

if [ -d $GIT_URL/.bzr ]; then
    bzr co --lightweight $USE_GIT_URL $SQUIDCLAMAVTMP
else
    git clone --depth 1 $USE_GIT_URL $SQUIDCLAMAVTMP
fi

# Detect Package variable
PACKAGE_VER="$(sed -n -e 's/^\(.*\)\(version \)\(.*\)$/\3/p' ChangeLog |head -n1)"

if [ ! -z "${PACKAGE_VER}" ]
then
    git archive --format=tar --prefix="${PACKAGENAME_DEBIAN}"-"${PACKAGE_VER}/" master | gzip > "${STARTPATH}"/"${PACKAGENAME_DEBIAN}"_"${PACKAGE_VER}".orig.tar.gz
else
    echo "Error: Unable to detect version number, please adjust the PACKAGE_VER string."
    exit 1
fi

rm -rf $SQUIDCLAMAVTMP

cd $STARTPATH

tar -xf ${PACKAGENAME_DEBIAN}_${PACKAGE_VER}.orig.tar.gz

if [ -d $PACKAGENAME_DEBIAN-$PACKAGE_VER/ ]
then
    echo " ---------------------- "
    echo "To build the debian packages, run the following: "
    echo "cd $PACKAGENAME_DEBIAN-$PACKAGE_VER/"
    echo
    echo "Install the needed build depends : "
    echo "apt install debhelper libclamav-dev libdb-dev libicapapi-dev libltdl-dev --autoremove"
    echo
    echo "Build the package:"
    echo "dpkg-buildpackage -uc -us -sa"
    echo
    echo "The resulting deb(s) can be found here : ls ..\*.deb"
    echo "And cleanup your system with : "
    echo "apt remove --autoremove debhelper libclamav-dev libdb-dev libicapapi-dev libltdl-dev"
    echo " ---------------------- "
else
    echo "Unable find folder $PACKAGENAME_DEBIAN-$PACKAGE_VER, did something go wrong?"
    exit 1
fi

exit 0
