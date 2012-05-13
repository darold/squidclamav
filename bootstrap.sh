#! /bin/sh
#-------------------------------------------------------------------------
#
# This bootstrap script i used to clean dist directory and rebuild
# all configure and install script from scratch.
#
# Do not execute this file is you don't have aclocal / autoconf and
# automake installed, I mean GNU Autotools.
#
#-------------------------------------------------------------------------
rm -rf  autoscan.log autom4te.cache config.h.in configure \
	Makefile.in config/* config.status Makefile config.h stamp-h1 \
	.deps config.log src/Makefile src/Makefile.in src/*.o libtool \
	src/squidclamav src/.deps etc/Makefile etc/Makefile.in src/.libs/

# Autotool versions preferred. To override either edit the script
# to match the versions you want to use, or set the variables on
# the command line like "env acver=.. amver=... ./bootstrap.sh"

acversions="${acver:-2.57}"
amversions="${amver:-1.6}"

check_version()
{
  eval $2 --version 2>/dev/null | grep -i "$1.*$3" >/dev/null
}

find_version()
{
  tool=$1
  found="NOT_FOUND"
  shift
  versions="$*"
  for version in $versions; do
    for variant in "" "-${version}" "`echo $version | sed -e 's/\.//g'`"; do
      if check_version $tool ${tool}${variant} $version; then
        found="${variant}"
        break
      fi
    done
    if [ "x$found" != "xNOT_FOUND" ]; then
      break
    fi
  done
  if [ "x$found" = "xNOT_FOUND" ]; then
    echo "WARNING: Cannot find $tool version $versions" >&2
    echo "Trying `$tool --version | head -1`" >&2
    found=""
  fi
  echo $found
  echo $found
}

bootstrap() {
  if "$@"; then
    true # Everything OK
  else
    echo "$1 failed"
    echo "Autotool bootstrapping failed. You will need to investigate and correc
t" ;
    echo "before you can develop on this source tree"
    exit 1
  fi
}

fixmakefiles() {
  bad_files="`find . -name Makefile.in | xargs grep -l "AR = ar"`"
  if [ -n "$bad_files" ]; then
    perl -i -p -e 's/^/#/ if /^AR = ar/' $bad_files
  fi
}

# Make sure config exists
mkdir -p config

# Adjust paths of required autool packages
amver=`find_version automake ${amversions}`
acver=`find_version autoconf ${acversions}`

# Bootstrap the autotool subsystems
libtoolize --copy --force
bootstrap aclocal$amver
bootstrap autoheader$acver
bootstrap automake$amver --foreign --add-missing --copy --force-missing
fixmakefiles
bootstrap autoconf$acver

echo "Autotool bootstrapping complete."

#aclocal \
#&& autoheader \
#&& automake --foreign --add-missing --copy --force-missing \
#&& autoconf


