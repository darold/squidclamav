dnl Process this file with autoconf to produce a configure script.


AC_INIT([SquidClamav], [7.2], [http://squidclamav.darold.net/], [squidclamav])

AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O
AC_C_BIGENDIAN
AC_CONFIG_MACRO_DIRS([m4])

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_OBJDIR
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl AC_CANONICAL_HOST

#if test "x$GCC" != "x" ; then
#	AC_USE_SYSTEM_EXTENSIONS
#fi

CFLAGS="$CFLAGS -Wall"

#check for c-icap
AC_ARG_WITH(c-icap,
[  --with-c-icap		  Where to find c-icap ],
[
    cicapdir="$withval"
    if test -f $withval/bin/c-icap-config; then
       cicapflags=`$withval/bin/c-icap-config --cflags`
       cicaplibs=`$withval/bin/c-icap-config --libs`
       cicapetc=`$withval/bin/c-icap-config --configdir`
       cicapprefix=`$withval/bin/c-icap-config --prefix`
       cicapmods=`$withval/bin/c-icap-config --modulesdir`
       cicapdatadir=`$withval/bin/c-icap-config --datarootdir`
       cicaplibflags=`$withval/bin/c-icap-libicapapi-config --cflags`
       cicapliblibs=`$withval/bin/c-icap-libicapapi-config --libs`
       cicapversion=`$withval/bin/c-icap-config --version`
       cicaphastmpl=`$withval/bin/c-icap-config --version | grep -v "^0.1"`
       cicaphasalldata=`c-icap-config --version | sed 's/\.//g'`
    else
       cicapflags=`c-icap-config --cflags`
       cicaplibs=`c-icap-config --libs` 
       cicapetc=`c-icap-config --configdir`
       cicapprefix=`c-icap-config --prefix`
       cicapmods=`c-icap-config --modulesdir`
       cicapdatadir=`c-icap-config --datarootdir`
       cicaplibflags=`c-icap-libicapapi-config --cflags`
       cicapliblibs=`c-icap-libicapapi-config --libs`
       cicapversion=`c-icap-config --version`
       cicaphastmpl=`c-icap-config --version | grep -v "^0.1"`
       cicaphasalldata=`c-icap-config --version | sed 's/\.//g'`
    fi
],
)

if test -z "$cicapdir"; then
    if c-icap-config >& /dev/null; then
        cicapflags=`c-icap-config --cflags`
        cicaplibs=`c-icap-config --libs` 
        cicapetc=`c-icap-config --configdir`
        cicapprefix=`c-icap-config --prefix`
        cicapmods=`c-icap-config --modulesdir`
        cicapdatadir=`c-icap-config --datarootdir`
        cicaplibflags=`c-icap-libicapapi-config --cflags`
        cicapliblibs=`c-icap-libicapapi-config --libs`
        cicapversion=`c-icap-config --version`
        cicaphastmpl=`c-icap-config --version | grep -v "^0.1"`
	cicaphasalldata=`c-icap-config --version | sed 's/\.//g'`
    else
        echo "ERROR: c-icap-config not found!"
	exit -1;
    fi
fi

# Check for libarchive
AC_ARG_WITH(libarchive,
[  --with-libarchive	  Where to find archive.h ],
[
    if test -f $withval/archive.h; then
	haslibarchive='yes'
	libarchivelibs=" -larchive -lz -lbz2"
        libarchivedir=" -I$withval"
    else
        if test -f $withval/include/archive.h; then
	    haslibarchive='yes'
	    libarchivelibs=" -larchive -lz -lbz2"
            libarchivedir=" -I$withval/include"
        fi
    fi
],
)

if test -z "$haslibarchive"; then
    if test -f "/usr/include/archive.h"; then
	haslibarchive='yes'
	libarchivelibs=" -larchive -lz -lbz2"
	libarchivedir=""
    else
	if test -f "/usr/local/include/archive.h"; then
	    haslibarchive='yes'
	    libarchivelibs=" -larchive -lz -lbz2"
	    libarchivedir=" -I/usr/local/include"
	fi
    fi
fi

AM_CONDITIONAL(CICAPMODULESDIR, [test -n $cicapmods])

CFLAGS="$CFLAGS $cicapflags $libarchivedir"
MODULES_LIBADD="$cicaplibs $libarchivelibs"
UTILITIES_LIBADD="$cicapliblibs"
UTILITIES_CFLAGS="$cicaplibflags"
CONFDIR="$cicapetc"
MODSDIR="$cicapmods"
DATADIR="$cicapdatadir"
CICAPVERSION="$cicapversion"
AC_SUBST(MODULES_LIBADD)
AC_SUBST(UTILITIES_LIBADD)
AC_SUBST(UTILITIES_CFLAGS)
AC_SUBST(CONFDIR)
AC_SUBST(MODSDIR)
AC_SUBST(DATADIR)

AC_MSG_CHECKING([if c-icap support templates])
if test "x$cicaphastmpl" != "x"; then
	AC_DEFINE([HAVE_CICAP_TEMPLATE],[1],[Define HAVE_CICAP_TEMPLATE, using c-icap templates is supported.])
	AC_SUBST(HAVE_TEMPLATE, [-DHAVE_CICAP_TEMPLATE])
	AC_MSG_RESULT(yes)
else
	AC_SUBST(HAVE_TEMPLATE)
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if c-icap supports hasalldata or flags])
if test $cicaphasalldata -lt 40; then
	AC_DEFINE([HAVE_CICAP_HASALLDATA],[1],[Define HAVE_CICAP_HASALLDATA, using c-icap hasalldata when supported otherwise use flags.])
	AC_SUBST(HAVE_HASALLDATA, [-DHAVE_CICAP_HASALLDATA])
	AC_MSG_RESULT(yes)
else
	AC_SUBST(HAVE_HASALLDATA)
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if libarchive is supported])
if test "x$haslibarchive" != "x"; then
	AC_DEFINE([HAVE_LIBARCHIVE],[1],[Define HAVE_LIBARCHIVE, using libarchive is supported.])
	AC_SUBST(HAVE_ARCHIVE, [-DHAVE_LIBARCHIVE])
	AC_MSG_RESULT(yes)
else
	AC_SUBST(HAVE_ARCHIVE)
	AC_MSG_RESULT(no)
fi


AC_MSG_CHECKING([if fds can send through unix sockets])
AC_TRY_COMPILE(
       [
      #include <stdlib.h>
      #include <sys/socket.h>
      #include <sys/un.h>
       ],
      [
      int main(int argc, char **argv) {
             struct msghdr mh;
             struct cmsghdr cmh;
             mh.msg_control = NULL;
             mh.msg_controllen = 0;
             cmh.cmsg_level = SOL_SOCKET;
             cmh.cmsg_type = SCM_RIGHTS;
      }
      ],
AC_DEFINE(HAVE_FD_PASSING,1,[Define HAVE_FD_PASSING if sending fd through unix socket supported]),
AC_MSG_RESULT(yes), 
AC_MSG_RESULT(no),
)

# Check for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h ctype.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h regex.h signal.h archive.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 gettimeofday memchr memset regcomp regexec regfree socket strdup strerror strspn strstr])

# Now determine which modules will going to build .....

AM_CONDITIONAL(USECLAMAV,[test a"$clamav" != ano])
AM_CONDITIONAL(USEBDB,   [test a"$libdb" != ano])
AM_CONDITIONAL(USE_VSCAN_PROFILES,[test a"$virus_scan_profiles_support" != a"no"])

dnl Fix compilation error on OpenSolaris
case "$host" in
	*-linux-*)
		ADDITONAL_LIB=''
	    ;;
	*-solaris*)
		ADDITONAL_LIB='-lnsl -lsocket'
	    ;;
	*-openbsd*)
		ADDITONAL_LIB='-lcompat'
	    ;;
	*-freebsd*)
		ADDITONAL_LIB=''
	    ;;
esac

AC_SUBST([ADDITONAL_LIB])

dnl Force config directory to be /etc/
CFGDIR=/etc
AC_SUBST([CFGDIR])

AC_OUTPUT([Makefile src/Makefile etc/Makefile])

