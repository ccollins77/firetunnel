AC_PREREQ([2.68])
AC_INIT(firetunnel, 0.8, netblue30@yahoo.com, , http://firejail.wordpress.com)
AC_CONFIG_SRCDIR([src/firetunnel/main.c])
#AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
#AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_RANLIB

HAVE_SPECTRE="no"
AC_MSG_CHECKING(for Spectre mitigation support in gcc or clang compiler)
AS_IF([test "$CC" = "gcc"], [
	HAVE_SPECTRE="yes"
	$CC -mindirect-branch=thunk -c dummy.c || HAVE_SPECTRE="no"
	rm -f dummy.o
	AS_IF([test "$HAVE_SPECTRE" = "yes"], [
		EXTRA_CFLAGS+=" -mindirect-branch=thunk "
	])
])
AS_IF([test "$CC" = "clang"], [
	HAVE_SPECTRE="yes"
	$CC -mretpoline -c dummy.c || HAVE_SPECTRE="no"
	rm -f dummy.o
	AS_IF([test "$HAVE_SPECTRE" = "yes"], [
		EXTRA_CFLAGS+=" -mretpoline "
	])
])
AS_IF([test "$HAVE_SPECTRE" = "yes"], [
	AC_MSG_RESULT(yes)
])
AS_IF([test "$HAVE_SPECTRE" = "no"], [
	AC_MSG_RESULT(... not available)
])
AC_SUBST([EXTRA_CFLAGS])


HAVE_SECCOMP=""
AC_ARG_ENABLE([seccomp],
    AS_HELP_STRING([--disable-seccomp], [disable seccomp]))
AS_IF([test "x$enable_seccomp" != "xno"], [
	HAVE_SECCOMP="-DHAVE_SECCOMP"
	EXTRA_LDFLAGS+=" -lseccomp "
	AC_SUBST(HAVE_SECCOMP)
])

HAVE_FATAL_WARNINGS=""
AC_ARG_ENABLE([fatal_warnings],
    AS_HELP_STRING([--enable-fatal-warnings], [-W -Wall -Werror]))
AS_IF([test "x$enable_fatal_warnings" = "xyes"], [
	HAVE_FATAL_WARNINGS="-W -Wall -Werror"
	AC_SUBST(HAVE_FATAL_WARNINGS)
])

HAVE_GCOV=""
AC_ARG_ENABLE([gcov],
    AS_HELP_STRING([--enable-gcov], [Gcov instrumentation]))
AS_IF([test "x$enable_gcov" = "xyes"], [
	HAVE_GCOV="--coverage -DHAVE_GCOV "
	EXTRA_LDFLAGS+=" -lgcov --coverage "
	AC_SUBST(HAVE_GCOV)
])
AC_SUBST([EXTRA_LDFLAGS])

# checking pthread library
AC_CHECK_LIB([pthread], [main], [], AC_MSG_ERROR([*** POSIX thread support not installed ***]))
AC_CHECK_HEADER(pthread.h,,AC_MSG_ERROR([*** POSIX thread support not installed ***]))

# set sysconfdir
if test "$prefix" = /usr; then
	sysconfdir="/etc"
fi

AC_OUTPUT(Makefile src/common.mk src/firetunnel/Makefile)

echo
echo "Configuration options:"
echo "   prefix: $prefix"
echo "   sysconfdir: $sysconfdir"
echo "   Spectre compiler patch: $HAVE_SPECTRE"
echo "   EXTRA_LDFLAGS: $EXTRA_LDFLAGS"
echo "   EXTRA_CFLAGS: $EXTRA_CFLAGS"
echo "   fatal warnings: $HAVE_FATAL_WARNINGS"
echo "   Gcov instrumentation: $HAVE_GCOV"
echo
