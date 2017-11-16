# Autoconf requirements
# Initialize
AC_INIT([sha256_test], 1.0)
# Force autoconf to be at least this version number:
AC_PREREQ([2.68])
# Safety check - list a source file that wouldn't be in other directories:
AC_CONFIG_SRCDIR([src/sha256_test.c])
# Put configuration results here, so we can easily #include them:
AC_CONFIG_HEADERS([config.h])
# Put autotools auxiliary files in a subdir, so they don't clutter top dir:
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
# Check for GNU GMP lib
AC_CHECK_LIB(gmp, __gmpz_init, ,
  [AC_MSG_ERROR([GNU MP not found, see https://gmplib.org/])])
AC_CONFIG_FILES(Makefile)
LT_INIT
# Look for a C compiler:
AC_PROG_CC
AM_PROG_CC_C_O


# Perhaps check for: (more) programs, libraries, header files, types,
# structures, compiler characteristics, library functions, system services.

# Do final output.
AC_OUTPUT
