dnl Copyright (C) 2018 by Carnegie Mellon University.

# ---------------------------------------------------------------------------
# INFOMODEL_AC_COLLECT_REGISTRIES(srcdir, infomodel_dir)
#
#    Create a list of infomodel IE registries located in
#    $srcdir/$infomodel_dir.  Place the list of registry names in
#    INFOMODEL_REGISTRIES.  Place a list of registry names in
#    INFOMODEL_REGISTRY_PREFIXES.  Place a list of registry include
#    files in INFOMODEL_REGISTRY_INCLUDE_FILES.  Place a list of
#    registry include dependencies based from $srcdir in
#    INFOMODEL_REGISTRY_INCLUDES.
#
#    Output variables: INFOMODEL_REGISTRIES INFOMODEL_REGISTRY_PREFIXES
#        INFOMODEL_REGISTRY_INCLUDE_FILES INFOMODEL_REGISTRY_INCLUDES
#
AC_DEFUN([INFOMODEL_AC_COLLECT_REGISTRIES],[
    AC_SUBST(INFOMODEL_REGISTRY_PREFIXES)
    AC_SUBST(INFOMODEL_REGISTRY_INCLUDES)
    AC_SUBST(INFOMODEL_REGISTRY_INCLUDE_FILES)
    AC_SUBST(INFOMODEL_REGISTRIES)

    AC_MSG_CHECKING([for information element files])
    files=[`echo $][srcdir/$1/[A-Za-z0-9_]*.xml`]
    prefixes=[`echo $files | sed 's,[^ ]*/\([^/ ]*\)\.xml,\1,g'`]
    xml=[`echo $prefixes | sed 's,\([^ ]*\),\1.xml,g'`]
    inc_files=[`echo $prefixes | sed 's,\([^ ]*\),\1.i,g'`]
    includes=[`echo $inc_files | sed 's,\([^ ]*\),$(top_builddir)/$1/\1,g'`]
    INFOMODEL_REGISTRY_PREFIXES=$prefixes
    INFOMODEL_REGISTRY_INCLUDE_FILES=$inc_files
    INFOMODEL_REGISTRY_INCLUDES=$includes
    INFOMODEL_REGISTRIES=$xml
    AC_MSG_RESULT([$1/{$INFOMODEL_REGISTRY_PREFIXES}])
])
