dnl @OPENSOURCE_LICENSE_START@
dnl libfixbuf 2.0
dnl
dnl Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
dnl
dnl NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
dnl ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
dnl BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
dnl EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
dnl LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
dnl EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
dnl MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
dnl ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
dnl COPYRIGHT INFRINGEMENT.
dnl
dnl Released under a GNU-Lesser GPL 3.0-style license, please see
dnl LICENSE.txt or contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for
dnl public release and unlimited distribution.  Please see Copyright
dnl notice for non-US Government use and distribution.
dnl
dnl Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
dnl and Trademark Office by Carnegie Mellon University.
dnl
dnl DM18-0325
dnl @OPENSOURCE_LICENSE_END@

# ---------------------------------------------------------------------------
# INFOMODEL_AC_COLLECT_REGISTRIES(infomodel_dir)
#
#    Create a list of infomodel IE registries located in
#    $(top_srcdir)/$infomodel_dir.  Place the list of registry names in
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
