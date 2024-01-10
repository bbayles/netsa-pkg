/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/
#ifndef _PYSILK_COMMON_H
#define _PYSILK_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_PYSILK_COMMON_H, "$SiLK: pysilk_common.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  pysilk_common.h
**
**  Stuff shared in common between the pysilk module and the
**  silkpython module.
**
*/

/* Assumes that Python.h has been included before this */
#ifndef PY_MAJOR_VERSION
#error "Python.h was not included before pysilk_common.h"
#endif

/* Python 3 versus Python 2.x (x >= 6) */
#if PY_MAJOR_VERSION >= 3
/* Python 3.x version */
#  define IS_STRING(o) PyUnicode_Check(o)
#  define IS_INT(o) (PyLong_Check(o) && !PyBool_Check(o))
#  define PyInt_FromLong(o) PyLong_FromLong(o)
#  define PyInt_AsLong(o) PyLong_AsLong(o)
#  define LONG_AS_UNSIGNED_LONGLONG(o) PyLong_AsUnsignedLongLong(o)
#  define COBJ_CHECK(o) PyCapsule_CheckExact(o)
#  define COBJ_PTR(o) PyCapsule_GetPointer(o, NULL)
#  define COBJ_SETPTR(o, ptr) PyCapsule_SetPointer(o, ptr)
#  define COBJ_SETPTR_FAILED(rv) (rv != 0)
#  define COBJ_CREATE(ptr) PyCapsule_New(ptr, NULL, NULL)
#  define BYTES_FROM_XCHAR(s) bytes_from_wchar(s)
#  define BYTES_AS_STRING(s) PyBytes_AS_STRING(s)
#  define STRING_FROM_STRING(s) PyUnicode_FromString(s)
#  define BUILTINS "builtins"
typedef void *cmpfunc;
#else  /* PY_MAJOR_VERSION < 3 */
#  if PY_VERSION_HEX < 0x02060000
/* Python 2.[45] version */
#    define PyBytes_AS_STRING PyString_AS_STRING
#    define PyBytes_AsString PyString_AsString
#    define PyBytes_Check PyString_Check
#    define PyBytes_GET_SIZE PyString_GET_SIZE
#    define PyBytes_FromStringAndSize PyString_FromStringAndSize
#    define PyUnicode_FromString string_to_unicode
#    define PyUnicode_FromFormat format_to_unicode
#    define Py_TYPE(o) ((o)->ob_type)
#    define PyVarObject_HEAD_INIT(a, b) PyObject_HEAD_INIT(a) b,
#  endif  /* PY_VERSION_HEX < 0x02060000 */
/* Python 2.x version */
#  define IS_STRING(o) (PyBytes_Check(o) || PyUnicode_Check(o))
#  define IS_INT(o) ((PyInt_Check(o) && !PyBool_Check(o)) || PyLong_Check(o))
#  define LONG_AS_UNSIGNED_LONGLONG(o)          \
    (PyLong_Check(o) ?                          \
     PyLong_AsUnsignedLongLong(o) :             \
     PyLong_AsUnsignedLong(o))
#  define COBJ_CHECK(o) PyCObject_Check(o)
#  define COBJ_PTR(o) PyCObject_AsVoidPtr(o)
#  define COBJ_SETPTR(o, ptr) PyCObject_SetVoidPtr(o, ptr)
#  define COBJ_SETPTR_FAILED(rv) (rv == 0)
#  define COBJ_CREATE(ptr) PyCObject_FromVoidPtr(ptr, NULL)
#  define BYTES_FROM_XCHAR(s) PyString_FromString(s)
#  define STRING_FROM_STRING(s) PyString_FromString(s)
#  define BUILTINS "__builtin__"
#  define PyUnicode_InternFromString PyUnicode_FromString
#endif  /* PY_MAJOR_VERSION */

PyObject *
bytes_from_string(
    PyObject           *obj);
PyObject *
bytes_from_wchar(
    const wchar_t      *wc);
#if PY_VERSION_HEX < 0x02060000
PyObject *
string_to_unicode(
    const char         *s);
PyObject *
format_to_unicode(
    const char         *s,
    ...);
#endif

/*
 *    declarations for DLL input/export changed between Python 2 and
 *    Python 3.  The entry point in Python 2 is called "initFOO" and
 *    it returns void; the entry point in Python 3 is called
 *    PyInit_FOO and it returns PyObject* (the module).
 */
#if PY_MAJOR_VERSION >= 3
#  ifndef PyMODINIT_FUNC
#    define PyMODINIT_FUNC PyObject *
#  endif
#  define INIT_RETURN(x) return x
#  define XMOD_INIT(x) PyInit_ ## x
#else
#  ifndef PyMODINIT_FUNC
#    define PyMODINIT_FUNC void
#  endif
#  define INIT_RETURN(x) x
#  define XMOD_INIT(x) init ## x
#endif

/* Avoid argument prescan problem by indirection */
#define MOD_INIT(x) XMOD_INIT(x)

/* Stringify */
#define SKPY_HELPER_STRINGIFY(x) #x
#define SKPY_STRINGIFY(x)        SKPY_HELPER_STRINGIFY(x)


/*
 *    PYSILK_INIT is loaded by the Python binary.  PYSILK_PIN_INIT
 *    is used by the silkpython plug-in code.
 */
#define PYSILK_NAME          pysilk
#define PYSILK_INIT          MOD_INIT(PYSILK_NAME)
#define PYSILK_STR           SKPY_STRINGIFY(PYSILK_NAME)

#define PYSILK_PIN_NAME      pysilk_pin
#define PYSILK_PIN_INIT      MOD_INIT(PYSILK_PIN_NAME)
#define PYSILK_PIN_STR       SKPY_STRINGIFY(PYSILK_PIN_NAME)

PyMODINIT_FUNC
PYSILK_INIT(
    void);
PyMODINIT_FUNC
PYSILK_PIN_INIT(
    void);


#ifdef __cplusplus
}
#endif
#endif /* _PYSILK_COMMON_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
