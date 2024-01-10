/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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

/*
**  Python wrappers
**
*/

#define PY_SSIZE_T_CLEAN        /* "s#" "y#" formats must use ssize_t */
#include <Python.h>             /* Must be included before any system
                                   headers */
#include <silk/silk.h>

RCSIDENT("$SiLK: pysilk.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skbag.h>
#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include <datetime.h>
#include <structmember.h>
#include "pysilk_common.h"

SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")
SK_DIAGNOSTIC_IGNORE_PUSH("-Wcast-function-type")


/* LOCAL DEFINES AND TYPEDEFS */

#define MAX_EPOCH (((INT64_C(1) << 31)-1)*1000) /* Tue Jan 19 03:14:07 2038 */

#define XSTR(s) #s
#define STR(s) XSTR(s)


/* In Python 2.4, length()-type functions are 'inquiry's that return
 * int.  In Python 2.5, they are 'lenfunc's that return Py_ssize_t. */
#if PY_VERSION_HEX < 0x02050000
#define Py_ssize_t     int
#define PY_SSIZE_T_MAX INT_MAX
#endif

#define NOT_SET -9999

#if SK_ENABLE_IPV6
#define UNUSED_NOv6(x) x
#else
#define UNUSED_NOv6(x) UNUSED(x)
#endif


#define CHECK_SITE(err)                         \
    do {                                        \
        if (init_site(NULL)) {                  \
            return err;                         \
        }                                       \
    } while(0)


/*
 *  ASSERT_RESULT(ar_func_args, ar_type, ar_expected);
 *
 *    ar_func_args  -- is a function and any arguments it requires
 *    ar_type       -- is the type that ar_func_args returns
 *    ar_expected   -- is the expected return value from ar_func_args
 *
 *    If assert() is disabled, simply call 'ar_func_args'.
 *
 *    If assert() is enabled, call 'ar_func_args', capture its result,
 *    and assert() that its result is 'ar_expected'.
 */
#ifdef  NDEBUG
/* asserts are disabled; just call the function */
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)  ar_func_args
#else
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)       \
    do {                                                        \
        ar_type ar_rv = (ar_func_args);                         \
        assert(ar_rv == (ar_expected));                         \
    } while(0)
#endif


typedef skBagErr_t (*silkBagModFn)(
    skBag_t *,
    const skBagTypedKey_t *,
    const skBagTypedCounter_t *,
    skBagTypedCounter_t *);

typedef struct silkpy_globals_st {
    PyObject *silkmod;
    PyObject *timedelta;
    PyObject *datetime;
    PyObject *maxelapsed;
    PyObject *minelapsed;
    PyObject *epochtime;
    PyObject *maxtime;
    PyObject *thousand;
    PyObject *havesite;
    PyObject *sensors;
    PyObject *classes;
    PyObject *flowtypes;
    PyObject *newrawrec;
    PyObject *maxintipv4;
#if SK_ENABLE_IPV6
    PyObject *maxintipv6;
#endif
    int site_configured;
} silkpy_globals_t;


/* LOCAL VARIABLE DEFINITIONS */

static  char error_buffer[1024];

#if PY_MAJOR_VERSION >= 3
/* Global state for 3.0 Python is found by searching for this
 * module */
static struct PyModuleDef *pysilk_module = NULL;

#define GLOBALS                                                         \
    ((silkpy_globals_t*)PyModule_GetState(PyState_FindModule(pysilk_module)))

#else

/* Global state for Pre-3.0 Python */
static silkpy_globals_t silkpy_globals_static;

#define GLOBALS   (&silkpy_globals_static)

#endif  /* #else of #if PY_MAJOR_VERSION >= 3 */

/*    A pointer to pass as the closure to C functions that implement
 *    multiple Python functions where some of the Python function
 *    names are deprecated. */
static const char deprecated_true_str[] = "1";

/*    Cast away the const */
#define deprecated_true ((void*)deprecated_true_str)


/* LOCAL FUNCTION PROTOTYPES */

/* basic support functions */
static PyObject *
any_obj_error(
    PyObject           *exc,
    const char         *format,
    PyObject           *obj);
#ifdef TEST_PRINTF_FORMATS
#define error_printf  printf
#else  /* TEST_PRINTF_FORMATS */
static int
error_printf(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif
static int init_classes(void);
static int init_flowtypes(void);
static int init_sensors(void);
static int
init_silkfile_module(
    PyObject           *mod);
static int
init_site(
    const char         *site_file);
static PyObject *
initpysilkbase(
    char*               name);
static PyObject *
iter_iter(
    PyObject           *self);
static void
obj_dealloc(
    PyObject           *obj);
static PyObject *
obj_error(
    const char         *format,
    PyObject           *obj);
static skstream_t *
open_silkfile_write(
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
reduce_error(
    PyObject           *self);
static int
silkPyDatetimeToSktime(
    sktime_t           *silktime,
    PyObject           *datetime);
#if !SK_ENABLE_IPV6
static PyObject *
silkPyNotImplemented(
    PyObject    UNUSED(*self),
    PyObject    UNUSED(*args),
    PyObject    UNUSED(*kwds));
#endif


/* FUNCTION DEFINITIONS */


/*
 *************************************************************************
 *   IPAddr
 *************************************************************************
 */

typedef struct silkPyIPAddr_st {
    PyObject_HEAD
    skipaddr_t addr;
} silkPyIPAddr;

/* function prototypes */
static PyObject *
silkPyIPAddr_country_code(
    silkPyIPAddr       *self);
static long
silkPyIPAddr_hash(
    silkPyIPAddr       *obj);
static PyObject *
silkPyIPAddr_int(
    silkPyIPAddr       *obj);
static PyObject *
silkPyIPAddr_is_ipv6(
    silkPyIPAddr        UNUSED_NOv6(*self));
static PyObject *
silkPyIPAddr_isipv6_deprecated(
    silkPyIPAddr       *self);
static PyObject *
silkPyIPAddr_mask(
    silkPyIPAddr       *self,
    PyObject           *mask);
static PyObject *
silkPyIPAddr_mask_prefix(
    silkPyIPAddr       *self,
    PyObject           *prefix);
static PyObject *
silkPyIPAddr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPAddr_octets(
    silkPyIPAddr       *self);
static PyObject *
silkPyIPAddr_padded(
    silkPyIPAddr       *obj);
static PyObject *
silkPyIPAddr_repr(
    silkPyIPAddr       *obj);
static PyObject *
silkPyIPAddr_richcompare(
    silkPyIPAddr       *self,
    PyObject           *obj,
    int                 cmp);
static int
silkPyIPAddr_setup(
    PyObject           *mod);
static PyObject *
silkPyIPAddr_str(
    silkPyIPAddr       *obj);
static PyObject *
silkPyIPAddr_to_ipv4(
    PyObject           *self);
#if SK_ENABLE_IPV6
static PyObject *
silkPyIPAddr_to_ipv6(
    PyObject           *self);
#endif
static int
silkPyIPv4Addr_init(
    silkPyIPAddr       *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPv4Addr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);
static int
silkPyIPv6Addr_init(
    silkPyIPAddr       *self,
    PyObject           *args,
    PyObject           *kwds);
#if SK_ENABLE_IPV6
static PyObject *
silkPyIPv6Addr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);
#endif
static PyObject *
silkPyIPvXAddr_new(
    PyTypeObject       *basetype,
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);

/* define docs and methods */
#define silkPyIPAddr_doc                        \
    "IPAddr(string) -> ip address\n"            \
    "IPAddr(ipaddr) -> copy of ip address"

#define silkPyIPv4Addr_doc                                      \
    "IPv4Addr(string) -> IPv4 address\n"                        \
    "IPv4Addr(int) -> IPv4 address\n"                           \
    "IPv4Addr(IPV6Addr) -> IPv4 from IPv4 in IPv6 address\n"    \
    "IPv4Addr(IPv4Addr) -> copy of ip address"

#define silkPyIPv6Addr_doc                              \
    "IPv6Addr(string) -> IPv6 address\n"                \
    "IPv6Addr(int) -> IPv6 address\n"                   \
    "IPv6Addr(IPV4Addr) -> IPv4 in IPv6 address\n"      \
    "IPv6Addr(IPv6Addr) -> copy of ip address"

static PyNumberMethods silkPyIPAddr_number_methods;

static PyMethodDef silkPyIPAddr_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"isipv6", (PyCFunction)silkPyIPAddr_isipv6_deprecated, METH_NOARGS,
     ("addr.isipv6() -> bool -- return whether addr is an IPv6 address."
      " DEPRECATED Use addr.is_ipv6() instead.")},
    {"is_ipv6", (PyCFunction)silkPyIPAddr_is_ipv6, METH_NOARGS,
     "addr.is_ipv6() -> bool -- return whether addr is an IPv6 address"},
    {"to_ipv6", (PyCFunction)
#if SK_ENABLE_IPV6
     silkPyIPAddr_to_ipv6, METH_NOARGS,
#else
     silkPyNotImplemented, METH_VARARGS | METH_KEYWORDS,
#endif
     "addr.to_ipv6() -- return addr converted to an IPv6 address"},
    {"to_ipv4", (PyCFunction)silkPyIPAddr_to_ipv4, METH_NOARGS,
     "addr.to_ipv4() -- return addr converted to an IPv4 address"},
    {"padded", (PyCFunction)silkPyIPAddr_padded, METH_NOARGS,
     "addr.padded() -> str -- return zero-padded IP string"},
    {"mask", (PyCFunction)silkPyIPAddr_mask, METH_O,
     "addr.mask(addr2) -> addr3 -- return addr masked by addr2"},
    {"mask_prefix", (PyCFunction)silkPyIPAddr_mask_prefix, METH_O,
     ("addr.mask(prefix) -> addr2 -- "
      "return addr masked by the top prefix bits")},
    {"country_code", (PyCFunction)silkPyIPAddr_country_code, METH_NOARGS,
     "addr.country_code() -> string -- 2-character country code"},
    {"octets", (PyCFunction)silkPyIPAddr_octets, METH_NOARGS,
     ("addr.octets() = (o1, o2 ...) -- "
      "return the octets of addr as a tuple")},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

/* define the object types */
static PyTypeObject silkPyIPAddrType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.IPAddr",              /* tp_name */
    sizeof(silkPyIPAddr),       /* tp_basicsize */
    0,                          /* tp_itemsize */
    obj_dealloc,                /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    (reprfunc)silkPyIPAddr_repr, /* tp_repr */
    &silkPyIPAddr_number_methods, /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    (hashfunc)silkPyIPAddr_hash, /* tp_hash  */
    0,                          /* tp_call */
    (reprfunc)silkPyIPAddr_str, /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
#if PY_MAJOR_VERSION < 3
    Py_TPFLAGS_HAVE_RICHCOMPARE |
#endif
    Py_TPFLAGS_DEFAULT,         /* tp_flags */
    silkPyIPAddr_doc,           /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    (richcmpfunc)silkPyIPAddr_richcompare, /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    silkPyIPAddr_methods,       /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    silkPyIPAddr_new,           /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyIPv4AddrType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.IPv4Addr",            /* tp_name */
    0,                          /* tp_basicsize */
    0,                          /* tp_itemsize */
    0,                          /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyIPv4Addr_doc,         /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    &silkPyIPAddrType,          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyIPv4Addr_init, /* tp_init */
    0,                          /* tp_alloc */
    silkPyIPv4Addr_new,         /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyIPv6AddrType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.IPv6Addr",            /* tp_name */
    0,                          /* tp_basicsize */
    0,                          /* tp_itemsize */
    0,                          /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyIPv6Addr_doc,         /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    &silkPyIPAddrType,          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyIPv6Addr_init, /* tp_init */
    0,                          /* tp_alloc */
#if SK_ENABLE_IPV6
    silkPyIPv6Addr_new,         /* tp_new */
#else
    (newfunc)silkPyNotImplemented, /* tp_new */
#endif
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyIPAddr_Check(op)                  \
    PyObject_TypeCheck(op, &silkPyIPAddrType)
#define silkPyIPv4Addr_Check(op)                \
    PyObject_TypeCheck(op, &silkPyIPv4AddrType)
#define silkPyIPv6Addr_Check(op)                \
    PyObject_TypeCheck(op, &silkPyIPv6AddrType)

static PyObject *
silkPyIPAddr_country_code(
    silkPyIPAddr       *self)
{
    char name[3];
    sk_countrycode_t code;
    int rv;

    rv = skCountrySetup(NULL, error_printf);
    if (rv != 0) {
        PyErr_SetString(PyExc_RuntimeError, error_buffer);
        return NULL;
    }

    code = skCountryLookupCode(&self->addr);
    if (code == SK_COUNTRYCODE_INVALID) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(skCountryCodeToName(code, name, sizeof(name)));
}

static long
silkPyIPAddr_hash(
    silkPyIPAddr       *obj)
{
    long retval;
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&obj->addr)) {
        uint8_t v6[16];
        skipaddrGetAsV6(&obj->addr, v6);
#if SK_SIZEOF_LONG == 8
        retval = *(long*)(&v6[8]);
#else  /* SK_SIZEOF_LONG */
        /* Assume long is 4 bytes */
        retval = *(long*)(&v6[12]);
#endif  /* SK_SIZEOF_LONG */
        return retval;
    }
#endif  /* SK_ENABLE_IPV6 */
    retval = skipaddrGetV4(&obj->addr);
    if (retval == -1) {
        retval = 0;
    }
    return retval;
}

static PyObject *
silkPyIPAddr_int(
    silkPyIPAddr       *obj)
{
    PyObject *result;

#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&obj->addr)) {
        char      buf[33];
        char     *p;
        int       i;
        uint32_t *v6;

        p = buf;
        v6 = (uint32_t*)obj->addr.ip_ip.ipu_ipv6;
        for (i = 0; i < 4; i++) {
            sprintf(p, "%08" PRIx32, ntohl(*v6));
            p += 8;
            ++v6;
        }
        result = PyLong_FromString(buf, NULL, 16);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        result = PyLong_FromUnsignedLong(skipaddrGetV4(&obj->addr));
    }

    return result;
}

static PyObject *
silkPyIPAddr_is_ipv6(
    silkPyIPAddr        UNUSED_NOv6(*self))
{
#if SK_ENABLE_IPV6
    return PyBool_FromLong(skipaddrIsV6(&self->addr));
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *
silkPyIPAddr_isipv6_deprecated(
    silkPyIPAddr       *self)
{
    /* deprecated in SiLK-2.2.0 */
    PyErr_Warn(PyExc_DeprecationWarning,
               ("IPAddr.isipv6() is deprecated.  "
                "Use IPAddr.is_ipv6() instead."));
    return silkPyIPAddr_is_ipv6(self);
}

static PyObject *
silkPyIPAddr_mask(
    silkPyIPAddr       *self,
    PyObject           *mask)
{
    silkPyIPAddr *retval;
    skipaddr_t addr;
    PyTypeObject *type;

    if (!silkPyIPAddr_Check(mask)) {
        PyErr_SetString(PyExc_TypeError, "Argument must be an IPAddr");
        return NULL;
    }

    skipaddrCopy(&addr, &self->addr);
    skipaddrMask(&addr, &((silkPyIPAddr*)mask)->addr);
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&addr)) {
        type = &silkPyIPv6AddrType;
    } else
#endif
    {
        type = &silkPyIPv4AddrType;
    }
    retval = PyObject_New(silkPyIPAddr, type);
    if (retval == NULL) {
        return NULL;
    }
    skipaddrCopy(&retval->addr, &addr);

    return (PyObject*)retval;
}

static PyObject *
silkPyIPAddr_mask_prefix(
    silkPyIPAddr       *self,
    PyObject           *prefix)
{
    silkPyIPAddr *retval;
    PyTypeObject *type;
    long p;
    int max;

    if (!IS_INT(prefix)) {
        PyErr_SetString(PyExc_TypeError, "Prefix must be an integer");
        return NULL;
    }

#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&self->addr)) {
        type = &silkPyIPv6AddrType;
        max = 128;
    } else
#endif
    {
        type = &silkPyIPv4AddrType;
        max = 32;
    }

    p = PyInt_AsLong(prefix);
    if (PyErr_Occurred()) {
        return NULL;
    }

    if (p < 0 || p > max) {
        return PyErr_Format(PyExc_ValueError,
                            "Prefix must be between 0 and %d", max);
    }

    retval = PyObject_New(silkPyIPAddr, type);
    if (retval == NULL) {
        return NULL;
    }

    skipaddrCopy(&retval->addr, &self->addr);
    skipaddrApplyCIDR(&retval->addr, p);

    return (PyObject*)retval;
}

static PyObject *
silkPyIPAddr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds)
{
    static char  *kwlist[] = {"address", NULL};
    silkPyIPAddr *self;
    PyObject     *o;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &o)) {
        return NULL;
    }

    if (Py_TYPE(o) == &silkPyIPv4AddrType ||
        Py_TYPE(o) == &silkPyIPv6AddrType)
    {
        /* IPv{4,6}Addr objects are immutable, so just incref*/
        Py_INCREF(o);
        return o;
    }
    if (silkPyIPAddr_Check(o)) {
        /* Unknown subclass of IPAddr, do a real copy */
        if (type == &silkPyIPAddrType) {
#if SK_ENABLE_IPV6
            if (skipaddrIsV6(&((silkPyIPAddr*)o)->addr)) {
                type = &silkPyIPv6AddrType;
            } else
#endif
            {
                type = &silkPyIPv4AddrType;
            }
        }
    } else if (IS_STRING(o)) {
        PyObject *bytes = bytes_from_string(o);
        const char *straddr;
        const char *c;

        if (bytes == NULL) {
            return NULL;
        }

        straddr = PyBytes_AS_STRING(bytes);
        c = strchr(straddr, ':');
        if (c) {
            type = &silkPyIPv6AddrType;
        } else {
            type = &silkPyIPv4AddrType;
        }
        Py_DECREF(bytes);
    } else if (IS_INT(o)) {
        /* The IPAddr(int) constructor is deprecated as of SiLK 2.2.0 */
        int rv = PyErr_Warn(PyExc_DeprecationWarning,
                            ("IPAddr(int) is deprecated.  Use IPv4Addr(int) "
                             "or IPv6Addr(int) instead."));
        if (rv) {
            return NULL;
        }
        type = &silkPyIPv4AddrType;

    } else {
        return PyErr_Format(PyExc_TypeError, "Must be a string or IPAddr");
    }

    /* Allocate the object */
    self = (silkPyIPAddr*)type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }

    return (PyObject*)self;
}

static PyObject *
silkPyIPAddr_octets(
    silkPyIPAddr       *self)
{
    PyObject *retval;
    PyObject *octet;
    int i;

#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&self->addr)) {
        uint8_t v6[16];
        retval = PyTuple_New(16);
        if (retval == NULL) {
            return NULL;
        }
        skipaddrGetV6(&self->addr, v6);

        for (i = 0; i < 16; i++) {
            octet = PyInt_FromLong(v6[i]);
            if (octet == NULL) {
                Py_DECREF(retval);
                return NULL;
            }
            PyTuple_SET_ITEM(retval, i, octet);
        }
    } else
#endif
    {
        uint32_t v4 = skipaddrGetV4(&self->addr);
        retval = PyTuple_New(4);
        if (retval == NULL) {
            return NULL;
        }

        for (i = 3; i >= 0; i--) {
            octet = PyInt_FromLong(v4 & 0xff);
            if (octet == NULL) {
                Py_DECREF(retval);
                return NULL;
            }
            PyTuple_SET_ITEM(retval, i, octet);
            v4 >>= 8;
        }
    }

    return retval;
}

static PyObject *
silkPyIPAddr_padded(
    silkPyIPAddr       *obj)
{
    char buf[SKIPADDR_STRLEN];

    skipaddrString(buf, &obj->addr, SKIPADDR_ZEROPAD);
    return PyUnicode_FromString(buf);
}

static PyObject *
silkPyIPAddr_repr(
    silkPyIPAddr       *obj)
{
    char buf[SKIPADDR_STRLEN];
    PyTypeObject *type;

    type = Py_TYPE(obj);
    if (type == NULL) {
        return NULL;
    }

    skipaddrString(buf, &obj->addr, SKIPADDR_CANONICAL);
    return PyUnicode_FromFormat("%s('%s')", type->tp_name, buf);
}

static PyObject *
silkPyIPAddr_richcompare(
    silkPyIPAddr       *self,
    PyObject           *obj,
    int                 cmp)
{
    int rv;
    silkPyIPAddr *other;

    if (!silkPyIPAddr_Check(obj)) {
        PyErr_SetString(PyExc_TypeError, "Expected silk.IPAddr");
        return NULL;
    }
    other = (silkPyIPAddr*)obj;
    rv = skipaddrCompare(&self->addr, &other->addr);
    if (rv < 0) {
        return PyBool_FromLong(cmp == Py_LT || cmp == Py_LE || cmp == Py_NE);
    }
    if (rv > 0) {
        return PyBool_FromLong(cmp == Py_GT || cmp == Py_GE || cmp == Py_NE);
    }
    return PyBool_FromLong(cmp == Py_EQ || cmp == Py_LE || cmp == Py_GE);
}

static int
silkPyIPAddr_setup(
    PyObject           *mod)
{
    /* Setup number methods */
    memset(&silkPyIPAddr_number_methods, 0,
           sizeof(silkPyIPAddr_number_methods));
    silkPyIPAddr_number_methods.nb_int = (unaryfunc)silkPyIPAddr_int;
#if PY_MAJOR_VERSION < 3
    silkPyIPAddr_number_methods.nb_long = (unaryfunc)silkPyIPAddr_int;
#endif

    /* Initialize type and add to module */
    if (PyType_Ready(&silkPyIPAddrType) < 0) {
        return -1;
    }
    return PyModule_AddObject(mod, "IPAddr", (PyObject*)&silkPyIPAddrType);
}

static PyObject *
silkPyIPAddr_str(
    silkPyIPAddr       *obj)
{
    char buf[SKIPADDR_STRLEN];

    skipaddrString(buf, &obj->addr, SKIPADDR_CANONICAL);
    return PyUnicode_FromString(buf);
}

static PyObject *
silkPyIPAddr_to_ipv4(
    PyObject           *self)
{
#if SK_ENABLE_IPV6
    PyObject *obj;

    obj = PyObject_CallFunctionObjArgs((PyObject*)&silkPyIPv4AddrType,
                                       self, NULL);
    if (obj == NULL) {
        if (PyErr_ExceptionMatches(PyExc_ValueError)) {
            PyErr_Clear();
            Py_RETURN_NONE;
        }
    }

    return obj;
#else  /* SK_ENABLE_IPV6 */
    Py_INCREF(self);
    return self;
#endif  /* SK_ENABLE_IPV6 */
}

#if SK_ENABLE_IPV6
static PyObject *
silkPyIPAddr_to_ipv6(
    PyObject           *self)
{
    return PyObject_CallFunctionObjArgs((PyObject*)&silkPyIPv6AddrType,
                                        self, NULL);
}
#endif  /* SK_ENABLE_IPV6 */

static int
silkPyIPv4Addr_init(
    silkPyIPAddr       *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char  *kwlist[] = {"address", NULL};
    PyObject     *addr;
    int           rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &addr)) {
        return -1;
    }

    if (addr == (PyObject*)self) {
        /* We were initialized by new */
        return 0;
    }

    if (IS_STRING(addr)) {
        PyObject *bytes;
        bytes = bytes_from_string(addr);
        if (bytes == NULL) {
            return -1;
        }
        rv = skStringParseIP(&self->addr, PyBytes_AS_STRING(bytes));
        Py_DECREF(bytes);
        if (rv != 0) {
            PyErr_SetString(PyExc_ValueError,
                            "String is not a valid IP address");
            return -1;
        }
#if SK_ENABLE_IPV6
        if (skipaddrIsV6(&self->addr)) {
            PyErr_SetString(PyExc_ValueError,
                            "String is not a valid IPv4 address");
            return -1;
        }
#endif
    } else if (IS_INT(addr)) {
        uint32_t value;
        PyObject *num;

        num = PyLong_FromLong(0);
        rv = PyObject_RichCompareBool(addr, num, Py_LT);
        Py_DECREF(num);
        if (rv) {
            /* Negative */
            PyErr_SetString(PyExc_ValueError,
                            "Illegal IPv4 address (negative)");
            return -1;
        }
        rv = PyObject_RichCompareBool(addr, GLOBALS->maxintipv4, Py_GT);
        if (rv) {
            PyErr_SetString(PyExc_ValueError,
                            "Illegal IPv4 address (integer too large)");
            return -1;
        }

        value = PyLong_AsUnsignedLong(addr);
        skipaddrSetV4(&self->addr, &value);

#if SK_ENABLE_IPV6
    } else if (silkPyIPv6Addr_Check(addr)) {
        /* Convert to v4 */
        silkPyIPAddr *v6addr = (silkPyIPAddr*)addr;

        if (skipaddrV6toV4(&v6addr->addr, &self->addr)) {
            PyErr_SetString(PyExc_ValueError,
                            "IP address not convertable to IPv4.");
            return -1;
        }
#endif  /* SK_ENABLE_IPV6 */

    } else if (silkPyIPv4Addr_Check(addr)) {
        /* Copy */
        skipaddrCopy(&self->addr, &((silkPyIPAddr*)addr)->addr);
    } else {
        PyErr_SetString(PyExc_TypeError, "Must be a string or integer");
        return -1;
    }

    return 0;
}

static PyObject *
silkPyIPv4Addr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds)
{
    return silkPyIPvXAddr_new(&silkPyIPv4AddrType, type, args, kwds);
}

static int
silkPyIPv6Addr_init(
    silkPyIPAddr       *self,
    PyObject           *args,
    PyObject           *kwds)
{
#if !SK_ENABLE_IPV6
    silkPyNotImplemented((PyObject*)self, args, kwds);
    return -1;
#else  /* if SK_ENABLE_IPV6 */
    static char  *kwlist[] = {"address", NULL};
    PyObject     *addr;
    int           rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &addr)) {
        return -1;
    }

    if (addr == (PyObject*)self) {
        /* We were initialized by new */
        return 0;
    }

    if (IS_STRING(addr)) {
        PyObject *bytes = bytes_from_string(addr);
        if (bytes == NULL) {
            return -1;
        }
        rv = skStringParseIP(&self->addr, PyBytes_AS_STRING(bytes));
        Py_DECREF(bytes);
        if (rv != 0) {
            PyErr_SetString(PyExc_ValueError,
                            "String is not a valid IP address");
            return -1;
        }
        if (!skipaddrIsV6(&self->addr)) {
            PyErr_SetString(PyExc_ValueError,
                            "String is not a valid IPv6 address");
            return -1;
        }
    } else if (IS_INT(addr)) {
        uint8_t   v6[16];
        uint32_t *v6_32;
        PyObject *next;
        PyObject *shift;
        PyObject *num;
        int i;

        num = PyLong_FromLong(0);
        rv = PyObject_RichCompareBool(addr, num, Py_LT);
        Py_DECREF(num);
        if (rv) {
            /* Negative */
            PyErr_SetString(PyExc_ValueError,
                            "Illegal IPv6 address (negative)");
            return -1;
        }
        rv = PyObject_RichCompareBool(addr, GLOBALS->maxintipv6, Py_GT);
        if (rv) {
            PyErr_SetString(PyExc_ValueError,
                            "Illegal IPv6 address (integer too large)");
            return -1;
        }

        /* Set IP */
        shift = PyLong_FromLong(32);
        v6_32 = (uint32_t*)v6 + 3;

        next = addr;
        Py_INCREF(next);
        for (i = 0; i < 4; i++, v6_32--) {
            PyObject *tmp;

            tmp = PyNumber_And(next, GLOBALS->maxintipv4);
            *v6_32 = htonl(PyLong_AsUnsignedLong(tmp));
            Py_DECREF(tmp);
            tmp = next;
            next = PyNumber_Rshift(tmp, shift);
            Py_DECREF(tmp);
        }
        Py_DECREF(next);
        Py_DECREF(shift);
        skipaddrSetV6(&self->addr, v6);

    } else if (silkPyIPv4Addr_Check(addr)) {
        /* Convert to v6 */
        silkPyIPAddr *v4addr = (silkPyIPAddr*)addr;

        if (skipaddrIsV6(&v4addr->addr)) {
            skipaddrCopy(&self->addr, &v4addr->addr);
        } else {
            skipaddrV4toV6(&v4addr->addr, &self->addr);
        }

    } else if (silkPyIPv6Addr_Check(addr)) {
        /* Copy */
        skipaddrCopy(&self->addr, &((silkPyIPAddr*)addr)->addr);
    } else {
        PyErr_SetString(PyExc_TypeError, "Must be a string or integer");
        return -1;
    }

    return 0;
#endif  /* else of !SK_ENABLE_IPV6 */
}

#if SK_ENABLE_IPV6
static PyObject *
silkPyIPv6Addr_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds)
{
    return silkPyIPvXAddr_new(&silkPyIPv6AddrType, type, args, kwds);
}
#endif  /* SK_ENABLE_IPV6 */

static PyObject *
silkPyIPvXAddr_new(
    PyTypeObject       *basetype,
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds)
{
    static char  *kwlist[] = {"address", NULL};
    PyObject   *self;
    PyObject   *o;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &o)) {
        return NULL;
    }

    if (type == basetype && Py_TYPE(o) == basetype) {
        Py_INCREF(o);
        return o;
    }

    self = type->tp_alloc(type, 0);
    return self;
}


/*
 *************************************************************************
 *   IPWildcard
 *************************************************************************
 */

typedef struct silkPyIPWildcard_st {
    PyObject_HEAD
    skIPWildcard_t  wildcard;
    PyObject       *name;
} silkPyIPWildcard;

typedef struct silkPyIPWildcardIter_st {
    PyObject_HEAD
    silkPyIPWildcard       *wildcard;
    skIPWildcardIterator_t  iter;
} silkPyIPWildcardIter;

/* function prototypes */
static void
silkPyIPWildcardIter_dealloc(
    silkPyIPWildcardIter   *self);
static PyObject *
silkPyIPWildcardIter_iternext(
    silkPyIPWildcardIter   *self);
static int
silkPyIPWildcard_contains(
    silkPyIPWildcard   *self,
    PyObject           *obj);
static void
silkPyIPWildcard_dealloc(
    silkPyIPWildcard   *obj);
static PyObject *
silkPyIPWildcard_is_ipv6(
    silkPyIPWildcard    UNUSED_NOv6(*self));
static PyObject *
silkPyIPWildcard_isipv6_deprecated(
    silkPyIPWildcard   *self);
static PyObject *
silkPyIPWildcard_iter(
    silkPyIPWildcard   *self);
static PyObject *
silkPyIPWildcard_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPWildcard_repr(
    silkPyIPWildcard   *obj);
static PyObject *
silkPyIPWildcard_str(
    silkPyIPWildcard   *obj);

/* define docs and methods */
#define silkPyIPWildcard_doc                    \
    "IPWildcard(string) -> IP Wildcard address"

static PyMethodDef silkPyIPWildcard_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"isipv6", (PyCFunction)silkPyIPWildcard_isipv6_deprecated, METH_NOARGS,
     ("wild.isipv6() -> bool -- return whether wild is an IPv6 wildcard."
      " DEPRECATED Use wild.is_ipv6() instead.")},
    {"is_ipv6", (PyCFunction)silkPyIPWildcard_is_ipv6, METH_NOARGS,
     "wild.is_ipv6() -> bool -- return whether wild is an IPv6 wildcard"},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PySequenceMethods silkPyIPWildcard_sequence_methods = {
    0,                          /* sq_length */
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    (objobjproc)silkPyIPWildcard_contains, /* sq_contains */
    0,                          /* sq_inplace_concat */
    0                           /* sq_inplace_repeat */
};

/* define the object types */
static PyTypeObject silkPyIPWildcardType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.IPWildcard",          /* tp_name */
    sizeof(silkPyIPWildcard),   /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyIPWildcard_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    (reprfunc)silkPyIPWildcard_repr, /* tp_repr */
    0,                          /* tp_as_number */
    &silkPyIPWildcard_sequence_methods, /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    (reprfunc)silkPyIPWildcard_str, /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
                                /* tp_flags */
    silkPyIPWildcard_doc,       /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    (getiterfunc)silkPyIPWildcard_iter, /* tp_iter */
    0,                          /* tp_iternext */
    silkPyIPWildcard_methods,   /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    silkPyIPWildcard_new,       /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyIPWildcardIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.IPWildcardIter", /* tp_name */
    sizeof(silkPyIPWildcardIter), /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyIPWildcardIter_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "IP Wildcard iterator object", /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    iter_iter,                  /* tp_iter */
    (iternextfunc)silkPyIPWildcardIter_iternext, /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyIPWildcard_Check(op)                      \
    PyObject_TypeCheck(op, &silkPyIPWildcardType)
#define silkPyIPWildcardIter_Check(op)                  \
    PyObject_TypeCheck(op, &silkPyIPWildcardIterType)

static void
silkPyIPWildcardIter_dealloc(
    silkPyIPWildcardIter   *self)
{
    Py_XDECREF(self->wildcard);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
silkPyIPWildcardIter_iternext(
    silkPyIPWildcardIter   *self)
{
    silkPyIPAddr       *addr;
    skIteratorStatus_t  rv;
    skipaddr_t          raw_addr;

    rv = skIPWildcardIteratorNext(&self->iter, &raw_addr);
    if (rv == SK_ITERATOR_NO_MORE_ENTRIES) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
    addr = (silkPyIPAddr*)silkPyIPv4AddrType.tp_alloc(&silkPyIPv4AddrType, 0);
    if (addr == NULL) {
        return NULL;
    }
    addr->addr = raw_addr;

    return (PyObject*)addr;
}

static int
silkPyIPWildcard_contains(
    silkPyIPWildcard   *self,
    PyObject           *obj)
{
    int           retval;
    silkPyIPAddr *silkaddr;

    if (IS_STRING(obj)) {
        obj = PyObject_CallFunctionObjArgs((PyObject*)&silkPyIPAddrType,
                                           obj, NULL);
        if (obj == NULL) {
            return -1;
        }
    } else if (silkPyIPAddr_Check(obj)) {
        Py_INCREF(obj);
    } else {
        PyErr_SetString(PyExc_TypeError, "Must be a string or silk.IPAddr");
        return -1;
    }

    silkaddr = (silkPyIPAddr*)obj;
    retval = skIPWildcardCheckIp(&self->wildcard, &silkaddr->addr);
    Py_DECREF(obj);

    return retval ? 1 : 0;
}

static void
silkPyIPWildcard_dealloc(
    silkPyIPWildcard   *obj)
{
    Py_XDECREF(obj->name);
    Py_TYPE(obj)->tp_free((PyObject*)obj);
}

static PyObject *
silkPyIPWildcard_is_ipv6(
    silkPyIPWildcard    UNUSED_NOv6(*self))
{
#if SK_ENABLE_IPV6
    return PyBool_FromLong(skIPWildcardIsV6(&self->wildcard));
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *
silkPyIPWildcard_isipv6_deprecated(
    silkPyIPWildcard   *self)
{
    /* deprecated in SiLK 3.0.0.  Function is undocumented. */
    PyErr_Warn(PyExc_DeprecationWarning,
               ("IPWildcard.isipv6() is deprecated.  "
                "Use IPWildcard.is_ipv6() instead."));
    return silkPyIPWildcard_is_ipv6(self);
}

static PyObject *
silkPyIPWildcard_iter(
    silkPyIPWildcard   *self)
{
    silkPyIPWildcardIter *iter;

    iter = (silkPyIPWildcardIter*)silkPyIPWildcardIterType.tp_alloc(
        &silkPyIPWildcardIterType, 0);
    if (iter) {
        ASSERT_RESULT(skIPWildcardIteratorBind(&iter->iter, &self->wildcard),
                      int, 0);
        Py_INCREF(self);
        iter->wildcard = self;
    }
    return (PyObject*)iter;
}

static PyObject *
silkPyIPWildcard_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"wildcard", NULL};
    silkPyIPWildcard *self;

    if (PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist,
                                    &silkPyIPWildcardType, &self))
    {
        Py_INCREF(self);
        return (PyObject*)self;
    } else {
        PyErr_Clear();
    }

    self = (silkPyIPWildcard*)type->tp_alloc(type, 0);
    if (self != NULL) {
        Py_ssize_t   len;
        const char  *wildcard;
        int          rv;

        if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#", kwlist,
                                         &wildcard, &len))
        {
            Py_DECREF(self);
            return NULL;
        }
        rv = skStringParseIPWildcard(&self->wildcard, wildcard);
        if (rv != 0) {
            Py_DECREF(self);
            return PyErr_Format(PyExc_ValueError,
                                "Illegal IP wildcard: %s", wildcard);
        }
        self->name = PyUnicode_DecodeASCII(wildcard, len, "strict");
        if (self->name == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject*)self;
}

static PyObject *
silkPyIPWildcard_repr(
    silkPyIPWildcard   *obj)
{
    PyObject *format;
    PyObject *arg;
    PyObject *retval;

    format = PyUnicode_FromString("silk.IPWildcard(\"%s\")");
    if (format == NULL) {
        return NULL;
    }
    arg = Py_BuildValue("(O)", obj->name);
    if (arg == NULL) {
        Py_DECREF(format);
        return NULL;
    }
    retval = PyUnicode_Format(format, arg);
    Py_DECREF(format);
    Py_DECREF(arg);

    return retval;
}

static PyObject *
silkPyIPWildcard_str(
    silkPyIPWildcard   *obj)
{
    Py_INCREF(obj->name);
    return obj->name;
}


/*
 *************************************************************************
 *   IPSet
 *************************************************************************
 */

typedef struct silkPyIPSet_st {
    PyObject_HEAD
    skipset_t  *ipset;
} silkPyIPSet;

typedef struct silkPyIPSetIter_st {
    PyObject_HEAD
    silkPyIPSet *set;
    skipset_iterator_t iter;
    unsigned is_cidr : 1;
} silkPyIPSetIter;

/* function prototypes */
static void
silkPyIPSetIter_dealloc(
    silkPyIPSetIter    *self);
static PyObject *
silkPyIPSetIter_iternext(
    silkPyIPSetIter    *self);
static PyObject *
silkPyIPSet_add(
    silkPyIPSet        *self,
    PyObject           *obj);
static PyObject *
silkPyIPSet_add_range(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPSet_cardinality(
    silkPyIPSet        *self);
static PyObject *
silkPyIPSet_cidr_iter(
    silkPyIPSet        *self);
static PyObject *
silkPyIPSet_clear(
    silkPyIPSet        *self);
static int
silkPyIPSet_contains(
    silkPyIPSet        *self,
    PyObject           *obj);
static PyObject *
silkPyIPSet_convert(
    silkPyIPSet        *self,
    PyObject           *obj);
static void
silkPyIPSet_dealloc(
    silkPyIPSet        *obj);
static PyObject *
silkPyIPSet_difference_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj);
static PyObject *
silkPyIPSet_discard(
    silkPyIPSet        *self,
    PyObject           *obj);
static int
silkPyIPSet_init(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPSet_intersection_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj);
static PyObject *
silkPyIPSet_isdisjoint(
    silkPyIPSet        *self,
    PyObject           *obj);
static PyObject *
silkPyIPSet_is_ipv6(
    silkPyIPSet        *self);
static PyObject *
silkPyIPSet_iter(
    silkPyIPSet        *self);
static Py_ssize_t
silkPyIPSet_len(
    silkPyIPSet        *self);
static PyObject *
silkPyIPSet_save(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyIPSet_union_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj);

/* define docs and methods */
#define silkPyIPSet_doc                         \
    "IPSetBase() -> empty IPset\n"              \
    "IPSetBase(filename) -> IPset from file"

static PyMethodDef silkPyIPSet_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"cardinality", (PyCFunction)silkPyIPSet_cardinality, METH_NOARGS,
     "ipset.cardinality() -> long -- number of IP Addresses in the IPSet"},
    {"intersection_update", (PyCFunction)silkPyIPSet_intersection_update,
     METH_O,
     ("Return the intersection of two IPSets as a new IPSet.\n"
      "\n"
      "(i.e. all elements that are in both IPSets.)")},
    {"update", (PyCFunction)silkPyIPSet_union_update,
     METH_O,
     ("Update the IPSet with the union of itself and another.")},
    {"difference_update", (PyCFunction)silkPyIPSet_difference_update,
     METH_O,
     ("Remove all elements of another IPSet from this IPSet.")},
    {"clear", (PyCFunction)silkPyIPSet_clear, METH_NOARGS,
     ("Remove all elements from this IPSet.")},
    {"save", (PyCFunction)silkPyIPSet_save, METH_KEYWORDS | METH_VARARGS,
     "ipset.save(filename[, compression]) -- Saves the set to a file."},
    {"cidr_iter", (PyCFunction)silkPyIPSet_cidr_iter, METH_NOARGS,
     "Return an iterator over IPAddr/prefix tuples."},
    {"add", (PyCFunction)silkPyIPSet_add, METH_O,
     ("Add an element to an IPSet.  The element may be an IP address, an\n"
      "IP wildcard, or the string representation of either.\n"
      "\n"
      "This has no effect for any element already present.")},
    {"add_range", (PyCFunction)silkPyIPSet_add_range,
     METH_KEYWORDS | METH_VARARGS,
     ("Add all IPs between start and end, inclusive, to an IPSet.  Each\n"
      "argument may be an IP address or the string representation of an\n"
      "IP address\n"
      "\n"
      "This has no effect when all elements are already present.")},
    {"discard", (PyCFunction)silkPyIPSet_discard, METH_O,
     ("Discard an element to an IPSet.  The element may be an IP address, an\n"
      "IP wildcard, or the string representation of either.\n"
      "\n"
      "This has no effect for any element not present in the IPset.")},
    {"isdisjoint", (PyCFunction)silkPyIPSet_isdisjoint, METH_O,
     "Return whether the IPSet has any elements in common with the argument"},
    {"is_ipv6", (PyCFunction)silkPyIPSet_is_ipv6, METH_NOARGS,
     "Return whether the IPSet is an IPv6 set."},
    {"convert", (PyCFunction)silkPyIPSet_convert, METH_VARARGS,
     ("Convert the current IPSet to IPv4 or IPv6 if the argument is 4 or 6.\n"
      "Converting an IPv6 set to IPv4 will throw a ValueError if there are\n"
      "addresses in the set that cannot be represented in IPv4.")},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PySequenceMethods silkPyIPSet_sequence_methods = {
#if PY_VERSION_HEX < 0x02050000
    (inquiry)silkPyIPSet_len,   /* sq_length */
#else
    (lenfunc)silkPyIPSet_len,   /* sq_length */
#endif
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    (objobjproc)silkPyIPSet_contains, /* sq_contains */
    0,                          /* sq_inplace_concat */
    0                           /* sq_inplace_repeat */
};

/* define the object types */
static PyTypeObject silkPyIPSetType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.IPSetBase",    /* tp_name */
    sizeof(silkPyIPSet),        /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyIPSet_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    &silkPyIPSet_sequence_methods, /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyIPSet_doc,            /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    (getiterfunc)silkPyIPSet_iter, /* tp_iter */
    0,                          /* tp_iternext */
    silkPyIPSet_methods,        /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyIPSet_init, /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyIPSetIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.IPSetIter",    /* tp_name */
    sizeof(silkPyIPSetIter),    /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyIPSetIter_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "IP Set iterator object",   /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    iter_iter,                  /* tp_iter */
    (iternextfunc)silkPyIPSetIter_iternext, /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};


/* macro and function defintions */
#define silkPyIPSet_Check(op)                   \
    PyObject_TypeCheck(op, &silkPyIPSetType)
#define silkPyIPSetIter_Check(op)                       \
    PyObject_TypeCheck(op, &silkPyIPSetIterType)

static void
silkPyIPSetIter_dealloc(
    silkPyIPSetIter    *self)
{
    Py_XDECREF(self->set);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
silkPyIPSetIter_iternext(
    silkPyIPSetIter    *self)
{
    silkPyIPAddr       *addr;
    int                 rv;
    PyObject           *retval;
    skipaddr_t          raw_addr;
    uint32_t            raw_prefix;

    rv = skIPSetIteratorNext(&self->iter, &raw_addr, &raw_prefix);
    if (rv == SK_ITERATOR_NO_MORE_ENTRIES) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    addr = (silkPyIPAddr*)silkPyIPAddrType.tp_alloc(&silkPyIPAddrType, 0);
    if (addr == NULL) {
        return NULL;
    }
    addr->addr = raw_addr;

    if (!self->is_cidr) {
        retval = (PyObject*)addr;
    } else {
        PyObject       *pair;
        PyObject       *len;

        len = PyInt_FromLong(raw_prefix);
        if (len == NULL) {
            Py_DECREF(addr);
            return NULL;
        }
        pair = PyTuple_New(2);
        if (pair == NULL) {
            Py_DECREF(addr);
            Py_DECREF(len);
        }
        PyTuple_SET_ITEM(pair, 0, (PyObject*)addr);
        PyTuple_SET_ITEM(pair, 1, len);

        retval = pair;
    }

    return retval;
}

static PyObject *
silkPyIPSet_add(
    silkPyIPSet        *self,
    PyObject           *obj)
{
    int           rv;

    if (silkPyIPAddr_Check(obj)) {
        silkPyIPAddr *addr = (silkPyIPAddr*)obj;

        rv = skIPSetInsertAddress(self->ipset, &addr->addr, 0);
    } else if (silkPyIPWildcard_Check(obj)) {
        silkPyIPWildcard *wild;

        assert(silkPyIPWildcard_Check(obj));

        wild = (silkPyIPWildcard*)obj;

        rv = skIPSetInsertIPWildcard(self->ipset, &wild->wildcard);
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "Must be a silk.IPAddr or a silk.IPWildcard");
        return NULL;
    }

    if (rv == SKIPSET_ERR_ALLOC) {
        return PyErr_NoMemory();
    }
    if (rv == SKIPSET_ERR_IPV6) {
        PyErr_SetString(PyExc_ValueError,
                        "Must only include IPv4 addresses");
        return NULL;
    }
    assert(rv == SKIPSET_OK);

    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject *
silkPyIPSet_add_range(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char  *kwlist[] = {"start", "end", NULL};
    PyObject     *start_obj;
    PyObject     *end_obj;
    silkPyIPAddr *start_addr;
    silkPyIPAddr *end_addr;
    int           rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                                     &start_obj, &end_obj))
    {
        return NULL;
    }
    if (!silkPyIPAddr_Check(start_obj)) {
        PyErr_SetString(PyExc_TypeError,
                        "The start argument must be a silk.IPAddr");
        return NULL;
    }
    if (!silkPyIPAddr_Check(end_obj)) {
        PyErr_SetString(PyExc_TypeError,
                        "The end argument must be a silk.IPAddr");
        return NULL;
    }

    start_addr = (silkPyIPAddr*)start_obj;
    end_addr =  (silkPyIPAddr*)end_obj;

    rv = skIPSetInsertRange(self->ipset, &start_addr->addr, &end_addr->addr);
    if (rv == SKIPSET_ERR_ALLOC) {
        return PyErr_NoMemory();
    }
    if (rv == SKIPSET_ERR_IPV6) {
        PyErr_SetString(PyExc_ValueError,
                        "Must only include IPv4 addresses");
        return NULL;
    }
    if (rv == SKIPSET_ERR_BADINPUT) {
        PyErr_SetString(PyExc_ValueError,
                        "The start of range must not be greater than the end");
        return NULL;
    }
    assert(rv == SKIPSET_OK);

    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject *
silkPyIPSet_cardinality(
    silkPyIPSet        *self)
{
    uint64_t count;
    double count_d;

    skIPSetClean(self->ipset);
    count = skIPSetCountIPs(self->ipset, &count_d);
    if (count == UINT64_MAX) {
        return PyLong_FromDouble(count_d);
    }
    return PyLong_FromUnsignedLongLong(count);
}

static PyObject *
silkPyIPSet_cidr_iter(
    silkPyIPSet        *self)
{
    silkPyIPSetIter *iter;

    iter = (silkPyIPSetIter*)silkPyIPSetIterType.tp_alloc(
        &silkPyIPSetIterType, 0);
    if (iter) {
        skIPSetClean(self->ipset);
        if (skIPSetIteratorBind(&iter->iter, self->ipset, 1,SK_IPV6POLICY_MIX))
        {
            Py_DECREF(iter);
            return PyErr_NoMemory();
        }
        Py_INCREF(self);
        iter->set = self;
        iter->is_cidr = 1;
    }
    return (PyObject*)iter;
}

static PyObject *
silkPyIPSet_clear(
    silkPyIPSet        *self)
{
    skIPSetRemoveAll(self->ipset);

    Py_INCREF(self);
    return (PyObject*)self;
}

static int
silkPyIPSet_contains(
    silkPyIPSet        *self,
    PyObject           *obj)
{
    int           retval;
    silkPyIPAddr *silkaddr;

    if (IS_STRING(obj)) {
        obj = PyObject_CallFunctionObjArgs((PyObject*)&silkPyIPAddrType,
                                           obj, NULL);
        if (obj == NULL) {
            return -1;
        }
    } else if (silkPyIPAddr_Check(obj)) {
        Py_INCREF(obj);
    } else {
        PyErr_SetString(PyExc_TypeError, "Must be a string or silk.IPAddr");
        return -1;
    }

    silkaddr = (silkPyIPAddr*)obj;
    retval = skIPSetCheckAddress(self->ipset, &silkaddr->addr);
    Py_DECREF(obj);

    return retval ? 1 : 0;
}

static PyObject *
silkPyIPSet_convert(
    silkPyIPSet        *self,
    PyObject           *args)
{
    int rv;
    int version;

    if (!PyArg_ParseTuple(args, "i", &version)) {
        return NULL;
    }
    if (version != 4 && version != 6) {
        PyErr_SetString(PyExc_ValueError, "Version must be 4 or 6");
        return NULL;
    }

    rv = skIPSetConvert(self->ipset, version);
    if (rv == 0) {
        Py_INCREF(self);
        return (PyObject*)self;
    }
    if (rv == SKIPSET_ERR_IPV6) {
#if SK_ENABLE_IPV6
        PyErr_SetString(
            PyExc_ValueError,
            "IPSet cannot be converted to v4, as it contains v6 addresses");
#else
        PyErr_SetString(PyExc_ValueError,
                        "This build of SiLK does not support IPv6");
#endif
        return NULL;
    }
    return PyErr_Format(PyExc_RuntimeError,
                        "Unexpected error converting IPSet: %d", rv);
}

static void
silkPyIPSet_dealloc(
    silkPyIPSet        *obj)
{
    if (obj->ipset) {
        skIPSetDestroy(&obj->ipset);
    }
    Py_TYPE(obj)->tp_free((PyObject*)obj);
}

static PyObject *
silkPyIPSet_difference_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj)
{
    if (!silkPyIPSet_Check(obj)) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "Argument must be a silk.IPSet");
        return NULL;
    }

    skIPSetClean(self->ipset);
    skIPSetClean(obj->ipset);
    skIPSetSubtract(self->ipset, obj->ipset);

    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject *
silkPyIPSet_discard(
    silkPyIPSet        *self,
    PyObject           *obj)
{
    int rv;

    if (silkPyIPAddr_Check(obj)) {
        silkPyIPAddr *addr = (silkPyIPAddr*)obj;

        rv = skIPSetRemoveAddress(self->ipset, &addr->addr, 0);
    } else if (silkPyIPWildcard_Check(obj)) {
        silkPyIPWildcard *wild;

        assert(silkPyIPWildcard_Check(obj));

        wild = (silkPyIPWildcard*)obj;

        rv = skIPSetRemoveIPWildcard(self->ipset, &wild->wildcard);
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "Must be a silk.IPAddr or a silk.IPWildcard");
        return NULL;
    }

    if (rv == SKIPSET_ERR_ALLOC) {
        return PyErr_NoMemory();
    }
    assert(rv == SKIPSET_OK);

    Py_INCREF(self);
    return (PyObject*)self;
}

static int
silkPyIPSet_init(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"filename", NULL};
    char         errbuf[2 * PATH_MAX];
    skstream_t  *stream = NULL;
    char        *fname = NULL;
    int          rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|et", kwlist,
                                     Py_FileSystemDefaultEncoding, &fname))
    {
        return -1;
    }

    if (fname) {
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, fname))
            || (rv = skStreamOpen(stream)))
        {
            skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
            PyErr_Format(PyExc_IOError, "Unable to read IPSet from %s: %s",
                         fname, errbuf);
            skStreamDestroy(&stream);
            PyMem_Free(fname);
            return -1;
        }
        rv = skIPSetRead(&self->ipset, stream);
        if (rv) {
            if (SKIPSET_ERR_FILEIO == rv) {
                skStreamLastErrMessage(stream,
                                       skStreamGetLastReturnValue(stream),
                                       errbuf, sizeof(errbuf));
            } else {
                strncpy(errbuf, skIPSetStrerror(rv), sizeof(errbuf) - 1);
                errbuf[sizeof(errbuf) - 1] = '\0';
            }
            PyErr_Format(PyExc_IOError, "Unable to read IPSet from %s: %s",
                         fname, errbuf);
            skStreamDestroy(&stream);
            PyMem_Free(fname);
            return -1;
        }
        skStreamDestroy(&stream);
        PyMem_Free(fname);
    } else {
        rv = skIPSetCreate(&self->ipset, 0);
        if (rv == SKIPSET_ERR_ALLOC) {
            PyErr_NoMemory();
            return -1;
        }
        assert(rv == SKIPSET_OK);
    }

    return 0;
}

static PyObject *
silkPyIPSet_is_ipv6(
    silkPyIPSet        *self)
{
    return PyBool_FromLong(skIPSetIsV6(self->ipset));
}

static PyObject *
silkPyIPSet_intersection_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj)
{
    if (!silkPyIPSet_Check(obj)) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "Argument must be a silk.IPSet");
        return NULL;
    }

    skIPSetClean(self->ipset);
    skIPSetClean(obj->ipset);
    skIPSetIntersect(self->ipset, obj->ipset);

    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject *
silkPyIPSet_isdisjoint(
    silkPyIPSet        *self,
    PyObject           *obj)
{
    int disjoint;

    if (silkPyIPSet_Check(obj)) {
        disjoint = !skIPSetCheckIPSet(
            self->ipset, ((silkPyIPSet*)obj)->ipset);
    } else if (silkPyIPWildcard_Check(obj)) {
        disjoint = !skIPSetCheckIPWildcard(
            self->ipset, &((silkPyIPWildcard*)obj)->wildcard);
    } else {
        PyErr_SetString(PyExc_TypeError, "Expected an IPSet or an IPWildcard");
        return NULL;
    }
    if (disjoint) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
silkPyIPSet_iter(
    silkPyIPSet        *self)
{
    silkPyIPSetIter *iter;

    iter = (silkPyIPSetIter*)silkPyIPSetIterType.tp_alloc(
        &silkPyIPSetIterType, 0);
    if (iter) {
        skIPSetClean(self->ipset);
        if (skIPSetIteratorBind(&iter->iter, self->ipset, 0,SK_IPV6POLICY_MIX))
        {
            Py_DECREF(iter);
            return PyErr_NoMemory();
        }
        Py_INCREF(self);
        iter->set = self;
    }
    return (PyObject*)iter;
}

static Py_ssize_t
silkPyIPSet_len(
    silkPyIPSet        *self)
{
    uint64_t count;
    double count_d;

    skIPSetClean(self->ipset);
    count = skIPSetCountIPs(self->ipset, &count_d);
    if (count > PY_SSIZE_T_MAX) {
        PyErr_SetString(PyExc_OverflowError, "IPSet too long for integer");
        return -1;
    }
    return (Py_ssize_t)count;
}

static PyObject *
silkPyIPSet_save(
    silkPyIPSet        *self,
    PyObject           *args,
    PyObject           *kwds)
{
    int rv;
    skstream_t *stream;

    if ((stream = open_silkfile_write(args, kwds)) == NULL) {
        return NULL;
    }

    skIPSetClean(self->ipset);
    rv = skIPSetWrite(self->ipset, stream);
    skStreamDestroy(&stream);
    if (rv != SKIPSET_OK) {
        PyErr_SetString(PyExc_IOError, skIPSetStrerror(rv));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
silkPyIPSet_union_update(
    silkPyIPSet        *self,
    silkPyIPSet        *obj)
{
    int rv;

    if (!silkPyIPSet_Check(obj)) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "Argument must be a silk.IPSet");
        return NULL;
    }

    skIPSetClean(self->ipset);
    skIPSetClean(obj->ipset);
    rv = skIPSetUnion(self->ipset, obj->ipset);
    if (rv != 0) {
        return PyErr_NoMemory();
    }

    Py_INCREF(self);
    return (PyObject*)self;
}


/* *************************************************************************
 *   Prefix Map
 *************************************************************************
 */

typedef struct silkPyPmap_st {
    PyObject_HEAD
    skPrefixMap_t *map;
} silkPyPmap;

typedef struct silkPyPmapIter_st {
    PyObject_HEAD
    silkPyPmap *map;
    skPrefixMapIterator_t iter;
} silkPyPmapIter;

/* function prototypes */
static void
silkPyPmapIter_dealloc(
    silkPyPmapIter     *self);
static PyObject *
silkPyPmapIter_iternext(
    silkPyPmapIter     *self);
static void
silkPyPmap_dealloc(
    silkPyPmap         *obj);
static PyObject *
silkPyPmap_get_content(
    silkPyPmap         *self,
    void        UNUSED(*cbdata));
static PyObject *
silkPyPmap_get_name(
    silkPyPmap         *self,
    void        UNUSED(*cbdata));
static PyObject *
silkPyPmap_get_num_values(
    silkPyPmap         *self,
    void        UNUSED(*cbdata));
static PyObject *
silkPyPmap_get_value_string(
    silkPyPmap         *self,
    PyObject           *value);
static int
silkPyPmap_init(
    silkPyPmap         *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyPmap_iter(
    silkPyPmap         *self);
static PyObject *
silkPyPmap_subscript(
    silkPyPmap         *self,
    PyObject           *sub);

/* define docs and methods */
#define silkPyPmap_doc                                  \
    "PMapBase(filename) -> Prefix map from file"

static PyMethodDef silkPyPmap_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"get_value_string", (PyCFunction)silkPyPmap_get_value_string, METH_O,
     ("Get the string associated with an integer value")},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PyGetSetDef silkPyPmap_getsetters[] = {
    {"content", (getter)silkPyPmap_get_content, NULL, "Content type", NULL},
    {"name", (getter)silkPyPmap_get_name, NULL, "Prefix map name", NULL},
    {"num_values", (getter)silkPyPmap_get_num_values, NULL,
     "Prefix map number of values", NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyMappingMethods silkPyPmap_mapping_methods = {
    0,
    (binaryfunc)silkPyPmap_subscript,
    0
};

/* define the object types */
static PyTypeObject silkPyPmapType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.PMapBase",     /* tp_name */
    sizeof(silkPyPmap),         /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyPmap_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    &silkPyPmap_mapping_methods, /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyPmap_doc,             /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    (getiterfunc)silkPyPmap_iter, /* tp_iter */
    0,                          /* tp_iternext */
    silkPyPmap_methods,         /* tp_methods */
    0,                          /* tp_members */
    silkPyPmap_getsetters,      /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyPmap_init,  /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyPmapIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.PMapBaseIter", /* tp_name */
    sizeof(silkPyPmapIterType), /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyPmapIter_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Prefix map iterator object", /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    iter_iter,                  /* tp_iter */
    (iternextfunc)silkPyPmapIter_iternext, /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyPmap_Check(op)                    \
    PyObject_TypeCheck(op, &silkPyPmapType)
#define silkPyPmapIter_Check(op)                \
    PyObject_TypeCheck(op, &silkPyPmapIterType)

static void
silkPyPmapIter_dealloc(
    silkPyPmapIter     *self)
{
    Py_XDECREF(self->map);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
silkPyPmapIter_iternext(
    silkPyPmapIter     *self)
{
    skIteratorStatus_t    rv;
    PyObject             *retval;
    PyObject             *startval = NULL;
    PyObject             *endval = NULL;
    union {
        skipaddr_t             addr;
        skPrefixMapProtoPort_t pp;
    } start, end;
    uint32_t              value;
    skPrefixMapContent_t  content;

    rv = skPrefixMapIteratorNext(&self->iter, &start, &end, &value);
    if (rv == SK_ITERATOR_NO_MORE_ENTRIES) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    content = skPrefixMapGetContentType(self->map->map);
    switch (content) {
      case SKPREFIXMAP_CONT_ADDR_V4:
      case SKPREFIXMAP_CONT_ADDR_V6:
        {
            PyTypeObject *type =
                (content == SKPREFIXMAP_CONT_ADDR_V4) ?
                &silkPyIPv4AddrType : &silkPyIPv6AddrType;

            startval = type->tp_alloc(type, 0);
            if (startval == NULL) {
                return NULL;
            }
            endval = type->tp_alloc(type, 0);
            if (endval == NULL) {
                Py_DECREF(startval);
                return NULL;
            }
            skipaddrCopy(&((silkPyIPAddr*)startval)->addr, &start.addr);
            skipaddrCopy(&((silkPyIPAddr*)endval)->addr, &end.addr);
        }
        break;
      case SKPREFIXMAP_CONT_PROTO_PORT:
        {
            startval = Py_BuildValue("BH", start.pp.proto, start.pp.port);
            if (startval == NULL) {
                return NULL;
            }
            endval = Py_BuildValue("BH", end.pp.proto, end.pp.port);
            if (endval == NULL) {
                Py_DECREF(startval);
                return NULL;
            }
        }
        break;
    }
    assert(startval && endval);

    retval = Py_BuildValue("NNk", startval, endval, value);
    if (retval == NULL) {
        Py_DECREF(startval);
        Py_DECREF(endval);
    }

    return retval;
}

static void
silkPyPmap_dealloc(
    silkPyPmap         *obj)
{
    if (obj->map) {
        skPrefixMapDelete(obj->map);
    }
    Py_TYPE(obj)->tp_free((PyObject*)obj);
}

static PyObject *
silkPyPmap_get_content(
    silkPyPmap         *self,
    void        UNUSED(*cbdata))
{
    return PyUnicode_FromString(skPrefixMapGetContentName(
                                    skPrefixMapGetContentType(self->map)));
}

static PyObject *
silkPyPmap_get_name(
    silkPyPmap         *self,
    void        UNUSED(*cbdata))
{
    const char *name = skPrefixMapGetMapName(self->map);
    if (name == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_FromString(name);
}

static PyObject *
silkPyPmap_get_num_values(
    silkPyPmap         *self,
    void        UNUSED(*cbdata))
{
    return PyInt_FromLong(skPrefixMapDictionaryGetWordCount(self->map));
}

static PyObject *
silkPyPmap_get_value_string(
    silkPyPmap         *self,
    PyObject           *value)
{
    uint32_t  val;
    uint32_t  size;
    char     *buf;
    int       rv;
    PyObject *retval;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return NULL;
    }

    val = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return NULL;
    }

    size = skPrefixMapDictionaryGetMaxWordSize(self->map) + 1;
    buf = (char*)malloc(size);
    if (buf == NULL) {
        return PyErr_NoMemory();
    }

    rv = skPrefixMapDictionaryGetEntry(self->map, val, buf, size);
    assert(rv < (int32_t)size);

    retval = PyUnicode_DecodeASCII(buf, rv, "strict");
    free(buf);

    return retval;
}

static int
silkPyPmap_init(
    silkPyPmap         *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char      *kwlist[] = {"filename", NULL};
    char              errbuf[2 * PATH_MAX];
    skstream_t       *stream = NULL;
    char             *fname;
    int               rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "et", kwlist,
                                     Py_FileSystemDefaultEncoding, &fname))
    {
        return -1;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, fname))
        || (rv = skStreamOpen(stream)))
    {
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        PyErr_Format(PyExc_IOError, "Unable to read prefix map from %s: %s",
                     fname, errbuf);
        skStreamDestroy(&stream);
        PyMem_Free(fname);
        return -1;
    }
    rv = (int)skPrefixMapRead(&self->map, stream);
    if (rv) {
        if (SKPREFIXMAP_ERR_IO == rv) {
            skStreamLastErrMessage(stream,
                                   skStreamGetLastReturnValue(stream),
                                   errbuf, sizeof(errbuf));
        } else {
            strncpy(errbuf, skPrefixMapStrerror(rv), sizeof(errbuf) - 1);
            errbuf[sizeof(errbuf) - 1] = '\0';
        }
        PyErr_Format(PyExc_IOError, "Unable to read prefix map from %s: %s",
                     fname, errbuf);
        skStreamDestroy(&stream);
        PyMem_Free(fname);
        return -1;
    }
    skStreamDestroy(&stream);
    PyMem_Free(fname);

    return 0;
}

static PyObject *
silkPyPmap_iter(
    silkPyPmap         *self)
{
    int             rv;
    silkPyPmapIter *iter;

    iter = (silkPyPmapIter*)silkPyPmapIterType.tp_alloc(
        &silkPyPmapIterType, 0);
    if (iter) {
        rv = skPrefixMapIteratorBind(&iter->iter, self->map);
        if (rv != 0) {
            Py_DECREF(iter);
            PyErr_SetString(PyExc_RuntimeError,
                            "Failed to create prefix map iterator");
            return NULL;
        }
        Py_INCREF(self);
        iter->map = self;
    }
    return (PyObject*)iter;
}

static PyObject *
silkPyPmap_subscript(
    silkPyPmap         *self,
    PyObject           *sub)
{
    void *key = NULL;
    uint32_t value;
    skPrefixMapProtoPort_t protoport;
    skPrefixMapContent_t content;
    PyObject *tuple;
    int32_t i32;
    int rv;

    content = skPrefixMapGetContentType(self->map);

    switch (content) {
      case SKPREFIXMAP_CONT_ADDR_V4:
      case SKPREFIXMAP_CONT_ADDR_V6:
        if (!silkPyIPAddr_Check(sub)) {
            PyErr_SetString(PyExc_TypeError, "Expected an IPAddr");
            return NULL;
        }
        key = &((silkPyIPAddr*)sub)->addr;
        break;
      case SKPREFIXMAP_CONT_PROTO_PORT:
        if (!PySequence_Check(sub) || PySequence_Size(sub) != 2) {
            PyErr_SetString(PyExc_TypeError, "Expected a (proto, port) pair");
            return NULL;
        }
        tuple = PySequence_Tuple(sub);
        if (tuple == NULL) {
            return NULL;
        }
        rv = PyArg_ParseTuple(tuple, "bi;Expected a (proto, port) pair",
                              &protoport.proto, &i32);
        Py_DECREF(tuple);
        if (!rv) {
            return NULL;
        }
        if (i32 < 0 || i32 > 0xFFFF) {
            PyErr_SetString(PyExc_ValueError, "Port is out of bounds");
            return NULL;
        }
        protoport.port = i32;
        key = &protoport;
        break;
    }

    value = skPrefixMapFindValue(self->map, key);

    return PyLong_FromUnsignedLong(value);
}


/*
 *************************************************************************
 *   Bag
 *************************************************************************
 */

typedef struct silkPyBag_st {
    PyObject_HEAD
    skBag_t *bag;
    unsigned is_ipaddr : 1;
} silkPyBag;

typedef struct silkPyBagIter_st {
    PyObject_HEAD
    silkPyBag       *bag;
    skBagIterator_t *iter;
    unsigned         ipaddr : 1;
} silkPyBagIter;

/* function prototypes */
static void
silkPyBagIter_dealloc(
    silkPyBagIter      *self);
static PyObject *
silkPyBagIter_iternext(
    silkPyBagIter      *self);
static PyObject *
silkPyBag__get_custom_type(
    PyObject    UNUSED(*self));
static PyObject *
silkPyBag__get_ipv4_type(
    PyObject    UNUSED(*self));
static PyObject *
silkPyBag__get_ipv6_type(
    PyObject    UNUSED(*self));
static int
silkPyBag_ass_subscript(
    silkPyBag          *self,
    PyObject           *sub,
    PyObject           *value);
static PyObject *
silkPyBag_clear(
    silkPyBag          *self);
static Py_ssize_t
silkPyBag_count(
    silkPyBag          *self);
static void
silkPyBag_dealloc(
    silkPyBag          *obj);
static PyObject *
silkPyBag_decr(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyBag_field_types(
    PyObject    UNUSED(*self));
static PyObject *
silkPyBag_get_info(
    silkPyBag          *self);
static PyObject *
silkPyBag_iadd(
    silkPyBag          *self,
    silkPyBag          *other);
#if 0
static skBagErr_t
silkPyBag_iadd_bounds(
    const skBagTypedKey_t       UNUSED(*key),
    skBagTypedCounter_t                *in_out_counter,
    const skBagTypedCounter_t   UNUSED(*in_counter),
    void                        UNUSED(*cb_data));
#endif
static PyObject *
silkPyBag_incr(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds);
static int
silkPyBag_init(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyBag_iter(
    silkPyBag          *self);
static PyObject *
silkPyBag_iter_helper(
    silkPyBag          *self,
    int                 sorted);
static int
silkPyBag_modify(
    silkPyBag          *self,
    PyObject           *sub,
    PyObject           *value,
    silkBagModFn        fn);
static PyObject *
silkPyBag_save(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyBag_set_info(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds);
static int
silkPyBag_setup(
    PyObject           *mod);
static PyObject *
silkPyBag_sorted_iter(
    silkPyBag          *self);
static PyObject *
silkPyBag_subscript(
    silkPyBag          *self,
    PyObject           *sub);
static PyObject *
silkPyBag_type_merge(
    PyObject    UNUSED(*self),
    PyObject           *args);

/* define docs and methods */
#define silkPyBag_doc                           \
    "BagBase(filename) -> Bag from file"

static PyNumberMethods silkPyBag_number_methods;

static PyMappingMethods silkPyBag_mapping_methods = {
#if PY_VERSION_HEX < 0x02050000
    (inquiry)silkPyBag_count,   /* mp_length */
#else
    (lenfunc)silkPyBag_count,   /* mp_length */
#endif
    (binaryfunc)silkPyBag_subscript,       /* mp_subscript */
    (objobjargproc)silkPyBag_ass_subscript /* mp_ass_subscript */
};

static PyMethodDef silkPyBag_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"incr", (PyCFunction)silkPyBag_incr, METH_KEYWORDS | METH_VARARGS,
     ("bag.incr(key, value) -- increments bag[key] by value")},
    {"decr", (PyCFunction)silkPyBag_decr, METH_KEYWORDS | METH_VARARGS,
     ("bag.decr(key, value) -- decrements bag[key] by value")},
    {"save", (PyCFunction)silkPyBag_save, METH_KEYWORDS | METH_VARARGS,
     "bag.save(filename[, compression]) -- saves the bag to a file"},
    {"clear", (PyCFunction)silkPyBag_clear, METH_NOARGS,
     "bag.clear() -- empties the bag"},
    {"sorted_iter", (PyCFunction)silkPyBag_sorted_iter, METH_NOARGS,
     ("bag.sorted_iter() -- returns an iterator whose values are "
      "sorted by key")},
    {"get_info", (PyCFunction)silkPyBag_get_info, METH_NOARGS,
     "get_info() -- returns (key_type, key_len, counter_type, counter_len)"},
    {"set_info", (PyCFunction)silkPyBag_set_info,
     METH_KEYWORDS | METH_VARARGS,
     ("set_info([key_type][, key_len][, counter_type][, counter_len]) --\n\t"
      "returns the result of bag.get_info()")},
    {"field_types", (PyCFunction)silkPyBag_field_types,
     METH_NOARGS | METH_STATIC,
     "field_types() -> Tuple of valid field types for Bag keys and counters"},
    {"type_merge", (PyCFunction)silkPyBag_type_merge,
     METH_VARARGS | METH_STATIC,
     "type_merge(keytype_a, keytype_b) -> key_type of merged output"},
    {"_get_custom_type", (PyCFunction)silkPyBag__get_custom_type,
     METH_NOARGS | METH_STATIC, NULL},
    {"_get_ipv4_type", (PyCFunction)silkPyBag__get_ipv4_type,
     METH_NOARGS | METH_STATIC, NULL},
    {"_get_ipv6_type", (PyCFunction)silkPyBag__get_ipv6_type,
     METH_NOARGS | METH_STATIC, NULL},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};


/* define the object types */
static PyTypeObject silkPyBagType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.BagBase",      /* tp_name */
    sizeof(silkPyBag),          /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyBag_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    &silkPyBag_number_methods,  /* tp_as_number */
    0,                          /* tp_as_sequence */
    &silkPyBag_mapping_methods, /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
#if PY_MAJOR_VERSION < 3
    Py_TPFLAGS_CHECKTYPES |
#endif
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyBag_doc,              /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    (getiterfunc)silkPyBag_iter, /* tp_iter */
    0,                          /* tp_iternext */
    silkPyBag_methods,          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyBag_init,   /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyBagIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.BagBaseIter",  /* tp_name */
    sizeof(silkPyBagIterType),  /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyBagIter_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Bag iterator object",      /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    iter_iter,                  /* tp_iter */
    (iternextfunc)silkPyBagIter_iternext, /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyBag_Check(op)                     \
    PyObject_TypeCheck(op, &silkPyBagType)
#define silkPyBagIter_Check(op)                 \
    PyObject_TypeCheck(op, &silkPyBagIterType)

#define IS_IPV4_KEY(k)                          \
    ((k) == SKBAG_FIELD_SIPv4                   \
     || (k) == SKBAG_FIELD_DIPv4                \
     || (k) == SKBAG_FIELD_NHIPv4               \
     || (k) == SKBAG_FIELD_ANY_IPv4)

#define IS_IPV6_KEY(k)                          \
    ((k) == SKBAG_FIELD_SIPv6                   \
     || (k) == SKBAG_FIELD_DIPv6                \
     || (k) == SKBAG_FIELD_NHIPv6               \
     || (k) == SKBAG_FIELD_ANY_IPv6)

#define IS_IP_KEY(k) (IS_IPV4_KEY(k) || IS_IPV6_KEY(k))

static void
silkPyBagIter_dealloc(
    silkPyBagIter      *self)
{
    Py_XDECREF(self->bag);
    skBagIteratorDestroy(self->iter);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
silkPyBagIter_iternext(
    silkPyBagIter      *self)
{
    skBagErr_t           rv;
    PyObject            *retkey;
    PyObject            *retval;
    skBagTypedKey_t      key;
    skBagTypedCounter_t  counter;

    counter.type = SKBAG_COUNTER_U64;
    key.type = self->ipaddr ? SKBAG_KEY_IPADDR : SKBAG_KEY_U32;

    rv = skBagIteratorNextTyped(self->iter, &key, &counter);
    if (rv == SKBAG_ERR_KEY_NOT_FOUND) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }
    if (rv == SKBAG_ERR_MODIFIED) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Underlying Bag changed during iteration");
        return NULL;
    }
    if (self->ipaddr) {
        PyTypeObject *type = (skipaddrIsV6(&key.val.addr)
                              ? &silkPyIPv6AddrType : &silkPyIPv4AddrType);
        retkey = type->tp_alloc(type, 0);
        if (retkey == NULL) {
            return NULL;
        }
        skipaddrCopy(&((silkPyIPAddr*)retkey)->addr, &key.val.addr);
    } else {
        retkey = PyLong_FromUnsignedLong(key.val.u32);
        if (retkey == NULL) {
            return NULL;
        }
    }

    retval = Py_BuildValue("OK", retkey, counter.val.u64);
    Py_DECREF(retkey);
    return retval;
}

static PyObject *
silkPyBag__get_custom_type(
    PyObject    UNUSED(*self))
{
    char buf[SKBAG_MAX_FIELD_BUFLEN];

    skBagFieldTypeAsString(SKBAG_FIELD_CUSTOM, buf, sizeof(buf));
    return PyUnicode_FromString(buf);
}

static PyObject *
silkPyBag__get_ipv4_type(
    PyObject    UNUSED(*self))
{
    char buf[SKBAG_MAX_FIELD_BUFLEN];

    skBagFieldTypeAsString(SKBAG_FIELD_ANY_IPv4, buf, sizeof(buf));
    return PyUnicode_FromString(buf);
}

static PyObject *
silkPyBag__get_ipv6_type(
    PyObject    UNUSED(*self))
{
    char buf[SKBAG_MAX_FIELD_BUFLEN];

    skBagFieldTypeAsString(SKBAG_FIELD_ANY_IPv6, buf, sizeof(buf));
    return PyUnicode_FromString(buf);
}

static int
silkPyBag_ass_subscript(
    silkPyBag          *self,
    PyObject           *sub,
    PyObject           *value)
{
    /* skBagCounterSet will ignore the extra NULL passed to it */
    return silkPyBag_modify(self, sub, value, (silkBagModFn)skBagCounterSet);
}

static PyObject *
silkPyBag_clear(
    silkPyBag          *self)
{
    skBagErr_t rv;
    skBagFieldType_t key, value;
    size_t keylen, valuelen;
    skBag_t *bag;

    key = skBagKeyFieldType(self->bag);
    keylen = skBagKeyFieldLength(self->bag);
    value = skBagCounterFieldType(self->bag);
    valuelen = skBagCounterFieldLength(self->bag);

    rv = skBagCreateTyped(&bag, key, value, keylen, valuelen);
    if (rv == SKBAG_ERR_MEMORY) {
        return PyErr_NoMemory();
    }
    assert(rv == SKBAG_OK);
    skBagAutoConvertDisable(bag);

    skBagDestroy(&self->bag);
    self->bag = bag;

    Py_RETURN_NONE;
}

static Py_ssize_t
silkPyBag_count(
    silkPyBag          *self)
{
    uint64_t count = skBagCountKeys(self->bag);
    return (Py_ssize_t)count;
}

static void
silkPyBag_dealloc(
    silkPyBag          *obj)
{
    if (obj->bag) {
        skBagDestroy(&obj->bag);
    }
    Py_TYPE(obj)->tp_free((PyObject*)obj);
}

static PyObject *
silkPyBag_decr(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"key", "value", NULL};
    PyObject *sub;
    PyObject *value;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &sub, &value)) {
        return NULL;
    }

    if (silkPyBag_modify(self, sub, value, skBagCounterSubtract)) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
silkPyBag_field_types(
    PyObject    UNUSED(*self))
{
    char buf[SKBAG_MAX_FIELD_BUFLEN];
    skBagFieldTypeIterator_t iter;
    Py_ssize_t count;
    PyObject *retval;

    /* First, count thee types */
    skBagFieldTypeIteratorBind(&iter);
    count = 0;
    while (skBagFieldTypeIteratorNext(&iter, NULL, NULL, NULL, 0) == SKBAG_OK)
    {
        count++;
    }

    /* Create the tuple */
    retval = PyTuple_New(count);
    if (retval == NULL) {
        return NULL;
    }

    /* Then fill in the tuple */
    skBagFieldTypeIteratorReset(&iter);
    count = 0;
    while (skBagFieldTypeIteratorNext(&iter, NULL, NULL, buf, sizeof(buf))
           == SKBAG_OK)
    {
        PyObject *name = PyUnicode_InternFromString(buf);
        if (name == NULL) {
            Py_DECREF(retval);
            return NULL;
        }
        PyTuple_SET_ITEM(retval, count, name);
        count++;
    }

    return retval;
}

static PyObject *
silkPyBag_get_info(
    silkPyBag          *self)
{
    char buf[80];
    unsigned int key_len;
    unsigned int counter_len;
    PyObject *key_name;
    PyObject *counter_name;

    skBagKeyFieldName(self->bag, buf, sizeof(buf));
    key_len = skBagKeyFieldLength(self->bag);
    key_name = PyUnicode_FromString(buf);
    if (key_name == NULL) {
        return NULL;
    }
    skBagCounterFieldName(self->bag, buf, sizeof(buf));
    counter_len = skBagCounterFieldLength(self->bag);
    counter_name = PyUnicode_FromString(buf);
    if (counter_name == NULL) {
        Py_DECREF(key_name);
        return NULL;
    }
    return Py_BuildValue("{sN sI sN sI}",
                         "key_type", key_name, "key_len", key_len,
                         "counter_type", counter_name,
                         "counter_len", counter_len);
}

static PyObject *
silkPyBag_iadd(
    silkPyBag          *self,
    silkPyBag          *other)
{
    skBagErr_t rv;

    if (!silkPyBag_Check(self) || !silkPyBag_Check(other)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    rv = skBagAddBag(self->bag, other->bag, NULL, NULL);
    switch (rv) {
      case SKBAG_OK:
        break;
      case SKBAG_ERR_MEMORY:
        PyErr_NoMemory();
        return NULL;
      case SKBAG_ERR_OP_BOUNDS:
        PyErr_SetString(PyExc_ValueError, skBagStrerror(rv));
        return NULL;
      case SKBAG_ERR_KEY_RANGE:
        PyErr_SetString(PyExc_ValueError, skBagStrerror(rv));
        return NULL;
      case SKBAG_ERR_INPUT:
      case SKBAG_ERR_KEY_NOT_FOUND:
        /* Fall through */
      default:
        skAbortBadCase(rv);
    }
    self->is_ipaddr = (skBagKeyFieldLength(self->bag) == 16
                       || IS_IP_KEY(skBagKeyFieldType(self->bag)));

    Py_INCREF(self);
    return (PyObject*)self;
}

#if 0
/* Clamp bag values for iadd to SKBAG_COUNTER_MAX without errors. */
static skBagErr_t
silkPyBag_iadd_bounds(
    const skBagTypedKey_t       UNUSED(*key),
    skBagTypedCounter_t                *in_out_counter,
    const skBagTypedCounter_t   UNUSED(*in_counter),
    void                        UNUSED(*cb_data))
{
    in_out_counter->type = SKBAG_COUNTER_U64;
    in_out_counter->val.u64 = SKBAG_COUNTER_MAX;
    return SKBAG_OK;
}
#endif

static PyObject *
silkPyBag_incr(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"key", "value", NULL};
    PyObject *sub;
    PyObject *value;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &sub, &value)) {
        return NULL;
    }

    if (silkPyBag_modify(self, sub, value, skBagCounterAdd)) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
silkPyBag_init(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"copy", "filename", "key_type", "counter_type",
                             "key_len", "counter_len", NULL};
    char          errbuf[2 * PATH_MAX];
    skstream_t   *stream       = NULL;
    char         *fname        = NULL;
    silkPyBag    *copy         = NULL;
    char         *key          = NULL;
    char         *counter      = NULL;
    unsigned int  key_size     = 0;
    unsigned int  counter_size = 0;
    skBagErr_t    bagerr;
    int           rv;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "|O!etssII", kwlist, &silkPyBagType,
            (PyObject*)&copy, Py_FileSystemDefaultEncoding, &fname,
            &key, &counter, &key_size, &counter_size))
    {
        return -1;
    }

    if ((copy && fname)
        || (copy && (key || counter))
        || (fname && (key || counter)))
    {
        PyErr_SetString(PyExc_ValueError, "Illegal argument combination");
        return -1;
    }

    if (fname) {
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, fname))
            || (rv = skStreamOpen(stream)))
        {
            skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
            PyErr_Format(PyExc_IOError, "Unable to read Bag from %s: %s",
                         fname, errbuf);
            skStreamDestroy(&stream);
            PyMem_Free(fname);
            return -1;
        }
        bagerr = skBagRead(&self->bag, stream);
        if (bagerr) {
            if (SKBAG_ERR_READ == bagerr) {
                skStreamLastErrMessage(stream,
                                       skStreamGetLastReturnValue(stream),
                                       errbuf, sizeof(errbuf));
            } else {
                strncpy(errbuf, skBagStrerror(bagerr), sizeof(errbuf) - 1);
                errbuf[sizeof(errbuf) - 1] = '\0';
            }
            PyErr_Format(PyExc_IOError, "Unable to read Bag from %s: %s",
                         fname, errbuf);
            skStreamDestroy(&stream);
            PyMem_Free(fname);
            return -1;
        }
        skStreamDestroy(&stream);
        PyMem_Free(fname);
        self->is_ipaddr = skBagKeyFieldLength(self->bag) == 16
                          || IS_IP_KEY(skBagKeyFieldType(self->bag));
    } else if (copy) {
        bagerr = skBagCopy(&self->bag, copy->bag);
        self->is_ipaddr = copy->is_ipaddr;
    } else {
        skBagFieldType_t key_type, counter_type;
        if (!key) {
            key_type = SKBAG_FIELD_CUSTOM;
        } else {
            bagerr = skBagFieldTypeLookup(key, &key_type, NULL);
            if (bagerr != SKBAG_OK) {
                PyErr_Format(PyExc_ValueError,
                             "'%s' is not a valid key type", key);
                return -1;
            }
        }
        if (key_type == SKBAG_FIELD_CUSTOM && key_size == 0) {
            key_size = 4;
        }
        if (!counter) {
            counter_type = SKBAG_FIELD_CUSTOM;
        } else {
            bagerr = skBagFieldTypeLookup(counter, &counter_type, NULL);
            if (bagerr != SKBAG_OK) {
                PyErr_Format(PyExc_ValueError,
                             "'%s' is not a valid counter type", counter);
                return -1;
            }
        }
        if (counter_type == SKBAG_FIELD_CUSTOM && counter_size == 0) {
            counter_size = 8;
        }

        bagerr = skBagCreateTyped(&self->bag, key_type, counter_type,
                                  key_size, counter_size);
        if (bagerr == SKBAG_ERR_INPUT) {
            PyErr_Format(PyExc_ValueError,
                         "Illegal arguments to Bag constructor");
            return -1;
        }
        skBagAutoConvertDisable(self->bag);
        self->is_ipaddr = (counter_size == 16 || IS_IP_KEY(key_type));
    }

    if (bagerr == SKBAG_ERR_MEMORY) {
        PyErr_NoMemory();
        return -1;
    }
    assert(bagerr == SKBAG_OK);

    return 0;
}

static PyObject *
silkPyBag_iter(
    silkPyBag          *self)
{
    return silkPyBag_iter_helper(self, 0);
}

static PyObject *
silkPyBag_iter_helper(
    silkPyBag          *self,
    int                 sorted)
{
    skBagErr_t     rv;
    silkPyBagIter *iter;

    iter = (silkPyBagIter*)silkPyBagIterType.tp_alloc(
        &silkPyBagIterType, 0);
    if (iter) {
        if (sorted) {
            rv = skBagIteratorCreate(self->bag, &iter->iter);
        } else {
            rv = skBagIteratorCreateUnsorted(self->bag, &iter->iter);
        }
        if (rv == SKBAG_ERR_MEMORY) {
            Py_DECREF(iter);
            return PyErr_NoMemory();
        }
        if (rv != SKBAG_OK) {
            Py_DECREF(iter);
            PyErr_SetString(PyExc_RuntimeError,
                            "Failed to create bag iterator");
            return NULL;
        }
        Py_INCREF(self);
        iter->bag = self;
        iter->ipaddr = self->is_ipaddr;
    }
    return (PyObject*)iter;
}

static int
silkPyBag_modify(
    silkPyBag          *self,
    PyObject           *sub,
    PyObject           *value,
    silkBagModFn        fn)
{
    skBagTypedCounter_t bagvalue;
    skBagTypedKey_t     key;
    skBagErr_t          rv;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer value");
        return -1;
    }
    bagvalue.val.u64 = LONG_AS_UNSIGNED_LONGLONG(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    bagvalue.type = SKBAG_COUNTER_U64;

    if (IS_INT(sub)) {
        if (self->is_ipaddr) {
            PyErr_SetString(PyExc_TypeError, "Expected an IPAddr index");
            return -1;
        }
        /* long long is 64-bits on 32 and 64-bit arches, so use it for
         * consistency. */
        key.val.u64 = LONG_AS_UNSIGNED_LONGLONG(sub);
        if (PyErr_Occurred()) {
            if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
                PyErr_Clear();
                PyErr_SetString(PyExc_IndexError, "Index out of range");
            }
            return -1;
        }
        if (key.val.u64 > 0xffffffff) {
            PyErr_SetString(PyExc_IndexError, "Index out of range");
            return -1;
        }
        key.val.u32 = key.val.u64;
        key.type = SKBAG_KEY_U32;
    } else if (silkPyIPAddr_Check(sub)) {
        silkPyIPAddr *addr;
        if (!self->is_ipaddr) {
            PyErr_SetString(PyExc_TypeError, "Expected an integer index");
            return -1;
        }
        addr = (silkPyIPAddr*)sub;
        skipaddrCopy(&key.val.addr, &addr->addr);
        key.type = SKBAG_KEY_IPADDR;
    } else {
        PyErr_SetString(PyExc_TypeError, "Expected an integer or IP address");
        return -1;
    }

    rv = fn(self->bag, &key, &bagvalue, NULL);
    switch (rv) {
      case SKBAG_OK:
        break;
      case SKBAG_ERR_INPUT:
      case SKBAG_ERR_KEY_RANGE:
        PyErr_SetString(PyExc_IndexError, "Address out of range");
        return -1;
      case SKBAG_ERR_MEMORY:
        PyErr_NoMemory();
        return -1;
      case SKBAG_ERR_OP_BOUNDS:
        PyErr_SetString(PyExc_ValueError, skBagStrerror(rv));
        return -1;
      case SKBAG_ERR_KEY_NOT_FOUND:
        /* Fall through */
      default:
        skAbortBadCase(rv);
    }

    return 0;
}

static PyObject *
silkPyBag_save(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds)
{
    skBagErr_t rv;
    skstream_t *stream;

    if ((stream = open_silkfile_write(args, kwds)) == NULL) {
        return NULL;
    }

    rv = skBagWrite(self->bag, stream);
    skStreamDestroy(&stream);
    if (rv != SKBAG_OK) {
        PyErr_SetString(PyExc_IOError, skBagStrerror(rv));
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
silkPyBag_set_info(
    silkPyBag          *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"key_type", "key_len",
                             "counter_type", "counter_len", NULL};
    size_t key_len = SKBAG_OCTETS_NO_CHANGE;
    size_t counter_len = SKBAG_OCTETS_NO_CHANGE;
    unsigned int key_len_tmp = UINT_MAX;
    unsigned int counter_len_tmp = UINT_MAX;
    char *key_name = NULL;
    char *counter_name = NULL;
    skBagFieldType_t key_type;
    skBagFieldType_t counter_type;
    skBagErr_t err;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sIsI", kwlist,
                                     &key_name, &key_len_tmp,
                                     &counter_name, &counter_len_tmp))
    {
        return NULL;
    }

    /* key_len_tmp and counter_len_tmp are unsigned ints, since there
     * were no conversion functions to size_t until Python 2.6 */
    if (key_len_tmp != UINT_MAX) {
        key_len = key_len_tmp;
    }
    if (counter_len_tmp != UINT_MAX) {
        counter_len = counter_len_tmp;
    }
    if (key_name) {
        err = skBagFieldTypeLookup(key_name, &key_type, NULL);
        if (err != SKBAG_OK) {
            assert(err == SKBAG_ERR_INPUT);
            return PyErr_Format(PyExc_ValueError,
                                "'%s' is not a valid key type", key_name);
        }
    } else {
        key_type = skBagKeyFieldType(self->bag);
    }

    if (counter_name) {
        err = skBagFieldTypeLookup(counter_name, &counter_type, NULL);
        if (err != SKBAG_OK) {
            assert(err == SKBAG_ERR_INPUT);
            return PyErr_Format(PyExc_ValueError,
                                "'%s' is not a valid counter type",
                                counter_name);
        }
    } else {
        counter_type = skBagCounterFieldType(self->bag);
    }

    err = skBagModify(self->bag, key_type, counter_type,
                      key_len, counter_len);
    if (err != SKBAG_OK) {
        PyErr_SetString(PyExc_ValueError,
                        "Illegal value was passed to Bag.set_info");
        return NULL;
    }

    self->is_ipaddr = (counter_len == 16 || IS_IP_KEY(key_type));

    return silkPyBag_get_info(self);
}

static int
silkPyBag_setup(
    PyObject           *mod)
{
    /* Setup number methods */
    memset(&silkPyBag_number_methods, 0, sizeof(silkPyBag_number_methods));
    silkPyBag_number_methods.nb_inplace_add = (binaryfunc)silkPyBag_iadd;

    /* Initialize type and add to module */
    silkPyBagType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyBagType) < 0) {
        return -1;
    }
    return PyModule_AddObject(mod, "BagBase", (PyObject*)&silkPyBagType);
}

static PyObject *
silkPyBag_sorted_iter(
    silkPyBag          *self)
{
    return silkPyBag_iter_helper(self, 1);
}

static PyObject *
silkPyBag_subscript(
    silkPyBag          *self,
    PyObject           *sub)
{
    skBagTypedKey_t     key;
    skBagTypedCounter_t value;
    skBagErr_t          rv;

    if (IS_INT(sub)) {
        if (self->is_ipaddr) {
            PyErr_SetString(PyExc_TypeError, "Expected an IPAddr index");
            return NULL;
        }
        /* long long is 64-bits on 32 and 64-bit arches, so use it for
         * consistency. */
        key.val.u64 = LONG_AS_UNSIGNED_LONGLONG(sub);
        if (PyErr_Occurred()) {
            if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
                PyErr_Clear();
                PyErr_SetString(PyExc_IndexError, "Index out of range");
            }
            return NULL;
        }
        if (key.val.u64 > 0xffffffff) {
            PyErr_SetString(PyExc_IndexError, "Index out of range");
            return NULL;
        }
        key.val.u32 = key.val.u64;
        key.type = SKBAG_KEY_U32;
    } else if (silkPyIPAddr_Check(sub)) {
        silkPyIPAddr *addr;
        if (!self->is_ipaddr) {
            PyErr_SetString(PyExc_TypeError, "Expected an integer index");
            return NULL;
        }
        addr = (silkPyIPAddr*)sub;
        skipaddrCopy(&key.val.addr, &addr->addr);
        key.type = SKBAG_KEY_IPADDR;
    } else {
        PyErr_SetString(PyExc_TypeError, "Expected an integer or IP address");
        return NULL;
    }

    value.type = SKBAG_COUNTER_U64;
    rv = skBagCounterGet(self->bag, &key, &value);

    assert(rv != SKBAG_ERR_KEY_NOT_FOUND);
    if (rv == SKBAG_ERR_KEY_RANGE) {
        PyErr_SetString(PyExc_IndexError, "Index out of range");
        return NULL;
    }
    if (rv != SKBAG_OK) {
        PyErr_SetString(PyExc_ValueError, skBagStrerror(rv));
        return NULL;
    }
    assert(value.type == SKBAG_COUNTER_U64);

    return PyLong_FromUnsignedLongLong(value.val.u64);
}

static PyObject *
silkPyBag_type_merge(
    PyObject    UNUSED(*self),
    PyObject           *args)
{
    char *a, *b;
    skBagFieldType_t a_type, b_type, c_type;
    skBagErr_t rv;
    char buf[SKBAG_MAX_FIELD_BUFLEN];

    if (!PyArg_ParseTuple(args, "ss", &a, &b)) {
        return NULL;
    }
    rv = skBagFieldTypeLookup(a, &a_type, NULL);
    if (rv != SKBAG_OK) {
        PyErr_Format(PyExc_ValueError, "'%s' is not a valid key type", a);
    }
    rv = skBagFieldTypeLookup(b, &b_type, NULL);
    if (rv != SKBAG_OK) {
        PyErr_Format(PyExc_ValueError, "'%s' is not a valid key type", b);
    }
    c_type = skBagFieldTypeMerge(a_type, b_type);
    skBagFieldTypeAsString(c_type, buf, sizeof(buf));
    return PyUnicode_FromString(buf);
}


/*
 *************************************************************************
 *   TCP Flags
 *************************************************************************
 */

typedef struct silkPyTCPFlags_st {
    PyObject_HEAD
    uint8_t val;
} silkPyTCPFlags;

/* function prototypes */
static PyObject *
silkPyTCPFlags_and(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b);
static PyObject *
silkPyTCPFlags_getflag(
    silkPyTCPFlags     *obj,
    void               *bit);
static PyObject *
silkPyTCPFlags_getflag_deprecated(
    silkPyTCPFlags     *obj,
    void               *bit);
static long
silkPyTCPFlags_hash(
    silkPyTCPFlags     *obj);
static int
silkPyTCPFlags_init(
    silkPyTCPFlags     *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyTCPFlags_int(
    silkPyTCPFlags     *obj);
static silkPyTCPFlags *
silkPyTCPFlags_invert(
    silkPyTCPFlags     *obj);
static PyObject *
silkPyTCPFlags_matches(
    silkPyTCPFlags     *self,
    PyObject           *arg);
static PyObject *
silkPyTCPFlags_new(
    PyTypeObject           *type,
    PyObject        UNUSED(*args),
    PyObject        UNUSED(*kwds));
static int
silkPyTCPFlags_nonzero(
    silkPyTCPFlags     *a);
static PyObject *
silkPyTCPFlags_or(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b);
static PyObject *
silkPyTCPFlags_padded(
    silkPyTCPFlags     *obj);
static PyObject *
silkPyTCPFlags_repr(
    silkPyTCPFlags     *obj);
static PyObject *
silkPyTCPFlags_richcompare(
    silkPyTCPFlags     *self,
    PyObject           *obj,
    int                 cmp);
static int
silkPyTCPFlags_setup(
    PyObject           *mod);
static PyObject *
silkPyTCPFlags_str(
    silkPyTCPFlags     *obj);
static PyObject *
silkPyTCPFlags_xor(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b);

/* define docs and methods */
#define silkPyTCPFlags_doc                                              \
    "TCPFlags(string)   -> TCPFlags based on flag string\n"             \
    "TCPFlags(int)      -> TCPFlags based on integer representation\n"  \
    "TCPFlags(TCPFlags) -> Copy of TCPFlags"

static PyNumberMethods silkPyTCPFlags_number_methods;

static PyMethodDef silkPyTCPFlags_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"matches", (PyCFunction)silkPyTCPFlags_matches, METH_O,
     "Return whether the flags match the high/mask flagstring"},
    {"padded", (PyCFunction)silkPyTCPFlags_padded, METH_NOARGS,
     "Returns the flags string padded with spaces, so flags line up"},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static uint8_t flags_array[] = {
    FIN_FLAG, SYN_FLAG, RST_FLAG, PSH_FLAG,
    ACK_FLAG, URG_FLAG, ECE_FLAG, CWR_FLAG};

static PyGetSetDef silkPyTCPFlags_getsetters[] = {
    {"fin", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the FIN flag is set; False otherwise", (void*)&flags_array[0]},
    {"syn", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the SYN flag is set; False otherwise", (void*)&flags_array[1]},
    {"rst", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the RST flag is set; False otherwise", (void*)&flags_array[2]},
    {"psh", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the PSH flag is set; False otherwise", (void*)&flags_array[3]},
    {"ack", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the ACK flag is set; False otherwise", (void*)&flags_array[4]},
    {"urg", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the URG flag is set; False otherwise", (void*)&flags_array[5]},
    {"ece", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the ECE flag is set; False otherwise", (void*)&flags_array[6]},
    {"cwr", (getter)silkPyTCPFlags_getflag, NULL,
     "True if the CWR flag is set; False otherwise", (void*)&flags_array[7]},

    {"FIN", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the FIN flag is set; False otherwise."
      " DEPRECATED Use flag.fin instead"), (void*)&flags_array[0]},
    {"SYN", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the SYN flag is set; False otherwise."
      " DEPRECATED Use flag.syn instead"), (void*)&flags_array[1]},
    {"RST", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the RST flag is set; False otherwise."
      " DEPRECATED Use flag.rst instead"), (void*)&flags_array[2]},
    {"PSH", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the PSH flag is set; False otherwise."
      " DEPRECATED Use flag.psh instead"), (void*)&flags_array[3]},
    {"ACK", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the ACK flag is set; False otherwise."
      " DEPRECATED Use flag.ack instead"), (void*)&flags_array[4]},
    {"URG", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the URG flag is set; False otherwise."
      " DEPRECATED Use flag.urg instead"), (void*)&flags_array[5]},
    {"ECE", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the ECE flag is set; False otherwise."
      " DEPRECATED Use flag.ece instead"), (void*)&flags_array[6]},
    {"CWR", (getter)silkPyTCPFlags_getflag_deprecated, NULL,
     ("True if the CWR flag is set; False otherwise."
      " DEPRECATED Use flag.cwr instead"), (void*)&flags_array[7]},
    {NULL, NULL, NULL, NULL, NULL}
};

/* define the object types */
static PyTypeObject silkPyTCPFlagsType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.TCPFlags",            /* tp_name */
    sizeof(silkPyTCPFlags),     /* tp_basicsize */
    0,                          /* tp_itemsize */
    obj_dealloc,                /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    (reprfunc)silkPyTCPFlags_repr, /* tp_repr */
    &silkPyTCPFlags_number_methods, /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    (hashfunc)silkPyTCPFlags_hash, /* tp_hash  */
    0,                          /* tp_call */
    (reprfunc)silkPyTCPFlags_str, /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
#if PY_MAJOR_VERSION < 3
    Py_TPFLAGS_CHECKTYPES | Py_TPFLAGS_HAVE_RICHCOMPARE |
#endif
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    silkPyTCPFlags_doc,         /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    (richcmpfunc)silkPyTCPFlags_richcompare, /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    silkPyTCPFlags_methods,     /* tp_methods */
    0,                          /* tp_members */
    silkPyTCPFlags_getsetters,  /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyTCPFlags_init, /* tp_init */
    0,                          /* tp_alloc */
    silkPyTCPFlags_new,         /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyTCPFlags_Check(op)                \
    PyObject_TypeCheck(op, &silkPyTCPFlagsType)

static PyObject *
silkPyTCPFlags_and(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b)
{
    PyObject *new_obj;

    if (!silkPyTCPFlags_Check(a) || !silkPyTCPFlags_Check(b)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    new_obj = silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType, 0);
    if (new_obj != NULL) {
        ((silkPyTCPFlags*)new_obj)->val = a->val & b->val;
    }
    return new_obj;
}

static PyObject *
silkPyTCPFlags_getflag(
    silkPyTCPFlags     *obj,
    void               *bit)
{
    return PyBool_FromLong(obj->val & *(uint8_t*)bit);
}

static PyObject *
silkPyTCPFlags_getflag_deprecated(
    silkPyTCPFlags     *obj,
    void               *bit)
{
    /* Deprecated as of SiLK 3.0.0. */
    PyErr_Warn(PyExc_DeprecationWarning,
               ("Use of upper-case flag check attributes for "
                "TCPFlags is deprecated"));
    return PyBool_FromLong(obj->val & *(uint8_t*)bit);
}

static long
silkPyTCPFlags_hash(
    silkPyTCPFlags     *obj)
{
    return obj->val;
}

static int
silkPyTCPFlags_init(
    silkPyTCPFlags     *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"value", NULL};
    PyObject *val;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &val)) {
        return -1;
    }

    if (silkPyTCPFlags_Check(val)) {
        silkPyTCPFlags *oflags = (silkPyTCPFlags*)val;
        self->val = oflags->val;
    } else if (IS_INT(val)) {
        long intval = PyLong_AsLong(val);
        if (intval < 0 || intval > (long)UINT8_MAX) {
            PyErr_Format(PyExc_ValueError,
                         "Illegal TCP flag value: %ld", intval);
            return -1;
        }
        self->val = intval;
    } else if (IS_STRING(val)) {
        PyObject *bytes = bytes_from_string(val);
        char *strval;

        if (bytes == NULL) {
            return -1;
        }
        strval = PyBytes_AS_STRING(bytes);
        if (skStringParseTCPFlags(&self->val, strval)) {
            PyErr_Format(PyExc_ValueError,
                         "Illegal TCP flag value: %s", strval);
            Py_DECREF(bytes);
            return -1;
        }
        Py_DECREF(bytes);
    } else {
        obj_error("Illegal value: %s", val);
        return -1;
    }

    return 0;
}

static PyObject *
silkPyTCPFlags_int(
    silkPyTCPFlags     *obj)
{
    return PyInt_FromLong(obj->val);
}

static silkPyTCPFlags *
silkPyTCPFlags_invert(
    silkPyTCPFlags     *obj)
{
    silkPyTCPFlags *new_obj =
        (silkPyTCPFlags*)silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType, 0);

    if (new_obj != NULL) {
        new_obj->val = ~obj->val;
    }
    return new_obj;
}

static PyObject *
silkPyTCPFlags_matches(
    silkPyTCPFlags     *self,
    PyObject           *arg)
{
    char *repr;
    PyObject *bytes;
    uint8_t high, mask;
    int rv;

    if (!IS_STRING(arg)) {
        PyErr_SetString(PyExc_TypeError, "Expected string");
        return NULL;
    }

    bytes = bytes_from_string(arg);
    repr = PyBytes_AS_STRING(bytes);
    rv = skStringParseTCPFlagsHighMask(&high, &mask, repr);
    Py_DECREF(bytes);
    if (rv == SKUTILS_ERR_SHORT) {
        mask = high;
    } else if (rv != 0) {
        PyErr_SetString(PyExc_ValueError, "Illegal flag/mask");
        return NULL;
    }

    return PyBool_FromLong((self->val & mask) == high);
}

static PyObject *
silkPyTCPFlags_new(
    PyTypeObject           *type,
    PyObject        UNUSED(*args),
    PyObject        UNUSED(*kwds))
{
    silkPyTCPFlags *self;

    self = (silkPyTCPFlags*)type->tp_alloc(type, 0);

    if (self != NULL) {
        self->val = 0;
    }

    return (PyObject*)self;
}

static int
silkPyTCPFlags_nonzero(
    silkPyTCPFlags     *a)
{
    return a->val ? 1 : 0;
}

static PyObject *
silkPyTCPFlags_or(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b)
{
    PyObject *new_obj;

    if (!silkPyTCPFlags_Check(a) || !silkPyTCPFlags_Check(b)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    new_obj = silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType, 0);
    if (new_obj != NULL) {
        ((silkPyTCPFlags*)new_obj)->val = a->val | b->val;
    }
    return new_obj;
}

static PyObject *
silkPyTCPFlags_padded(
    silkPyTCPFlags     *obj)
{
    char flags[SK_TCPFLAGS_STRLEN];

    skTCPFlagsString(obj->val, flags, SK_PADDED_FLAGS);

    return PyUnicode_FromString(flags);
}

static PyObject *
silkPyTCPFlags_repr(
    silkPyTCPFlags     *obj)
{
    char flags[SK_TCPFLAGS_STRLEN];

    skTCPFlagsString(obj->val, flags, SK_PADDED_FLAGS);

    return PyUnicode_FromFormat("silk.TCPFlags('%s')", flags);
}

static PyObject *
silkPyTCPFlags_richcompare(
    silkPyTCPFlags     *self,
    PyObject           *obj,
    int                 cmp)
{
    if (cmp != Py_EQ && cmp != Py_NE) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    if (!silkPyTCPFlags_Check(obj)) {
        PyErr_SetString(PyExc_TypeError, "Expected silk.TCPFlags");
        return NULL;
    }

    if (self->val == ((silkPyTCPFlags*)obj)->val) {
        if (cmp == Py_EQ) {
            Py_RETURN_TRUE;
        } else {
            Py_RETURN_FALSE;
        }
    }
    if (cmp == Py_NE) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static int
silkPyTCPFlags_setup(
    PyObject           *mod)
{
    /* Setup number methods */
    memset(&silkPyTCPFlags_number_methods, 0,
           sizeof(silkPyTCPFlags_number_methods));
#if PY_MAJOR_VERSION >= 3
    silkPyTCPFlags_number_methods.nb_bool =
        (inquiry)silkPyTCPFlags_nonzero;
#else
    silkPyTCPFlags_number_methods.nb_nonzero =
        (inquiry)silkPyTCPFlags_nonzero;
#endif
    silkPyTCPFlags_number_methods.nb_invert =
        (unaryfunc)silkPyTCPFlags_invert;
    silkPyTCPFlags_number_methods.nb_and = (binaryfunc)silkPyTCPFlags_and;
    silkPyTCPFlags_number_methods.nb_xor = (binaryfunc)silkPyTCPFlags_xor;
    silkPyTCPFlags_number_methods.nb_or = (binaryfunc)silkPyTCPFlags_or;
    silkPyTCPFlags_number_methods.nb_int = (unaryfunc)silkPyTCPFlags_int;

    /* Initialize type and add to module */
    if (PyType_Ready(&silkPyTCPFlagsType) < 0) {
        return -1;
    }
    return PyModule_AddObject(mod, "TCPFlags",
                              (PyObject*)&silkPyTCPFlagsType);
}

static PyObject *
silkPyTCPFlags_str(
    silkPyTCPFlags     *obj)
{
    char flags[SK_TCPFLAGS_STRLEN];

    skTCPFlagsString(obj->val, flags, 0);

    return PyUnicode_FromString(flags);
}

static PyObject *
silkPyTCPFlags_xor(
    silkPyTCPFlags     *a,
    silkPyTCPFlags     *b)
{
    PyObject *new_obj;

    if (!silkPyTCPFlags_Check(a) || !silkPyTCPFlags_Check(b)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    new_obj = silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType, 0);
    if (new_obj != NULL) {
        ((silkPyTCPFlags*)new_obj)->val = a->val ^ b->val;
    }
    return new_obj;
}


/*
 *************************************************************************
 *   RWRec
 *************************************************************************
 */

typedef struct silkPyRawRWRec_st {
    PyObject_HEAD
    rwRec rec;
} silkPyRawRWRec;

typedef struct silkPyRWRec_st {
    PyObject_HEAD
    silkPyRawRWRec *raw;
} silkPyRWRec;

/* function prototypes */
static PyObject *
silkPyRWRec_application_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_application_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_bytes_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_bytes_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_classname_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_classtype_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_classtype_id_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_classtype_id_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static int
silkPyRWRec_classtype_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static void
silkPyRWRec_dealloc(
    silkPyRWRec        *obj);
static PyObject *
silkPyRWRec_dip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_dip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_dport_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_dport_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_duration_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_duration_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_duration_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static int
silkPyRWRec_duration_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_etime_epoch_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_etime_epoch_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_etime_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_etime_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_finnoack_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_finnoack_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_icmpcode_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_icmpcode_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_icmptype_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_icmptype_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_new(
    PyTypeObject       *type,
    PyObject           *args,
    PyObject           *kwds);
static int
silkPyRWRec_init(
    silkPyRWRec        *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyRWRec_initial_tcpflags_get(
    silkPyRWRec        *obj,
    void               *deprecated);
static int
silkPyRWRec_initial_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void               *deprecated);
static PyObject *
silkPyRWRec_input_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_input_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_is_icmp(
    silkPyRWRec        *obj);
static PyObject *
silkPyRWRec_is_ipv6(
    silkPyRWRec         UNUSED_NOv6(*obj));
static PyObject *
silkPyRWRec_is_web(
    silkPyRWRec        *obj);
static PyObject *
silkPyRWRec_nhip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_nhip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_output_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_output_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_packets_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_packets_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_protocol_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_protocol_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_richcompare(
    silkPyRWRec        *self,
    PyObject           *obj,
    int                 cmp);
static PyObject *
silkPyRWRec_sensor_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_sensor_id_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_to_ipv4(
    silkPyRWRec        *obj);
#if SK_ENABLE_IPV6
static PyObject *
silkPyRWRec_to_ipv6(
    silkPyRWRec        *obj);
#endif
static int
silkPyRWRec_sensor_id_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static int
silkPyRWRec_sensor_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_session_tcpflags_get(
    silkPyRWRec        *obj,
    void               *deprecated);
static int
silkPyRWRec_session_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void               *deprecated);
static PyObject *
silkPyRWRec_sip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_sip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_sport_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_sport_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_stime_epoch_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_stime_epoch_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_stime_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_stime_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_tcpflags_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_timeout_killed_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_timeout_killed_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_timeout_started_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_timeout_started_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_typename_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static PyObject *
silkPyRWRec_uniform_packets_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure));
static int
silkPyRWRec_uniform_packets_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure));
static int
silkPyRawRWRec_init(
    silkPyRawRWRec     *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyRawRWRec_new(
    PyTypeObject           *type,
    PyObject        UNUSED(*args),
    PyObject        UNUSED(*kwds));

/* define docs and methods */
static PyMethodDef silkPyRWRec_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"is_icmp", (PyCFunction)silkPyRWRec_is_icmp, METH_NOARGS,
     "Returns whether the record is an ICMP record"},
    {"is_ipv6", (PyCFunction)silkPyRWRec_is_ipv6, METH_NOARGS,
     "Returns whether record uses IPv6 addresses"},
    {"is_web", (PyCFunction)silkPyRWRec_is_web, METH_NOARGS,
     "Returns whether record can be stored in a SiLK WWW file format"},
    {"to_ipv4", (PyCFunction)silkPyRWRec_to_ipv4, METH_NOARGS,
     "Returns a new raw copy of the record converted to IPv4"},
    {"to_ipv6", (PyCFunction)
#if SK_ENABLE_IPV6
     silkPyRWRec_to_ipv6, METH_NOARGS,
#else
     silkPyNotImplemented, METH_VARARGS | METH_KEYWORDS,
#endif
     "Returns a new raw copy of the record converted to IPv6"},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PyGetSetDef silkPyRWRec_getseters[] = {
    {"application",
     (getter)silkPyRWRec_application_get, (setter)silkPyRWRec_application_set,
     "\"service\" port set by the collector", NULL},
    {"bytes",
     (getter)silkPyRWRec_bytes_get,       (setter)silkPyRWRec_bytes_set,
     "Count of bytes", NULL},
    {"classname",
     (getter)silkPyRWRec_classname_get,   NULL,
     "class name (read-only)", NULL},
    {"classtype",
     (getter)silkPyRWRec_classtype_get,   (setter)silkPyRWRec_classtype_set,
     "class name, type name pair", NULL},
    {"classtype_id",
     (getter)silkPyRWRec_classtype_id_get,(setter)silkPyRWRec_classtype_id_set,
     "class, type pair ID", NULL},
    {"dip",
     (getter)silkPyRWRec_dip_get,         (setter)silkPyRWRec_dip_set,
     "destination IP", NULL},
    {"dport",
     (getter)silkPyRWRec_dport_get,       (setter)silkPyRWRec_dport_set,
     "Destination port", NULL},
    {"duration",
     (getter)silkPyRWRec_duration_get,    (setter)silkPyRWRec_duration_set,
     "duration of flow as datetime.timedelta", NULL},
    {"duration_secs",
     (getter)silkPyRWRec_duration_secs_get,
     (setter)silkPyRWRec_duration_secs_set,
     "duration of flow in seconds", NULL},
    {"etime",
     (getter)silkPyRWRec_etime_get,       (setter)silkPyRWRec_etime_set,
     "end time of flow as datetime.timedelta", NULL},
    {"etime_epoch_secs",
     (getter)silkPyRWRec_etime_epoch_secs_get,
     (setter)silkPyRWRec_etime_epoch_secs_set,
     "end time of flow as a number of seconds since the epoch time", NULL},
    {"finnoack",
     (getter)silkPyRWRec_finnoack_get,    (setter)silkPyRWRec_finnoack_set,
     "FIN followed by not ACK", NULL},
    {"icmpcode",
     (getter)silkPyRWRec_icmpcode_get,    (setter)silkPyRWRec_icmpcode_set,
     "ICMP code", NULL},
    {"icmptype",
     (getter)silkPyRWRec_icmptype_get,    (setter)silkPyRWRec_icmptype_set,
     "ICMP type", NULL},
    {"initflags", /* Deprecated in SiLK 3.0.0 */
     (getter)silkPyRWRec_initial_tcpflags_get,
     (setter)silkPyRWRec_initial_tcpflags_set,
     "TCP flags of first packet. DEPRECATED Use initial_tcpflags instead",
      deprecated_true},
    {"initial_tcpflags",
     (getter)silkPyRWRec_initial_tcpflags_get,
     (setter)silkPyRWRec_initial_tcpflags_set,
     "TCP flags of first packet", NULL},
    {"input",
     (getter)silkPyRWRec_input_get,       (setter)silkPyRWRec_input_set,
     "router incoming SNMP interface", NULL},
    {"nhip",
     (getter)silkPyRWRec_nhip_get,        (setter)silkPyRWRec_nhip_set,
     "router next hop IP", NULL},
    {"output",
     (getter)silkPyRWRec_output_get,      (setter)silkPyRWRec_output_set,
     "router outgoing SNMP interface", NULL},
    {"packets",
     (getter)silkPyRWRec_packets_get,     (setter)silkPyRWRec_packets_set,
     "count of packets", NULL},
    {"protocol",
     (getter)silkPyRWRec_protocol_get,    (setter)silkPyRWRec_protocol_set,
     "IP protocol", NULL},
    {"restflags", /* Deprecated,SiLK 3.0.0 */
     (getter)silkPyRWRec_session_tcpflags_get,
     (setter)silkPyRWRec_session_tcpflags_set,
     ("TCP flags on non-initial packets."
      " DEPRECATED Use session_tcpflags instead"), deprecated_true},
    {"sensor",
     (getter)silkPyRWRec_sensor_get,      (setter)silkPyRWRec_sensor_set,
     "sensor name", NULL},
    {"sensor_id",
     (getter)silkPyRWRec_sensor_id_get,   (setter)silkPyRWRec_sensor_id_set,
     "sensor ID", NULL},
    {"session_tcpflags",
     (getter)silkPyRWRec_session_tcpflags_get,
     (setter)silkPyRWRec_session_tcpflags_set,
     "TCP flags on non-initial packets", NULL},
    {"sip",
     (getter)silkPyRWRec_sip_get,         (setter)silkPyRWRec_sip_set,
     "source IP", NULL},
    {"sport",
     (getter)silkPyRWRec_sport_get,       (setter)silkPyRWRec_sport_set,
     "source port", NULL},
    {"stime",
     (getter)silkPyRWRec_stime_get,       (setter)silkPyRWRec_stime_set,
     "start time of flow as datetime.datetime", NULL},
    {"stime_epoch_secs",
     (getter)silkPyRWRec_stime_epoch_secs_get,
     (setter)silkPyRWRec_stime_epoch_secs_set,
     "start time of flow as a number of seconds since the epoch time", NULL},
    {"tcpflags",
     (getter)silkPyRWRec_tcpflags_get,    (setter)silkPyRWRec_tcpflags_set,
     "OR of all tcpflags", NULL},
    {"timeout_killed",
     (getter)silkPyRWRec_timeout_killed_get,
     (setter)silkPyRWRec_timeout_killed_set,
     "flow ended prematurely due to timeout by the collector", NULL},
    {"timeout_started",
     (getter)silkPyRWRec_timeout_started_get,
     (setter)silkPyRWRec_timeout_started_set,
     "flow is a continuation of a flow timed-out by the collector", NULL},
    {"typename",
     (getter)silkPyRWRec_typename_get,    NULL,
     "type name (read-only)", NULL},
    {"uniform_packets",
     (getter)silkPyRWRec_uniform_packets_get,
     (setter)silkPyRWRec_uniform_packets_set,
     "flow contained only packets of uniform size", NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

/* define the object types */
static PyTypeObject silkPyRawRWRecType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.RWRawRec",     /* tp_name */
    sizeof(silkPyRawRWRec),     /* tp_basicsize */
    0,                          /* tp_itemsize */
    obj_dealloc,                /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Raw RW Record",            /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyRawRWRec_init, /* tp_init */
    0,                          /* tp_alloc */
    silkPyRawRWRec_new,         /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

static PyTypeObject silkPyRWRecType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.RWRecBase",    /* tp_name */
    sizeof(silkPyRWRec),        /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyRWRec_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
#if PY_MAJOR_VERSION < 3
    Py_TPFLAGS_HAVE_RICHCOMPARE |
#endif
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Base RW Record",           /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    (richcmpfunc)silkPyRWRec_richcompare, /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    silkPyRWRec_methods,        /* tp_methods */
    0,                          /* tp_members */
    silkPyRWRec_getseters,      /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyRWRec_init, /* tp_init */
    0,                          /* tp_alloc */
    silkPyRWRec_new,            /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyRawRWRec_Check(op)                \
    PyObject_TypeCheck(op, &silkPyRawRWRecType)
#define silkPyRWRec_Check(op)                   \
    PyObject_TypeCheck(op, &silkPyRWRecType)

static PyObject *
silkPyRWRec_application_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetApplication(&obj->raw->rec));
}

static int
silkPyRWRec_application_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The application value must be a 16-bit integer");
        return -1;
    }

    rwRecSetApplication(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_to_ipv4(
    silkPyRWRec        *obj)
{
    silkPyRawRWRec *copy = (silkPyRawRWRec*)PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyRawRWRecType, obj->raw, NULL);
    if (copy == NULL) {
        return NULL;
    }
#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(&copy->rec) && rwRecConvertToIPv4(&copy->rec)) {
        Py_DECREF(copy);
        Py_RETURN_NONE;
    }
#endif  /* SK_ENABLE_IPV6 */
    return (PyObject *)copy;
}

#if SK_ENABLE_IPV6
static PyObject *
silkPyRWRec_to_ipv6(
    silkPyRWRec        *obj)
{
    silkPyRawRWRec *copy = (silkPyRawRWRec*)PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyRawRWRecType, obj->raw, NULL);
    if (copy == NULL) {
        return NULL;
    }
    rwRecConvertToIPv6(&copy->rec);
    return (PyObject *)copy;
}
#endif  /* SK_ENABLE_IPV6 */

static PyObject *
silkPyRWRec_bytes_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyLong_FromUnsignedLong(rwRecGetBytes(&obj->raw->rec));
}

static int
silkPyRWRec_bytes_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    unsigned long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred() || val > UINT32_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The bytes value must be a 32-bit integer");
        return -1;
    }

    rwRecSetBytes(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_classname_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    char              class_name[SK_MAX_STRLEN_FLOWTYPE+1];
    sk_flowtype_id_t  flowtype = rwRecGetFlowType(&obj->raw->rec);

    CHECK_SITE(NULL);

    sksiteFlowtypeGetClass(class_name, sizeof(class_name), flowtype);

    return PyUnicode_InternFromString(class_name);
}

static PyObject *
silkPyRWRec_classtype_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    char              class_name[SK_MAX_STRLEN_FLOWTYPE+1];
    char              type_name[SK_MAX_STRLEN_FLOWTYPE+1];
    sk_flowtype_id_t  flowtype = rwRecGetFlowType(&obj->raw->rec);
    PyObject         *pair     = PyTuple_New(2);

    if (pair == NULL) {
        return NULL;
    }

    CHECK_SITE(NULL);

    sksiteFlowtypeGetClass(class_name, sizeof(class_name), flowtype);
    sksiteFlowtypeGetType(type_name, sizeof(type_name), flowtype);

    PyTuple_SET_ITEM(pair, 0, PyUnicode_InternFromString(class_name));
    PyTuple_SET_ITEM(pair, 1, PyUnicode_InternFromString(type_name));

    return pair;
}

static PyObject *
silkPyRWRec_classtype_id_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetFlowType(&obj->raw->rec));
}

static int
silkPyRWRec_classtype_id_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT8_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The classtype_id value must be an 8-bit integer");
        return -1;
    }

    rwRecSetFlowType(&obj->raw->rec, val);
    return 0;
}

static int
silkPyRWRec_classtype_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    char *class_name, *type_name;
    sk_flowtype_id_t flowtype;


    if (!PyArg_ParseTuple(value, "ss", &class_name, &type_name)) {
        return -1;
    }

    CHECK_SITE(-1);

    flowtype = sksiteFlowtypeLookupByClassType(class_name, type_name);

    if (flowtype == SK_INVALID_FLOWTYPE) {
        PyErr_SetString(PyExc_ValueError, "Invalid (class_name, type) pair");
        return -1;
    }

    rwRecSetFlowType(&obj->raw->rec, flowtype);
    return 0;
}

static void
silkPyRWRec_dealloc(
    silkPyRWRec        *obj)
{
    Py_XDECREF((PyObject*)obj->raw);
    Py_TYPE(obj)->tp_free(obj);
}

static PyObject *
silkPyRWRec_dip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    silkPyIPAddr *addr;
    PyTypeObject *type;

#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(&obj->raw->rec)) {
        type = &silkPyIPv6AddrType;
    } else
#endif
    {
        type = &silkPyIPv4AddrType;
    }

    addr = PyObject_New(silkPyIPAddr, type);
    if (addr != NULL) {
        rwRecMemGetDIP(&obj->raw->rec, &addr->addr);
    }

    return (PyObject*)addr;
}

static int
silkPyRWRec_dip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    if (IS_STRING(value)) {
        skipaddr_t  addr;
        PyObject   *bytes;
        char       *repr;
        int         rv;

        bytes = bytes_from_string(value);
        if (bytes == NULL) {
            return -1;
        }
        repr = PyBytes_AS_STRING(bytes);
        rv = skStringParseIP(&addr, repr);
        if (rv != 0) {
            PyErr_Format(PyExc_ValueError, "Illegal IP address: %s", repr);
            Py_DECREF(bytes);
            return -1;
        }
        Py_DECREF(bytes);
        rwRecMemSetDIP(&obj->raw->rec, &addr);
        return 0;
    }

    if (silkPyIPAddr_Check(value)) {
        silkPyIPAddr *addr = (silkPyIPAddr*)value;
        rwRecMemSetDIP(&obj->raw->rec, &addr->addr);
        return 0;
    }

    PyErr_SetString(PyExc_TypeError, "The dip must be a valid IP address");
    return -1;
}

static PyObject *
silkPyRWRec_dport_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetDPort(&obj->raw->rec));
}

static int
silkPyRWRec_dport_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The dport value must be a 16-bit integer");
        return -1;
    }

    rwRecSetDPort(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_duration_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyObject_CallFunction(GLOBALS->timedelta, "IIII", 0, 0, 0,
                                 rwRecGetElapsed(&obj->raw->rec));
}

static PyObject *
silkPyRWRec_duration_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    double elapsed = ((double)rwRecGetElapsed(&obj->raw->rec)) / 1.0e3;

    return PyFloat_FromDouble(elapsed);
}

static int
silkPyRWRec_duration_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    const char *errstr = ("The duration_secs value must be a positive "
                          "number not greater than 4294967.295");
    PyObject *pyfloat_val;
    PyObject *pyint_val;
    int64_t long_val;

    if (!PyNumber_Check(value)) {
        PyErr_SetString(PyExc_TypeError, errstr);
        return -1;
    }

    pyfloat_val = PyNumber_Multiply(value, GLOBALS->thousand);
    if (pyfloat_val == NULL) {
        return -1;
    }

    pyint_val = PyNumber_Long(pyfloat_val);
    Py_DECREF(pyfloat_val);
    if (pyint_val == NULL) {
        return -1;
    }
    long_val = PyLong_AsLongLong(pyint_val);
    Py_DECREF(pyint_val);
    if (long_val < 0) {
        PyErr_SetString(PyExc_ValueError, errstr);
        return -1;
    }

    if (long_val > UINT32_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        ("The total duration must be not greater than "
                         "4294967.295 seconds"));
        return -1;
    }

    rwRecSetElapsed(&obj->raw->rec, long_val);
    return 0;
}

static int
silkPyRWRec_duration_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    PyObject *days;
    PyObject *secs;
    PyObject *usecs;
    uint32_t millisecs;

    if (!PyDelta_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                        "The duration value must be a datetime.timedelta");
        return -1;
    }
    if (PyObject_RichCompareBool(value, GLOBALS->minelapsed, Py_LT) ||
        PyObject_RichCompareBool(value, GLOBALS->maxelapsed, Py_GT))
    {
        PyErr_SetString(PyExc_ValueError,
                        ("The duration must be in the range [0,4294967295] "
                         "milliseconds"));
        return -1;
    }
    days = PyObject_GetAttrString(value, "days");
    secs = PyObject_GetAttrString(value, "seconds");
    usecs = PyObject_GetAttrString(value, "microseconds");
    millisecs = PyLong_AsLong(days) * 1000 * 3600 * 24 +
                PyLong_AsLong(secs) * 1000 +
                PyLong_AsLong(usecs) / 1000;
    Py_DECREF(secs);
    Py_DECREF(usecs);

    rwRecSetElapsed(&obj->raw->rec, millisecs);
    return 0;
}

static PyObject *
silkPyRWRec_etime_epoch_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    double duration = (double)(rwRecGetStartTime(&obj->raw->rec) +
                               rwRecGetElapsed(&obj->raw->rec)) / 1.0e3;

    return PyFloat_FromDouble(duration);
}

static int
silkPyRWRec_etime_epoch_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    PyObject *s_time, *dur;
    int       retval;

    s_time = silkPyRWRec_stime_epoch_secs_get(obj, NULL);
    if (s_time == NULL) {
        return -1;
    }

    if (PyObject_RichCompareBool(value, s_time, Py_LT)) {
        PyErr_SetString(PyExc_ValueError,
                        "etime may not be less than stime");
        Py_DECREF(s_time);
        return -1;
    }
    dur = PyNumber_Subtract(value, s_time);
    Py_DECREF(s_time);
    if (dur == NULL) {
        return -1;
    }

    retval = silkPyRWRec_duration_secs_set(obj, dur, NULL);
    Py_DECREF(dur);

    return retval;
}

static PyObject *
silkPyRWRec_etime_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    PyObject *s_time, *dur;
    PyObject *retval;

    s_time = silkPyRWRec_stime_get(obj, NULL);
    if (s_time == NULL) {
        return NULL;
    }
    dur = silkPyRWRec_duration_get(obj, NULL);
    if (dur == NULL) {
        Py_DECREF(s_time);
        return NULL;
    }

    retval = PyNumber_Add(s_time, dur);

    Py_DECREF(s_time);
    Py_DECREF(dur);

    return retval;
}

static int
silkPyRWRec_etime_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    PyObject *s_time, *dur;
    int       retval;

    s_time = silkPyRWRec_stime_get(obj, NULL);
    if (s_time == NULL) {
        return -1;
    }

    if (PyObject_RichCompareBool(value, s_time, Py_LT)) {
        PyErr_SetString(PyExc_ValueError,
                        "etime may not be less than stime");
        Py_DECREF(s_time);
        return -1;
    }
    dur = PyNumber_Subtract(value, s_time);
    Py_DECREF(s_time);
    if (dur == NULL) {
        return -1;
    }

    retval = silkPyRWRec_duration_set(obj, dur, NULL);
    Py_DECREF(dur);

    return retval;
}

static PyObject *
silkPyRWRec_finnoack_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    uint8_t state;

    state = rwRecGetTcpState(&obj->raw->rec);
    return PyBool_FromLong(state & SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK);
}

static int
silkPyRWRec_finnoack_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    int     rv;
    uint8_t state;

    rv = PyObject_IsTrue(value);
    if (rv == -1) {
        return -1;
    }
    state = rwRecGetTcpState(&obj->raw->rec);
    if (rv) {
        state |= SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK;
    } else {
        state &= ~SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK;
    }
    rwRecSetTcpState(&obj->raw->rec, state);

    return 0;
}

static PyObject *
silkPyRWRec_icmpcode_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetIcmpCode(&obj->raw->rec));
}

static int
silkPyRWRec_icmpcode_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT8_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The icmpcode value must be a 8-bit integer");
        return -1;
    }

    rwRecSetIcmpCode(&obj->raw->rec, (uint8_t)val);
    return 0;
}

static PyObject *
silkPyRWRec_icmptype_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetIcmpType(&obj->raw->rec));
}

static int
silkPyRWRec_icmptype_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT8_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The icmptype value must be a 8-bit integer");
        return -1;
    }

    rwRecSetIcmpType(&obj->raw->rec, (uint8_t)val);
    return 0;
}

static PyObject *
silkPyRWRec_new(
    PyTypeObject           *type,
    PyObject        UNUSED(*args),
    PyObject        UNUSED(*kwds))
{
    silkPyRWRec *self;
    PyObject *newrawrec = GLOBALS->newrawrec;

    self = (silkPyRWRec *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->raw = (silkPyRawRWRec *)newrawrec;
        Py_INCREF(newrawrec);
    }
    return (PyObject *)self;
}

static int
silkPyRWRec_init(
    silkPyRWRec        *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"clone", "copy", NULL};
    silkPyRawRWRec *clne = NULL;
    silkPyRWRec    *copy  = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!O!", kwlist,
                                     &silkPyRawRWRecType, (PyObject **)&clne,
                                     &silkPyRWRecType, (PyObject **)&copy))
    {
        return -1;
    }

    if (clne && copy) {
        PyErr_SetString(PyExc_RuntimeError, "Cannot clone and copy");
        return -1;
    }

    Py_XDECREF((PyObject*)self->raw);
    if (clne) {
        Py_INCREF(clne);
        self->raw = clne;
    } else if (copy) {
        self->raw = (silkPyRawRWRec*)PyObject_CallFunctionObjArgs(
            (PyObject*)&silkPyRawRWRecType, copy->raw, NULL);
    } else {
        self->raw = (silkPyRawRWRec*)PyObject_CallFunctionObjArgs(
            (PyObject*)&silkPyRawRWRecType, NULL);
    }

    if (self->raw == NULL) {
        return -1;
    }

    return 0;
}

static PyObject *
silkPyRWRec_initial_tcpflags_get(
    silkPyRWRec        *obj,
    void               *deprecated)
{
    silkPyTCPFlags *flags;

    if (deprecated == deprecated_true) {
        /* Deprecated in SiLK 3.0.0 */
        int rv = PyErr_Warn(PyExc_DeprecationWarning,
                            ("'initflags' is deprecated in favor of"
                             " 'initial_tcpflags'."));
        if (rv) {
            return NULL;
        }
    }

    if (!(rwRecGetTcpState(&obj->raw->rec) & SK_TCPSTATE_EXPANDED)) {
        Py_RETURN_NONE;
    }
    flags = (silkPyTCPFlags*)silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType,
                                                          0);
    if (flags != NULL) {
        flags->val = rwRecGetInitFlags(&obj->raw->rec);
    }

    return (PyObject*)flags;
}

static int
silkPyRWRec_initial_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void               *deprecated)
{
    uint8_t state;
    uint8_t flagval;
    silkPyTCPFlags *flags;

    if (deprecated == deprecated_true) {
        /* Deprecated in SiLK 3.0.0 */
        int rv = PyErr_Warn(PyExc_DeprecationWarning,
                            ("'initflags' is deprecated in favor of"
                             " 'initial_tcpflags'."));
        if (rv) {
            return -1;
        }
    }

    if (rwRecGetProto(&obj->raw->rec) != IPPROTO_TCP) {
        PyErr_SetString(
            PyExc_AttributeError,
            "Cannot set initial_tcpflags when protocol is not TCP");
        return -1;
    }

    flags = (silkPyTCPFlags *)PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyTCPFlagsType, value, NULL);
    if (flags == NULL) {
        return -1;
    }
    flagval = flags->val;
    Py_DECREF(flags);

    state = rwRecGetTcpState(&obj->raw->rec);
    rwRecSetInitFlags(&obj->raw->rec, flagval);
    if (! (state & SK_TCPSTATE_EXPANDED)) {
        rwRecSetTcpState(&obj->raw->rec, state | SK_TCPSTATE_EXPANDED);
        rwRecSetRestFlags(&obj->raw->rec, 0);
    }
    rwRecSetFlags(&obj->raw->rec, rwRecGetRestFlags(&obj->raw->rec) | flagval);
    return 0;
}

static PyObject *
silkPyRWRec_input_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return  PyInt_FromLong(rwRecGetInput(&obj->raw->rec));
}

static int
silkPyRWRec_input_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The input value must be a 16-bit integer");
        return -1;
    }

    rwRecSetInput(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_is_icmp(
    silkPyRWRec        *obj)
{
    return PyBool_FromLong(rwRecIsICMP(&obj->raw->rec));
}

static PyObject *
silkPyRWRec_is_ipv6(
    silkPyRWRec         UNUSED_NOv6(*obj))
{
    return PyBool_FromLong(rwRecIsIPv6(&obj->raw->rec));
}

static PyObject *
silkPyRWRec_is_web(
    silkPyRWRec        *obj)
{
    return PyBool_FromLong(rwRecIsWeb(&obj->raw->rec));
}

static PyObject *
silkPyRWRec_nhip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    silkPyIPAddr *addr;
    PyTypeObject *type;

#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(&obj->raw->rec)) {
        type = &silkPyIPv6AddrType;
    } else
#endif
    {
        type = &silkPyIPv4AddrType;
    }

    addr = PyObject_New(silkPyIPAddr, type);
    if (addr != NULL) {
        rwRecMemGetNhIP(&obj->raw->rec, &addr->addr);
    }
    return (PyObject*)addr;
}

static int
silkPyRWRec_nhip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    if (IS_STRING(value)) {
        skipaddr_t  addr;
        PyObject   *bytes;
        char       *repr;
        int         rv;

        bytes = bytes_from_string(value);
        if (bytes == NULL) {
            return -1;
        }
        repr = PyBytes_AS_STRING(bytes);
        rv   = skStringParseIP(&addr, repr);
        if (rv != 0) {
            PyErr_Format(PyExc_ValueError, "Illegal IP address: %s", repr);
            Py_DECREF(bytes);
            return -1;
        }
        Py_DECREF(bytes);
        rwRecMemSetNhIP(&obj->raw->rec, &addr);
        return 0;
    }

    if (silkPyIPAddr_Check(value)) {
        silkPyIPAddr *addr = (silkPyIPAddr*)value;
        rwRecMemSetNhIP(&obj->raw->rec, &addr->addr);
        return 0;
    }

    PyErr_SetString(PyExc_TypeError, "The nhip must be a valid IP address");
    return -1;
}

static PyObject *
silkPyRWRec_output_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetOutput(&obj->raw->rec));
}

static int
silkPyRWRec_output_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The output value must be a 16-bit integer");
        return -1;
    }

    rwRecSetOutput(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_packets_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyLong_FromUnsignedLong(rwRecGetPkts(&obj->raw->rec));
}

static int
silkPyRWRec_packets_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    unsigned long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred() || val > UINT32_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The packets value must be a 32-bit integer");
        return -1;
    }

    rwRecSetPkts(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_protocol_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetProto(&obj->raw->rec));
}

static int
silkPyRWRec_protocol_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT8_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The protocol value must be an 8-bit integer");
        return -1;
    }

    rwRecSetProto(&obj->raw->rec, val);
    if (val != IPPROTO_TCP) {
        /* Initial and session flags are not allowed for non-TCP. */
        uint8_t state = rwRecGetTcpState(&obj->raw->rec);
        rwRecSetTcpState(&obj->raw->rec, state & ~SK_TCPSTATE_EXPANDED);
        rwRecSetInitFlags(&obj->raw->rec, 0);
        rwRecSetRestFlags(&obj->raw->rec, 0);
    }
    return 0;
}

static PyObject *
silkPyRWRec_richcompare(
    silkPyRWRec        *self,
    PyObject           *obj,
    int                 cmp)
{
    int rv;

    if ((cmp != Py_EQ && cmp != Py_NE) ||
        !silkPyRWRec_Check(obj))
    {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }

    rv = memcmp(&self->raw->rec, &((silkPyRWRec*)obj)->raw->rec,
                sizeof(self->raw->rec));
    rv = (rv == 0) ? 1 : 0;
    if (cmp == Py_NE) {
        rv = !rv;
    }

    return PyBool_FromLong(rv);
}

static PyObject *
silkPyRWRec_sensor_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    char name[SK_MAX_STRLEN_SENSOR+1];

    CHECK_SITE(NULL);

    sksiteSensorGetName(name, sizeof(name), rwRecGetSensor(&obj->raw->rec));
    return PyUnicode_InternFromString(name);
}

static PyObject *
silkPyRWRec_sensor_id_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetSensor(&obj->raw->rec));
}

static int
silkPyRWRec_sensor_id_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The sensor_id value must be a 16-bit integer");
        return -1;
    }

    rwRecSetSensor(&obj->raw->rec, val);
    return 0;
}

static int
silkPyRWRec_sensor_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    char *repr;
    sk_sensor_id_t sensor;
    PyObject *bytes;

    bytes = bytes_from_string(value);
    if (bytes == NULL) {
        PyErr_SetString(PyExc_TypeError, "The sensor value must be a string");
        return -1;
    }
    repr = PyBytes_AS_STRING(bytes);

    if (init_site(NULL)) {
        Py_DECREF(bytes);
        return -1;
    }

    sensor = sksiteSensorLookup(repr);
    Py_DECREF(bytes);
    if (sensor == SK_INVALID_SENSOR) {
        PyErr_SetString(PyExc_ValueError, "Invalid sensor name");
        return -1;
    }

    rwRecSetSensor(&obj->raw->rec, sensor);
    return 0;
}

static PyObject *
silkPyRWRec_session_tcpflags_get(
    silkPyRWRec        *obj,
    void               *deprecated)
{
    silkPyTCPFlags *flags;

    if (deprecated == deprecated_true) {
        /* Deprecated in SiLK 3.0.0 */
        int rv = PyErr_Warn(PyExc_DeprecationWarning,
                            ("'restflags' is deprecated in favor of"
                             " 'session_tcpflags'."));
        if (rv) {
            return NULL;
        }
    }

    if (!(rwRecGetTcpState(&obj->raw->rec) & SK_TCPSTATE_EXPANDED)) {
        Py_RETURN_NONE;
    }
    flags = (silkPyTCPFlags*)silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType,
                                                          0);
    if (flags != NULL) {
        flags->val = rwRecGetRestFlags(&obj->raw->rec);
    }

    return (PyObject*)flags;
}

static int
silkPyRWRec_session_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void               *deprecated)
{
    uint8_t state;
    uint8_t flagval;
    silkPyTCPFlags *flags;

    if (deprecated == deprecated_true) {
        /* Deprecated in SiLK 3.0.0 */
        int rv = PyErr_Warn(PyExc_DeprecationWarning,
                            ("'restflags' is deprecated in favor of"
                             " 'session_tcpflags'."));
        if (rv) {
            return -1;
        }
    }

    if (rwRecGetProto(&obj->raw->rec) != IPPROTO_TCP) {
        PyErr_SetString(
            PyExc_AttributeError,
            "Cannot set session_tcpflags when protocol is not TCP");
        return -1;
    }

    flags = (silkPyTCPFlags *)PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyTCPFlagsType, value, NULL);
    if (flags == NULL) {
        return -1;
    }
    flagval = flags->val;
    Py_DECREF(flags);

    state = rwRecGetTcpState(&obj->raw->rec);
    rwRecSetRestFlags(&obj->raw->rec, flagval);
    if (! (state & SK_TCPSTATE_EXPANDED)) {
        rwRecSetTcpState(&obj->raw->rec, state | SK_TCPSTATE_EXPANDED);
        rwRecSetInitFlags(&obj->raw->rec, 0);
    }
    rwRecSetFlags(&obj->raw->rec, rwRecGetInitFlags(&obj->raw->rec) | flagval);
    return 0;
}

static PyObject *
silkPyRWRec_sip_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    silkPyIPAddr *addr;
    PyTypeObject *type;

#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(&obj->raw->rec)) {
        type = &silkPyIPv6AddrType;
    } else
#endif
    {
        type = &silkPyIPv4AddrType;
    }

    addr = PyObject_New(silkPyIPAddr, type);
    if (addr != NULL) {
        rwRecMemGetSIP(&obj->raw->rec, &addr->addr);
    }
    return (PyObject*)addr;
}

static int
silkPyRWRec_sip_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    if (IS_STRING(value)) {
        skipaddr_t  addr;
        PyObject   *bytes;
        char       *repr;
        int         rv;

        bytes = bytes_from_string(value);
        if (bytes == NULL) {
            return -1;
        }
        repr = PyBytes_AS_STRING(bytes);
        rv   = skStringParseIP(&addr, repr);
        if (rv != 0) {
            PyErr_Format(PyExc_ValueError, "Illegal IP address: %s", repr);
            Py_DECREF(bytes);
            return -1;
        }
        Py_DECREF(bytes);
        rwRecMemSetSIP(&obj->raw->rec, &addr);
        return 0;
    }

    if (silkPyIPAddr_Check(value)) {
        silkPyIPAddr *addr = (silkPyIPAddr*)value;
        rwRecMemSetSIP(&obj->raw->rec, &addr->addr);
        return 0;
    }

    PyErr_SetString(PyExc_TypeError, "The sip must be a valid IP address");
    return -1;
}

static PyObject *
silkPyRWRec_sport_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    return PyInt_FromLong(rwRecGetSPort(&obj->raw->rec));
}

static int
silkPyRWRec_sport_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    long val;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return -1;
    }

    val = PyLong_AsLong(value);
    if (PyErr_Occurred() || val < 0 || val > (long)UINT16_MAX) {
        PyErr_SetString(PyExc_ValueError,
                        "The sport value must be a 16-bit integer");
        return -1;
    }

    rwRecSetSPort(&obj->raw->rec, val);
    return 0;
}

static PyObject *
silkPyRWRec_stime_epoch_secs_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    double s_time = ((double)rwRecGetStartTime(&obj->raw->rec)) / 1.0e3;

    return PyFloat_FromDouble(s_time);
}

static int
silkPyRWRec_stime_epoch_secs_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    const char *errstr = ("The stime_epoch_secs value must be a "
                          "positive number");
    PyObject *pyfloat_val;
    PyObject *pyint_val;
    int64_t long_val;

    if (!PyNumber_Check(value)) {
        PyErr_SetString(PyExc_TypeError, errstr);
        return -1;
    }

    pyfloat_val = PyNumber_Multiply(value, GLOBALS->thousand);
    if (pyfloat_val == NULL) {
        return -1;
    }

    pyint_val = PyNumber_Long(pyfloat_val);
    Py_DECREF(pyfloat_val);
    if (pyint_val == NULL) {
        PyErr_SetString(PyExc_TypeError, errstr);
        return -1;
    }
    long_val = PyLong_AsLongLong(pyint_val);
    Py_DECREF(pyint_val);
    if (long_val < 0) {
        PyErr_SetString(PyExc_ValueError, errstr);
        return -1;
    }
    if (long_val > MAX_EPOCH) {
        PyErr_SetString(PyExc_ValueError,
                        "Maximum stime is 03:14:07, Jan 19, 2038");
        return -1;
    }

    rwRecSetStartTime(&obj->raw->rec, long_val);
    return 0;
}

static PyObject *
silkPyRWRec_stime_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    PyObject *delta;
    PyObject *final;
    imaxdiv_t d = imaxdiv(rwRecGetStartTime(&obj->raw->rec), 1000);

    delta = PyObject_CallFunction(GLOBALS->timedelta, "ILIL",
                                  0, d.quot, 0, d.rem);
    if (delta == NULL) {
        return NULL;
    }
    final = PyNumber_Add(GLOBALS->epochtime, delta);
    Py_DECREF(delta);
    return final;
}

static int
silkPyRWRec_stime_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    sktime_t t;
    int rv;

    rv = silkPyDatetimeToSktime(&t, value);

    if (rv == 0) {
        rwRecSetStartTime(&obj->raw->rec, t);
    }
    return rv;
}

static PyObject *
silkPyRWRec_tcpflags_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    silkPyTCPFlags *flags;

    flags = (silkPyTCPFlags*)silkPyTCPFlagsType.tp_alloc(&silkPyTCPFlagsType,
                                                          0);
    if (flags != NULL) {
        flags->val = rwRecGetFlags(&obj->raw->rec);
    }

    return (PyObject*)flags;
}

static int
silkPyRWRec_tcpflags_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    uint8_t flagval;
    uint8_t state;
    silkPyTCPFlags *flags;

    state = rwRecGetTcpState(&obj->raw->rec) & ~SK_TCPSTATE_EXPANDED;

    flags = (silkPyTCPFlags *)PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyTCPFlagsType, value, NULL);
    if (flags == NULL) {
        return -1;
    }
    flagval = flags->val;
    Py_DECREF(flags);

    rwRecSetFlags(&obj->raw->rec, flagval);
    rwRecSetInitFlags(&obj->raw->rec, 0);
    rwRecSetInitFlags(&obj->raw->rec, 0);
    rwRecSetTcpState(&obj->raw->rec, state);
    return 0;
}

static PyObject *
silkPyRWRec_timeout_killed_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    uint8_t state;

    state = rwRecGetTcpState(&obj->raw->rec);
    return PyBool_FromLong(state & SK_TCPSTATE_TIMEOUT_KILLED);
}

static int
silkPyRWRec_timeout_killed_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    int     rv;
    uint8_t state;

    rv = PyObject_IsTrue(value);
    if (rv == -1) {
        return -1;
    }
    state = rwRecGetTcpState(&obj->raw->rec);
    if (rv) {
        state |= SK_TCPSTATE_TIMEOUT_KILLED;
    } else {
        state &= ~SK_TCPSTATE_TIMEOUT_KILLED;
    }
    rwRecSetTcpState(&obj->raw->rec, state);

    return 0;
}

static PyObject *
silkPyRWRec_timeout_started_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    uint8_t state;

    state = rwRecGetTcpState(&obj->raw->rec);
    return PyBool_FromLong(state & SK_TCPSTATE_TIMEOUT_STARTED);
}

static int
silkPyRWRec_timeout_started_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    int     rv;
    uint8_t state;

    rv = PyObject_IsTrue(value);
    if (rv == -1) {
        return -1;
    }
    state = rwRecGetTcpState(&obj->raw->rec);
    if (rv) {
        state |= SK_TCPSTATE_TIMEOUT_STARTED;
    } else {
        state &= ~SK_TCPSTATE_TIMEOUT_STARTED;
    }
    rwRecSetTcpState(&obj->raw->rec, state);

    return 0;
}

static PyObject *
silkPyRWRec_typename_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    char              type_name[SK_MAX_STRLEN_FLOWTYPE+1];
    sk_flowtype_id_t  flowtype = rwRecGetFlowType(&obj->raw->rec);

    CHECK_SITE(NULL);

    sksiteFlowtypeGetType(type_name, sizeof(type_name), flowtype);
    return PyUnicode_InternFromString(type_name);
}

static PyObject *
silkPyRWRec_uniform_packets_get(
    silkPyRWRec        *obj,
    void        UNUSED(*closure))
{
    uint8_t state;

    state = rwRecGetTcpState(&obj->raw->rec);
    return PyBool_FromLong(state & SK_TCPSTATE_UNIFORM_PACKET_SIZE);
}

static int
silkPyRWRec_uniform_packets_set(
    silkPyRWRec        *obj,
    PyObject           *value,
    void        UNUSED(*closure))
{
    int     rv;
    uint8_t state;

    rv = PyObject_IsTrue(value);
    if (rv == -1) {
        return -1;
    }
    state = rwRecGetTcpState(&obj->raw->rec);
    if (rv) {
        state |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
    } else {
        state &= ~SK_TCPSTATE_UNIFORM_PACKET_SIZE;
    }
    rwRecSetTcpState(&obj->raw->rec, state);

    return 0;
}

static int
silkPyRawRWRec_init(
    silkPyRawRWRec     *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"rec", NULL};
    PyObject *copy = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!", kwlist,
                                     &silkPyRawRWRecType, &copy))
    {
        return -1;
    }

    if (copy) {
        RWREC_COPY(&self->rec, &((silkPyRawRWRec*)copy)->rec);
    }
    return 0;
}

static PyObject *
silkPyRawRWRec_new(
    PyTypeObject           *type,
    PyObject        UNUSED(*args),
    PyObject        UNUSED(*kwds))
{
    silkPyRawRWRec *self;

    self = (silkPyRawRWRec*)type->tp_alloc(type, 0);

    if (self != NULL) {
        RWREC_CLEAR(&self->rec);
    }

    return (PyObject*)self;
}


/*
 *************************************************************************
 *   SiLK File
 *************************************************************************
 */

typedef struct silkPySilkFile_st {
    PyObject_HEAD
    skstream_t *io;
} silkPySilkFile;

/* function prototypes */
static PyObject *
silkPySilkFile_close(
    silkPySilkFile     *obj);
static void
silkPySilkFile_dealloc(
    silkPySilkFile     *obj);
static PyObject *
silkPySilkFile_get_mode(
    silkPySilkFile         *obj,
    void            UNUSED(*closure));
static PyObject *
silkPySilkFile_get_name(
    silkPySilkFile         *obj,
    void            UNUSED(*closure));
static int
silkPySilkFile_init(
    silkPySilkFile     *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPySilkFile_invocations(
    silkPySilkFile     *obj);
static PyObject *
silkPySilkFile_notes(
    silkPySilkFile     *obj);
static PyObject *
silkPySilkFile_read(
    silkPySilkFile     *obj);
static PyObject *
silkPySilkFile_write(
    silkPySilkFile     *obj,
    PyObject           *rec);
static PyObject *
silkPySilkFile_skip(
    silkPySilkFile     *obj,
    PyObject           *value);

/* define docs and methods */
static PyMethodDef silkPySilkFile_methods[] = {
    {"__reduce__", (PyCFunction)reduce_error, METH_NOARGS, ""},
    {"read", (PyCFunction)silkPySilkFile_read, METH_NOARGS,
     "Read a RWRec from a RW File"},
    {"write", (PyCFunction)silkPySilkFile_write, METH_O,
     "Write a RWRec to a RW File"},
    {"skip", (PyCFunction)silkPySilkFile_skip, METH_O,
     "Skip some number of RWRecs in a RW File;"
     " return number of records skipped"},
    {"close", (PyCFunction)silkPySilkFile_close, METH_NOARGS,
     "Close an RW File"},
    {"notes", (PyCFunction)silkPySilkFile_notes, METH_NOARGS,
     "Get the file's annotations"},
    {"invocations", (PyCFunction)silkPySilkFile_invocations, METH_NOARGS,
     "Get the file's invocations"},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PyGetSetDef silkPySilkFile_getseters[] = {
    {"name", (getter)silkPySilkFile_get_name, NULL,
     "name of file associated with SilkFile", NULL},
    {"mode", (getter)silkPySilkFile_get_mode, NULL,
     "mode associated with SilkFile", NULL},
    {NULL, NULL, NULL, NULL, NULL}    /* Sentinel */
};

/* define the object types */
static PyTypeObject silkPySilkFileType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.SilkFileBase", /* tp_name */
    sizeof(silkPySilkFile),         /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPySilkFile_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Base Silk File",           /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    silkPySilkFile_methods,     /* tp_methods */
    0,                          /* tp_members */
    silkPySilkFile_getseters,   /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPySilkFile_init, /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPySilkFile_Check(op) \
    PyObject_TypeCheck(op, &silkPySilkFileType)

static PyObject *
throw_ioerror(
    silkPySilkFile     *obj,
    int                 errcode)
{
    skStreamPrintLastErr(obj->io, errcode, error_printf);
    PyErr_SetString(PyExc_IOError, error_buffer);
    return NULL;
}

static PyObject *
silkPySilkFile_close(
    silkPySilkFile     *obj)
{
    int rv;

    rv = skStreamClose(obj->io);
    if (rv == 0) {
        Py_RETURN_NONE;
    }

    return throw_ioerror(obj, rv);
}

static void
silkPySilkFile_dealloc(
    silkPySilkFile     *obj)
{
    if (obj->io) {
        skStreamDestroy(&obj->io);
    }
    Py_TYPE(obj)->tp_free(obj);
}

static PyObject *
silkPySilkFile_get_mode(
    silkPySilkFile         *obj,
    void            UNUSED(*closure))
{
    return PyInt_FromLong(skStreamGetMode(obj->io));
}

static PyObject *
silkPySilkFile_get_name(
    silkPySilkFile         *obj,
    void            UNUSED(*closure))
{
    const char *name = skStreamGetPathname(obj->io);
    if (name) {
        return PyUnicode_FromString(name);
    }
    Py_RETURN_NONE;
}

static int
silkPySilkFile_init(
    silkPySilkFile     *self,
    PyObject           *args,
    PyObject           *kwds)
{
    char             *filename;
    int               mode;
    int               format      = NOT_SET;
    int               policy      = NOT_SET;
    int               compr       = NOT_SET;
    int               file_des    = NOT_SET;
    PyObject         *annotations = NULL;
    PyObject         *invocations = NULL;
    sk_file_header_t *hdr;
    int               rv;

    static char *kwlist[] = {"filename", "mode", "compression",
                             "format", "policy", "invocations",
                             "notes", "_fileno", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "si|iiiO!O!i", kwlist,
                                     &filename, &mode, &compr,
                                     &format, &policy,
                                     &PyList_Type, &invocations,
                                     &PyList_Type, &annotations,
                                     &file_des))
    {
        return -1;
    }

    if (mode != SK_IO_READ && mode != SK_IO_WRITE && mode != SK_IO_APPEND) {
        PyErr_SetString(PyExc_ValueError, "Illegal mode");
        Py_DECREF(self);
        return -1;
    }
    if (self->io) {
        skStreamDestroy(&self->io);
    }
    rv = skStreamCreate(&self->io, (skstream_mode_t)mode,SK_CONTENT_SILK_FLOW);
    if (rv != 0) {
        throw_ioerror(self, rv);
        return -1;
    }

    rv = skStreamBind(self->io, filename);
    if (rv != 0) {
        throw_ioerror(self, rv);
        return -1;
    }

    hdr = skStreamGetSilkHeader(self->io);

    if (policy != NOT_SET) {
        rv = skStreamSetIPv6Policy(self->io, (sk_ipv6policy_t)policy);
        if (rv != 0) {
            throw_ioerror(self, rv);
            return -1;
        }
    }

    if (compr != NOT_SET) {
        if (mode != SK_IO_WRITE) {
            PyErr_SetString(PyExc_ValueError,
                            "Cannot set compression unless in WRITE mode");
            return -1;
        }
        rv = skHeaderSetCompressionMethod(hdr, compr);
        if (rv != 0) {
            throw_ioerror(self, rv);
            return -1;
        }
    }

    if (format != NOT_SET) {
        if (mode != SK_IO_WRITE) {
            PyErr_SetString(PyExc_ValueError,
                            "Cannot set file format unless in WRITE mode");
            return -1;
        }
        rv = skHeaderSetFileFormat(hdr, format);
        if (rv != 0) {
            throw_ioerror(self, rv);
            return -1;
        }
    }

    if (annotations != NULL) {
        if (mode != SK_IO_WRITE) {
            PyErr_SetString(PyExc_ValueError,
                            "Cannot set annotations unless in WRITE mode");
            return -1;
        }
        if (hdr != NULL) {
            ssize_t len = PyList_GET_SIZE(annotations);
            ssize_t i;

            for (i = 0; i < len; i++) {
                PyObject *bytes;
                PyObject *item = PyList_GET_ITEM(annotations, i);

                if (!IS_STRING(item)) {
                    PyErr_SetString(PyExc_TypeError,
                                    "Annotation was not a string");
                    return -1;
                }
                bytes = bytes_from_string(item);
                if (bytes == NULL) {
                    return -1;
                }

                rv = skHeaderAddAnnotation(hdr, PyBytes_AS_STRING(bytes));
                Py_DECREF(bytes);
                if (rv != 0) {
                    throw_ioerror(self, rv);
                }
            }
        }
    }

    if (invocations != NULL) {
        if (mode != SK_IO_WRITE) {
            PyErr_SetString(PyExc_ValueError,
                            "Cannot set invocations unless in WRITE mode");
            return -1;
        }
        if (hdr != NULL) {
            ssize_t len = PyList_GET_SIZE(invocations);
            ssize_t i;

            for (i = 0; i < len; i++) {
                PyObject *item = PyList_GET_ITEM(invocations, i);
                char     *value;
                PyObject *bytes;

                if (!IS_STRING(item)) {
                    PyErr_SetString(PyExc_TypeError,
                                    "Invocation was not a string");
                    return -1;
                }

                bytes = bytes_from_string(item);
                if (bytes == NULL) {
                    return -1;
                }
                value = PyBytes_AS_STRING(bytes);
                rv = skHeaderAddInvocation(hdr, 0, 1, &value);
                Py_DECREF(bytes);
                if (rv != 0) {
                    throw_ioerror(self, rv);
                }
            }
        }
    }

    if (file_des == NOT_SET) {
        rv = skStreamOpen(self->io);
    } else {
        rv = skStreamFDOpen(self->io, file_des);
    }
    if (rv != 0) {
        throw_ioerror(self, rv);
        return -1;
    }

    if (mode == SK_IO_WRITE) {
        rv = skStreamWriteSilkHeader(self->io);
        if (rv != 0) {
            throw_ioerror(self, rv);
            return -1;
        }
    } else {
        rv = skStreamReadSilkHeader(self->io, NULL);
        if (rv != 0) {
            throw_ioerror(self, rv);
            return -1;
        }
    }

    return 0;
}

static PyObject *
silkPySilkFile_invocations(
    silkPySilkFile     *obj)
{
    sk_file_header_t     *hdr;
    sk_header_entry_t    *entry;
    sk_hentry_iterator_t  iter;
    PyObject             *list;
    PyObject             *invoc;
    int                   rv;

    list = PyList_New(0);
    if (list == NULL) {
        return NULL;
    }
    hdr = skStreamGetSilkHeader(obj->io);
    if (hdr != NULL) {
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_INVOCATION_ID);
        while ((entry = skHeaderIteratorNext(&iter)) != NULL) {
            invoc = PyUnicode_FromString(
                skHentryInvocationGetInvocation(entry));
            if (invoc == NULL) {
                Py_DECREF(list);
                return NULL;
            }
            rv = PyList_Append(list, invoc);
            Py_DECREF(invoc);
            if (rv != 0) {
                Py_DECREF(list);
                return NULL;
            }
        }
    }

    return list;
}

static PyObject *
silkPySilkFile_notes(
    silkPySilkFile     *obj)
{
    sk_file_header_t     *hdr;
    sk_header_entry_t    *entry;
    sk_hentry_iterator_t  iter;
    PyObject             *list;
    PyObject             *annot;
    int                   rv;

    list = PyList_New(0);
    if (list == NULL) {
        return NULL;
    }
    hdr = skStreamGetSilkHeader(obj->io);
    if (hdr != NULL) {
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_ANNOTATION_ID);
        while ((entry = skHeaderIteratorNext(&iter)) != NULL) {
            annot = PyUnicode_FromString(
                skHentryAnnotationGetNote(entry));
            if (annot == NULL) {
                Py_DECREF(list);
                return NULL;
            }
            rv = PyList_Append(list, annot);
            Py_DECREF(annot);
            if (rv != 0) {
                Py_DECREF(list);
                return NULL;
            }
        }
    }

    return list;
}

static PyObject *
silkPySilkFile_read(
    silkPySilkFile     *obj)
{
    PyObject *pyrec;
    int rv;

    pyrec = silkPyRawRWRecType.tp_alloc(&silkPyRawRWRecType, 0);
    if (pyrec == NULL) {
        return NULL;
    }

    rv = skStreamReadRecord(obj->io, &((silkPyRawRWRec*)pyrec)->rec);
    if (rv != 0) {
        Py_DECREF(pyrec);
        if (rv == SKSTREAM_ERR_EOF) {
            Py_RETURN_NONE;
        }
        return throw_ioerror(obj, rv);
    }

    return pyrec;
}

static PyObject *
silkPySilkFile_write(
    silkPySilkFile     *obj,
    PyObject           *rec)
{
    int rv;

    if (!silkPyRWRec_Check(rec)) {
        PyErr_SetString(PyExc_TypeError, "Argument not a RWRec");
        return NULL;
    }

    rv = skStreamWriteRecord(obj->io, &((silkPyRWRec*)rec)->raw->rec);
    if (rv == 0) {
        Py_RETURN_NONE;
    }

    return throw_ioerror(obj, rv);
}

static PyObject *
silkPySilkFile_skip(
    silkPySilkFile     *obj,
    PyObject           *value)
{
    size_t skipped = 0;
    uint64_t val;
    int rv;

    if (!IS_INT(value)) {
        PyErr_SetString(PyExc_TypeError, "Expected an integer");
        return NULL;
    }

    val = LONG_AS_UNSIGNED_LONGLONG(value);
    if (PyErr_Occurred()) {
        return NULL;
    }

    rv = skStreamSkipRecords(obj->io, val, &skipped);
    if (rv == 0 || rv == SKSTREAM_ERR_EOF) {
        return PyLong_FromUnsignedLongLong(skipped);
    }

    return throw_ioerror(obj, rv);
}


/*
 *************************************************************************
 *   RepoIter
 *************************************************************************
 */

typedef struct silkPyRepoIter_st {
    PyObject_HEAD
    sksite_repo_iter_t *iter;
} silkPyRepoIter;

/* function prototypes */
static void
silkPyRepoIter_dealloc(
    silkPyRepoIter     *self);
static int
silkPyRepoIter_init(
    silkPyRepoIter     *self,
    PyObject           *args,
    PyObject           *kwds);
static PyObject *
silkPyRepoIter_iternext(
    silkPyRepoIter     *self);

/* define the object types */
static PyTypeObject silkPyRepoIterType ={
    PyVarObject_HEAD_INIT(NULL, 0)
    "silk.pysilk.RepoIter",    /* tp_name */
    sizeof(silkPyRepoIterType), /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor)silkPyRepoIter_dealloc, /* tp_dealloc */
    0,                          /* tp_vectorcall_offset (Py 3.8) */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_as_async (tp_compare in Py2.x) */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash  */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "SiLK repo file iterator object", /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    iter_iter,                  /* tp_iter */
    (iternextfunc)silkPyRepoIter_iternext, /* tp_iternext */
    0,                          /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc)silkPyRepoIter_init, /* tp_init */
    0,                          /* tp_alloc */
    0,                          /* tp_new */
    0,                          /* tp_free */
    0,                          /* tp_is_gc */
    0,                          /* tp_bases */
    0,                          /* tp_mro */
    0,                          /* tp_cache */
    0,                          /* tp_subclasses */
    0,                          /* tp_weaklist */
    0                           /* tp_del */
#if PY_VERSION_HEX >= 0x02060000
    ,0                          /* tp_version_tag */
#endif
#if PY_VERSION_HEX >= 0x03040000
    ,0                          /* tp_finalize */
#endif
#if PY_VERSION_HEX >= 0x03080000
    ,0                          /* tp_vectorcall */
#endif
};

/* macro and function defintions */
#define silkPyRepoIter_Check(op)                \
    PyObject_TypeCheck(op, &silkPyRepoIterType)

static void
silkPyRepoIter_dealloc(
    silkPyRepoIter     *self)
{
    sksiteRepoIteratorDestroy(&self->iter);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
silkPyRepoIter_init(
    silkPyRepoIter     *self,
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"start", "end", "flowtypes",
                             "sensors", "missing", NULL};
    PyObject *start     = NULL;
    PyObject *end       = NULL;
    PyObject *flowtypes = NULL;
    PyObject *sensors   = NULL;
    PyObject *missing   = NULL;
    PyObject *fast      = NULL;
    sk_vector_t *ft_vec     = NULL;
    sk_vector_t *sensor_vec = NULL;
    sktime_t starttime, endtime;
    sk_flowtype_iter_t ft_iter;
    sk_flowtype_id_t ft;
    uint32_t flags;
    unsigned int start_precision;
    unsigned int end_precision;
    int rv;

    CHECK_SITE(-1);

    ft_vec = skVectorNew(sizeof(sk_flowtype_id_t));
    if (ft_vec == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO|OOO", kwlist,
                                     &start, &end, &flowtypes,
                                     &sensors, &missing))
    {
        goto error;
    }

    /* Calculate starttime */
    if (PyDate_Check(start)) {
        rv = silkPyDatetimeToSktime(&starttime, start);
        if (rv != 0) {
            goto error;
        }
        start_precision = (PyDateTime_Check(start)
                           ? SK_PARSED_DATETIME_HOUR
                           : SK_PARSED_DATETIME_DAY);
    } else if (IS_STRING(start)) {
        PyObject *bytes = bytes_from_string(start);
        if (bytes == NULL) {
            goto error;
        }
        rv = skStringParseDatetime(&starttime, PyBytes_AS_STRING(bytes),
                                   &start_precision);
        Py_DECREF(bytes);
        if (rv != 0) {
            PyErr_SetString(PyExc_ValueError, skStringParseStrerror(rv));
            goto error;
        }
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "start must be a string or a "
                        "datetime.date[time] object");
        goto error;
    }
    starttime -= starttime % 3600000;

    /* Calculate endtime */
    if (end == NULL || end == Py_None) {
        end = NULL;
    } else if (PyDate_Check(end)) {
        rv = silkPyDatetimeToSktime(&endtime, end);
        if (rv != 0) {
            goto error;
        }
        end_precision = (PyDateTime_Check(end)
                         ? SK_PARSED_DATETIME_HOUR
                         : SK_PARSED_DATETIME_DAY);
    } else if (IS_STRING(end)) {
        PyObject *bytes = bytes_from_string(end);
        if (bytes == NULL) {
            goto error;
        }
        rv = skStringParseDatetime(&endtime, PyBytes_AS_STRING(bytes),
                                   &end_precision);
        Py_DECREF(bytes);
        if (rv != 0) {
            PyErr_SetString(PyExc_ValueError, skStringParseStrerror(rv));
            goto error;
        }
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "end must be a string or a "
                        "datetime.date[time] object");
        goto error;
    }

    /* End-time mashup */
    if (end) {
        if (end_precision & SK_PARSED_DATETIME_EPOCH) {
            /* when end-time is specified as an epoch, use it as-is */

        } else if (SK_PARSED_DATETIME_GET_PRECISION(start_precision)
                   == SK_PARSED_DATETIME_DAY)
        {
            /* when no starting hour given, we look at the full days,
             * regardless of the precision of the ending time; go to
             * the last hour of the ending day. */
            if (skDatetimeCeiling(&endtime, &endtime, start_precision)) {
                PyErr_SetString(PyExc_ValueError,
                                "Could not determine end time");
                goto error;
            }
            endtime -= endtime % 3600000;
        } else if (SK_PARSED_DATETIME_GET_PRECISION(end_precision)
                   < SK_PARSED_DATETIME_HOUR)
        {
            /* starting time has an hour but ending time does not; use
             * same hour for ending time */
#if  SK_ENABLE_LOCALTIME
            time_t t;
            struct tm work_tm;
            int work_hour;

            /* get starting hour */
            t = starttime / 1000;
            localtime_r(&t, &work_tm);
            work_hour = work_tm.tm_hour;
            /* break apart end time */
            t = endtime / 1000;
            localtime_r(&t, &work_tm);
            /* set end hour to start hour and re-combine */
            work_tm.tm_hour = work_hour;
            t = mktime(&work_tm);
            endtime = sktimeCreate((t - (t % 3600)), 0);
#else
            endtime = endtime - (endtime % 86400000) + (starttime % 86400000);
#endif
        } else {
            endtime -= endtime % 3600000;
        }

    } else if ((SK_PARSED_DATETIME_GET_PRECISION(start_precision)
                   >= SK_PARSED_DATETIME_HOUR)
               || (start_precision & SK_PARSED_DATETIME_EPOCH))
    {
        /* no ending time was given and the starting time contains an
         * hour or the starting time was expressed as epoch seconds;
         * we only look at that single hour */
        endtime = starttime;

    } else {
        /* no ending time was given and the starting time was to the
         * day; look at that entire day */
        if (skDatetimeCeiling(&endtime, &starttime, start_precision)) {
            PyErr_SetString(PyExc_ValueError,
                            "Could not determine end time");
            goto error;
        }
        endtime -= endtime % 3600000;
    }

    if (starttime > endtime) {
        PyErr_SetString(PyExc_ValueError,
                        "start must be less or equal to end");
        goto error;
    }

    /* Calculate flowtypes */
    if (flowtypes == NULL || flowtypes == Py_None) {
        sksiteFlowtypeIterator(&ft_iter);
        while (sksiteFlowtypeIteratorNext(&ft_iter, &ft)) {
            rv = skVectorAppendValue(ft_vec, &ft);
            if (rv != 0) {
                PyErr_NoMemory();
                goto error;
            }
        }
    } else if (PySequence_Check(flowtypes)) {
        Py_ssize_t len;
        PyObject **items;
        fast = PySequence_Fast(flowtypes, "flowtypes must be a sequence");
        if (fast == NULL) {
            goto error;
        }
        len = PySequence_Fast_GET_SIZE(fast);
        items = PySequence_Fast_ITEMS(fast);
        for (/*empty*/; len; len--, items++) {
            const char *class_name, *type_name;
            if (!PyArg_ParseTuple(*items, "ss", &class_name, &type_name)) {
                goto error;
            }
            ft = sksiteFlowtypeLookupByClassType(class_name, type_name);
            if (ft == SK_INVALID_FLOWTYPE) {
                PyErr_Format(PyExc_ValueError,
                             "Invalid (class, type) pair ('%s', '%s')",
                             class_name, type_name);
                return -1;
            }
            rv = skVectorAppendValue(ft_vec, &ft);
            if (rv != 0) {
                PyErr_NoMemory();
                goto error;
            }
        }
        Py_CLEAR(fast);
    } else {
        PyErr_SetString(
            PyExc_TypeError,
            "flowtypes should be a sequence of (class, type) pairs");
        goto error;
    }

    /* Calculate sensors */
    if (sensors && PySequence_Check(sensors)) {
        Py_ssize_t len;
        PyObject **items;
        sk_sensor_id_t sensor;

        sensor_vec = skVectorNew(sizeof(sk_sensor_id_t));
        if (sensor_vec == NULL) {
            PyErr_NoMemory();
            goto error;
        }

        fast = PySequence_Fast(sensors, "sensors must be a sequence");
        if (fast == NULL) {
            goto error;
        }
        len = PySequence_Fast_GET_SIZE(fast);
        items = PySequence_Fast_ITEMS(fast);
        for (/*empty*/; len; len--, items++) {
            PyObject *bytes;
            if (!IS_STRING(*items)) {
                PyErr_SetString(PyExc_TypeError,
                                "sensors must be strings");
                goto error;
            }
            bytes = bytes_from_string(*items);
            if (bytes == NULL) {
                goto error;
            }
            sensor = sksiteSensorLookup(PyBytes_AS_STRING(bytes));
            if (sensor == SK_INVALID_SENSOR) {
                PyErr_SetString(PyExc_ValueError, "Invalid sensor name");
                goto error;
            }
            rv = skVectorAppendValue(sensor_vec, &sensor);
            if (rv != 0) {
                PyErr_NoMemory();
                goto error;
            }
        }
        Py_CLEAR(fast);
    } else if (sensors != NULL && sensors != Py_None) {
        PyErr_SetString(PyExc_TypeError,
                        "sensors should be a sequence of strings");
        goto error;
    }

    if (missing && PyObject_IsTrue(missing)) {
        flags = RETURN_MISSING;
    } else {
        flags = 0;
    }

    rv = sksiteRepoIteratorCreate(
        &self->iter, ft_vec, sensor_vec, starttime, endtime, flags);
    if (rv != 0) {
        PyErr_NoMemory();
        goto error;
    }

    rv = 0;

  cleanup:
    Py_XDECREF(fast);
    if (ft_vec) {
        skVectorDestroy(ft_vec);
    }
    if (sensor_vec) {
        skVectorDestroy(sensor_vec);
    }

    return rv;

  error:
    rv = -1;
    goto cleanup;
}

static PyObject *
silkPyRepoIter_iternext(
    silkPyRepoIter     *self)
{
    char path[PATH_MAX];
    int missing;
    int rv;

    rv = sksiteRepoIteratorNextPath(self->iter, path, sizeof(path), &missing);
    if (rv == SK_ITERATOR_NO_MORE_ENTRIES) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    return Py_BuildValue("sO", path, missing ? Py_False : Py_True);
}


/*
 *************************************************************************
 *   Misc Globals
 *************************************************************************
 */

/* function prototypes */
static PyObject *silk_class_info(void);
static PyObject *silk_flowtype_info(void);
static PyObject *silk_get_rootdir(void);
static PyObject *silk_get_siteconf(void);
static PyObject *silk_have_site_config(void);
static PyObject *
silk_init_country_codes(
    PyObject    UNUSED(*self),
    PyObject           *args);
static int
silk_init_set_envvar(
    const char         *value,
    const char         *envvar);
static PyObject *
silk_init_site(
    PyObject    UNUSED(*self),
    PyObject           *args,
    PyObject           *kwds);
static PyObject *silk_get_compression_methods(void);
static PyObject *silk_get_timezone_support(void);
static PyObject *silk_initial_tcpflags_enabled(void);
static PyObject *silk_ipset_supports_ipv6(void);
static PyObject *silk_ipv6_enabled(void);
static silkPyRawRWRec *
silk_raw_rwrec_copy(
    PyObject    UNUSED(*self),
    PyObject           *c_rec);
static PyObject *silk_sensor_info(void);
static PyObject *
silk_set_rootdir(
    PyObject    UNUSED(*self),
    PyObject           *args);
static PyObject *silk_version(void);

static PyMethodDef silk_methods[] = {
    {"get_compression_methods", (PyCFunction)silk_get_compression_methods,
     METH_NOARGS,
     ("Return a list of strings containing the compression methods"
      " enabled at compile-time")},
    {"get_timezone_support", (PyCFunction)silk_get_timezone_support,
     METH_NOARGS,
     ("Return whether \"UTC\" or the \"local\" timezone was selected"
      " at compile-time")},
    {"ipv6_enabled", (PyCFunction)silk_ipv6_enabled,
     METH_NOARGS,
     ("Return whether IPv6 was enabled at compile-time")},
    {"ipset_supports_ipv6", (PyCFunction)silk_ipset_supports_ipv6,
     METH_NOARGS,
     ("Return whether IPv6-support for IPsets was enabled at compile-time")},
    {"initial_tcpflags_enabled", (PyCFunction)silk_initial_tcpflags_enabled,
     METH_NOARGS,
     ("Return whether initial tcpflags were enabled at compile-time")},
    {"init_site", (PyCFunction)silk_init_site,
     METH_VARARGS | METH_KEYWORDS,
     ("init_site([siteconf][, rootdir])\n"
      "Initialize the silk site.\n"
      "When siteconf is None, PySiLK uses the file named by the environment\n"
      "variable " SILK_CONFIG_FILE_ENVAR ", if available, or the file\n"
      "'silk.conf' in the rootdir, the directories '$SILK_PATH/share/silk/'\n"
      "and '$SILK_PATH/share/', and the 'share/silk/' and 'share/'\n"
      "directories parallel to the application's directory.\n"
      "When rootdir is not supplied, SiLK's default value is used.\n"
      "Throw an exception if the site is already initialized.")},
    {"have_site_config", (PyCFunction)silk_have_site_config,
     METH_NOARGS,
     ("Return whether the site configuration file has been loaded")},
    {"get_site_config", (PyCFunction)silk_get_siteconf,
     METH_NOARGS,
     ("Return the current site configuration file; None if not set")},
    {"set_data_rootdir", (PyCFunction)silk_set_rootdir,
     METH_VARARGS,
     ("Change the data root directory to the given path")},
    {"get_data_rootdir", (PyCFunction)silk_get_rootdir,
     METH_NOARGS,
     ("Return the current root directory")},
    {"sensor_info", (PyCFunction)silk_sensor_info,
     METH_NOARGS,
     ("Returns a list of information for configured sensors")},
    {"class_info", (PyCFunction)silk_class_info,
     METH_NOARGS,
     ("Return a list of information for configured classes")},
    {"flowtype_info", (PyCFunction)silk_flowtype_info,
     METH_NOARGS,
     ("Return a list of information for configured flowtypes")},
    {"silk_version", (PyCFunction)silk_version,
     METH_NOARGS,
     ("Return the version of SiLK that PySilk was linked against")},
    {"init_country_codes", (PyCFunction)silk_init_country_codes,
     METH_VARARGS,
     ("Initialize the country codes from the given file (can be left blank)")},
    {"_raw_rwrec_copy", (PyCFunction)silk_raw_rwrec_copy,
     METH_O,
     ("Create a RawRWRec from a C rwrec PyCObject, copying the value")},
    {NULL, NULL, 0, NULL}       /* Sentinel */
};

static PyObject *
silk_class_info(
    void)
{
    CHECK_SITE(NULL);

    Py_INCREF(GLOBALS->classes);
    return GLOBALS->classes;
}

static PyObject *
silk_flowtype_info(
    void)
{
    CHECK_SITE(NULL);

    Py_INCREF(GLOBALS->flowtypes);
    return GLOBALS->flowtypes;
}

static PyObject *
silk_get_rootdir(
    void)
{
    char rootdir[PATH_MAX];

    sksiteGetRootDir(rootdir, sizeof(rootdir));
    return PyUnicode_InternFromString(rootdir);
}

static PyObject *
silk_get_siteconf(
    void)
{
    char siteconf[PATH_MAX];

    sksiteGetConfigPath(siteconf, sizeof(siteconf));
    return PyUnicode_InternFromString(siteconf);
}

static PyObject *
silk_have_site_config(
    void)
{
    Py_INCREF(GLOBALS->havesite);
    return GLOBALS->havesite;
}

static PyObject *
silk_init_country_codes(
    PyObject    UNUSED(*self),
    PyObject           *args)
{
    int   rv;
    char *filename = NULL;

    rv = PyArg_ParseTuple(args, "|et",
                          Py_FileSystemDefaultEncoding, &filename);
    if (!rv) {
        return NULL;
    }

    skCountryTeardown();
    rv = skCountrySetup(filename, error_printf);
    PyMem_Free(filename);
    if (rv != 0) {
        PyErr_SetString(PyExc_RuntimeError, error_buffer);
        return NULL;
    }

    Py_RETURN_NONE;
}

static int
silk_init_set_envvar(
    const char         *value,
    const char         *envvar)
{
    static char env_buf[101 + PATH_MAX];
    PyObject *os;
    int rv;

    if (value == NULL) {
        return 0;
    }

    /* setenv() does not exist on Solaris 9, so we use putenv()
     * instead */
    rv = snprintf(env_buf, sizeof(env_buf),
                  "%s=%s", envvar, value);
    if (rv >= (int)sizeof(env_buf) || putenv(env_buf) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        ("Could not set " SILK_CONFIG_FILE_ENVAR));
        return -1;
    }

    /* Attempt to add the environment variable to Python's
     * environment list as well */
    os = PyImport_ImportModule("os");
    if (os != NULL) {
        PyObject *env = PyObject_GetAttrString(os, "environ");
        if (env != NULL) {
            PyObject *s = PyUnicode_Decode(value,
                                           strlen(value),
                                           Py_FileSystemDefaultEncoding,
                                           "strict");
            if (s != NULL) {
                PyMapping_SetItemString(env, (char*)envvar, s);
                Py_DECREF(s);
            }
            Py_DECREF(env);
        }
        Py_DECREF(os);
    }

    return 0;
}

static PyObject *
silk_init_site(
    PyObject    UNUSED(*self),
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"siteconf", "rootdir", NULL};
    char *siteconf = NULL;
    char *rootdir  = NULL;
    int   rv;

    rv = PyArg_ParseTupleAndKeywords(args, kwds, "|etet", kwlist,
                                     Py_FileSystemDefaultEncoding, &siteconf,
                                     Py_FileSystemDefaultEncoding, &rootdir);
    if (!rv) {
        goto error;
    }

    if (GLOBALS->site_configured) {
        PyErr_SetString(PyExc_RuntimeError, "Site already initialized");
        goto error;
    }

    if (siteconf) {
        ASSERT_RESULT(sksiteSetConfigPath(siteconf), int, 0);
    }

    if (rootdir) {
        if (!skDirExists(rootdir)) {
            PyErr_Format(PyExc_IOError,
                         "The directory %s does not exist", rootdir);
            goto error;
        }
        rv = sksiteSetRootDir(rootdir);
        if (rv != 0) {
            PyErr_SetString(PyExc_ValueError, "Illegal root directory");
            goto error;
        }
    }

    if (init_site(siteconf) != 0) {
        goto error;
    }

    /* These are needed for subprocess calls to silk */
    if (silk_init_set_envvar(siteconf, SILK_CONFIG_FILE_ENVAR)) {
        goto error;
    }
    if (silk_init_set_envvar(rootdir, SILK_DATA_ROOTDIR_ENVAR)) {
        goto error;
    }

    Py_INCREF(GLOBALS->havesite);
    return GLOBALS->havesite;

  error:
    PyMem_Free(siteconf);
    PyMem_Free(rootdir);

    return NULL;
}

static PyObject *
silk_initial_tcpflags_enabled(
    void)
{
    Py_RETURN_TRUE;
}

static PyObject *
silk_ipset_supports_ipv6(
    void)
{
#if SK_ENABLE_IPV6
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *
silk_ipv6_enabled(
    void)
{
#if SK_ENABLE_IPV6
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *
silk_get_timezone_support(
    void)
{
#if SK_ENABLE_LOCALTIME
    return STRING_FROM_STRING("local");
#else
    return STRING_FROM_STRING("UTC");
#endif
}

static PyObject *
silk_get_compression_methods(
    void)
{
    const char *compmethods[] = {
        "NO_COMPRESSION",
#if SK_ENABLE_ZLIB
        "ZLIB",
#endif
#if SK_ENABLE_LZO
        "LZO1X",
#endif
#if SK_ENABLE_SNAPPY
        "SNAPPY",
#endif
        NULL
    };
    PyObject *list;
    PyObject *val;
    size_t i;
    int rv;

    list = PyList_New(0);
    if (NULL == list) {
        return NULL;
    }

    for (i = 0; compmethods[i] != NULL; ++i) {
        val = STRING_FROM_STRING(compmethods[i]);
        if (NULL == val) {
            goto ERROR;
        }
        rv = PyList_Append(list, val);
        Py_DECREF(val);
        if (rv != 0) {
            goto ERROR;
        }
    }

    return list;

  ERROR:
    Py_DECREF(list);
    return NULL;
}

static silkPyRawRWRec *
silk_raw_rwrec_copy(
    PyObject    UNUSED(*self),
    PyObject           *c_rec)
{
    silkPyRawRWRec *pyrec;
    rwRec       *rec;

    if (!COBJ_CHECK(c_rec)) {
        PyErr_SetString(PyExc_TypeError, "Illegal argument type");
        return NULL;
    }

    pyrec = (silkPyRawRWRec*)silkPyRawRWRecType.tp_alloc(
        &silkPyRawRWRecType, 0);
    if (pyrec != NULL) {
        rec = (rwRec*)COBJ_PTR(c_rec);
        if (rec != NULL) {
            RWREC_COPY(&pyrec->rec, rec);
        }
    }

    return pyrec;
}

static PyObject *
silk_sensor_info(
    void)
{
    CHECK_SITE(NULL);

    Py_INCREF(GLOBALS->sensors);
    return GLOBALS->sensors;
}

static PyObject *
silk_set_rootdir(
    PyObject    UNUSED(*self),
    PyObject           *args)
{
    int   rv;
    char *rootdir = NULL;

    CHECK_SITE(NULL);

    rv = PyArg_ParseTuple(args, "|et",
                          Py_FileSystemDefaultEncoding, &rootdir);
    if (!rv) {
        return NULL;
    }
    if (!skDirExists(rootdir)) {
        PyErr_Format(PyExc_IOError,
                     "The directory %s does not exist", rootdir);
        PyMem_Free(rootdir);
        return NULL;
    }
    rv = sksiteSetRootDir(rootdir);
    PyMem_Free(rootdir);
    if (rv != 0) {
        PyErr_SetString(PyExc_ValueError, "Illegal root directory");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
silk_version(
    void)
{
    return PyUnicode_InternFromString(SK_PACKAGE_VERSION);
}


/*
 *************************************************************************
 *   SUPPORT FUNCTIONS
 *************************************************************************
 */

static PyObject *
any_obj_error(
    PyObject           *exc,
    const char         *format,
    PyObject           *obj)
{
    PyObject *pformat = PyUnicode_FromString(format);
    PyObject *msg = PyUnicode_Format(pformat, obj);
    PyErr_SetObject(exc, msg);
    Py_DECREF(pformat);
    Py_DECREF(msg);
    return NULL;
}

#ifndef TEST_PRINTF_FORMATS
static int
error_printf(
    const char         *fmt,
    ...)
{
    int rv;

    va_list args;
    va_start(args, fmt);
    rv = vsnprintf(error_buffer, sizeof(error_buffer), fmt, args);
    error_buffer[sizeof(error_buffer) - 1] = '\0';
    va_end(args);

    return rv;
}
#endif  /* TEST_PRINTF_FORMATS */


static int
init_classes(
    void)
{
    sk_class_iter_t iter;
    sk_class_id_t   class_id;
    char            name[SK_MAX_STRLEN_FLOWTYPE+1];
    PyObject       *list;
    PyObject       *dict;
    PyObject       *classes;
    PyObject       *val;
    PyObject       *class_data;
    int             rv;

    classes = PyDict_New();
    if (classes == NULL) {
        goto error;
    }
    class_id = sksiteClassGetDefault();
    if (class_id == SK_INVALID_CLASS) {
        val = Py_None;
        Py_INCREF(val);
    } else {
        val = PyInt_FromLong(sksiteClassGetDefault());
        if (val == NULL) {
            goto error;
        }
    }
    rv = PyDict_SetItemString(classes, "default", val);
    Py_DECREF(val);
    if (rv != 0) {
        goto error;
    }

    class_data = PyDict_New();
    if (class_data == NULL) {
        goto error;
    }
    rv = PyDict_SetItemString(classes, "data", class_data);
    Py_DECREF(class_data);
    if (rv != 0) {
        goto error;
    }

    sksiteClassIterator(&iter);
    while (sksiteClassIteratorNext(&iter, &class_id)) {
        sk_sensor_iter_t    sensor_iter;
        sk_sensor_id_t      sensor;
        sk_flowtype_iter_t  flowtype_iter;
        sk_flowtype_id_t    flowtype;

        dict = PyDict_New();
        if (dict == NULL) {
            goto error;
        }
        val = PyInt_FromLong(class_id);
        if (val == NULL) {
            Py_DECREF(dict);
            goto error;
        }
        rv = PyDict_SetItem(class_data, val, dict);
        Py_DECREF(dict);
        if (rv != 0) {
            Py_DECREF(val);
            goto error;
        }
        rv = PyDict_SetItemString(dict, "id", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        sksiteClassGetName(name, sizeof(name), class_id);
        val = PyUnicode_InternFromString(name);
        if (val == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "name", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        list = PyList_New(0);
        if (list == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "sensors", list);
        Py_DECREF(list);
        if (rv != 0) {
            goto error;
        }
        sksiteClassSensorIterator(class_id, &sensor_iter);
        while (sksiteSensorIteratorNext(&sensor_iter, &sensor)) {
            val = PyInt_FromLong(sensor);
            if (val == NULL) {
                goto error;
            }
            rv = PyList_Append(list, val);
            Py_DECREF(val);
            if (rv != 0) {
                goto error;
            }
        }

        list = PyList_New(0);
        if (list == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "flowtypes", list);
        Py_DECREF(list);
        if (rv != 0) {
            goto error;
        }
        sksiteClassFlowtypeIterator(class_id, &flowtype_iter);
        while (sksiteFlowtypeIteratorNext(&flowtype_iter, &flowtype)) {
            val = PyInt_FromLong(flowtype);
            if (val == NULL) {
                goto error;
            }
            rv = PyList_Append(list, val);
            Py_DECREF(val);
            if (rv != 0) {
                goto error;
            }
        }

        list = PyList_New(0);
        if (list == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "default_flowtypes", list);
        Py_DECREF(list);
        if (rv != 0) {
            goto error;
        }
        sksiteClassDefaultFlowtypeIterator(class_id, &flowtype_iter);
        while (sksiteFlowtypeIteratorNext(&flowtype_iter, &flowtype)) {
            val = PyInt_FromLong(flowtype);
            if (val == NULL) {
                goto error;
            }
            rv = PyList_Append(list, val);
            Py_DECREF(val);
            if (rv != 0) {
                goto error;
            }
        }
    }

    GLOBALS->classes = classes;
    return 0;

  error:
    Py_XDECREF(classes);

    return -1;
}

static int
init_flowtypes(
    void)
{
    sk_flowtype_iter_t   flowtype_iter;
    sk_flowtype_id_t     flowtype;
    char                 name[SK_MAX_STRLEN_SENSOR+1];
    PyObject            *dict;
    PyObject            *flowtypes;
    int                  rv;

    flowtypes = PyDict_New();
    if (flowtypes == NULL) {
        goto error;
    }

    sksiteFlowtypeIterator(&flowtype_iter);
    while (sksiteFlowtypeIteratorNext(&flowtype_iter, &flowtype)) {
        sk_class_id_t class_id;
        PyObject     *val;

        dict = PyDict_New();
        if (dict == NULL) {
            goto error;
        }
        val = PyInt_FromLong(flowtype);
        if (val == NULL) {
            Py_DECREF(dict);
            goto error;
        }
        rv = PyDict_SetItem(flowtypes, val, dict);
        Py_DECREF(dict);
        if (rv != 0) {
            Py_DECREF(val);
            goto error;
        }
        rv = PyDict_SetItemString(dict, "id", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        sksiteFlowtypeGetName(name, sizeof(name), flowtype);
        val = PyUnicode_InternFromString(name);
        if (val == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "name", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        sksiteFlowtypeGetType(name, sizeof(name), flowtype);
        val = PyUnicode_InternFromString(name);
        if (val == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "type", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        class_id = sksiteFlowtypeGetClassID(flowtype);
        val = PyInt_FromLong(class_id);
        if (val == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "class", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }
    }

    GLOBALS->flowtypes = flowtypes;
    return 0;

  error:
    Py_XDECREF(flowtypes);

    return -1;
}

static int
init_sensors(
    void)
{
    sk_sensor_iter_t   sensor_iter;
    sk_sensor_id_t     sensor;
    char               name[SK_MAX_STRLEN_SENSOR+1];
    PyObject          *list;
    PyObject          *dict;
    PyObject          *sensors;
    int                rv;

    sensors = PyDict_New();
    if (sensors == NULL) {
        goto error;
    }

    sksiteSensorIterator(&sensor_iter);
    while (sksiteSensorIteratorNext(&sensor_iter, &sensor)) {
        sk_class_iter_t   class_iter;
        sk_class_id_t     class_id;
        PyObject         *val;
        const char       *desc;

        dict = PyDict_New();
        if (dict == NULL) {
            goto error;
        }
        val = PyInt_FromLong(sensor);
        if (val == NULL) {
            Py_DECREF(dict);
            goto error;
        }
        rv = PyDict_SetItem(sensors, val, dict);
        Py_DECREF(dict);
        if (rv != 0) {
            Py_DECREF(val);
            goto error;
        }
        rv = PyDict_SetItemString(dict, "id", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        sksiteSensorGetName(name, sizeof(name), sensor);
        val = PyUnicode_InternFromString(name);
        if (val == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "name", val);
        Py_DECREF(val);
        if (rv != 0) {
            goto error;
        }

        desc = sksiteSensorGetDescription(sensor);
        if (desc) {
            val = PyUnicode_FromString(desc);
            if (val == NULL) {
                goto error;
            }
            rv = PyDict_SetItemString(dict, "description", val);
            Py_DECREF(val);
            if (rv != 0) {
                goto error;
            }
        }

        list = PyList_New(0);
        if (list == NULL) {
            goto error;
        }
        rv = PyDict_SetItemString(dict, "classes", list);
        Py_DECREF(list);
        if (rv != 0) {
            goto error;
        }
        sksiteSensorClassIterator(sensor, &class_iter);
        while (sksiteClassIteratorNext(&class_iter, &class_id)) {
            val = PyInt_FromLong(class_id);
            if (val == NULL) {
                goto error;
            }
            rv = PyList_Append(list, val);
            Py_DECREF(val);
            if (rv != 0) {
                goto error;
            }
        }
    }

    GLOBALS->sensors = sensors;
    return 0;

  error:
    Py_XDECREF(sensors);

    return -1;
}

static int
init_silkfile_module(
    PyObject           *mod)
{
    int rv;

    PyModule_AddIntConstant(mod, "IGNORE", SK_IPV6POLICY_IGNORE);
    PyModule_AddIntConstant(mod, "ASV4", SK_IPV6POLICY_ASV4);
    PyModule_AddIntConstant(mod, "MIX", SK_IPV6POLICY_MIX);
    PyModule_AddIntConstant(mod, "FORCE", SK_IPV6POLICY_FORCE);
    PyModule_AddIntConstant(mod, "ONLY", SK_IPV6POLICY_ONLY);

    PyModule_AddIntConstant(mod, "READ", SK_IO_READ);
    PyModule_AddIntConstant(mod, "WRITE", SK_IO_WRITE);
    PyModule_AddIntConstant(mod, "APPEND", SK_IO_APPEND);

    PyModule_AddIntConstant(mod, "DEFAULT", NOT_SET);
    PyModule_AddIntConstant(mod, "NO_COMPRESSION", SK_COMPMETHOD_NONE);
    PyModule_AddIntConstant(mod, "ZLIB", SK_COMPMETHOD_ZLIB);
    PyModule_AddIntConstant(mod, "LZO1X", SK_COMPMETHOD_LZO1X);
    PyModule_AddIntConstant(mod, "SNAPPY", SK_COMPMETHOD_SNAPPY);

    PyModule_AddObject(mod, "BAG_COUNTER_MAX",
                       PyLong_FromUnsignedLongLong(SKBAG_COUNTER_MAX));

    silkPySilkFileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPySilkFileType) < 0) {
        return -1;
    }
    rv = PyModule_AddObject(mod, "SilkFileBase",
                            (PyObject*)&silkPySilkFileType);
    if (rv != 0) {
        return -1;
    }

    return 0;
}

static int
init_site(
    const char         *site_file)
{
    int rv;
    int siterv;
    int retval = 0;

    if (GLOBALS->site_configured) {
        return 0;
    }

    siterv = sksiteConfigure(0);
    if (siterv == 0) {
        GLOBALS->havesite = Py_True;
    } else if (siterv == -2) {
        GLOBALS->havesite = Py_False;
        if (site_file) {
            Py_INCREF(GLOBALS->havesite);
            PyErr_Format(PyExc_IOError,
                         "could not read site file %s", site_file);
            retval = -1;
        }
    } else {
        GLOBALS->havesite = Py_False;
        PyErr_SetString(PyExc_RuntimeError,
                        "error parsing site configuration file");
        retval = -1;
    }
    Py_INCREF(GLOBALS->havesite);
    rv = PyModule_AddObject(GLOBALS->silkmod, "_havesite", GLOBALS->havesite);
    if (rv != 0) {
        return -1;
    }

    rv = init_sensors();
    if (rv != 0) {
        return -1;
    }
    rv = PyModule_AddObject(GLOBALS->silkmod, "_sensors", GLOBALS->sensors);
    if (rv != 0) {
        return -1;
    }

    rv = init_classes();
    if (rv != 0) {
        return -1;
    }
    rv = PyModule_AddObject(GLOBALS->silkmod, "_classes", GLOBALS->classes);
    if (rv != 0) {
        return -1;
    }

    rv = init_flowtypes();
    if (rv != 0) {
        return -1;
    }
    rv = PyModule_AddObject(GLOBALS->silkmod, "_flowtypes",
                            GLOBALS->flowtypes);
    if (rv != 0) {
        return -1;
    }

    if (siterv == 0) {
        GLOBALS->site_configured = 1;
    }

    return retval;
}

static PyObject *
iter_iter(
    PyObject           *self)
{
    Py_INCREF(self);
    return self;
}

static void
obj_dealloc(
    PyObject           *obj)
{
    Py_TYPE(obj)->tp_free(obj);
}

static PyObject *
obj_error(
    const char         *format,
    PyObject           *obj)
{
    return any_obj_error(PyExc_ValueError, format, obj);
}

static skstream_t *
open_silkfile_write(
    PyObject           *args,
    PyObject           *kwds)
{
    static char *kwlist[] = {"filename", "compression", NULL};

    PyObject *name;
    PyObject *bytes;
    char errbuf[2 * PATH_MAX];
    skstream_t *stream = NULL;
    int compr = NOT_SET;
    const char *fname;
    sk_file_header_t *hdr;
    int rv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist,
                                     &name, &compr))
    {
        return NULL;
    }

    if (!IS_STRING(name)) {
        PyErr_SetString(PyExc_TypeError, "Filename required");
        return NULL;
    }
#if PY_MAJOR_VERSION < 3
    if (PyBytes_Check(name)) {
        bytes = name;
        Py_INCREF(bytes);
    } else
#endif
    {
        bytes = PyUnicode_AsEncodedString(name, Py_FileSystemDefaultEncoding,
                                          "strict");
        if (bytes == NULL) {
            return NULL;
        }
    }

    fname = PyBytes_AS_STRING(bytes);
    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, fname))
        || (rv = skStreamOpen(stream)))
    {
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        PyErr_Format(PyExc_IOError, "Unable to open %s for writing: %s",
                     fname, errbuf);
        skStreamDestroy(&stream);
        Py_DECREF(bytes);
        return NULL;
    }

    if (compr != NOT_SET) {
        hdr = skStreamGetSilkHeader(stream);
        rv = skHeaderSetCompressionMethod(hdr, compr);
        if (rv != 0) {
            skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
            PyErr_Format(PyExc_IOError,
                         "Unable to open set compression on %s: %s",
                         fname, errbuf);
            skStreamDestroy(&stream);
            Py_DECREF(bytes);
            return NULL;
        }
    }

    Py_DECREF(bytes);

    return stream;
}

static PyObject *
reduce_error(
    PyObject           *obj)
{
    if (Py_TYPE(obj) && Py_TYPE(obj)->tp_name) {
        PyErr_Format(PyExc_TypeError, "can't pickle %s objects",
                     Py_TYPE(obj)->tp_name);
    } else {
        PyErr_SetString(PyExc_TypeError, "This object cannot be pickled");
    }
    return NULL;
}

static int
silkPyDatetimeToSktime(
    sktime_t           *silktime,
    PyObject           *datetime)
{
    PyObject *delta = NULL;
    PyObject *days = NULL;
    PyObject *secs = NULL;
    PyObject *usecs = NULL;
    int64_t millisecs;
    int retval = -1;

    if (!PyDateTime_Check(datetime)) {
        if (PyDate_Check(datetime)) {
            datetime = PyDateTime_FromDateAndTime(
                PyDateTime_GET_YEAR(datetime),
                PyDateTime_GET_MONTH(datetime),
                PyDateTime_GET_DAY(datetime),
                0, 0, 0, 0);
            if (datetime == NULL) {
                return -1;
            }
        } else {
            PyErr_SetString(PyExc_TypeError, "Expected a datetime.date");
            return -1;
        }
    } else {
        Py_INCREF(datetime);
    }
    if (PyObject_RichCompareBool(datetime, GLOBALS->epochtime, Py_LT)) {
        PyErr_SetString(PyExc_ValueError, "Minimum time is Jan 1, 1970");
        Py_DECREF(datetime);
        return -1;
    }
    if (PyObject_RichCompareBool(datetime, GLOBALS->maxtime, Py_GT)) {
        PyErr_SetString(PyExc_ValueError,
                        "Maximum time is 03:14:07, Jan 19, 2038");
        Py_DECREF(datetime);
        return -1;
    }
    delta = PyNumber_Subtract(datetime, GLOBALS->epochtime);
    Py_DECREF(datetime);
    days = PyObject_GetAttrString(delta, "days");
    secs = PyObject_GetAttrString(delta, "seconds");
    usecs = PyObject_GetAttrString(delta, "microseconds");
    millisecs = (int64_t)PyLong_AsLong(days) * 1000 * 24 * 3600 +
                (int64_t)PyLong_AsLong(secs) * 1000 +
                PyLong_AsLong(usecs) / 1000;
    if (!PyErr_Occurred()) {
        *silktime = millisecs;
        retval = 0;
    }
    Py_XDECREF(delta);
    Py_XDECREF(days);
    Py_XDECREF(secs);
    Py_XDECREF(usecs);

    return retval;
}

#if !SK_ENABLE_IPV6
static PyObject *
silkPyNotImplemented(
    PyObject    UNUSED(*self),
    PyObject    UNUSED(*args),
    PyObject    UNUSED(*kwds))
{
    return PyErr_Format(PyExc_NotImplementedError,
                        "SiLK was not built with IPv6 support.");
}
#endif  /* !SK_ENABLE_IPV6 */


static PyObject *
initpysilkbase(
    char*               name)
{
#if PY_MAJOR_VERSION >= 3
    /* Module information for Python 3.0 */
    static struct PyModuleDef pysilk_module_static = {
        PyModuleDef_HEAD_INIT,
        NULL,                       /* m_name */
        NULL,                       /* m_doc */
        sizeof(silkpy_globals_t),   /* m_size */
        silk_methods,               /* m_methods */
        NULL,                       /* m_reaload (unused) */
        NULL,                       /* m_traverse */
        NULL,                       /* m_clear */
        NULL                        /* m_free */
    };
#endif

    PyObject         *silkmod;
    PyObject         *tmp;
    silkpy_globals_t *globals;

    PyDateTime_IMPORT;

#if PY_MAJOR_VERSION >= 3
    pysilk_module = &pysilk_module_static;
    pysilk_module->m_name = name;
    silkmod = PyModule_Create(pysilk_module);
    if (silkmod == NULL) {
        skAppPrintErr("Could not create module silk");
        goto err;
    }
    globals = (silkpy_globals_t*)PyModule_GetState(silkmod);
#else
    /* Globals are in the static global variable */
    globals = &silkpy_globals_static;
    silkmod = Py_InitModule3(name, silk_methods, "SiLK extension module");
    if (silkmod == NULL) {
        skAppPrintErr("Could not create module silk");
        goto err;
    }
#endif  /* #else of #if PY_MAJOR_VERSION >= 3 */

    memset(globals, 0, sizeof(*globals));
    globals->silkmod = silkmod;
    globals->havesite = Py_False;
    Py_INCREF(globals->havesite);

    if (init_silkfile_module(silkmod)) {
        goto err;
    }

    if (silkPyIPAddr_setup(silkmod) != 0) {
        goto err;
    }

    if (PyType_Ready(&silkPyIPv4AddrType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPv4Addr",
                                     (PyObject*)&silkPyIPv4AddrType),
                  int, 0);

    if (PyType_Ready(&silkPyIPv6AddrType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPv6Addr",
                                     (PyObject*)&silkPyIPv6AddrType),
                  int, 0);

    if (PyType_Ready(&silkPyIPWildcardType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPWildcard",
                                     (PyObject*)&silkPyIPWildcardType),
                  int, 0);

    silkPyIPWildcardIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyIPWildcardIterType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPWildcardIter",
                                     (PyObject*)&silkPyIPWildcardIterType),
                  int, 0);

    silkPyIPSetType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyIPSetType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPSetBase",
                                     (PyObject*)&silkPyIPSetType),
                  int, 0);

    silkPyIPSetIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyIPSetIterType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "IPSetIter",
                                     (PyObject*)&silkPyIPSetIterType),
                  int, 0);

    silkPyPmapType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyPmapType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "PMapBase",
                                     (PyObject*)&silkPyPmapType),
                  int, 0);

    silkPyPmapIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyPmapIterType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "PMapBaseIter",
                                     (PyObject*)&silkPyPmapIterType),
                  int, 0);

    if (silkPyBag_setup(silkmod) != 0) {
        goto err;
    }

    silkPyBagIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyBagIterType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "BagBaseIter",
                                     (PyObject*)&silkPyBagIterType),
                  int, 0);

    silkPyRepoIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyRepoIterType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "RepoIter",
                                     (PyObject*)&silkPyRepoIterType),
                  int, 0);

    if (silkPyTCPFlags_setup(silkmod)) {
        goto err;
    }

    if (PyType_Ready(&silkPyRawRWRecType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "RawRWRec",
                                     (PyObject*)&silkPyRawRWRecType),
                  int, 0);

    silkPyRWRecType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&silkPyRWRecType) < 0) {
        goto err;
    }
    ASSERT_RESULT(PyModule_AddObject(silkmod, "RWRecBase",
                                     (PyObject*)&silkPyRWRecType),
                  int, 0);

    tmp = PyImport_ImportModule("datetime");
    if (tmp == NULL) {
        skAppPrintErr("Failed to import datetime module");
        goto err;
    }

    globals->timedelta = PyObject_GetAttrString(tmp, "timedelta");
    assert(globals->timedelta != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_timedelta", globals->timedelta),
                  int, 0);

    globals->datetime = PyObject_GetAttrString(tmp, "datetime");
    assert(globals->datetime != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_datetime", globals->datetime),
                  int, 0);

    Py_DECREF(tmp);

    globals->maxelapsed = PyObject_CallFunction(globals->timedelta,
                                                "iiik", 0, 0, 0, UINT32_MAX);
    assert(globals->maxelapsed != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_maxelapsed",
                                     globals->maxelapsed),
                  int, 0);

    globals->minelapsed = PyObject_CallObject(globals->timedelta, NULL);
    assert(globals->minelapsed != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_minelapsed",
                                     globals->minelapsed),
                  int, 0);

    globals->epochtime = PyObject_CallFunction(globals->datetime, "iii",
                                              1970, 1, 1);
    assert(globals->epochtime != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_epochtime",
                                     globals->epochtime),
                  int, 0);

    globals->maxtime = PyObject_CallFunction(
        globals->datetime, "iiiiii", 2038, 1, 19, 3, 14, 7);
    assert(globals->maxtime != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_maxtime",
                                     globals->maxtime),
                  int, 0);

    globals->thousand = PyFloat_FromDouble(1000.0);
    assert(globals->thousand != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_thousand", globals->thousand),
                  int, 0);

    globals->maxintipv4 = PyLong_FromString("0xffffffff", NULL, 0);
    assert(globals->maxintipv4 != NULL);
    ASSERT_RESULT(PyModule_AddObject(globals->silkmod, "_maxintipv4",
                                     globals->maxintipv4),
                  int, 0);

#if SK_ENABLE_IPV6
    globals->maxintipv6 =
        PyLong_FromString("0xffffffffffffffffffffffffffffffff", NULL, 0);
    assert(globals->maxintipv6 != NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_maxintipv6",
                                     globals->maxintipv6),
                  int, 0);
#endif  /* SK_ENABLE_IPV6 */

    globals->newrawrec = PyObject_CallFunctionObjArgs(
        (PyObject *)&silkPyRawRWRecType, NULL);
    ASSERT_RESULT(PyModule_AddObject(silkmod, "_newrawrec",
                                     globals->newrawrec),
                  int, 0);

    return silkmod;

  err:
    if (silkmod) {
        Py_DECREF(silkmod);
    }
#if PY_MAJOR_VERSION >= 3
    return NULL;
#else /* PY_MAJOR_VERSION < 3 */
    if (PyErr_Occurred()) {
        PyErr_Print();
    }
    exit(EXIT_FAILURE);
#endif  /* PY_MAJOR_VERSION */
}

PyMODINIT_FUNC
PYSILK_INIT(
    void)
{
    PyObject *nameobj;

    nameobj = BYTES_FROM_XCHAR(Py_GetProgramName());

    if (nameobj == NULL) {
        skAppRegister("PySiLK_program");
    } else {
        skAppRegister(PyBytes_AS_STRING(nameobj));
        Py_DECREF(nameobj);
    }
    INIT_RETURN(initpysilkbase(STR(PYSILK_NAME)));
}

PyMODINIT_FUNC
PYSILK_PIN_INIT(
    void)
{
    INIT_RETURN(initpysilkbase("silk." STR(PYSILK_PIN_NAME)));
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
