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

/*
**  Common functions for pysilk and silkpython
**
*/


#define PY_SSIZE_T_CLEAN        /* "s#" "y#" formats must use ssize_t */
#include <Python.h>
#include <silk/silk.h>

RCSIDENT("$SiLK: pysilk_common.c a9d59cf951c7 2023-04-26 20:21:33Z mthomas $");

#include "pysilk_common.h"

/* FUNCTION DEFINITIONS */

PyObject *
bytes_from_string(
    PyObject           *obj)
{
    PyObject *bytes;

    if (PyBytes_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }
    bytes = PyUnicode_AsASCIIString(obj);
    return bytes;
}

PyObject *
bytes_from_wchar(
    const wchar_t      *wc)
{
    PyObject *bytes;
    PyObject *pstr = PyUnicode_FromWideChar(wc, -1);
    if (pstr == NULL) {
        return NULL;
    }
    bytes = bytes_from_string(pstr);
    Py_DECREF(pstr);

    return bytes;
}

#if PY_VERSION_HEX < 0x02060000

PyObject *
string_to_unicode(
    const char         *s)
{
    return PyUnicode_DecodeUTF8(s, strlen(s), "strict");
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH

PyObject *
format_to_unicode(
    const char         *s,
    ...)
{
    va_list ap;
    PyObject *str;
    PyObject *uni;

    va_start(ap, s);
    str = PyString_FromFormatV(s, ap);
    va_end(ap);

    if (str == NULL) {
        return NULL;
    }
    uni = PyUnicode_FromObject(str);
    Py_DECREF(str);

    return uni;
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP

#endif

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
