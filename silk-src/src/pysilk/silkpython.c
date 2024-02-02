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
**  silkpython.c
**
**  Python plugin for rwfilter, rwcut, rwsort, and rwuniq
*/

#define PY_SSIZE_T_CLEAN        /* "s#" "y#" formats must use ssize_t */
#include <Python.h>
#include <silk/silk.h>

RCSIDENT("$SiLK: silkpython.c a9d59cf951c7 2023-04-26 20:21:33Z mthomas $");

#include <silk/silkpython.h>
#include <silk/skplugin.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include <dlfcn.h>
#include <osdefs.h>
#include "pysilk_common.h"

SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

/* The name of the Python function rwfilter will call for each record */
#define PYFILTER_NAME "rwfilter"

/* The name of the Python function rwfilter will call before exiting */
#define FINALIZER_NAME "finalize"

/* The name of the rwrec when an expression is accepted on the command
 * line */
#define PYREC_NAME "rec"

/* Block size when reading python files over an skStream */
#define FILE_BLOCK_SIZE SKSTREAM_DEFAULT_BLOCKSIZE

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0


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


/*
 *    The field index's integer value relates to the position in the
 *    tuple returned by _get_field_data.  The order of these enumerated
 *    values should be the same as the order of the entries in the
 *    _plugin_name_list variable in plugin.py.
 */
typedef enum {
    FIELD_NAME = 0,
    FIELD_DESCRIPTION,
    FIELD_INIT,
    FIELD_COLUMN_LEN,
    FIELD_REC_TO_TEXT,
    FIELD_BIN_LEN,
    FIELD_REC_TO_BIN,
    FIELD_BIN_TO_TEXT,
    FIELD_ADD_TO_BIN,
    FIELD_BIN_MERGE,
    FIELD_BIN_COMPARE,
    FIELD_INITIAL_VALUE,

    FIELD_INDEX_MAX
} field_index_t;

/* The filter index's integer value relates to the position in the
 * tuple returned by _get_filter_data.  The order of these enumerated
 * values should be the same as the order of the entries in the
 * _filter_name_list variable in plugin.py. */
typedef enum {
    FILTER_FILTER = 0,
    FILTER_INIT,
    FILTER_FINALIZE,

    FILTER_INDEX_MAX
} filter_index_t;

/* The switch index's integer value relates to the position in the
 * tuple returned by _get_cmd_line_args.  The order of these
 * enumerated values should be the same as the order of the entries in
 * the _cmd_line_name_list variable in plugin.py. */
typedef enum {
    SWITCH_NAME = 0,
    SWITCH_HANDLER,
    SWITCH_ARG,
    SWITCH_HELP,

    SWITCH_INDEX_MAX
} switch_index_t;


/* Whether the python filename option has been used */
static int python_file_used = 0;

/* Whether the python expression option has been used */
static int python_expr_used = 0;

/* The rwrec to raw python function */
static PyObject *rwrec_to_raw_python = NULL;

/* The rwrec to python function */
static PyObject *rwrec_to_python_fn = NULL;

/* The record wrapper */
static PyObject *python_rec = NULL;

/* An empty tuple */
static PyObject *empty_tuple = NULL;

/* A keyword dictionary */
static PyObject *kwd_dict = NULL;

/* The plugin module */
static PyObject *plugin_module = NULL;

/* The silk module */
static PyObject *silk_module = NULL;

/* Maintains refcounts for objects assigned to plugin data structures */
static PyObject *refchain = NULL;

/* Whether to act as a real plugin or just ignore.  Set to 1 on an MPI
 * master. */
static int ignore_plugin = 0;

/* Option names */
static const char *python_file_option = "python-file";
static const char *python_expr_option = "python-expr";


/* LOCAL FUNCTION DECLARATIONS */

static int  silkpython_python_init(void);
static void silkpython_uninitialize(void);
static PyObject *silkpython_expr_init(const char *python_expr);
static PyObject *silkpython_file_init(skstream_t *stream);
static int silkpython_register(void);
static int silkpython_register_switches(void);
static skplugin_err_t
silkpython_filter(
    const rwRec        *rec,
    void               *data,
    void              **extra);
static skplugin_err_t
silkpython_field_init(
    void               *data);
static skplugin_err_t
silkpython_filter_init(
    void               *data);
static skplugin_err_t
silkpython_filter_finalize(
    void               *data);
static skplugin_err_t
silkpython_get_text(
    const rwRec        *rwrec,
    char               *dest,
    size_t              width,
    void               *data,
    void              **extra);
static skplugin_err_t
silkpython_get_bin(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *data,
    void              **extra);
static skplugin_err_t
silkpython_add_to_bin(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *data,
    void              **extra);
static skplugin_err_t
silkpython_bin_to_text(
    const uint8_t      *bin_value,
    char               *dest,
    size_t              width,
    void               *data);
static skplugin_err_t
silkpython_bin_merge(
    uint8_t            *dest,
    const uint8_t      *src,
    void               *data);
static skplugin_err_t
silkpython_bin_compare(
    int                *val,
    const uint8_t      *a,
    const uint8_t      *b,
    void               *data);


/** Function Definitions **/

/* Command line option handler for python file */
static skplugin_err_t
silkpython_handle_python_file(
    const char         *opt_arg,
    void        UNUSED(*cbdata))
{
    skstream_t     *stream;
    int             rv;
    PyObject       *globals = NULL;
    skplugin_err_t  retval = SKPLUGIN_ERR_FATAL;

    assert(opt_arg);

    if (python_expr_used) {
        skAppPrintErr("Cannot use --%s at the same time as --%s",
                      python_file_option, python_expr_option);
        return SKPLUGIN_ERR;
    }

    python_file_used = 1;

    /* Get a handle to the python file before starting up python.
       This is so, if we are running on an MPI master, we don't
       have to bother starting python. */
    rv = skpinOpenDataInputStream(&stream, SK_CONTENT_TEXT, opt_arg);
    if (rv == 1) {
        ignore_plugin = 1;
        return SKPLUGIN_OK;
    }
    if (rv != 0) {
        skAppPrintErr("Could not access %s", opt_arg);
        return SKPLUGIN_ERR;
    }

    if (silkpython_python_init()) {
        goto END;
    }
    globals = silkpython_file_init(stream);
    if (globals == NULL) {
        goto END;
    }
    if (silkpython_register_switches()) {
        goto END;
    }
    if (silkpython_register()) {
        goto END;
    }

    retval = SKPLUGIN_OK;

  END:
    skStreamDestroy(&stream);
    Py_XDECREF(globals);

    /* Register the cleanup function */
    ASSERT_RESULT(skpinRegCleanup(silkpython_uninitialize),
                  skplugin_err_t, SKPLUGIN_OK);

    return retval;
}


/* Command line option handler for python expressions */
static skplugin_err_t
silkpython_handle_python_expr(
    const char         *opt_arg,
    void        UNUSED(*cbdata))
{
    skplugin_err_t  retval  = SKPLUGIN_ERR;
    PyObject       *globals = NULL;

    assert(opt_arg);

    if (python_expr_used) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      python_expr_option);
        return SKPLUGIN_ERR;
    }
    if (python_file_used) {
        skAppPrintErr("Cannot use --%s at the same time as --%s",
                      python_file_option, python_expr_option);
        return SKPLUGIN_ERR;
    }

    python_expr_used = 1;

    if (silkpython_python_init()) {
        goto END;
    }
    globals = silkpython_expr_init(opt_arg);
    if (globals == NULL) {
        goto END;
    }
    if (silkpython_register()) {
        goto END;
    }

    retval = SKPLUGIN_OK;

  END:
    Py_XDECREF(globals);

    /* Register the cleanup function */
    ASSERT_RESULT(skpinRegCleanup(silkpython_uninitialize),
                  skplugin_err_t, SKPLUGIN_OK);

    return retval;
}


/* Public plugin entry point */
skplugin_err_t
skSilkPythonAddFields(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*data))
{
    skplugin_err_t err;

    /* Check API version */
    err = skpinSimpleCheckVersion(major_version, minor_version,
                                  PLUGIN_API_VERSION_MAJOR,
                                  PLUGIN_API_VERSION_MINOR,
                                  skAppPrintErr);
    if (err != SKPLUGIN_OK) {
        return err;
    }

    /* rwfilter command-line options */
    skpinRegOption2(python_file_option, REQUIRED_ARG,
                    ("Will execute the filter functions registered\n"
                     "\tby 'register_filter' from the given file "
                     "over all the records"),
                    NULL, silkpython_handle_python_file, NULL,
                    1, SKPLUGIN_FN_FILTER);
    skpinRegOption2(python_expr_option, REQUIRED_ARG,
                    ("Uses the return value of given python expression\n"
                     "\tas the pass/fail determiner (flow "
                     "record is called \"" PYREC_NAME "\")"),
                    NULL, silkpython_handle_python_expr, NULL,
                    1, SKPLUGIN_FN_FILTER);

    /* rwcut, rwsort, ... command line options */
    skpinRegOption2(python_file_option, REQUIRED_ARG,
                    ("Uses the field data registered by\n"
                     "\t'register_field' in the given "
                     "python file as extra fields"),
                    NULL, silkpython_handle_python_file, NULL,
                    3, SKPLUGIN_FN_REC_TO_BIN, SKPLUGIN_FN_REC_TO_TEXT,
                    SKPLUGIN_FN_ADD_REC_TO_BIN);

    return SKPLUGIN_OK;
}

/* Python initialization */
static int
silkpython_python_init(
    void)
{
    PyObject       *pysilk_module = NULL;
    PyObject       *result        = NULL;
    int             retval        = 0;

    if (Py_IsInitialized()) {
        return 0;
    }

    /* We are not thread safe */
    skpinSetThreadNonSafe();

    /* Register the function that creates the silk.pysilk_pin module */
    PyImport_AppendInittab("silk." PYSILK_PIN_STR, PYSILK_PIN_INIT);

    /* Initialize the python interpreter */
    Py_InitializeEx(0);

    /* Import the silk modules */
    silk_module = PyImport_ImportModule("silk");
    if (silk_module == NULL) {
        skAppPrintErr("Could not load the \"silk\" python module");
        goto err;
    }

    /* Import the silk plugin module */
    plugin_module = PyImport_ImportModule("silk.plugin");
    if (plugin_module == NULL) {
        skAppPrintErr("Could not load the \"silk.plugin\" python module");
        goto err;
    }

    /* Initialize the silk plugin module */
    result = PyObject_CallMethod(plugin_module, "_init_silkpython_plugin",
                                 "s", skAppName());
    if (result == NULL) {
        goto err;
    }

    /* Get a handle to silk.pysilk_pin */
    pysilk_module = PyImport_ImportModule("silk." PYSILK_PIN_STR);
    if (pysilk_module == NULL) {
        skAppPrintErr("Could not load the \"silk." PYSILK_PIN_STR
                      "\" python module");
        goto err;
    }

    /* Get conversion functions for rwrec objects  */
    rwrec_to_raw_python = PyObject_GetAttrString(pysilk_module,
                                                 "_raw_rwrec_copy");
    if (rwrec_to_raw_python == NULL) {
        skAppPrintErr("Could not find the \"silk._raw_rwrec_copy\" function");
        goto err;
    }
    rwrec_to_python_fn = PyObject_GetAttrString(silk_module, "RWRec");
    if (rwrec_to_python_fn == NULL) {
        skAppPrintErr("Could not find the \"silk.RWRec\" function");
        goto err;
    }

    /* Create a keyword dictionary used in creating rwrec objects */
    kwd_dict = PyDict_New();
    if (kwd_dict == NULL) {
        goto err;
    }

    /* Create an empty tuple used in creating rwrec objects */
    empty_tuple = PyTuple_New(0);
    if (empty_tuple == NULL) {
        goto err;
    }

    /* Create an empty CObject (Arg is ignored, but can't be NULL.) */
    python_rec = COBJ_CREATE(empty_tuple);
    if (python_rec == NULL) {
        goto err;
    }

    refchain = PyList_New(0);
    if (refchain == NULL) {
        goto err;
    }

  cleanup:
    Py_XDECREF(pysilk_module);
    Py_XDECREF(result);

    return retval;

  err:
    if (PyErr_Occurred()) {
        PyErr_Print();
        PyErr_Clear();
    }
    retval = -1;
    goto cleanup;
}


/* Cleanup for python globals */
static void
silkpython_uninitialize(
    void)
{
    if (Py_IsInitialized()) {
        Py_CLEAR(rwrec_to_raw_python);
        Py_CLEAR(rwrec_to_python_fn);
        Py_CLEAR(python_rec);
        Py_CLEAR(empty_tuple);
        Py_CLEAR(kwd_dict);
        Py_CLEAR(plugin_module);
        Py_CLEAR(silk_module);
        Py_CLEAR(refchain);

        Py_Finalize();
    }
}


/* Initialization for reading a python file.  Returns the global
 * dictionary after reading the file. */
static PyObject *
silkpython_file_init(
    skstream_t         *stream)
{
    int         rv;
    size_t      size;
    size_t      remain;
    char       *loc;
    ssize_t     num_read;
    char       *contents = NULL;
    PyObject   *builtins = NULL;
    PyObject   *compiled = NULL;
    PyObject   *none     = NULL;
    PyObject   *all      = NULL;
    PyObject   *name     = NULL;
    PyObject   *function = NULL;
    PyObject   *globals  = NULL;
    PyObject   *dotpath  = NULL;
    const char *python_filename;
    PyObject   *path;
    int         all_len;
    int         i;

    /* Ensure cwd is in the python path */
    path = PySys_GetObject("path");
    if (path == NULL) {
        goto err;
    }
    dotpath = STRING_FROM_STRING(".");
    if (dotpath == NULL) {
        goto err;
    }
    rv = PySequence_SetSlice(path, 0, 0, dotpath);
    if (rv != 0) {
        goto err;
    }

    /* Create a global context */
    globals = PyDict_New();
    if (globals == NULL) {
        goto err;
    }

    /* Add functions from the plugin module to the current globals */
    all = PyObject_GetAttrString(plugin_module, "__all__");
    if (all == NULL) {
        goto err;
    }
    all_len = PySequence_Size(all);
    if (all_len == -1) {
        goto err;
    }
    for (i = 0; i < all_len; i++) {
        name = PySequence_GetItem(all, i);
        if (name == NULL) {
            goto err;
        }

        function = PyObject_GetAttr(plugin_module, name);
        if (function == NULL) {
            goto err;
        }

        rv = PyDict_SetItem(globals, name, function);
        if (rv != 0) {
            goto err;
        }
        Py_CLEAR(function);
        Py_CLEAR(name);
    }

    /* Set up data storage for reading in a python file */
    contents = (char*)malloc(FILE_BLOCK_SIZE);
    if (contents == NULL) {
        skAppPrintErr("Memory error setting up file block");
        goto err;
    }

    /* Read the stream's data into contents */
    loc = contents;
    size = FILE_BLOCK_SIZE;
    remain = size;
    while ((num_read = skStreamRead(stream, loc, remain)) > 0) {
        remain -= num_read;
        loc += num_read;
        if (remain == 0) {
            char *realloced;

            size += FILE_BLOCK_SIZE;
            realloced = (char*)realloc(contents, size);
            if (realloced == NULL) {
                skAppPrintOutOfMemory("resize file block");
                goto err;
            }
            remain = FILE_BLOCK_SIZE;
            contents = realloced;
            loc = contents + (size - FILE_BLOCK_SIZE);
        }
    }
    if (num_read != 0) {
        skAppPrintErr("Read error: %s",
                      strerror(skStreamGetLastErrno(stream)));
        goto err;
    }
    python_filename = skStreamGetPathname(stream);
    if (python_filename == NULL) {
        python_filename = "<unknown>";
    }

    /* Import the builtins module */
    builtins = PyImport_ImportModule(BUILTINS);
    if (builtins == NULL) {
        skAppPrintErr("Could not load the \"" BUILTINS "\" module");
        goto err;
    }

    /* Compile the code */
    compiled = PyObject_CallMethod(builtins, "compile", "s#ss",
                                   contents, loc - contents,
                                   python_filename, "exec");
    if (compiled == NULL) {
        skAppPrintErr("Could not compile %s", python_filename);
        goto err;
    }

    /* Then evaluate the code, putting the result in the
       python_globals */
    none = PyObject_CallMethod(builtins, "eval", "OO", compiled, globals);
    if (none == NULL || PyErr_Occurred()) {
        skAppPrintErr("Could not parse %s", python_filename);
        goto err;
    }

  cleanup:
    free(contents);
    Py_XDECREF(dotpath);
    Py_XDECREF(builtins);
    Py_XDECREF(compiled);
    Py_XDECREF(none);
    Py_XDECREF(function);
    Py_XDECREF(name);
    Py_XDECREF(all);

    return globals;

  err:
    if (PyErr_Occurred()) {
        PyErr_Print();
        PyErr_Clear();
    }
    Py_CLEAR(globals);
    goto cleanup;
}


/* Initialization for reading a python expression */
static PyObject *
silkpython_expr_init(
    const char         *python_expr)
{
    /* Create and compile an expression as a function */
    static const char *prefix = ("def " PYFILTER_NAME "(" PYREC_NAME "): "
                                 "return ");
    size_t  len         = strlen(prefix) + strlen(python_expr);
    char   *command     = (char *)malloc(len + 1);

    int       rv;
    PyObject *builtins = NULL;
    PyObject *compiled = NULL;
    PyObject *globals  = NULL;
    PyObject *none     = NULL;
    PyObject *filter;


    if (command == NULL) {
        skAppPrintErr("Memory error allocating string");
        goto err;
    }

    /* Generate the function */
    strcpy(command, prefix);
    strcat(command, python_expr);

    /* Create a global context */
    globals = PyDict_New();
    if (globals == NULL) {
        goto err;
    }

    /* Import the builtins module */
    builtins = PyImport_ImportModule(BUILTINS);
    if (builtins == NULL) {
        skAppPrintErr("Could not load the \"" BUILTINS "\" module");
        goto err;
    }

    /* Compile the function */
    compiled = PyObject_CallMethod(builtins, "compile", "sss",
                                   command, "<command-line>", "exec");
    if (compiled == NULL) {
        skAppPrintErr("Could not compile python expression");
        goto err;
    }

    /* Add the silk module to the python_globals, so the function
       can use it */
    rv = PyDict_SetItemString(globals, "silk", silk_module);
    if (rv != 0) {
        skAppPrintErr("Python dictionary error");
        goto err;
    }

    /* Evaluate the function, putting the result in
       python_globals */
    none = PyObject_CallMethod(builtins, "eval", "OO", compiled, globals);
    if (none == NULL || PyErr_Occurred()) {
        skAppPrintErr("Could not parse python expression");
        goto err;
    }
    Py_DECREF(none);

    filter = PyDict_GetItemString(globals, PYFILTER_NAME);
    assert(filter);

    none = PyObject_CallMethod(plugin_module, "register_filter", "O", filter);

  cleanup:
    if (command) {
        free(command);
    }
    Py_XDECREF(builtins);
    Py_XDECREF(compiled);
    Py_XDECREF(none);

    return globals;

  err:
    if (PyErr_Occurred()) {
        PyErr_Print();
        PyErr_Clear();
    }
    Py_CLEAR(globals);
    goto cleanup;
}

static int
register_fieldlike(
    PyObject           *o)
{
    PyObject                  *obj;
    size_t                     width_text    = 0;
    size_t                     width_bin     = 0;
    const uint8_t             *initial_value = NULL;
    const char                *name;
    const char                *description   = NULL;
    skplugin_callback_fn_t     init_fn       = NULL;
    skplugin_text_fn_t         rec_to_text   = NULL;
    skplugin_bin_fn_t          rec_to_bin    = NULL;
    skplugin_bin_fn_t          add_to_bin    = NULL;
    skplugin_bin_to_text_fn_t  bin_to_text   = NULL;
    skplugin_bin_merge_fn_t    bin_merge     = NULL;
    skplugin_bin_cmp_fn_t      bin_compare   = NULL;
    skplugin_err_t             err;
    skplugin_callbacks_t       regdata;

    if (PyTuple_GET_SIZE(o) != FIELD_INDEX_MAX) {
        skAppPrintErr("Incorrect number of entries for a field");
        return -1;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_NAME);
    if (obj == NULL) {
        return -1;
    }
    name = PyBytes_AS_STRING(obj);
    if (name == NULL) {
        skAppPrintErr("Memory error copying field name");
        return -1;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_DESCRIPTION);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        description = PyBytes_AS_STRING(obj);
        if (description == NULL) {
            skAppPrintErr("Memory error copying field documentation");
            return -1;
        }
    }

    obj = PyTuple_GET_ITEM(o, FIELD_INIT);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        init_fn = silkpython_field_init;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_COLUMN_LEN);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        width_text = PyLong_AsLong(obj);
    }
    obj = PyTuple_GET_ITEM(o, FIELD_BIN_LEN);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        width_bin = PyLong_AsLong(obj);
    }

    obj = PyTuple_GET_ITEM(o, FIELD_BIN_TO_TEXT);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        bin_to_text = silkpython_bin_to_text;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_ADD_TO_BIN);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        add_to_bin = silkpython_add_to_bin;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_BIN_MERGE);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        bin_merge = silkpython_bin_merge;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_BIN_COMPARE);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        bin_compare = silkpython_bin_compare;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_INITIAL_VALUE);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        initial_value = (uint8_t *)PyBytes_AS_STRING(obj);
        if (initial_value == NULL) {
            skAppPrintErr("Memory error copying field initial value");
            return -1;
        }
    }

    obj = PyTuple_GET_ITEM(o, FIELD_REC_TO_BIN);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        rec_to_bin = silkpython_get_bin;
    }

    obj = PyTuple_GET_ITEM(o, FIELD_REC_TO_TEXT);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        rec_to_text = silkpython_get_text;
    }

    memset(&regdata, 0, sizeof(regdata));

    regdata.init           = init_fn;
    regdata.column_width   = width_text;
    regdata.bin_bytes      = width_bin;
    regdata.add_rec_to_bin = add_to_bin;
    regdata.bin_to_text    = bin_to_text;
    regdata.bin_merge      = bin_merge;
    regdata.bin_compare    = bin_compare;
    regdata.initial        = initial_value;
    regdata.rec_to_text    = rec_to_text;
    regdata.rec_to_bin     = rec_to_bin;
    regdata.bin_to_text    = bin_to_text;

    err = skpinRegField(NULL, name, description, &regdata, o);
    if (err != SKPLUGIN_OK) {
        return -1;
    }

    if (PyList_Append(refchain, o)) {
        return -1;
    }

    return 0;
}


static int
register_filter(
    PyObject           *o)
{
    skplugin_err_t          err;
    PyObject               *obj;
    skplugin_callback_fn_t  init_fn  = NULL;
    skplugin_filter_fn_t    filter   = NULL;
    skplugin_callback_fn_t  finalize = NULL;
    skplugin_callbacks_t    regdata;

    if (PyTuple_GET_SIZE(o) != FILTER_INDEX_MAX) {
        skAppPrintErr("Incorrect number of entries for a filter");
        return -1;
    }

    obj = PyTuple_GET_ITEM(o, FILTER_FILTER);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        filter = silkpython_filter;
    }

    obj = PyTuple_GET_ITEM(o, FILTER_INIT);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        init_fn = silkpython_filter_init;
    }

    obj = PyTuple_GET_ITEM(o, FILTER_FINALIZE);
    if (obj == NULL) {
        return -1;
    }
    if (obj != Py_None) {
        finalize = silkpython_filter_finalize;
    }

    memset(&regdata, 0, sizeof(regdata));

    regdata.init = init_fn;
    regdata.cleanup = finalize;
    regdata.filter = filter;

    err = skpinRegFilter(NULL, &regdata, o);
    if (err != SKPLUGIN_OK) {
        return -1;
    }

    if (PyList_Append(refchain, o)) {
        return -1;
    }

    return 0;
}


/* Python command line argument handler callback */
static skplugin_err_t
silkpython_handle_option(
    const char         *opt_arg,
    void               *cbdata)
{
    PyObject *rv;
    PyObject *fn = (PyObject *)cbdata;

    if (opt_arg) {
        rv = PyObject_CallFunction(fn, "s", opt_arg);
    } else {
        rv = PyObject_CallFunctionObjArgs(fn, NULL);
    }
    if (rv == NULL) {
        if (PyErr_Occurred()) {
            PyErr_Print();
            PyErr_Clear();
        }
        return SKPLUGIN_ERR_FATAL;
    }
    Py_DECREF(rv);

    /* If the option handler registered any fields, we need to notice
     * that now. */
    if (silkpython_register()) {
        return SKPLUGIN_ERR;
    }

    return SKPLUGIN_OK;
}


/* Register command line arguments */
static int
silkpython_register_switches(
    void)
{
    PyObject *seq  = NULL;
    PyObject *fast = NULL;
    PyObject **o;
    int       num_entries;
    int       i;
    int       retval = 0;

    /* Get command line argument data for plugin */
    seq = PyObject_CallMethod(plugin_module, "_get_cmd_line_args", NULL);
    fast = PySequence_Fast(seq, "Invalid sequence");
    if (fast == NULL) {
        goto err;
    }
    num_entries = PySequence_Fast_GET_SIZE(fast);
    if (num_entries < 0) {
        goto err;
    }
    for (i = 0, o = PySequence_Fast_ITEMS(fast);
         i < num_entries;
         i++, o++)
    {
        const char          *name;
        const char          *help;
        int                  rv;
        skplugin_arg_mode_t  arg;
        skplugin_err_t       p_err;
        PyObject            *obj;

        obj = PyTuple_GET_ITEM(*o, SWITCH_NAME);
        if (obj == NULL) {
            goto err;
        }
        name = PyBytes_AsString(obj);
        if (name == NULL) {
            goto err;
        }

        obj = PyTuple_GET_ITEM(*o, SWITCH_ARG);
        if (obj == NULL) {
            goto err;
        }
        rv = PyObject_IsTrue(obj);
        if (rv == -1) {
            goto err;
        }
        arg = rv ? REQUIRED_ARG : NO_ARG;

        obj = PyTuple_GET_ITEM(*o, SWITCH_HELP);
        if (obj == NULL) {
            goto err;
        }
        help = PyBytes_AsString(obj);
        if (help == NULL) {
            goto err;
        }

        obj = PyTuple_GET_ITEM(*o, SWITCH_HANDLER);
        if (obj == NULL) {
            goto err;
        }

        p_err = skpinRegOption2(name, arg, help, NULL,
                                silkpython_handle_option, obj,
                                1, SKPLUGIN_FN_ANY);
        if (p_err != SKPLUGIN_OK) {
            goto err;
        }

        if (PyList_Append(refchain, obj)) {
            goto err;
        }
    }

  cleanup:
    Py_XDECREF(seq);
    Py_XDECREF(fast);

    return retval;

  err:
    if (PyErr_Occurred()) {
        PyErr_Print();
        PyErr_Clear();
    }
    retval = -1;
    goto cleanup;

}


/* Register all the fields and functions with the plugin library */
static int
silkpython_register(
    void)
{
    PyObject  *seq    = NULL;
    PyObject  *fast   = NULL;
    PyObject **o;
    int        num_entries;
    int        i;
    int        rv;
    int        retval = 0;

    if (ignore_plugin) {
        return 0;
    }

    /* Get filter data for plugins */
    seq = PyObject_CallMethod(plugin_module, "_get_filter_data", NULL);
    fast = PySequence_Fast(seq, "Invalid sequence");
    if (fast == NULL) {
        goto err;
    }
    num_entries = PySequence_Fast_GET_SIZE(fast);
    if (num_entries < 0) {
        goto err;
    }
    for (i = 0, o = PySequence_Fast_ITEMS(fast);
         i < num_entries;
         i++, o++)
    {
        rv = register_filter(*o);
        if (rv != 0) {
            goto err;
        }
    }
    Py_DECREF(seq);
    Py_DECREF(fast);

    /* Get field data for plugins */
    seq = PyObject_CallMethod(plugin_module, "_get_field_data", NULL);
    fast = PySequence_Fast(seq, "Invalid sequence");
    if (fast == NULL) {
        goto err;
    }
    num_entries = PySequence_Fast_GET_SIZE(fast);
    if (num_entries < 0) {
        goto err;
    }
    for (i = 0, o = PySequence_Fast_ITEMS(fast);
         i < num_entries;
         i++, o++)
    {
        rv = register_fieldlike(*o);
        if (rv != 0) {
            goto err;
        }
    }

  cleanup:
    Py_XDECREF(seq);
    Py_XDECREF(fast);

    return retval;

  err:
    if (PyErr_Occurred()) {
        PyErr_Print();
        PyErr_Clear();
    }
    retval = -1;
    goto cleanup;
}


/* This function creates an RWRec python object from a C rwRec pointer */
static PyObject *
rwrec_to_python(
    const rwRec        *rwrec)
{
    int       rv;
    PyObject *rawrec;
    PyObject *rec;

    assert(!ignore_plugin);

    rv = COBJ_SETPTR(python_rec, (rwRec *)rwrec);
    if (COBJ_SETPTR_FAILED(rv)) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    rawrec = PyObject_CallFunctionObjArgs(rwrec_to_raw_python,
                                          python_rec, NULL);
    if (rawrec == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    rv = PyDict_SetItemString(kwd_dict, "_clone", rawrec);
    if (rv != 0) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    Py_DECREF(rawrec);

    rec = PyObject_Call(rwrec_to_python_fn, empty_tuple, kwd_dict);
    if (rec == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    return rec;
}


/* Filter based on an rwrec */
static skplugin_err_t
silkpython_filter(
    const rwRec            *rwrec,
    void                   *data,
    void           UNUSED(**extra))
{
    PyObject *obj = (PyObject *)data;
    PyObject *fun;
    PyObject *retval;
    PyObject *rec;
    int       rv;

    assert(!ignore_plugin);

    fun = PyTuple_GET_ITEM(obj, FILTER_FILTER);
    assert(fun != NULL);
    Py_INCREF(fun);

    rec = rwrec_to_python(rwrec);

    retval = PyObject_CallFunctionObjArgs(fun, rec, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    rv = PyObject_IsTrue(retval);
    Py_DECREF(fun);
    Py_DECREF(retval);
    Py_DECREF(rec);

    return (rv == 1) ? SKPLUGIN_FILTER_PASS : SKPLUGIN_FILTER_FAIL;
}


static skplugin_err_t
silkpython_x_call(
    int                 offset,
    void               *data)
{
    PyObject *obj = (PyObject *)data;
    PyObject *fun;
    PyObject *retval;

    fun = PyTuple_GET_ITEM(obj, offset);
    assert(fun != NULL);
    Py_INCREF(fun);

    retval = PyObject_CallFunctionObjArgs(fun, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    Py_DECREF(fun);
    Py_DECREF(retval);

    return SKPLUGIN_OK;
}


static skplugin_err_t
silkpython_field_init(
    void               *data)
{
    return silkpython_x_call(FIELD_INIT, data);
}


static skplugin_err_t
silkpython_filter_init(
    void               *data)
{
    return silkpython_x_call(FILTER_INIT, data);
}


static skplugin_err_t
silkpython_filter_finalize(
    void               *data)
{
    return silkpython_x_call(FILTER_FINALIZE, data);
}


/* Create a text value from an rwrec */
static skplugin_err_t
silkpython_get_text(
    const rwRec            *rwrec,
    char                   *dest,
    size_t                  width,
    void                   *data,
    void           UNUSED(**extra))
{
    PyObject *obj = (PyObject *)data;
    PyObject *fun;
    PyObject *rec;
    PyObject *retval;
    PyObject *str;
    PyObject *bytes;

    fun = PyTuple_GET_ITEM(obj, FIELD_REC_TO_TEXT);
    assert(fun != NULL);
    Py_INCREF(fun);

    rec = rwrec_to_python(rwrec);

    retval = PyObject_CallFunctionObjArgs(fun, rec, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    Py_DECREF(fun);
    Py_DECREF(rec);

    str = PyObject_Str(retval);
    Py_DECREF(retval);
    if (str == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    bytes = bytes_from_string(str);
    Py_DECREF(str);
    if (bytes == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    snprintf(dest, width, "%s", PyBytes_AS_STRING(bytes));

    return SKPLUGIN_OK;
}


/* Create a binary value from an rwrec */
static skplugin_err_t
silkpython_get_bin(
    const rwRec            *rwrec,
    uint8_t                *dest,
    void                   *data,
    void           UNUSED(**extra))
{
    PyObject *obj = (PyObject *)data;
    PyObject *fun;
    PyObject *rec;
    PyObject *retval;
    char     *str;
    ssize_t   slen;
    ssize_t   len;

    fun = PyTuple_GET_ITEM(obj, FIELD_REC_TO_BIN);
    assert(fun != NULL);
    Py_INCREF(fun);

    len = PyLong_AsLong(PyTuple_GET_ITEM(obj, FIELD_BIN_LEN));

    rec = rwrec_to_python(rwrec);

    retval = PyObject_CallFunctionObjArgs(fun, rec, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    Py_DECREF(fun);
    Py_DECREF(rec);

    str = PyBytes_AsString(retval);
    if (str == NULL) {
        PyErr_Print();
        PyErr_Clear();
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    slen = PyBytes_GET_SIZE(retval);
    if (slen != len) {
        skAppPrintErr("Binary bin value returned from python is the "
                      "wrong length");
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    memcpy(dest, str, len);
    Py_DECREF(retval);

    return SKPLUGIN_OK;
}


/* Add to a binary value from an rwrec */
static skplugin_err_t
silkpython_add_to_bin(
    const rwRec            *rwrec,
    uint8_t                *dest,
    void                   *data,
    void           UNUSED(**extra))
{
    PyObject *obj = (PyObject *)data;
    PyObject *fun;
    PyObject *pdest;
    PyObject *rec;
    PyObject *retval;
    char     *str;
    ssize_t   slen;
    ssize_t   len;

    fun = PyTuple_GET_ITEM(obj, FIELD_ADD_TO_BIN);
    assert(fun != NULL);
    Py_INCREF(fun);

    len = PyLong_AsLong(PyTuple_GET_ITEM(obj, FIELD_BIN_LEN));
    pdest = PyBytes_FromStringAndSize((char *)dest, len);
    if (pdest == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    rec = rwrec_to_python(rwrec);

    retval = PyObject_CallFunctionObjArgs(fun, rec, pdest, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    Py_DECREF(fun);
    Py_DECREF(rec);
    Py_DECREF(pdest);

    str = PyBytes_AsString(retval);
    if (str == NULL) {
        PyErr_Print();
        PyErr_Clear();
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    slen = PyBytes_GET_SIZE(retval);
    if (slen != len) {
        skAppPrintErr("Binary bin value returned from python is the "
                      "wrong length");
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    memcpy(dest, str, len);
    Py_DECREF(retval);

    return SKPLUGIN_OK;
}


/* Convert from binary value to text */
static skplugin_err_t
silkpython_bin_to_text(
    const uint8_t      *bin_value,
    char               *dest,
    size_t              width,
    void               *data)
{
    PyObject *obj = (PyObject *)data;
    PyObject *bin;
    PyObject *pystr;
    PyObject *bytes;
    PyObject *fun;
    PyObject *retval;
    ssize_t   len;

    Py_INCREF(obj);

    len = PyLong_AsLong(PyTuple_GET_ITEM(obj, FIELD_BIN_LEN));
    bin = PyBytes_FromStringAndSize((char *)bin_value, len);
    if (bin == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    fun = PyTuple_GET_ITEM(obj, FIELD_BIN_TO_TEXT);
    assert(fun != NULL);
    Py_INCREF(fun);
    Py_DECREF(obj);

    retval = PyObject_CallFunctionObjArgs(fun, bin, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    Py_DECREF(fun);
    Py_DECREF(bin);

    pystr = PyObject_Str(retval);
    Py_DECREF(retval);
    if (pystr == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    bytes = bytes_from_string(pystr);
    Py_DECREF(pystr);
    if (bytes == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }

    snprintf(dest, width, "%s", PyBytes_AS_STRING(bytes));
    Py_DECREF(bytes);

    return SKPLUGIN_OK;
}

/* Do a merge operation */
static skplugin_err_t
silkpython_bin_merge(
    uint8_t            *dest,
    const uint8_t      *src,
    void               *data)
{
    PyObject *obj = (PyObject *)data;
    PyObject *pdest;
    PyObject *psrc;
    PyObject *fun;
    PyObject *retval;
    char     *str;
    ssize_t   slen;
    ssize_t   len;

    Py_INCREF(obj);

    len = PyLong_AsLong(PyTuple_GET_ITEM(obj, FIELD_BIN_LEN));
    pdest = PyBytes_FromStringAndSize((char *)dest, len);
    if (pdest == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    psrc = PyBytes_FromStringAndSize((char *)src, len);
    if (psrc == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    fun = PyTuple_GET_ITEM(obj, FIELD_BIN_MERGE);
    assert(fun != NULL);
    Py_INCREF(fun);
    Py_DECREF(obj);

    retval = PyObject_CallFunctionObjArgs(fun, pdest, psrc, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    Py_DECREF(fun);
    Py_DECREF(psrc);
    Py_DECREF(pdest);

    str = PyBytes_AsString(retval);
    if (str == NULL) {
        PyErr_Print();
        PyErr_Clear();
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    slen = PyBytes_GET_SIZE(retval);
    if (slen != len) {
        skAppPrintErr("Binary bin value returned from python is the "
                      "wrong length");
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    memcpy(dest, str, len);
    Py_DECREF(retval);

    return SKPLUGIN_OK;
}

/* Do a compare operation */
static skplugin_err_t
silkpython_bin_compare(
    int                *val,
    const uint8_t      *a,
    const uint8_t      *b,
    void               *data)
{
    PyObject   *obj = (PyObject *)data;
    PyObject   *pa;
    PyObject   *pb;
    PyObject   *fun;
    PyObject   *retval;
    ssize_t     len;

    Py_INCREF(obj);

    len = PyLong_AsLong(PyTuple_GET_ITEM(obj, FIELD_BIN_LEN));
    pa = PyBytes_FromStringAndSize((char *)a, len);
    if (pa == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    pb = PyBytes_FromStringAndSize((char *)b, len);
    if (pb == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    fun = PyTuple_GET_ITEM(obj, FIELD_BIN_COMPARE);
    assert(fun != NULL);
    Py_INCREF(fun);
    Py_DECREF(obj);

    retval = PyObject_CallFunctionObjArgs(fun, pa, pb, NULL);
    if (retval == NULL) {
        PyErr_Print();
        PyErr_Clear();
        exit(EXIT_FAILURE);
    }
    Py_DECREF(fun);
    Py_DECREF(pa);
    Py_DECREF(pb);

    if (!PyNumber_Check(retval)) {
        PyErr_SetString(PyExc_TypeError, ("Return value of comparison "
                                          "function must be an integer"));
        PyErr_Print();
        PyErr_Clear();
        Py_DECREF(retval);
        exit(EXIT_FAILURE);
    }

    /* PyNumber_AsSsize_t does not exist in Python 2.4.  PyObject_Cmp
     * does not exist in Python 3.x. */
#if PY_VERSION_HEX < 0x02050000
    {
        int rv;
        PyObject *zero = PyInt_FromLong(0);
        if (zero == NULL) {
            PyErr_Print();
            PyErr_Clear();
            exit(EXIT_FAILURE);
        }
        rv = PyObject_Cmp(retval, zero, val);
        Py_DECREF(retval);
        if (rv) {
            PyErr_Print();
            PyErr_Clear();
            exit(EXIT_FAILURE);
        }
    }
#else  /* PY_VERSION_HEX >= 0x02050000 */
    {
        Py_ssize_t rv = PyNumber_AsSsize_t(retval, NULL);
        Py_DECREF(retval);

        if (rv < 0) {
            *val = -1;
        } else if (rv > 0) {
            *val = 1;
        } else {
            *val = 0;
        }
    }
#endif  /* PY_VERSION_HEX */

    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
