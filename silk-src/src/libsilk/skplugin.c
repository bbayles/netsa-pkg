/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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
**  SiLK plugin implementation
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skplugin.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skdllist.h>
#include <silk/skplugin.h>
#include <silk/skstream.h>
#include <silk/skvector.h>
#include <dlfcn.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* the value of HANDLE_FIELD is a true value if the application
 * handles fields */
#define HANDLE_FIELD                                    \
    (skp_handle_type(SKPLUGIN_APP_CUT)                  \
     | skp_handle_type(SKPLUGIN_APP_SORT)               \
     | skp_handle_type(SKPLUGIN_APP_GROUP)              \
     | skp_handle_type(SKPLUGIN_APP_UNIQ_FIELD)         \
     | skp_handle_type(SKPLUGIN_APP_UNIQ_VALUE)         \
     | skp_handle_type(SKPLUGIN_APP_STATS_FIELD)        \
     | skp_handle_type(SKPLUGIN_APP_STATS_VALUE))

/* another macro to say whether an application supports fields */
#define SKPLUGIN_FNS_FIELD                      \
    (SKPLUGIN_APP_CUT |                         \
     SKPLUGIN_APP_SORT |                        \
     SKPLUGIN_APP_GROUP |                       \
     SKPLUGIN_APP_UNIQ_FIELD |                  \
     SKPLUGIN_APP_UNIQ_VALUE |                  \
     SKPLUGIN_APP_STATS_FIELD |                 \
     SKPLUGIN_APP_STATS_VALUE)

/* print a message and exit the application if memory for the object
 * 'x' is NULL */
#define CHECK_MEM(x)                                            \
    if (x) { /* no-op */ } else {                               \
        skAppPrintErr(("skplugin: unable to allocate memory"    \
                       " for object %s at %s:%d"),              \
                      #x, __FILE__, __LINE__);                  \
        abort();                                                \
    }

/*
 *  ASSERT_RESULT(ar_func_args, ar_type, ar_expected);
 *
 *    ar_func_args  -- is a function and any arugments it requires
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


/* members common to all three groups of plugins: (1) those that
 * filter, (2) those that transform, and (3) those that support
 * fields */
typedef struct skp_function_common_st {
    const char                 *plugin_name;
    skplugin_callback_fn_t      init;
    skplugin_callback_fn_t      cleanup;
    skplugin_callback_fn_t      cbfree;
    void                       *data;
    sk_dllist_t                *extra;
    ssize_t                    *extra_remap;
    size_t                      remap_size;
} skp_function_common_t;

/* filter identifier */
/* typedef struct skp_filter_st skplugin_filter_t; // skplugin.h */
typedef struct skp_filter_st {
    skp_function_common_t       common; /* Must be first element */
    skplugin_filter_fn_t        filter;
} skp_filter_t;

/* transformer identifier */
/* typedef struct skp_transform_st skplugin_transform_t; // skplugin.h */
typedef struct skp_transform_st {
    skp_function_common_t       common; /* Must be first element */
    skplugin_transform_fn_t     transform;
} skp_transform_t;

/* field identifier */
/* typedef struct skp_field_st skplugin_field_t;  // skplugin.h */
typedef struct skp_field_st {
    skp_function_common_t       common; /* Must be first element */
    skplugin_text_fn_t          rec_to_text;
    skplugin_bin_fn_t           rec_to_bin;
    skplugin_bin_fn_t           add_rec_to_bin;
    skplugin_bin_to_text_fn_t   bin_to_text;
    skplugin_bin_merge_fn_t     bin_merge;
    skplugin_bin_cmp_fn_t       bin_compare;
    skplugin_fn_mask_t          fn_mask;
    char                       *title;
    char                      **names;
    char                       *description;
    uint8_t                    *initial_value;
    size_t                      field_width_text;
    size_t                      field_width_bin;
} skp_field_t;


typedef struct skp_option_st {
    /* opt[1] is the sentinel */
    struct option         opt[2];
    skplugin_help_fn_t    help_fn;
    skplugin_option_fn_t  opt_fn;
    const char           *help_string;
    const char           *plugin_name;
    void                 *cbdata;
} skp_option_t;


/* LOCAL VARIABLE DEFINITIONS */

/* Whether to print debug information when loading a plugin */
static int skp_debug = 0;

/* Set to non-zero once skPluginSetup has been called */
static int skp_initialized = 0;

/* Set to non-zero when we are in the process of running a a plugin's
   setup function */
static int skp_in_plugin_init = 0;

/* The current operating plugin */
static const char *skp_current_plugin_name = NULL;

/* A list of plugin names */
static sk_dllist_t *skp_plugin_names = NULL;

/* Specifies the types of functionality the app wants from its
 * plugins */
static skplugin_fn_mask_t *skp_app_type = NULL;

/* Holds the extra arguments the application says it will handle */
static sk_dllist_t *skp_app_support_extra_args = NULL;

/* Holds the application extra arg array for the plugin to use */
static char **skp_app_extra_arg_array;

/* Holds the extra arguments the plugins require */
static sk_dllist_t *skp_plugin_extra_args = NULL;

/* Holds the plugin extra arg array for the app to use */
static char **skp_plugin_extra_arg_array;

/* Holds the extra arguments the application will actually use */
static sk_dllist_t *skp_app_use_extra_args = NULL;

/* Holds the command line option information */
static sk_dllist_t *skp_option_list = NULL;

/* Holds the filter functions */
static sk_dllist_t *skp_filter_list = NULL;

/* Holds the transform functions */
static sk_dllist_t *skp_transform_list = NULL;

/* Holds the list of fields */
static sk_dllist_t *skp_field_list = NULL;

/* Holds the list of active fields */
static sk_dllist_t *skp_active_field_list = NULL;

/* Holds the list of non-function specific plugin cleanup functions */
static sk_dllist_t *skp_cleanup_list = NULL;

/* The library dlopen() handles */
static sk_dllist_t *skp_library_list = NULL;

/* Function to call to open streams.  Applications may set this. */
static open_data_input_fn_t open_data_input_fn;

/* Whether the current set of loaded plugins are all thread-safe */
static int skp_thread_safe = 1;

/* Structure representing some members of the skplugin_callbacks_t
 * structure.  If the verbose flag is set and a field fails to be
 * registered because callback members are unset, this structure is
 * used find the missing members' names for the error message. */
static const struct skp_callback_string_st {
    const char *name;
    uint32_t    bit;
} skp_callback_string[] = {
    {"rec_to_bin",      SKPLUGIN_FN_REC_TO_BIN},
    {"add_rec_to_bin",  SKPLUGIN_FN_ADD_REC_TO_BIN},
    {"bin_to_text",     SKPLUGIN_FN_BIN_TO_TEXT},
    {"rec_to_text",     SKPLUGIN_FN_REC_TO_TEXT},
    {"bin_merge",       SKPLUGIN_FN_MERGE},
    {"bin_compare",     SKPLUGIN_FN_COMPARE},
    {"bin_bytes",       SKPLUGIN_FN_BIN_BYTES},
    {"column_width",    SKPLUGIN_FN_COLUMN_WIDTH},
    {NULL,              0}      /* sentinel */
};

/* A number whose length is greater than the sum of the lengths of the
 * above strings, including an extra 2 char padding per field. */
#define MAX_CALLBACKS_STRING_WIDTH 200


/* LOCAL FUNCTION PROTOTYPES */

static sk_dllist_t *skp_arg_list_from_array(const char **array);
static char **skp_arg_array_from_list(sk_dllist_t *list);
static char **skp_arg_array_from_string(const char *string);
static void skp_arg_array_destroy(char **array);
static void skp_arg_add_to_list(const char *arg, sk_dllist_t *list);
static void skp_arg_list_add_to_list(sk_dllist_t *src, sk_dllist_t *dest);
static int skp_arg_list_subset_of_list(sk_dllist_t *subset, sk_dllist_t *set);
static int skp_option_handler(clientData  cData, int opt_index, char *opt_arg);
static void skp_function_common_destroy(void *vcommon);
static void skp_function_field_destroy(void *vfield);
static skplugin_fn_mask_t skp_field_mask(const skplugin_callbacks_t *regdata);
static void
skp_setup_remap(
    skp_function_common_t  *common,
    sk_dllist_t            *extra_map);
static void **
skp_remap(
    const skp_function_common_t    *common,
    void                          **extra);
static int
skp_list_find(
    sk_dll_iter_t      *iter,
    const void         *target,
    sk_dllist_t        *fields);
static void skp_unload_library(void *handle);


/* FUNCTION DEFINITIONS */

/* return 1 if the application handles fields containing one of the
 * types listed in the 'fn_mask'; return 0 otherwise.  */
static int
skp_handle_type(
    skplugin_fn_mask_t  fn_mask)
{
    skplugin_fn_mask_t *mask;

    assert(skp_initialized);
    assert(skp_app_type);

    mask = skp_app_type;
    if (*mask == SKPLUGIN_FN_ANY) {
        return 1;
    }

    for ( ; *mask; ++mask) {
        if ((fn_mask & *mask) == fn_mask) {
            return 1;
        }
    }

    return 0;
}


static int
skp_handle_field(
    skp_field_t        *field,
    int                 verbose)
{
    skplugin_fn_mask_t *mask;

    assert(skp_initialized);
    assert(skp_app_type);
    assert(field);

    mask = skp_app_type;
    if (*mask == SKPLUGIN_FN_ANY) {
        return 1;
    }

    for ( ; *mask; ++mask) {
        if ((field->fn_mask & *mask) == *mask) {
            /* this application can use this field; return */
            return 1;
        }
        /* this field cannot be used; print an explanation if verbose
         * is set */
        if (verbose) {
            char missing_fields[MAX_CALLBACKS_STRING_WIDTH];
            char *pos = missing_fields;
            int len = sizeof(missing_fields);
            const struct skp_callback_string_st *cbs;
            int rv;
            int count = 0;

            for (cbs = skp_callback_string; cbs->name; ++cbs) {
                if ((*mask & cbs->bit) && !(field->fn_mask & cbs->bit)) {
                    rv = snprintf(pos, len, "%s%s",
                                  (count ? ", " : ""), cbs->name);
                    len -= rv;
                    pos += rv;
                    ++count;
                    if (len <= 0) {
                        skAbort();
                    }
                }
            }
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR ": ignoring field '%s' due "
                           "to missing skplugin_callbacks_t member%s %s"),
                          field->title, ((count > 1) ? "s" : ""),
                          missing_fields);
        }
    }

    return 0;
}


/* This is used to initialize the skplugin library.  'num_entries' is
 * the number of function mask entries in the vararg list. */
void
skPluginSetup(
    int                 num_entries,
    ...)
{
    va_list             ap;
    char               *env_value;
    int                 rv;
    skplugin_fn_mask_t  fn_mask;
    sk_vector_t        *app_type_vec;

    assert(!skp_initialized);
    assert(num_entries >= 0);

#ifndef NDEBUG
    /* verify MAX_CALLBACKS_STRING_WIDTH is large enough to hold a
     * comma-separated list of the names in skp_callback_string */
    {
        const struct skp_callback_string_st *cbs;
        size_t len;

        len = 0;
        for (cbs = skp_callback_string; cbs->name; ++cbs) {
            len += 2 + strlen(cbs->name);
        }
        assert(len < MAX_CALLBACKS_STRING_WIDTH);
    }
#endif  /* NDEBUG */

    /* Check for debugging */
    env_value = getenv(SKPLUGIN_DEBUG_ENVAR);
    if ((env_value != NULL) && (env_value[0] != '\0')) {
        skp_debug = 1;
    }

    /* Make the application type array */
    app_type_vec = skVectorNew(sizeof(skplugin_fn_mask_t));
    CHECK_MEM(app_type_vec);
    va_start(ap, num_entries);
    while (num_entries--) {
        fn_mask = va_arg(ap, skplugin_fn_mask_t);
        rv = skVectorAppendValue(app_type_vec, &fn_mask);
        CHECK_MEM(rv == 0);
    }
    fn_mask = 0;
    rv = skVectorAppendValue(app_type_vec, &fn_mask);
    CHECK_MEM(rv == 0);
    va_end(ap);
    skp_app_type = (skplugin_fn_mask_t*)calloc(skVectorGetCount(app_type_vec),
                                               sizeof(skplugin_fn_mask_t));
    CHECK_MEM(skp_app_type);
    skVectorToArray(skp_app_type, app_type_vec);
    skVectorDestroy(app_type_vec);

    /* Set once we have a proper skp_app_type */
    skp_initialized = 1;

    /* Create all the internal lists */
    skp_app_support_extra_args = skDLListCreate(free);
    CHECK_MEM(skp_app_support_extra_args);
    skp_app_extra_arg_array = NULL;
    skp_plugin_extra_args = skDLListCreate(free);
    CHECK_MEM(skp_plugin_extra_args);
    skp_plugin_extra_arg_array = NULL;
    skp_app_use_extra_args = skDLListCreate(free);
    CHECK_MEM(skp_app_use_extra_args);
    skp_option_list = skDLListCreate(free);
    CHECK_MEM(skp_option_list);
    if (skp_handle_type(SKPLUGIN_APP_FILTER)) {
        skp_filter_list = skDLListCreate(skp_function_common_destroy);
        CHECK_MEM(skp_filter_list);
    }
    if (skp_handle_type(SKPLUGIN_APP_TRANSFORM)) {
        skp_transform_list = skDLListCreate(skp_function_common_destroy);
        CHECK_MEM(skp_transform_list);
    }
    if (HANDLE_FIELD) {
        skp_field_list = skDLListCreate(skp_function_field_destroy);
        CHECK_MEM(skp_field_list);
        skp_active_field_list = skDLListCreate(NULL);
        CHECK_MEM(skp_active_field_list);
    }
    skp_cleanup_list = skDLListCreate(NULL);
    CHECK_MEM(skp_cleanup_list);
    skp_library_list = skDLListCreate(skp_unload_library);
    CHECK_MEM(skp_library_list);
    skp_plugin_names = skDLListCreate(free);
    CHECK_MEM(skp_plugin_names);
}


/* Unloads all plugins and frees all plugin data.  Does not call
 * cleanup functions. */
void
skPluginTeardown(
    void)
{
    assert(skp_initialized);

    skDLListDestroy(skp_app_support_extra_args);
    skp_arg_array_destroy(skp_app_extra_arg_array);
    skDLListDestroy(skp_plugin_extra_args);
    skp_arg_array_destroy(skp_plugin_extra_arg_array);
    skDLListDestroy(skp_app_use_extra_args);
    skDLListDestroy(skp_option_list);
    if (skp_handle_type(SKPLUGIN_APP_FILTER)) {
        skDLListDestroy(skp_filter_list);
    }
    if (skp_handle_type(SKPLUGIN_APP_TRANSFORM)) {
        skDLListDestroy(skp_transform_list);
    }
    if (HANDLE_FIELD) {
        skDLListDestroy(skp_field_list);
        skDLListDestroy(skp_active_field_list);
    }
    skDLListDestroy(skp_cleanup_list);
    skDLListDestroy(skp_plugin_names);

    free(skp_app_type);
    skp_app_type = NULL;

    /* Unload all the libraries */
    skDLListDestroy(skp_library_list);

    skp_initialized = 0;
}


/* Sets the extra arguments that the application handles.  'extra' is
 * a NULL terminated array of strings.  If 'extra' is NULL, no extra
 * arguments are registered.  (This is the default) */
void
skPluginSetAppExtraArgs(
    const char        **extra)
{
    assert(skp_initialized);

    skDLListDestroy(skp_app_support_extra_args);
    skDLListDestroy(skp_app_use_extra_args);

    /* These are the arguments this app supports */
    skp_app_support_extra_args = skp_arg_list_from_array(extra);

    /* By default, these are also the arguments this app will use.  To
     * change this, call skPluginSetUsedAppExtraArgs(). */
    skp_app_use_extra_args = skp_arg_list_from_array(extra);

    return;
}


/* Create an sk_dllist_t from a char ** */
static sk_dllist_t *
skp_arg_list_from_array(
    const char        **array)
{
    const char **arg;
    sk_dllist_t *list = skDLListCreate(free);

    CHECK_MEM(list);

    if (array == NULL) {
        return list;
    }

    for (arg = array; *arg != NULL; arg++) {
        char *arg_dup = strdup(*arg);

        CHECK_MEM(arg_dup);
        CHECK_MEM(0 == skDLListPushTail(list, arg_dup));
    }

    return list;
}

/* Create a char ** from a sk_dllist_t */
static char **
skp_arg_array_from_list(
    sk_dllist_t        *list)
{
    char          **array;
    size_t          count;
    size_t          i;
    sk_dll_iter_t   iter;
    const char     *arg;

    if (skDLListIsEmpty(list)) {
        return NULL;
    }

    /* Count the elements of the list */
    skDLLAssignIter(&iter, list);
    for (count = 0; skDLLIterForward(&iter, NULL) == 0; count++)
        ;  /* empty */

    /* Create the array */
    array = (char **)calloc(count + 1, sizeof(char *));
    CHECK_MEM(array);

    /* Fill the array */
    for (i = 0; skDLLIterForward(&iter, (void **)&arg); i++) {
        array[i] = strdup(arg);
        CHECK_MEM(array[i]);
    }

    return array;
}


/* Create a single entry char ** from a string */
static char **
skp_arg_array_from_string(
    const char         *str)
{
    char **array;

    /* Create the array */
    array = (char **)calloc(2, sizeof(char *));
    CHECK_MEM(array);

    /* Fill the array */
    array[0] = strdup(str);
    CHECK_MEM(array[0]);

    return array;
}


/* Destroy a char** */
static void
skp_arg_array_destroy(
    char              **array)
{
    char **arg;

    if (!array) {
        return;
    }

    for (arg = array; *arg; arg++) {
        free(*arg);
    }

    free(array);
}


/* Find the location of a string is in an arg list */
static ssize_t
skp_arg_location(
    const char         *arg,
    sk_dllist_t        *list)
{
    sk_dll_iter_t  iter;
    char          *list_arg;
    ssize_t        loc;

    skDLLAssignIter(&iter, list);
    for (loc = 0; skDLLIterForward(&iter, (void **)&list_arg) == 0; loc++) {
        if (strcmp(arg, list_arg) == 0) {
            return loc;
        }
    }

    return -1;
}


/* Add an argument uniquely to an argument list */
static void
skp_arg_add_to_list(
    const char         *arg,
    sk_dllist_t        *list)
{
    if (skp_arg_location(arg, list) == -1) {
        char *duplicate = strdup(arg);
        CHECK_MEM(duplicate);
        CHECK_MEM(0 == skDLListPushTail(list, duplicate));
    }
}


/* Add an elements of an argument list uniquely to another list */
static void
skp_arg_list_add_to_list(
    sk_dllist_t        *src,
    sk_dllist_t        *dest)
{
    sk_dll_iter_t  iter;
    const char    *arg;

    skDLLAssignIter(&iter, src);
    while (skDLLIterForward(&iter, (void **)&arg) == 0) {
        skp_arg_add_to_list(arg, dest);
    }
}



/* Check if an argumnt list is a subset of another argument list */
static int
skp_arg_list_subset_of_list(
    sk_dllist_t        *subset,
    sk_dllist_t        *set)
{
    const char    *arg;
    sk_dll_iter_t  iter;

    skDLLAssignIter(&iter, subset);

    while (skDLLIterForward(&iter, (void **)&arg) == 0) {
        if (skp_arg_location(arg, set) == -1) {
            return 0;
        }
    }

    return 1;
}

#if 0
/* Check to see if there is a duplicate name in a list of fields */
static int
skp_find_name(
    const char         *name,
    sk_dllist_t        *list)
{
    sk_dll_iter_t  iter;
    skp_field_t   *field;
    char         **fieldname;

    skDLLAssignIter(&iter, list);
    while (skDLLIterForward(&iter, (void **)&field) == 0) {
        for (fieldname = field->names; *fieldname; fieldname++) {
            if (strcasecmp(name, *fieldname) == 0) {
                return  1;
            }
        }
    }

    return 0;
}
#endif  /* 0 */


/* Gets the applications list of extra arguments as a NULL-terminated
 * list of strings. */
const char **
skpinGetAppExtraArgs(
    void)
{
    assert(skp_initialized);

    if (!skp_app_extra_arg_array) {
        assert(skp_app_support_extra_args);
        skp_app_extra_arg_array = skp_arg_array_from_list(
            skp_app_support_extra_args);
    }

    return (const char **)skp_app_extra_arg_array;
}


/* Gets the list of extra arguments of the application that the
 * plugins support.  The returned array will be a NULL-terminated list
 * of strings. */
const char **
skPluginGetPluginExtraArgs(
    void)
{
    assert(skp_initialized);

    if (!skp_plugin_extra_arg_array) {
        assert(skp_plugin_extra_args);
        skp_plugin_extra_arg_array = skp_arg_array_from_list(
            skp_plugin_extra_args);
    }

    return (const char **)skp_plugin_extra_args;
}


/* Sets which extra arguments the application will actually use.
 * 'extra' is a NULL * terminated array of strings.  If 'extra' is
 * NULL, no extra arguments are registered.  */
void
skPluginSetUsedAppExtraArgs(
    const char        **extra)
{
    sk_dll_iter_t    iter;
    skp_filter_t    *filt;
    skp_transform_t *transform;
    skp_field_t     *field;

    assert(skp_initialized);

    skDLListDestroy(skp_app_use_extra_args);
    skp_app_use_extra_args = skp_arg_list_from_array(extra);

    if (!skp_arg_list_subset_of_list(skp_app_use_extra_args,
                                     skp_app_support_extra_args))
    {
        skAppPrintErr("skPluginSetUsedAppExtraArgs: "
                      "Not subset of supported extra arguments");
        exit(EXIT_FAILURE);
    }

    skDLLAssignIter(&iter, skp_filter_list);
    while (skDLLIterForward(&iter, (void **)&filt) == 0) {
        skp_setup_remap(&filt->common, skp_app_use_extra_args);
    }

    skDLLAssignIter(&iter, skp_transform_list);
    while (skDLLIterForward(&iter, (void **)&transform) == 0) {
        skp_setup_remap(&transform->common, skp_app_use_extra_args);
    }

    skDLLAssignIter(&iter, skp_field_list);
    while (skDLLIterForward(&iter, (void **)&field) == 0) {
        skp_setup_remap(&field->common, skp_app_use_extra_args);
    }
}


/* Set function that skpinOpenDataInputStream() uses. */
void
skPluginSetOpenInputFunction(
    open_data_input_fn_t    open_fn)
{
    open_data_input_fn = open_fn;
}


/* Create and open a stream to process 'filename'. */
int
skpinOpenDataInputStream(
    skstream_t        **stream,
    skcontent_t         content_type,
    const char         *filename)
{
    int rv;

    assert(stream);
    assert(filename);

    if (open_data_input_fn) {
        return open_data_input_fn(stream, content_type, filename);
    }

    if ((rv = (skStreamCreate(stream, SK_IO_READ, content_type)))
        || (rv = skStreamBind((*stream), filename))
        || (rv = skStreamOpen(*stream)))
    {
        skStreamPrintLastErr((*stream), rv, &skAppPrintErr);
        skStreamDestroy(stream);
        return -1;
    }
    return 0;
}


/* Register an option for command-line processing.
 *   opt(opt_arg, data) will be called back when the option_name is
 *       seen as an option.  If no arg is given, opt_arg will be NULL.
 *   mode should be one of NO_ARG, OPTIONAL_ARG, or REQUIRED_ARG.
 *   num_entries is the number of app_types in the va-list.
 *   app_types should be SKPLUGIN_APP_ANY or a list of
 *       SKPLUGIN_APP_FILTER, SKPLUGIN_APP_CUT, etc.
 */
skplugin_err_t
skpinRegOption2(
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    const char             *option_help_string,
    skplugin_help_fn_t      option_help_fn,
    skplugin_option_fn_t    opt_callback_fn,
    void                   *callback_data,
    int                     num_entries,
    ...)
{
    va_list            ap;
    skplugin_fn_mask_t fn_mask;
    skplugin_err_t     rv = SKPLUGIN_ERR_DID_NOT_REGISTER;
    skp_option_t      *optrec;

    assert(skp_initialized);
    assert(skp_in_plugin_init);

    if (num_entries < 0) {
        skAbort();
    }
    if (NULL == option_name || NULL == opt_callback_fn) {
        return SKPLUGIN_ERR;
    }

    va_start(ap, num_entries);
    while (num_entries--) {
        fn_mask = va_arg(ap, skplugin_fn_mask_t);
        if (!skp_handle_type(fn_mask)) {
            continue;
        }

        optrec = (skp_option_t *)calloc(1, sizeof(*optrec));
        CHECK_MEM(optrec);

        optrec->opt[0].name = (char*)option_name;
        optrec->opt[0].has_arg = mode;
        optrec->help_string = option_help_string;
        optrec->help_fn = option_help_fn;
        optrec->opt_fn = opt_callback_fn;
        optrec->cbdata = callback_data;
        optrec->plugin_name = skp_current_plugin_name;

        if (0 != skOptionsRegister(optrec->opt, skp_option_handler, optrec)) {
            free(optrec);
            rv = SKPLUGIN_ERR_FATAL;
            break;
        }

        CHECK_MEM(0 == skDLListPushTail(skp_option_list, optrec));

        rv = SKPLUGIN_OK;
        break;
    }
    va_end(ap);

    return rv;
}

skplugin_err_t
skpinRegOption(
    skplugin_fn_mask_t      fn_mask,
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    const char             *option_help,
    skplugin_option_fn_t    opt,
    void                   *data)
{
    return skpinRegOption2(option_name, mode, option_help, NULL, opt, data,
                           1, fn_mask);
}

skplugin_err_t
skpinRegOptionWithHelpFn(
    skplugin_fn_mask_t      fn_mask,
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    skplugin_help_fn_t      option_help,
    skplugin_option_fn_t    opt,
    void                   *data)
{
    return skpinRegOption2(option_name, mode, NULL, option_help, opt, data,
                           1, fn_mask);
}


/* Option handler for plugin options */
static int
skp_option_handler(
    clientData          cData,
    int          UNUSED(opt_index),
    char               *opt_arg)
{
    skplugin_err_t  err;
    skp_option_t   *optrec              = (skp_option_t *)cData;
    int             save_in_plugin_init = skp_in_plugin_init;

    assert(optrec);

    skp_in_plugin_init = 1;
    skp_current_plugin_name = optrec->plugin_name;
    err = optrec->opt_fn(opt_arg, optrec->cbdata);
    skp_current_plugin_name = NULL;
    skp_in_plugin_init = save_in_plugin_init;

    return (err != SKPLUGIN_OK);
}


/* Called by plug-in to register a filter predicate. */
skplugin_err_t
skpinRegFilter(
    skp_filter_t                  **return_filter,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata)
{
    skp_filter_t *filter_data;
    sk_dllist_t  *extra;

    assert(skp_initialized);
    assert(skp_in_plugin_init);

    if (return_filter) {
        *return_filter = NULL;
    }

    if (!skp_handle_type(SKPLUGIN_FN_FILTER)) {
        return SKPLUGIN_OK;
    }

    assert(skp_filter_list);

    if (NULL == regdata) {
        if (skp_debug) {
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR
                           ": ignoring filter due to NULL regdata"));
        }
        return SKPLUGIN_ERR;
    }
    if (NULL == regdata->filter) {
        if (skp_debug) {
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR
                           ": ignoring filter due to NULL filter() callback"));
        }
        return SKPLUGIN_ERR;
    }

    extra = skp_arg_list_from_array(regdata->extra);
    CHECK_MEM(extra);

    if (!skp_arg_list_subset_of_list(extra, skp_app_support_extra_args)) {
        skAppPrintErr("skpinRegFilterWithExtraArgsDLL: "
                      "extra arguments required by plugin "
                      "not supported by application");
        exit(EXIT_FAILURE);
    }

    filter_data = (skp_filter_t *)calloc(1, sizeof(*filter_data));
    CHECK_MEM(filter_data);

    filter_data->common.plugin_name = skp_current_plugin_name;
    filter_data->common.init = regdata->init;
    filter_data->common.cleanup = regdata->cleanup;
    filter_data->common.extra = extra;
    filter_data->common.data = cbdata;
    filter_data->filter = regdata->filter;

    CHECK_MEM(0 == skDLListPushTail(skp_filter_list, filter_data));

    skp_arg_list_add_to_list(extra, skp_plugin_extra_args);

    skp_setup_remap(&filter_data->common, skp_app_support_extra_args);

    if (return_filter) {
        *return_filter = filter_data;
    }

    return SKPLUGIN_OK;
}


/* Called by plug-in to register a transformation predicate */
skplugin_err_t
skpinRegTransformer(
    skp_transform_t               **return_transformer,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata)
{
    skp_transform_t *transform_data;
    sk_dllist_t     *extra;

    assert(skp_initialized);
    assert(skp_in_plugin_init);

    if (return_transformer) {
        *return_transformer = NULL;
    }

    if (!skp_handle_type(SKPLUGIN_FN_TRANSFORM)) {
        return SKPLUGIN_OK;
    }

    assert(skp_transform_list);

    if (NULL == regdata) {
        if (skp_debug) {
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR
                           ": ignoring transformer due to NULL regdata"));
        }
        return SKPLUGIN_ERR;
    }
    if (NULL == regdata->transform) {
        if (skp_debug) {
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR
                           ": ignoring transformer due to NULL transform()"
                           " callback"));
        }
        return SKPLUGIN_ERR;
    }

    extra = skp_arg_list_from_array(regdata->extra);
    CHECK_MEM(extra);

    if (!skp_arg_list_subset_of_list(extra, skp_app_support_extra_args)) {
        skAppPrintErr("skpinRegTransformWithExtraArgsDLL: "
                      "extra arguments required by plugin "
                      "not supported by application");
        exit(EXIT_FAILURE);
    }

    transform_data = (skp_transform_t *)calloc(1, sizeof(*transform_data));
    CHECK_MEM(transform_data);

    transform_data->common.plugin_name = skp_current_plugin_name;
    transform_data->common.init = regdata->init;
    transform_data->common.cleanup = regdata->cleanup;
    transform_data->common.extra = extra;
    transform_data->common.data = cbdata;
    transform_data->transform = regdata->transform;

    CHECK_MEM(0 == skDLListPushTail(skp_transform_list, transform_data));

    skp_arg_list_add_to_list(extra, skp_plugin_extra_args);

    skp_setup_remap(&transform_data->common, skp_app_support_extra_args);

    if (return_transformer) {
        *return_transformer = transform_data;
    }

    return SKPLUGIN_OK;
}


/* Called by plug-in to register a field */
skplugin_err_t
skpinRegField(
    skplugin_field_t              **return_field,
    const char                     *name,
    const char                     *description,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata)
{
    skplugin_field_t *field;
    sk_dllist_t      *extra;

    assert(skp_initialized);
    assert(skp_in_plugin_init);

    if (return_field) {
        *return_field = NULL;
    }

    /* return if this application does not support fields */
    if (!HANDLE_FIELD) {
        return SKPLUGIN_OK;
    }

    assert(skp_field_list);

    if (!name) {
        if (skp_debug) {
            skAppPrintErr(SKPLUGIN_DEBUG_ENVAR
                          ": ignoring field due to NULL name");
        }
        return SKPLUGIN_ERR;
    }
    if (!regdata) {
        if (skp_debug) {
            skAppPrintErr((SKPLUGIN_DEBUG_ENVAR
                           ": ignoring field '%s' due to NULL regdata"),
                          name);
        }
        return SKPLUGIN_ERR;
    }
#if 0
    if (skp_find_name(name, skp_field_list)) {
        skAppPrintErr("A field already has the name, \"%s\"", name);
        return SKPLUGIN_ERR;
    }
#endif  /* 0 */

    extra = skp_arg_list_from_array(regdata->extra);
    CHECK_MEM(extra);

    if (!skp_arg_list_subset_of_list(extra, skp_app_support_extra_args)) {
        skAppPrintErr(("Error when registering field '%s': Extra arguments "
                       "required by plug-in not supported by application"),
                      name);
        exit(EXIT_FAILURE);
    }

    field = (skplugin_field_t *)calloc(1, sizeof(*field));
    CHECK_MEM(field);

    field->common.plugin_name = skp_current_plugin_name;
    field->common.init = regdata->init;
    field->common.cleanup = regdata->cleanup;
    field->common.extra = extra;
    field->common.data = cbdata;
    field->title = strdup(name);
    CHECK_MEM(field->title);
    if (description) {
        field->description = strdup(description);
        CHECK_MEM(field->description);
    }
    field->names = skp_arg_array_from_string(name);
    field->rec_to_text = regdata->rec_to_text;
    field->rec_to_bin = regdata->rec_to_bin;
    field->add_rec_to_bin = regdata->add_rec_to_bin;
    field->bin_to_text = regdata->bin_to_text;
    field->field_width_text = regdata->column_width;
    field->field_width_bin = regdata->bin_bytes;
    field->bin_merge = regdata->bin_merge;
    field->bin_compare = regdata->bin_compare;
    if (regdata->initial && regdata->bin_bytes) {
        field->initial_value = (uint8_t*)malloc(regdata->bin_bytes);
        CHECK_MEM(field->initial_value);
        memcpy(field->initial_value, regdata->initial, regdata->bin_bytes);
    }

    field->fn_mask = skp_field_mask(regdata);

    /* when debugging, complain when a field is not usable at all by
     * this application.  No messages are generated for key field that
     * cannot be used as aggregate value, and vice versa. */
    if (skp_debug && !skp_handle_field(field, 0)) {
        skp_handle_field(field, 1);
    }

    CHECK_MEM(0 == skDLListPushTail(skp_field_list, field));

    skp_arg_list_add_to_list(extra, skp_plugin_extra_args);

    skp_setup_remap(&field->common, skp_app_support_extra_args);

    if (return_field) {
        *return_field = field;
    }

    return SKPLUGIN_OK;
}


/* Adjust a field's field mask */
static skplugin_fn_mask_t
skp_field_mask(
    const skplugin_callbacks_t *regdata)
{
    skplugin_fn_mask_t mask = 0;

    if (regdata->bin_bytes) {
        mask |= SKPLUGIN_FN_BIN_BYTES;
    }
    if (regdata->column_width) {
        mask |= SKPLUGIN_FN_COLUMN_WIDTH;
    }
    if (regdata->rec_to_text) {
        mask |= SKPLUGIN_FN_REC_TO_TEXT;
    }
    if (regdata->rec_to_bin) {
        mask |= SKPLUGIN_FN_REC_TO_BIN;
    }
    if (regdata->add_rec_to_bin) {
        mask |= SKPLUGIN_FN_ADD_REC_TO_BIN;
    }
    if (regdata->bin_to_text) {
        mask |= SKPLUGIN_FN_BIN_TO_TEXT;
    }
    if (regdata->bin_merge) {
        mask |= SKPLUGIN_FN_MERGE;
    }
    if (regdata->bin_compare) {
        mask |= SKPLUGIN_FN_COMPARE;
    }
    if (regdata->filter) {
        mask |= SKPLUGIN_FN_FILTER;
    }
    if (regdata->transform) {
        mask |= SKPLUGIN_FN_TRANSFORM;
    }
    if (regdata->initial) {
        mask |= SKPLUGIN_FN_INITIAL;
    }

    return mask;
}


/*
 *    Returns the function mask for a field.
 */
skplugin_fn_mask_t
skPluginFieldFnMask(
    const skplugin_field_t *field)
{
    return field->fn_mask;
}


/* Destroy a skp_function_t object */
static void
skp_function_common_destroy(
    void               *vcommon)
{
    skp_function_common_t *common = (skp_function_common_t *)vcommon;

    if (common->extra) {
        skDLListDestroy(common->extra);
    }
    if (common->cbfree) {
        common->cbfree(common->data);
    }
    free(common);
}

/* Destroy a skp_field_t object */
static void
skp_function_field_destroy(
    void               *vfield)
{
    skp_field_t *field = (skp_field_t *)vfield;

    free(field->title);
    if (field->description) {
        free(field->description);
    }
    if (field->initial_value) {
        free(field->initial_value);
    }
    skp_arg_array_destroy(field->names);
    skp_function_common_destroy(vfield);
}


/* Create an extra arg remapping for a function */
static void
skp_setup_remap(
    skp_function_common_t  *common,
    sk_dllist_t            *extra_map)
{
    sk_dll_iter_t  iter;
    size_t         count;
    ssize_t        loc;
    size_t         i;
    int            out_of_order = 0;
    const char    *arg;

    if (common->extra_remap) {
        free(common->extra_remap);
        common->extra_remap = NULL;
        common->remap_size = 0;
    }

    skDLLAssignIter(&iter, common->extra);
    for (count = 0; skDLLIterForward(&iter, (void **)&arg) == 0; count++) {
        loc = skp_arg_location(arg, extra_map);
        assert(loc != -1);
        if (loc != (ssize_t)count) {
            out_of_order = 1;
        }
    }

    if (!out_of_order) {
        /* No mapping needed */
        return;
    }

    common->extra_remap = (ssize_t *)malloc(sizeof(ssize_t) * count);
    CHECK_MEM(common->extra_remap);
    skDLLAssignIter(&iter, common->extra);
    for (i = 0; i < count; i++) {
        ASSERT_RESULT(skDLLIterForward(&iter, (void **)&arg),
                      int, 0);
        loc = skp_arg_location(arg, extra_map);
        assert(loc != -1);
        common->extra_remap[i] = loc;
    }

    common->remap_size = count;
}


/* Remaps extra args from application order to plugin function order */
static void **
skp_remap(
    const skp_function_common_t    *common,
    void                          **extra)
{
    size_t   i;
    void   **remap = (void**)malloc(sizeof(void *) * common->remap_size);

    CHECK_MEM(remap);

    for (i = 0; i < common->remap_size; i++) {
        remap[i] = extra[common->extra_remap[i]];
    }

    return remap;
}

static skplugin_err_t
skPluginRunInitHelper(
    const skp_function_common_t    *common,
    const char                     *code_type)
{
    skplugin_err_t err = SKPLUGIN_OK;

    if (common->init) {
        skp_in_plugin_init = 1;
        err = common->init(common->data);
        skp_in_plugin_init = 0;
        if (err == SKPLUGIN_ERR_FATAL) {
            skAppPrintErr("Fatal error in initializing %s code", code_type);
            exit(EXIT_FAILURE);
        }
    }

    return err;
}


static skplugin_err_t
skPluginRunCleanupHelper(
    const skp_function_common_t    *common,
    const char                     *code_type)
{
    skplugin_err_t err = SKPLUGIN_OK;

    if (common->cleanup) {
        skp_in_plugin_init = 1;
        err = common->cleanup(common->data);
        skp_in_plugin_init = 0;
        if (err == SKPLUGIN_ERR_FATAL) {
            skAppPrintErr("Fatal error in cleaning up %s code", code_type);
            exit(EXIT_FAILURE);
        }
    }

    return err;
}


/*
 *    Runs the init routines for the apps and fields (if activated)
 *    listed.  If app does not include SKPLUGIN_APP_FIELDS, field_mask
 *    is ignored.  If this includes SKPLUGIN_APP_FIELDS, you should
 *    not run skPluginFieldRunInitialize on the individual fields,
 *    unless you know the initialization functions will be idempotent.
 */
static skplugin_err_t
skPluginRunHelper(
    skplugin_fn_mask_t  fn_mask,
    skplugin_err_t    (*helper)(const skp_function_common_t *, const char *))
{
    sk_dll_iter_t          iter;
    skplugin_err_t         err;
    skp_function_common_t *common;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);

    if (skp_handle_type(SKPLUGIN_FN_FILTER) &&
        ((fn_mask == SKPLUGIN_FN_ANY) || (fn_mask & SKPLUGIN_FN_FILTER)))
    {
        skDLLAssignIter(&iter, skp_filter_list);
        while (skDLLIterForward(&iter, (void **)&common) == 0) {
            err = helper(common, "filter");
            if (err == SKPLUGIN_FILTER_IGNORE) {
                skDLLIterDel(&iter);
                skp_function_common_destroy(common);
            } else if (err != SKPLUGIN_OK) {
                return err;
            }
        }
    }

    if (skp_handle_type(SKPLUGIN_FN_TRANSFORM) &&
        ((fn_mask == SKPLUGIN_FN_ANY) || (fn_mask & SKPLUGIN_FN_TRANSFORM)))
    {
        skDLLAssignIter(&iter, skp_transform_list);
        while (skDLLIterForward(&iter, (void **)&common) == 0) {
            err = helper(common, "transformer");
            if (err == SKPLUGIN_FILTER_IGNORE) {
                skDLLIterDel(&iter);
                skp_function_common_destroy(common);
            } else if (err != SKPLUGIN_OK) {
                return err;
            }
        }
    }

    if (HANDLE_FIELD &&
        ((fn_mask == SKPLUGIN_FN_ANY) || (fn_mask & SKPLUGIN_FNS_FIELD)))
    {
        skp_field_t *field;

        skDLLAssignIter(&iter, skp_active_field_list);
        while (skDLLIterForward(&iter, (void **)&field) == 0) {
            if (fn_mask == SKPLUGIN_FN_ANY || (fn_mask & field->fn_mask)) {
                common = &field->common;
                err = helper(common, "field");
                if (err != SKPLUGIN_OK && err != SKPLUGIN_FILTER_IGNORE) {
                    return err;
                }
            }
        }
    }

    return SKPLUGIN_OK;
}


skplugin_err_t
skPluginRunInititialize(
    skplugin_fn_mask_t  fn_mask)
{
    return skPluginRunHelper(fn_mask, skPluginRunInitHelper);
}


/* Runs a specific plugin field's initialization function. */
skplugin_err_t
skPluginFieldRunInitialize(
    const skplugin_field_t *field)
{
    skplugin_err_t err;

    assert(field);
    assert(skp_initialized);
    assert(!skp_in_plugin_init);

    err = skPluginRunInitHelper(&field->common, "field");
    if (err != SKPLUGIN_OK  && err != SKPLUGIN_FILTER_IGNORE) {
        return err;
    }

    return SKPLUGIN_OK;
}


skplugin_err_t
skPluginRunCleanup(
    skplugin_fn_mask_t  fn_mask)
{
    skplugin_err_t        err;
    skplugin_cleanup_fn_t cleanup;

    if (skp_in_plugin_init) {
        /* We never expect this to be set when this function is
         * called.  Someone has probably called exit() from within a
         * plug-in initialization function which is causing an
         * atexit() handler to invoke skPluginRunCleanup().  Simply
         * return since we do not know which plug-in called exit(). */
        return SKPLUGIN_OK;
    }

    err = skPluginRunHelper(fn_mask, skPluginRunCleanupHelper);

    if (SKPLUGIN_OK == err) {
        sk_dll_iter_t iter;

        skDLLAssignIter(&iter, skp_cleanup_list);
        while (skDLLIterForward(&iter, (void **)&cleanup) == 0) {
            skDLLIterDel(&iter);
            cleanup();
        }
    }

    return err;
}


/* Runs a specific plugin field's cleanup function. */
skplugin_err_t
skPluginFieldRunCleanup(
    const skplugin_field_t *field)
{
    skplugin_err_t err;

    assert(field);
    assert(skp_initialized);
    assert(!skp_in_plugin_init);

    err = skPluginRunCleanupHelper(&field->common, "field");

    return err;
}


/* Returns 1 if any filters are currently registered, 0 if not. */
int
skPluginFiltersRegistered(
    void)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(skp_handle_type(SKPLUGIN_FN_FILTER));

    return !skDLListIsEmpty(skp_filter_list);
}


/* Runs the filter functions over the record 'rec'.  The 'extra'
 * fields are determined by the current set of arguments registed by
 * skPluginRegisterUsedAppExtraArgs().  */
skplugin_err_t
skPluginRunFilterFn(
    const rwRec        *rec,
    void              **extra)
{
    sk_dll_iter_t iter;
    skp_filter_t *filt;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(skp_handle_type(SKPLUGIN_FN_FILTER));

    skDLLAssignIter(&iter, skp_filter_list);

    while (skDLLIterForward(&iter, (void **)&filt) == 0) {
        skplugin_err_t err;

        if (filt->common.extra_remap == NULL) {
            err = filt->filter(rec, filt->common.data, extra);
        } else {
            void **remap = skp_remap(&filt->common, extra);
            err = filt->filter(rec, filt->common.data, remap);
            free(remap);
        }

        switch (err) {
          case SKPLUGIN_FILTER_PASS:
            break;

          case SKPLUGIN_FILTER_PASS_NOW:
            return SKPLUGIN_FILTER_PASS;

          case SKPLUGIN_FILTER_FAIL:
          case SKPLUGIN_FILTER_IGNORE:
          case SKPLUGIN_ERR:
          case SKPLUGIN_ERR_SYSTEM:
            return err;

          case SKPLUGIN_OK:
            return SKPLUGIN_ERR;

          case SKPLUGIN_ERR_FATAL:
          case SKPLUGIN_ERR_VERSION_TOO_NEW:
          case SKPLUGIN_ERR_DID_NOT_REGISTER:
            skAppPrintErr("Fatal error running filter");
            exit(EXIT_FAILURE);
        }
    }

    return SKPLUGIN_FILTER_PASS;
}


/* Runs the transform functions over the record 'rec'.  'extra'
 * fields are determined by the current set of arguments registed by
 * skPluginRegisterUsedAppExtraArgs(). */
skplugin_err_t
skPluginRunTransformFn(
    rwRec              *rec,
    void              **extra)
{
    sk_dll_iter_t    iter;
    skp_transform_t *transform;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(skp_handle_type(SKPLUGIN_FN_TRANSFORM));

    skDLLAssignIter(&iter, skp_transform_list);

    while (skDLLIterForward(&iter, (void **)&transform) == 0) {
        skplugin_err_t err;

        if (transform->common.extra_remap == NULL) {
            err = transform->transform(rec, transform->common.data, extra);
        } else {
            void **remap = skp_remap(&transform->common, extra);
            err = transform->transform(rec, transform->common.data, remap);
            free(remap);
        }

        switch (err) {
          case SKPLUGIN_FILTER_PASS:
            break;

          case SKPLUGIN_FILTER_PASS_NOW:
            return SKPLUGIN_FILTER_PASS;

          case SKPLUGIN_FILTER_FAIL:
          case SKPLUGIN_FILTER_IGNORE:
          case SKPLUGIN_ERR:
          case SKPLUGIN_ERR_SYSTEM:
            return err;

          case SKPLUGIN_OK:
            return SKPLUGIN_ERR;

          case SKPLUGIN_ERR_FATAL:
          case SKPLUGIN_ERR_VERSION_TOO_NEW:
          case SKPLUGIN_ERR_DID_NOT_REGISTER:
            skAppPrintErr("Fatal error running transform");
            exit(EXIT_FAILURE);
        }
    }

    return SKPLUGIN_FILTER_PASS;
}

/* Retrieves a pointer to the constant names of a field (NULL terminated) */
skplugin_err_t
skPluginFieldName(
    const skplugin_field_t     *field,
    const char               ***name)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    *name = (const char **)field->names;

    return SKPLUGIN_OK;
}

/* Retrieves a pointer to the constant title of a field */
skplugin_err_t
skPluginFieldTitle(
    const skplugin_field_t     *field,
    const char                **title)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    *title = field->title;
    return SKPLUGIN_OK;
}

/* Retrieves a pointer to the constant description of a field, or NULL
 * if none */
skplugin_err_t
skPluginFieldDescription(
    const skplugin_field_t     *field,
    const char                **description)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    *description = field->description;
    return SKPLUGIN_OK;
}

/* Returns the name of the plugin that created this field */
skplugin_err_t
skPluginFieldGetPluginName(
    const skplugin_field_t     *field,
    const char                **plugin_name)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    *plugin_name = field->common.plugin_name;
    return SKPLUGIN_OK;
}

/* Retrieves the length of bins for this field.  Returns SKPLUGIN_ERR
 * if none. */
skplugin_err_t
skPluginFieldGetLenBin(
    const skplugin_field_t *field,
    size_t                 *len)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    if (field->rec_to_bin || field->add_rec_to_bin || field->bin_to_text) {
        *len = field->field_width_bin;
        return SKPLUGIN_OK;
    }

    return SKPLUGIN_ERR;
}

/* Retrieves the maximum length of text fields (including terminating
 * null) for this field.  Returns SKPLUGIN_ERR if none. */
skplugin_err_t
skPluginFieldGetLenText(
    const skplugin_field_t *field,
    size_t                 *len)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);

    if (field->rec_to_text || field->bin_to_text) {
        *len = field->field_width_text;
        return SKPLUGIN_OK;
    }

    return SKPLUGIN_ERR;
}


/* Retrieves the initial binary value for this aggregate. */
skplugin_err_t
skPluginFieldGetInitialValue(
    const skplugin_field_t *aggregate,
    uint8_t                *initial_value)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(aggregate);
    assert(aggregate->field_width_bin || initial_value);

    if (aggregate->initial_value) {
        memcpy(initial_value, aggregate->initial_value,
               aggregate->field_width_bin);
    } else {
        memset(initial_value, 0, aggregate->field_width_bin);
    }

    return SKPLUGIN_OK;
}



/* Runs the bin function that converts from record to bin value for
 * this field.  'extra' fields are determined by the current set of
 * arguments registed by skPluginRegisterUsedAppExtraArgs(). */
skplugin_err_t
skPluginFieldRunRecToBinFn(
    const skplugin_field_t     *field,
    uint8_t                    *bin,
    const rwRec                *rec,
    void                      **extra)
{
    skplugin_err_t err;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(bin);

    if (field->common.extra_remap == NULL) {
        err = field->rec_to_bin(rec, bin, field->common.data, extra);
    } else {
        void **remap = skp_remap(&field->common, extra);
        err = field->rec_to_bin(rec, bin, field->common.data, remap);
        free(remap);
    }

    return err;
}


/* Runs the bin function that adds to the bin value for this field
 * based on a given record.  'extra' fields are determined by the
 * current set of arguments registed by
 * skPluginRegisterUsedAppExtraArgs(). */
skplugin_err_t
skPluginFieldRunAddRecToBinFn(
    const skplugin_field_t     *field,
    uint8_t                    *bin,
    const rwRec                *rec,
    void                      **extra)
{
    skplugin_err_t err;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(bin);

    if (field->common.extra_remap == NULL) {
        err = field->add_rec_to_bin(rec, bin, field->common.data, extra);
    } else {
        void **remap = skp_remap(&field->common, extra);
        err = field->add_rec_to_bin(rec, bin, field->common.data, remap);
        free(remap);
    }

    return err;
}


/* Runs the bin function that converts from bin value to text value
   for this field */
skplugin_err_t
skPluginFieldRunBinToTextFn(
    const skplugin_field_t *field,
    char                   *text,
    size_t                  width,
    const uint8_t          *bin)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(text);

    return field->bin_to_text(bin, text, width, field->common.data);
}


/* Runs the bin function that converts from record to text value for
   this field */
skplugin_err_t
skPluginFieldRunRecToTextFn(
    const skplugin_field_t     *field,
    char                       *text,
    size_t                      width,
    const rwRec                *rec,
    void                      **extra)
{
    skplugin_err_t err;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(text);

    if (field->common.extra_remap == NULL) {
        err = field->rec_to_text(rec, text, width, field->common.data, extra);
    } else {
        void **remap = skp_remap(&field->common, extra);
        err = field->rec_to_text(rec, text, width, field->common.data, remap);
        free(remap);
    }

    return err;
}

/* Runs the function that merges two binary values for this field.
 * The binary value in 'src' is merged with 'dst', and the result is
 * put back in 'dst'. */
skplugin_err_t
skPluginFieldRunBinMergeFn(
    const skplugin_field_t *field,
    uint8_t                *dst,
    const uint8_t          *src)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(dst);
    assert(src);

    if (field->bin_merge == NULL) {
        return SKPLUGIN_ERR;
    }

    return field->bin_merge(dst, src, field->common.data);
}

/* Runs the function that compares two binary values for this field.
 * The binary value in 'a' is compared with 'b', and the result (less
 * than zero, zero, greater than zero) is put in 'val'. */
skplugin_err_t
skPluginFieldRunBinCompareFn(
    const skplugin_field_t *field,
    int                    *val,
    const uint8_t          *a,
    const uint8_t          *b)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(val);
    assert(a);
    assert(b);

    if (field->bin_compare == NULL) {
        *val = memcmp(a, b, field->field_width_bin);
        return SKPLUGIN_OK;
    }

    return field->bin_compare(val, a, b, field->common.data);
}


/* Get the iterator of a specific item in a list.  Return -1 if not
 * found. */
static int
skp_list_find(
    sk_dll_iter_t      *iter,
    const void         *target,
    sk_dllist_t        *fields)
{
    void *item;

    skDLLAssignIter(iter, fields);
    while (skDLLIterForward(iter, &item) == 0) {
        if (item == target) {
            return 0;
        }
    }

    return -1;
}

/* Activate a field.  All fields start deactivated.  Activating a
 * field allows its init and cleanup functions to run. */
skplugin_err_t
skPluginFieldActivate(
    const skplugin_field_t *field)
{
    int           rv;
    sk_dll_iter_t iter;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(skp_list_find(&iter, field, skp_field_list) == 0);

    rv = skp_list_find(&iter, field, skp_active_field_list);
    if (rv == -1) {
        CHECK_MEM(0 == skDLListPushTail(skp_active_field_list, (void*)field));
    }

    return SKPLUGIN_OK;
}

/* Deactivate a field.  All fields start deactivated */
skplugin_err_t
skPluginFieldDeactivate(
    const skplugin_field_t *field)
{
    int           rv;
    sk_dll_iter_t iter;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(field);
    assert(skp_list_find(&iter, field, skp_filter_list) == 0);

    rv = skp_list_find(&iter, field, skp_active_field_list);
    if (rv == 0) {
        rv = skDLLIterDel(&iter);
        assert(rv == 0);
    }

    return SKPLUGIN_OK;
}


/*
 *     Compares the version number of the plugin api supported by the
 *     plugin with the version reported by the application.  If
 *     sk_msg_fn_t is non-null, will print version mismatches via the
 *     error function.  Returns SKPLUGIN_OK if the versions "match",
 *     or a value that can be returned from the setup function (either
 *     SKPLUGIN_ERR or SKPLUGIN_ERR_VERSION_TOO_NEW).
 */
skplugin_err_t
skpinSimpleCheckVersion(
    uint16_t            protocol_major,
    uint16_t            protocol_minor,
    uint16_t            plugin_major,
    uint16_t            plugin_minor,
    sk_msg_fn_t         errfn)
{
    switch (SKPLUGIN_VERSION_CHECK(protocol_major, protocol_minor,
                                   plugin_major, plugin_minor))
    {
      case SKPLUGIN_VERSION_TOO_NEW:
        if (errfn) {
            errfn(("The version of the skplugin protocol is too new "
                   "(%d.%d > %d.%d)"), protocol_major, protocol_minor,
                  plugin_major, plugin_minor);
        }
        return SKPLUGIN_ERR_VERSION_TOO_NEW;
      case SKPLUGIN_VERSION_OLD:
        if (errfn) {
         errfn(("The version of the skplugin protocol is too old "
                "(%d.%d < %d.%d)"), protocol_major, protocol_minor,
               plugin_major, plugin_minor);
        }
        return SKPLUGIN_ERR;
      case SKPLUGIN_VERSION_OK:
        break;
      default:
        skAbort();
    }
    return SKPLUGIN_OK;
}


/* Set field widths for a field.  Meant to be used within an init
 * function. */
skplugin_err_t
skpinSetFieldWidths(
    skplugin_field_t   *field,
    size_t              field_width_text,
    size_t              field_width_bin)
{
    assert(skp_in_plugin_init);

    if (!field) {
        return SKPLUGIN_ERR;
    }

    field->field_width_text = field_width_text;
    field->field_width_bin = field_width_bin;

    return SKPLUGIN_OK;
}


/* Add an alias for a field. */
skplugin_err_t
skpinAddFieldAlias(
    skplugin_field_t   *field,
    const char         *alias)
{
    char **entry;
    char **new_names;
    int count;

    assert(skp_in_plugin_init);

    /* If field is NULL, nothing to do */
    if (NULL == field) {
        return SKPLUGIN_OK;
    }

    count = 1;                  /* One to account for the NULL pointer */
    for (entry = field->names; *entry; entry++) {
        if (strcmp(*entry, alias) == 0) {
            return SKPLUGIN_ERR;
        }
        count++;
    }

    new_names = (char **)realloc(field->names, sizeof(char *) * (count + 1));
    CHECK_MEM(new_names);
    new_names[count - 1] = strdup(alias);
    CHECK_MEM(new_names[count - 1]);
    new_names[count] = NULL;
    field->names = new_names;

    return SKPLUGIN_OK;
}

/* Sets a field's title */
skplugin_err_t
skpinSetFieldTitle(
    skplugin_field_t   *field,
    const char         *title)
{
    assert(skp_initialized);
    assert(skp_in_plugin_init);

    if (!field || !title) {
        return SKPLUGIN_ERR;
    }

    assert(field->title);
    free(field->title);
    field->title = strdup(title);
    CHECK_MEM(field->title);

    return SKPLUGIN_OK;
}

/* Register a cleanup function for the plugin.  This will be called by
 * skPluginRunCleanup after all the function-specific cleanups are
 * called. */
skplugin_err_t
skpinRegCleanup(
    skplugin_cleanup_fn_t   cleanup)
{
    void *clean_fn;

    assert(skp_initialized);
    assert(skp_in_plugin_init);
    assert(cleanup);

    if (NULL == cleanup) {
        return SKPLUGIN_ERR;
    }

    /* This avoids a function * to void * warning by the compiler. */
    *((skplugin_cleanup_fn_t *)&clean_fn) = cleanup;
    CHECK_MEM(0 == skDLListPushTail(skp_cleanup_list, clean_fn));

    return SKPLUGIN_OK;
}

/* Declare this plugin to be non-safe. */
void
skpinSetThreadNonSafe(
    void)
{
    assert(skp_initialized);
    assert(skp_in_plugin_init);

    skp_thread_safe = 0;
}

/* Returns 1 if the plugin can be safely be run in a threaded context,
   0 otherwise. */
int
skPluginIsThreadSafe(
    void)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);

    return skp_thread_safe;
}

/* Binds an iterator around all fields that contain information that
 * matches the field_mask.  If 'all_fields' is false, will only
 * iterate over "activated" fields.  */
skplugin_err_t
skPluginFieldIteratorBind(
    skplugin_field_iter_t  *iter,
    skplugin_fn_mask_t      fn_mask,
    int                     all_fields)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(iter);

    if (!HANDLE_FIELD) {
        return SKPLUGIN_ERR;
    }

    iter->fn_mask = fn_mask;
    iter->all_fields = all_fields;

    return skPluginFieldIteratorReset(iter);
}


/* Resets a field iterator so it can be iterated over again */
skplugin_err_t
skPluginFieldIteratorReset(
    skplugin_field_iter_t  *iter)
{
    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(iter);

    if (iter->all_fields) {
        skDLLAssignIter(&iter->list_iter, skp_field_list);
    } else {
        skDLLAssignIter(&iter->list_iter, skp_active_field_list);
    }

    return SKPLUGIN_OK;
}

/* Retrieves the field identifier for the next field, returns 1 on
   success, 0 on failure. */
int
skPluginFieldIteratorNext(
    skplugin_field_iter_t  *iter,
    skplugin_field_t      **rfield)
{
    skp_field_t *field;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(iter);

    for (;;) {
        int rv = skDLLIterForward(&iter->list_iter, (void **)&field);
        if (rv != 0) {
            return 0;
        }
        if ((iter->fn_mask == SKPLUGIN_FN_ANY) ||
            ((iter->fn_mask & field->fn_mask) == iter->fn_mask))
        {
            if (rfield) {
                *rfield = field;
            }
            return 1;
        }
    }

    skAbort();                  /* NOTREACHED */
}

/* Print the usage information registered by plugins to 'fh'.*/
skplugin_err_t
skPluginOptionsUsage(
    FILE               *fh)
{
    sk_dll_iter_t       iter;
    skp_option_t       *option;

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(fh);

    skDLLAssignIter(&iter, skp_option_list);
    while (skDLLIterForward(&iter, (void **)&option) == 0) {
        if (option->help_fn) {
            option->help_fn(fh, &option->opt[0], option->cbdata);
        } else {
            fprintf(fh, "--%s %s. %s\n",
                    option->opt[0].name, SK_OPTION_HAS_ARG(option->opt[0]),
                    option->help_string ? option->help_string : "");
        }
    }

    return SKPLUGIN_OK;
}

/* Unload a library opened by dlopen() */
static void
skp_unload_library(
    void               *handle)
{
    int rv = dlclose(handle);
    if (rv != 0) {
        skAppPrintErr("dlclose: %s", dlerror());
    }
}


/* Given a setup function, execute it and add the plugin to the list */
static skplugin_err_t
skp_add_plugin(
    void                   *handle,
    const char             *name,
    skplugin_setup_fn_t     setup_fn)
{
    skplugin_err_t err;

    /* Call the setup function */
    skp_in_plugin_init = 1;
    skp_current_plugin_name = strdup(name);
    CHECK_MEM(skp_current_plugin_name);
    CHECK_MEM(0 == skDLListPushTail(skp_plugin_names,
                                    (void *)skp_current_plugin_name));
    err = setup_fn(SKPLUGIN_INTERFACE_VERSION_MAJOR,
                   SKPLUGIN_INTERFACE_VERSION_MINOR, NULL);
    skp_current_plugin_name = NULL;
    skp_in_plugin_init = 0;

    if (err == SKPLUGIN_OK) {
        if (handle) {
            CHECK_MEM(0 == skDLListPushTail(skp_library_list, handle));
        }
    } else if (err == SKPLUGIN_ERR_FATAL) {
        skAppPrintErr("Fatal error loading plugin %s", name);
        exit(EXIT_FAILURE);
    } else {
        sk_dllist_t           *list[3];
        sk_dll_iter_t          iter;
        skp_function_common_t *common;
        size_t                 i;
        char                  *plugin_name;

        ASSERT_RESULT(skDLListPopTail(skp_plugin_names, (void **)&plugin_name),
                      int, 0);
        if (plugin_name == NULL) {
            skAppPrintErr(("Fatal error loading plugin %s "
                           "(could not unload)"), name);
            exit(EXIT_FAILURE);
        }
        list[0] = skp_filter_list;
        list[1] = skp_transform_list;
        list[2] = skp_field_list;

        /* Loop through all registered filters, transforms, and
         * fields, and remove any created by this plugin. */
        for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
            if (list[i]) {
                skDLLAssignIter(&iter, list[i]);
                while (skDLLIterForward(&iter, (void **)&common) == 0) {
                    if (common->plugin_name == plugin_name) {
                        skDLLIterDel(&iter);
                        if (list[i] == skp_field_list) {
                            skp_function_field_destroy(common);
                        } else {
                            skp_function_common_destroy(common);
                        }
                    }
                }
            }
        }
        free(plugin_name);

        if (handle) {
            skp_unload_library(handle);
        }
    }

    return err;
}


/* Given a name and a setup function, acts as if the setup function
 * was from a plugin. */
skplugin_err_t
skPluginAddAsPlugin(
    const char             *name,
    skplugin_setup_fn_t     setup_fn)
{
    return skp_add_plugin(NULL, name, setup_fn);
}


/* Loads the plugin represented by the filename 'name'. */
skplugin_err_t
skPluginLoadPlugin(
    const char         *name,
    int                 complain_on_error)
{
    void                *handle;
    char                 plugin_path[PATH_MAX+1];
    skplugin_setup_fn_t  setup_fn;
    skplugin_err_t       err;
    const char          *error_prefix = "";

    assert(skp_initialized);
    assert(!skp_in_plugin_init);
    assert(name);

    if (!complain_on_error) {
        error_prefix = (SKPLUGIN_DEBUG_ENVAR ": ");
    }

    /* Attempt to find the full path to the plug-in, and set
     * 'plugin_path' to its path; if we cannot find the path, copy the
     * plug-in's name to 'plugin_path' and we'll let dlopen() handle
     * finding the plug-in. */
    if (skp_debug) {
        skAppPrintErr(SKPLUGIN_DEBUG_ENVAR ": attempting to find plugin '%s'",
                      name);
    }
    if (!skFindPluginPath(name, plugin_path, PATH_MAX,
                          (skp_debug ? (SKPLUGIN_DEBUG_ENVAR ": ") : NULL)))
    {
        strncpy(plugin_path, name, PATH_MAX);
        plugin_path[PATH_MAX] = '\0';
    }

    /* try to dlopen() the plug-in  */
    if (skp_debug > 0) {
        skAppPrintErr(SKPLUGIN_DEBUG_ENVAR ": dlopen'ing '%s'", plugin_path);
    }
    handle = dlopen(plugin_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        if (complain_on_error || (skp_debug > 0)) {
            skAppPrintErr("%sdlopen warning: %s", error_prefix, dlerror());
        }
        return SKPLUGIN_ERR_SYSTEM;
    }
    if (skp_debug > 0) {
        skAppPrintErr(SKPLUGIN_DEBUG_ENVAR ": dlopen() successful");
    }

    /* Find the setup function */
    *((void **)&setup_fn) = dlsym(handle, SKPLUGIN_SETUP_FN_NAME);
    if (setup_fn == NULL) {
        if (complain_on_error || skp_debug > 0) {
            skAppPrintErr(("%sFunction '" SKPLUGIN_SETUP_FN_NAME "' not found"),
                          error_prefix);
        }
        skp_unload_library(handle);
        return SKPLUGIN_ERR;
    } else {
        err = skp_add_plugin(handle, plugin_path, setup_fn);
        if (err != SKPLUGIN_OK && (complain_on_error || skp_debug > 0)) {
            skAppPrintErr(("%sFunction '" SKPLUGIN_SETUP_FN_NAME "'"
                           " returned a non-OK error status"), error_prefix);
        }
    }

    return err;
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
