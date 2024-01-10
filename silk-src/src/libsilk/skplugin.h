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

/**
**  @file
**
**  skplugin.h
**
**
**    The SKPLUGIN library defines the layer between the application
**    that want to make use of a plugin and the plugin code that
**    implements some functionality.
**
*/
#ifndef _SKPLUGIN_H
#define _SKPLUGIN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKPLUGIN_H, "$SiLK: skplugin.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>
#include <silk/utils.h>         /* need "struct option" */

/*
**
**    The plugin author will need to use the API specified in the
**    "PLUG-IN INTERFACE" section of this file.  In general, these
**    functions all begin with "skpin".
**
**    There are two APIs that the plugin author can use.  One is the
**    simple API that makes defining new fields relatively easy.  The
**    other is an advanced API that gives one finer control.  Both of
**    these APIs are similar to the APIs used when registering plugins
**    from PySiLK.  You may find it useful to read the silkpython(3)
**    manual page.
**
**    The application author will need to use the API specified in the
**    "APPLICATION INTERFACE section of this file.  In general, these
**    functions all begin with "skPlugin".
**
**    The top of this file specifies macros and typedefs that are
**    common to both APIs.
**
*/


/**
 *    Return value from most skplugin functions
 */
typedef enum {
    /** all is well */
    SKPLUGIN_OK,

    /** result passes filter */
    SKPLUGIN_FILTER_PASS,

    /** result passes filter immediately. Do not check any more plugin
     * filter or transform functions */
    SKPLUGIN_FILTER_PASS_NOW,

    /** result fails filter */
    SKPLUGIN_FILTER_FAIL,

    /** result is marked as neither pass nor fail.  Do not check any
     * more plugin filter or transform functions */
    SKPLUGIN_FILTER_IGNORE,

    /** all is not well */
    SKPLUGIN_ERR,

    /** serious corruption possible, abort now */
    SKPLUGIN_ERR_FATAL,

    /** plugin could not be loaded due to system errors */
    SKPLUGIN_ERR_SYSTEM,

    /** plugin did not register options because app did not support the
     * function mask  */
    SKPLUGIN_ERR_DID_NOT_REGISTER,

    /** version of library is too new for plugin */
    SKPLUGIN_ERR_VERSION_TOO_NEW

} skplugin_err_t;


/**
 *    Types of command-line switches (NO_ARG, REQUIRED_ARG,
 *    OPTIONAL_ARG, from utils.h
 */
typedef int skplugin_arg_mode_t;


/**
 *    The plugin interface uses a common API regardless of the type of
 *    application.  The following bitfields specify functionality that an
 *    application requires from its plugins.  Plugins can use these
 *    bitfields when registering options.
 */
typedef int skplugin_fn_mask_t;

#define SKPLUGIN_FN_ANY             (0)
#define SKPLUGIN_FN_REC_TO_BIN      (1)
#define SKPLUGIN_FN_ADD_REC_TO_BIN  (1 << 1)
#define SKPLUGIN_FN_BIN_TO_TEXT     (1 << 2)
#define SKPLUGIN_FN_REC_TO_TEXT     (1 << 3)
#define SKPLUGIN_FN_MERGE           (1 << 4)
#define SKPLUGIN_FN_COMPARE         (1 << 5)
#define SKPLUGIN_FN_INITIAL         (1 << 6)
#define SKPLUGIN_FN_FILTER          (1 << 7)
#define SKPLUGIN_FN_TRANSFORM       (1 << 8)
#define SKPLUGIN_FN_BIN_BYTES       (1 << 9)
#define SKPLUGIN_FN_COLUMN_WIDTH    (1 << 10)

/* Plugin required fields for particular apps */
#define SKPLUGIN_APP_CUT            SKPLUGIN_FN_REC_TO_TEXT
#define SKPLUGIN_APP_SORT           SKPLUGIN_FN_REC_TO_BIN
#define SKPLUGIN_APP_GROUP          SKPLUGIN_FN_REC_TO_BIN
#define SKPLUGIN_APP_UNIQ_FIELD     (SKPLUGIN_FN_REC_TO_BIN     \
                                     | SKPLUGIN_FN_BIN_TO_TEXT)
#define SKPLUGIN_APP_UNIQ_VALUE     (SKPLUGIN_FN_ADD_REC_TO_BIN \
                                     | SKPLUGIN_FN_BIN_TO_TEXT  \
                                     | SKPLUGIN_FN_MERGE)
#define SKPLUGIN_APP_STATS_FIELD    (SKPLUGIN_FN_REC_TO_BIN     \
                                     | SKPLUGIN_FN_BIN_TO_TEXT)
#define SKPLUGIN_APP_STATS_VALUE    (SKPLUGIN_FN_ADD_REC_TO_BIN \
                                     | SKPLUGIN_FN_BIN_TO_TEXT  \
                                     | SKPLUGIN_FN_MERGE        \
                                     | SKPLUGIN_FN_COMPARE)
#define SKPLUGIN_APP_FILTER         SKPLUGIN_FN_FILTER
#define SKPLUGIN_APP_TRANSFORM      SKPLUGIN_FN_TRANSFORM

/** filter identifier */
struct skp_filter_st;
typedef struct skp_filter_st skplugin_filter_t;

/** transformer identifier */
struct skp_transform_st;
typedef struct skp_transform_st skplugin_transform_t;

/** field identifier */
struct skp_field_st;
typedef struct skp_field_st skplugin_field_t;


/********************************************************************
 *
 *    PLUG-IN INTERFACE
 *
 ********************************************************************
 *
 *    The following defines, typedefs, and functions are meant to be
 *    used/called by the plugin code.
 *
 ********************************************************************/

/*******************************/
/*** Plugin entry point type ***/
/*******************************/

/**
 *    The name of the "entry port" function that plugins export.
 *
 *    The "entry point" of the plugin is the single function the
 *    plugin must define and export, and which is found by dlsym(3).
 *    All other functions and global variables in the plugin should be
 *    static, unless the plugin consists of more than one file.
 */
#define SKPLUGIN_SETUP_FN skplugin_init
#define TO_STR(a) _TO_STR(a)
#define _TO_STR(a) #a
#define SKPLUGIN_SETUP_FN_NAME TO_STR(SKPLUGIN_SETUP_FN)

/**
 *    Function prototype for the setup function that plugins export.
 *    'data' is an opaque type determined by the value 'version'.  In
 *    the current version (1.0), the 'data' is not used, and NULL will
 *    be passed as the 'data' argument.
 */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void               *data);

/**
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
    sk_msg_fn_t         errfn);


/*** SIMPLE FIELD REGISTRATION FUNCTIONS ***/

/*****************************************************************/
/*** Callback function types for simple registration functions ***/
/*****************************************************************/

/**
 *    Integer-based field callback.  Given an rwRec, should return an
 *    unsigned integer to associate with that record.  Used in
 *    skpinRegIntField, skpinRegTextField, skpinRegStringListField,
 *    skpinRegIntAggregator, skpinRegIntSumAggregator,
 *    skpinRegIntMinAggregator, and skpinRegIntMaxAggregator.
 */
typedef uint64_t
(*skplugin_int_field_fn_t)(
    const rwRec        *rec);

/**
 *    IPv4 address field callback.  Given an rwRec, should return an
 *    IPv4 address as a uint32_t (in host byte order) to associate
 *    with that record.  Used in skpinRegIPv4Field.
 */
typedef uint32_t
(*skplugin_ipv4_field_fn_t)(
    const rwRec        *rec);

/**
 *    IP address field callback.  Given an rwRec, should fill in the
 *    given skipaddr_t with an IP address to associate with that
 *    record.  Used in skpinRegIPAddressField.
 */
typedef void
(*skplugin_ip_field_fn_t)(
    skipaddr_t         *dest,
    const rwRec        *rec);

/**
 *    Text field callback.  Converts a uint64_t value to a text value
 *    in 'dest'.  The size of the 'dest' buffer is given by 'width'.
 *    The text value must be null-terminated.  Used in
 *    skpinRegTextField.
 */
typedef void
(*skplugin_text_field_fn_t)(
    char               *dest,
    size_t              width,
    uint64_t            val);

/**
 *    Integer aggregation function callback.  Given a 'current' value,
 *    "adds" or "merges" the 'operand', and returns the new value.
 *    Used in skpinRegIntAggregator.
 */
typedef uint64_t
(*skplugin_int_agg_fn_t)(
    uint64_t            current,
    uint64_t            operand);


/*******************************************/
/*** Simple field registration functions ***/
/*******************************************/

/**
 *   Registers a field whose value is an integer.
 *
 *   The field's name (and title) will be 'name'.  'min' is the
 *   minimum integer value for the field.  'max' is the maximum value
 *   of the field.  If 'max' is set to 0, 'max' is defaulted to
 *   UINT64_MAX.  'rec_to_int' is a function that takes an rwRec, and
 *   returns the integer associated with it.  'width' is the column
 *   width of the field to use when printing the value.  If 'width' is
 *   set to 0, 'width' is defaulted to the textual width of 'max'.
 */
skplugin_err_t
skpinRegIntField(
    const char                 *name,
    uint64_t                    min,
    uint64_t                    max,
    skplugin_int_field_fn_t     rec_to_int,
    size_t                      width);

/**
 *   Registers a field whose value is an IPv4 address.
 *
 *   The field's name (and title) will be 'name'.  'rec_to_ipv4' is a
 *   function that takes an rwRec, and returns the IPv4 address
 *   associated with it as a uint32_t in host byte order.  'width' is
 *   the column width of the field to use when printing the value.  If
 *   'width' is set to 0, 'width' is defaulted to 15.
 */
skplugin_err_t
skpinRegIPv4Field(
    const char                 *name,
    skplugin_ipv4_field_fn_t    rec_to_ipv4,
    size_t                      width);

/**
 *   Registers a field whose value is an IP address.
 *
 *   The field's name (and title) will be 'name'.  'rec_to_ipaddr' is
 *   a function that takes an rwRec, and fills in an IP address
 *   associated with it as a skipaddr_t.  'width' is the column width
 *   of the field to use when printing the value.  If 'width' is set
 *   to 0, 'width' is defaulted to 39 (15 if not SiLK is not compiled
 *   with IPv6 support.
 */
skplugin_err_t
skpinRegIPAddressField(
    const char             *name,
    skplugin_ip_field_fn_t  rec_to_ipaddr,
    size_t                  width);

/**
 *   Registers a field whose value is text.
 *
 *   The field's name (and title) will be 'name'.  The field's text
 *   value is based on an intermediate integer value.  'min' is the
 *   minimum integer value for the field.  'max' is the maximum value
 *   of the field.  If 'max' is set to 0, 'max' is defaulted to
 *   UINT64_MAX.  'value_fn' is a function that takes an rwRec, and
 *   returns the integer associated with it.  'text_fn' is a function
 *   that takes a buffer, width, and integer, and fills the buffer
 *   with the text value associated with that integer, where the width
 *   is the size of the buffer.  'width' is the column width of the
 *   field to use when printing the value.
 */
skplugin_err_t
skpinRegTextField(
    const char                 *name,
    uint64_t                    min,
    uint64_t                    max,
    skplugin_int_field_fn_t     value_fn,
    skplugin_text_field_fn_t    text_fn,
    size_t                      width);

/**
 *   Registers a field whose value is one of a list of strings.
 *
 *   The field's name (and title) will be 'name'.  'list' is a static
 *   list of strings.  The list should either be NULL-terminated, or
 *   'entries' should have a non-zero value.  'entries' should be the
 *   number of entries in 'list'.  If 'entries' is zero, the list is
 *   assumed to be NULL-terminated.  'rec_to_index' is a function that
 *   takes an rwRec, and returns an index into 'list'.  If the index
 *   value is greater than the number of entries in 'list',
 *   'default_value' will be used instead.  'default_value' may be
 *   NULL.  'width' is the column width of the field to use when
 *   printing the value.  If 'width' is set to 0, 'width' is defaulted
 *   to the width of the largest string in 'list' and 'default_value'.
 */
skplugin_err_t
skpinRegStringListField(
    const char                 *name,
    const char                **list,
    size_t                      entries,
    const char                 *default_value,
    skplugin_int_field_fn_t     rec_to_index,
    size_t                      width);

/**
 *   Registers an aggregate value field that maintains a running
 *   unsigned integer sum.
 *
 *   The field's name (and title) will be 'name'.  The maximum value
 *   of the field is 'max'.  If 'max' is zero, the maximum value is
 *   assumed to be UINT64_MAX.  'rec_to_int' is a function that takes
 *   an rwRec, and returns an integer value associated with that
 *   record.  'width' is the column width of the field to use when
 *   printing the value.  If 'width' is set to 0, 'width' is defaulted
 *   to the textual width of 'max'.
 */
skplugin_err_t
skpinRegIntSumAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     rec_to_int,
    size_t                      width);

/**
 *   Registers an aggregate value field that keeps track of a minimum
 *   unsigned integer value.
 *
 *   The field's name (and title) will be 'name'.  The maximum value
 *   of the field is 'max'.  If 'max' is zero, the maximum value is
 *   assumed to be UINT64_MAX.  'rec_to_int' is a function that takes
 *   an rwRec, and returns an integer value associated with that
 *   record.  'width' is the column width of the field to use when
 *   printing the value.  If 'width' is set to 0, 'width' is defaulted
 *   to the textual width of 'max'.
 */
skplugin_err_t
skpinRegIntMinAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     rec_to_int,
    size_t                      width);

/**
 *   Registers an aggregate value field that keeps track of a maximum
 *   unsigned integer value.
 *
 *   The field's name (and title) will be 'name'.  The maximum value
 *   of the field is 'max'.  If 'max' is zero, the maximum value is
 *   assumed to be UINT64_MAX.  'rec_to_int' is a function that takes
 *   an rwRec, and returns an integer value associated with that
 *   record.  'width' is the column width of the field to use when
 *   printing the value.  If 'width' is set to 0, 'width' is defaulted
 *   to the textual width of 'max'.
 */
skplugin_err_t
skpinRegIntMaxAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     rec_to_int,
    size_t                      width);

/**
 *   Registers an unsigned integer aggregate value field.
 *
 *   The field's name (and title) will be 'name'.  The maximum value
 *   of the field is 'max'.  If 'max' is zero, the maximum value is
 *   assumed to be UINT64_MAX.  'rec_to_int' is a function that takes
 *   an rwRec, and returns an integer value associated with that
 *   record.  'agg' is the aggregation function, which takes the
 *   current value of the field and a value returned by 'rec_to_int',
 *   and returns the new value of the field.  'initial' should be the
 *   initial value of the field.  'width' is the column width of the
 *   field to use when printing the value.  If 'width' is set to 0,
 *   'width' is defaulted to the textual width of 'max'.
 */
skplugin_err_t
skpinRegIntAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     rec_to_int,
    skplugin_int_agg_fn_t       agg,
    uint64_t                    initial,
    size_t                      width);


/*** LOW LEVEL PLUGIN FUNCTIONALITY ***/

/*******************************************/
/*** Callback function types for plugins ***/
/*******************************************/

/**
 * In all the following function prototypes, 'cbdata' is callback data
 * provided by the plugin at callback registration time.  'extra' are
 * extra arguments as defined in Extra Arguments above.
 */

/**
 *    Type defininition for non-function-specific plugin cleanup
 *    functions.  Registered by skpinRegCleanup().  Called by
 *    skPluginRunCleanup().
 */
typedef void
(*skplugin_cleanup_fn_t)(
    void);


/**
 *    Argument processing callback: Called to process a plugin
 *    command-line argument (switch).  Registered by
 *    skpinRegOption2().
 *
 *    In cases where the plugin is only active when a command line
 *    argument is present, part of this function's duties will be to
 *    call skpinRegFilter() or skpinRegTransformer().
 */
typedef skplugin_err_t
(*skplugin_option_fn_t)(
    const char         *opt_arg,
    void               *opt_cbdata);


/**
 *    Option help callback.  Meant to output option help to the given
 *    file handle.  Registered by skpinRegOption2().  Called by
 *    skPluginOptionsUsage().
 *
 *    There are two fields of interest in the struct option structure:
 *    'name' contains the 'option_name' used when the function was
 *    registered, and 'has_arg' contains the 'mode' that was used.
 */
typedef void
(*skplugin_help_fn_t)(
    FILE                   *fh,
    const struct option    *option,
    void                   *opt_cbdata);


/**
 *    Basic callback: used for any startup/shutdown code.  Called by
 *    skPluginRunInititialize() or skPluginRunCleanup().
 *
 *    skplugin_callbacks_t.init
 *    skplugin_callbacks_t.cleanup
 */
typedef skplugin_err_t
(*skplugin_callback_fn_t)(
    void               *cbdata);

/**
 *    Filter callback to filter a record 'rec'.  If the function
 *    returns SKPLUGIN_FILTER_PASS, the record is accepted.  If it
 *    returns SKPLUGIN_FILTER_FAIL, it is rejected.  Registered by
 *    skpinRegFilter().  Called by skPluginRunFilterFn()
 *
 *    skplugin_callbacks_t.filter
 */
typedef skplugin_err_t
(*skplugin_filter_fn_t)(
    const rwRec        *rec,
    void               *cbdata,
    void              **extra);

/**
 *    Transform callback.  Modifies 'rec' in place.  Registered by
 *    skpinRegTransformer().  Called by skPluginRunTransformFn()
 *
 *    skplugin_callbacks_t.transform
 */
typedef skplugin_err_t
(*skplugin_transform_fn_t)(
    rwRec              *rec,
    void               *cbdata,
    void              **extra);

/**
 *    Record to text callback.  Fills in 'dest' given 'rec'.  The
 *    function should write no more than 'width' characters into
 *    'dest'.  The value should be NUL-terminated.  Registered by
 *    skpinRegField().  Called by skPluginFieldRunRecToTextFn().
 *
 *    skplugin_callbacks_t.rec_to_text
 */
typedef skplugin_err_t
(*skplugin_text_fn_t)(
    const rwRec        *rec,
    char               *dest,
    size_t              width,
    void               *cbdata,
    void              **extra);

/**
 *    Record to binary callback.  Fills in 'dest' given 'rec'.
 *    Registered by skpinRegField().  When used in an aggregate
 *    definition, 'dest' is presumed to contain the current binary
 *    value, which should be modified or replaced by the function.
 *    The function may assume that the 'dest' is large enough to hold
 *    'field_bin_width' bytes.
 *
 *    skplugin_callbacks_t.rec_to_bin
 *    skplugin_callbacks_t.add_rec_to_bin
 */
typedef skplugin_err_t
(*skplugin_bin_fn_t)(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *cbdata,
    void              **extra);

/**
 *    Binary to text callback.  Just like record to text callback, but
 *    converts data from a binary value (as produced by a
 *    skplugin_bin_fn_t) to text.
 *
 *    skplugin_callbacks_t.bin_to_text
 */
typedef skplugin_err_t
(*skplugin_bin_to_text_fn_t)(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *cbdata);

/**
 *    Binary value merge callback.  This function takes two binary
 *    values (as produced by a skplugin_bin_fn_t) in dest and src and
 *    merges them into dest.
 *
 *    skplugin_callbacks_t.bin_merge
 */
typedef skplugin_err_t
(*skplugin_bin_merge_fn_t)(
    uint8_t            *dest,
    const uint8_t      *src,
    void               *cbdata);

/**
 *    Binary value comparison function.  Compares two binary values
 *    (as produced by a skplugin_bin_fn_t) in value_a and value_b and
 *    places a integer less than, equal to, or greater than zero in
 *    cmp depending on whether value_a is less than, equal, or greater
 *    than value_b.
 *
 *    skplugin_callbacks_t.bin_compare
 */
typedef skplugin_err_t
(*skplugin_bin_cmp_fn_t)(
    int                *cmp,
    const uint8_t      *value_a,
    const uint8_t      *value_b,
    void               *cbdata);


/******************************************/
/*** Struct for registration functions  ***/
/******************************************/

/**
 *    skplugin_callbacks_t is used as the 'regdata' argument to the
 *    skpinRegFilter(), skpinRegTransformer(), and skpinRegField()
 *    functions.  Its members are described in detail in the
 *    description of those functions.
 */
struct skplugin_callbacks_st {
    skplugin_callback_fn_t     init;
    skplugin_callback_fn_t     cleanup;
    size_t                     column_width;
    size_t                     bin_bytes;
    skplugin_text_fn_t         rec_to_text;
    skplugin_bin_fn_t          rec_to_bin;
    skplugin_bin_fn_t          add_rec_to_bin;
    skplugin_bin_to_text_fn_t  bin_to_text;
    skplugin_bin_merge_fn_t    bin_merge;
    skplugin_bin_cmp_fn_t      bin_compare;
    skplugin_filter_fn_t       filter;
    skplugin_transform_fn_t    transform;
    const uint8_t             *initial;
    const char               **extra;
};
typedef struct skplugin_callbacks_st skplugin_callbacks_t;


/************************/
/*** Plugin functions ***/
/************************/

/* This set of functions are meant to be called by the plugins
 * themselves. */


/**
 *    The following function registers an option (switch) for
 *    command-line processing.
 *
 *    'option_name' is the command line switch to create.
 *
 *    'mode' determines whether the switch takes an argument.  It
 *    should be one of NO_ARG, OPTIONAL_ARG, or REQUIRED_ARG.
 *
 *    'option_help' is the usage string to print when the user
 *    requests --help.  This will be used if 'option_help_fn' is NULL.
 *    This argument may be NULL.
 *
 *    'option_help_fn' is a function which optionally prints a help
 *    message for the option.  This argument may be NULL.
 *
 *    'opt' is a callback function.  'opt(opt_arg, cbdata)' will be
 *    called back when the 'option_name' is seen as an option.  If no
 *    argument is given to the switch, 'opt_arg' will be NULL.
 *
 *    'opt_cbdata' will be passed back unchanged to the plugin as a
 *    parameter in the 'opt' and 'option_help_fn' callback functions.
 *
 *    'num_entries' is the number of function type combinations that
 *    will be supplied after the 'num_entries' argument.
 *
 *    Each of the entries after num_entries should be an function
 *    combination of type skplugin_fn_mask_t.  As long as the
 *    application supports one of the function combinations in this
 *    list, the registration should succeed.
 *
 *    If the application does not support any of the function
 *    combinations, this function will return
 *    SKPLUGIN_ERR_DID_NOT_REGISTER.
 */
skplugin_err_t
skpinRegOption2(
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    const char             *option_help,
    skplugin_help_fn_t      option_help_fn,
    skplugin_option_fn_t    opt,
    void                   *opt_cbdata,
    int                     num_entries,
    ...);

/**
 *  DEPRECATED.  Replace with
 *
 *    skpinRegOption2(option_name, mode, option_help, NULL, opt, data,
 *                    1, fn_mask);
 *
 *    To be removed in SiLK 4.
 */
skplugin_err_t
skpinRegOption(
    skplugin_fn_mask_t      fn_mask,
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    const char             *option_help,
    skplugin_option_fn_t    opt,
    void                   *opt_cbdata);

/**
 *  DEPRECATED.  Replace with
 *
 *    skpinRegOption2(option_name, mode, NULL, option_help_fn, opt, data,
 *                    1, fn_mask);
 *
 *    To be removed in SiLK 4.
 */
skplugin_err_t
skpinRegOptionWithHelpFn(
    skplugin_fn_mask_t      fn_mask,
    const char             *option_name,
    skplugin_arg_mode_t     mode,
    skplugin_help_fn_t      option_help_fn,
    skplugin_option_fn_t    opt,
    void                   *opt_cbdata);


/**
 *    Register a new filter predicate to pass or fail records.
 *
 *    Registering a filter predicate in an application that does not
 *    support filtering results in skpinRegFilter() setting
 *    'return_filter', if provided, to NULL and returning SKPLUGIN_OK.
 *
 *    If 'return_filter' is not NULL, the function will set it to the
 *    newly created filter.
 *
 *    'cbdata' will be passed back unchanged to the plugin as a
 *    parameter in the various callback functions.
 *
 *    'regdata' is a struct of type skplugin_callbacks_t, which should
 *    be filled out as follows:
 *
 *      'init(cbdata)' is called for all registered filter predicates.
 *      It is called after argument processing and before processing
 *      of records.  It may be NULL.
 *
 *      'filter(record, cbdata)' is called for each record.  If
 *      'filter()' returns SKPLUGIN_FILTER_PASS, the record is
 *      accepted; if it returns SKPLUGIN_FILTER_FAIL, the record is
 *      rejected.
 *
 *      'cleanup(cbdata)' is called after all records have been
 *      processed.  It may be NULL.
 *
 *    If 'regdata' or the 'filter' member of 'regdata' is NULL,
 *    skpinRegFilter() sets 'return_filter', if provided, to NULL and
 *    returns SKPLUGIN_ERR.
 */
skplugin_err_t
skpinRegFilter(
    skplugin_filter_t             **return_filter,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata);


/**
 *    Register a new transformer function to apply to all records.
 *
 *    Registering a transformer function in an application that does
 *    not support transforms results in skpinRegTransformer() setting
 *    'return_transformer', if provided, to NULL and returning
 *    SKPLUGIN_OK.
 *
 *    If 'return_transformer' is not NULL, the function will set it to
 *    the newly created transformer.
 *
 *    'cbdata' will be passed back unchanged to the plugin as a
 *    parameter in the various callback functions.
 *
 *    'regdata' is a struct of type skplugin_callbacks_t, which should
 *    be filled out as follows:
 *
 *      'init(cbdata)' is called for all registered transformers.  It
 *      is called after argument processing and before processing of
 *      records.  It may be NULL.
 *
 *      'transform(rec, cbdata)' is called for each record.  Any
 *      changes made by 'transform()' are seen by the application.
 *
 *      'cleanup(cbdata)' is called after all records have been
 *      processed.  It may be NULL.
 *
 *    If 'regdata' or the 'transform' member of 'regdata' is NULL,
 *    skpinRegTransformer() sets 'return_transformer', if provided, to
 *    NULL and returns SKPLUGIN_ERR.
 */
skplugin_err_t
skpinRegTransformer(
    skplugin_transform_t          **return_transformer,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata);


/**
 *    Register a new derived field for record processing.
 *
 *    Registering a field in an application that does not work in terms
 *    of fields results in skpinRegField() setting 'return_field', if
 *    provided, to NULL and returning SKPLUGIN_OK.
 *
 *    'return_field' is a handle to the newly created field.  (Can be
 *    NULL.)
 *
 *    'name' is the string that is the primary name of the field, and
 *    by default will be the value returned by skPluginFieldTitle() to
 *    the application.
 *
 *    'description' is a textual description of the field.  If
 *    provided, it will be returned by skPluginFieldDescription().
 *
 *    'regdata' is a struct of type skplugin_callbacks_t, which should
 *    be filled out as follows:
 *
 *      'column_width' is the number of characters (not including
 *      trailing NUL) required to hold a string representation of the
 *      longest value of the field.  This value can be zero if not
 *      used, or if it will be set later using skpinSetFieldWidths().
 *
 *      'bin_bytes' is the number of bytes required to hold a binary
 *      representation of a value of the field.  This value can be
 *      zero if not used, or if it will be set later using
 *      skpinSetFieldWidths().
 *
 *      The application will call 'init(cbdata)' when the application
 *      has decided this field will be used, before processing data.
 *      It may be NULL.
 *
 *      'cleanup(cbdata)' is called after all records have been
 *      processed.  It may be NULL.
 *
 *      'rec_to_text' is a callback function of type
 *      skplugin_text_fn_t.  'rec_to_text(rec, dst, width, cbdata)' is
 *      called to fetch the textual value for a field given the SiLK
 *      Flow record 'rec'.  'rec_to_text()' should write no more than
 *      'column_width' bytes into 'dst'.  The parameter 'width'
 *      specifies the size of 'dst', which may be equal to
 *      'column_width'.
 *
 *      'rec_to_bin' is a callback function of type skplugin_bin_fn_t.
 *      'rec_to_bin(rec, dst, cbdata)' is called to fetch the binary
 *      value for this field given the SiLK Flow record 'rec'.
 *      'rec_to_bin' should write exactly 'bin_bytes' bytes into
 *      'dst'.  If an application requires a rec-to-binary function
 *      but 'rec_to_bin' is NULL and 'rec_to_text' is present,
 *      'rec_to_text' will be used instead, and 'column_width' will be
 *      used as the width for binary values (zeroing out the
 *      destination area before it is written to).
 *
 *      'add_rec_to_bin' is a callback function of type
 *      skplugin_bin_fn_t.  'rec_to_bin(rec, dst, cbdata)' is called
 *      to add to the binary value in 'dst' based on the SiLK Flow
 *      record given in 'rec'.  'rec_to_bin' should write exactly
 *      'bin_bytes' bytes into 'dst'.  This function is only used for
 *      aggregate value fields.
 *
 *      'bin_to_text(bin, dst, width, cbdata)' is called to get a
 *      textual representation of the value in 'bin', where 'bin' was
 *      set by a call to 'rec_to_bin' or 'add_rec_to_bin'.  The
 *      'bin_to_text' callback should write no more than 'width'
 *      characters into 'dst'.
 *
 *      'bin_merge(dst, src, cbdata)' is called to merge (or add) the
 *      binary aggregate values of 'src' and 'dst' into 'dst'.
 *      Whereas 'add_rec_to_bin' combines a Flow record's field's
 *      value and a bin, 'bin_merge' combines the values of two bins.
 *
 *      'bin_compare(val, a, b, cbdata)' is called to compare the
 *      binary aggregate values 'a' and 'b'.  It must set 'val' to an
 *      integer indicating whether 'a' is less than, equal to, or
 *      greater than 'b'.  If this function is NULL, memcmp() will be
 *      used on the binary values instead.
 *
 *      'initial' represents the inital value of the binary aggregate
 *      value.  It should contain be exactly 'bin_bytes' bytes.  If
 *      not given, the field will be initialzed to all NULs.
 *
 *      'extra' is a NULL-terminated constant array of strings
 *      representing "extra arguments".  Read the EXTRA ARGUMENTS
 *      section for information on these arguments.  It may be NULL.
 *
 *    NOTE: When sorting, the binary values provided by 'rec_to_bin()
 *    will be sorted using memcmp().  If the plugin wants to enforce a
 *    specific ordering, it should be sure to produce values that will
 *    sort correctly.
 *
 *    If 'name' or 'regdata' is NULL, skpinRegField() sets
 *    'return_field', if provided, to NULL and returns SKPLUGIN_ERR.
 */
skplugin_err_t
skpinRegField(
    skplugin_field_t              **return_field,
    const char                     *name,
    const char                     *description,
    const skplugin_callbacks_t     *regdata,
    void                           *cbdata);

/**
 *    Set the textual and binary widths for a field.  Meant to be used
 *    within an 'init' function.
 */
skplugin_err_t
skpinSetFieldWidths(
    skplugin_field_t   *field,
    size_t              field_width_text,
    size_t              field_width_bin);

/**
 *    Adds an alias (name) for a field.  Returns SKPLUGIN_ERR if the
 *    name already exists, SKPLUGIN_OK otherwise.
 */
skplugin_err_t
skpinAddFieldAlias(
    skplugin_field_t   *field,
    const char         *alias);

/**
 *    Sets the title for a field.
 */
skplugin_err_t
skpinSetFieldTitle(
    skplugin_field_t   *field,
    const char         *title);

/**
 *    Register a cleanup function for the plugin.  This will be called
 *    by skPluginRunCleanup() after all the function-specific cleanups
 *    are called.
 */
skplugin_err_t
skpinRegCleanup(
    skplugin_cleanup_fn_t   cleanup);


/**
 *    Declare that this plugin is not thread safe.  This function
 *    should only be called when the plugin is active; otherwise the
 *    mere presence of the plug-in will prevent rwfilter from running
 *    with multiple threads.
 */
void
skpinSetThreadNonSafe(
    void);


/**
 *      Create an skstream_t object using the specified 'content_type'
 *      and 'filename', open it, and fill the location pointed to by
 *      'stream' with the object.  If the application has called
 *      skPluginSetOpenInputFunction(), that function will be used if
 *      it is non-null.
 *  Inputs:
 *      location in which to return address of skstream_t object
 *      content_type of the filename
 *      name of file to open
 *  Outputs:
 *      Returns 0 if stream was successfully opened and should be
 *      used.  Returns -1 on error.  Returns 1 if the plug-in should
 *      ignore the file.
 *  Side Effects:
 *      'stream' is filled with address of skstream_t object.
 */
int
skpinOpenDataInputStream(
    skstream_t        **stream,
    skcontent_t         content_type,
    const char         *filename);



/********************************************************************
 *
 *    APPLICATION INTERFACE
 *
 ********************************************************************
 *
 *    The following defines, typedefs, and functions are meant to be
 *    used/called by the application code which is loading and using
 *    plugins.
 *
 ********************************************************************/


/**
 *    Version check result type
 */
typedef enum {
    SKPLUGIN_VERSION_OK,
    SKPLUGIN_VERSION_OLD,
    SKPLUGIN_VERSION_TOO_NEW
} skplugin_version_result_t;


/**
 *  SK_PLUGIN_ADD_SUFFIX(name)
 *
 *    Adds the appropriate suffix to 'name' to get the file name that
 *    skplugin should attempt to dlopen().  'name' should be a string;
 *    we rely on CPP concatenation to add the suffix.
 */
#define SK_PLUGIN_ADD_SUFFIX(file_basename) (file_basename SK_PLUGIN_SUFFIX)

/**
 *   The current major version of the skplugin interface.
 */
#define SKPLUGIN_INTERFACE_VERSION_MAJOR 1

/**
 *   The current minor version of the skplugin interface.
 */
#define SKPLUGIN_INTERFACE_VERSION_MINOR 0

/**
 *    Name of envar that if set will enable debugging output
 */
#define SKPLUGIN_DEBUG_ENVAR "SILK_PLUGIN_DEBUG"

/**
 *   Version number check
 */
#define SKPLUGIN_VERSION_CHECK(protocol_major, protocol_minor,          \
                               plugin_major, plugin_minor)              \
    ((plugin_major < protocol_major) ? SKPLUGIN_VERSION_TOO_NEW :       \
     ((plugin_major > protocol_major) ? SKPLUGIN_VERSION_OLD :          \
      ((plugin_minor > protocol_minor) ? SKPLUGIN_VERSION_OLD :         \
       SKPLUGIN_VERSION_OK)))

/**
 *    field iterator
 */
typedef struct skplugin_field_iter_st {
    sk_dll_iter_t      list_iter;
    skplugin_fn_mask_t fn_mask;
    unsigned           all_fields : 1;
} skplugin_field_iter_t;


/**
 *    Type signature of the function that skpinOpenDataInputStream()
 *    will call.
 */
typedef int (*open_data_input_fn_t)(
    skstream_t        **stream,
    skcontent_t         content_type,
    const char         *filename);

/**
 *    The type of the setup function that plugins export.  'pi_data'
 *    is an opaque type determined by the values 'major_version' and
 *    'minor_version'.  In the current version (1), the 'pi_data' is
 *    not used, and NULL will be passed as the 'pi_data' argument.
 */
typedef skplugin_err_t (*skplugin_setup_fn_t)(
    uint16_t  major_version,
    uint16_t  minor_version,
    void     *pi_data);


/**
 *    This is used to initialize the skplugin library.  'num_entries'
 *    is the number of function masks that will be passed to this
 *    function.  Each function mask should indicate a type of
 *    plugin functionality the application wants.
 */
void
skPluginSetup(
    int                 num_entries,
    ...);

/**
 *    Unloads all plugins and frees all plugin data.  Does not call
 *    the 'cleanup' functions that the plugins have registered.  The
 *    'cleanup' functions are called by skPluginRunCleanup().
 */
void
skPluginTeardown(
    void);

/**
 *    Loads the plugin represented by the filename 'name'.  If
 *    complain_on_error is non-zero, error messages will be written to
 *    the error stream.
 */
skplugin_err_t
skPluginLoadPlugin(
    const char         *name,
    int                 complain_on_error);

/**
 *    Uses 'setup_fn' as a plugin entry point, and treats the result
 *    as a loaded plugin.
 */
skplugin_err_t
skPluginAddAsPlugin(
    const char             *name,
    skplugin_setup_fn_t     setup_fn);

/**
 *    Print, to 'fh', the usage information for the options which the
 *    plugins have registered through calls to skpinRegOption2().
 */
skplugin_err_t
skPluginOptionsUsage(
    FILE               *fh);

/**
 *    Sets the function that skpinOpenDataInputStream() should use for
 *    opening files to 'open_fn'.
 *
 *    If this function is not called or called with a NULL parameter,
 *    the sequence of functions skStreamCreate(), skStreamBind(),
 *    skStreamOpen() is called.
 */
void
skPluginSetOpenInputFunction(
    open_data_input_fn_t    open_fn);

/**
 *    Returns 1 if all loaded plugins can be safely be run in a
 *    threaded context, 0 otherwise.
 */
int
skPluginIsThreadSafe(
    void);

/**
 *    Returns 1 if any filtering plugins are currently registered, 0
 *    if not.
 */
int
skPluginFiltersRegistered(
    void);

/**
 *    Returns 1 if any transform plugins are currently registered, 0
 *    if not.
 */
int
skPluginTransformsRegistered(
    void);

/**
 *    Binds an iterator around all fields that contain information
 *    that matches the 'fn_mask'.  If 'all_fields' is false, will
 *    only iterate over "activated" fields.
 */
skplugin_err_t
skPluginFieldIteratorBind(
    skplugin_field_iter_t  *iter,
    skplugin_fn_mask_t      fn_mask,
    int                     all_fields);

/**
 *    Resets a field iterator so it can be iterated over again.
 */
skplugin_err_t
skPluginFieldIteratorReset(
    skplugin_field_iter_t  *iter);

/**
 *    Retrieves the field identifier for the next field.  Returns 1 on
 *    success, 0 on failure.
 */
int
skPluginFieldIteratorNext(
    skplugin_field_iter_t  *iter,
    skplugin_field_t      **field);

/**
 *    Returns the function mask for a field.
 */
skplugin_fn_mask_t
skPluginFieldFnMask(
    const skplugin_field_t *field);

/**
 *    Activate the field 'field'.  All fields start deactivated.
 *    Activating a field allows its 'init' and 'cleanup' functions to
 *    run.  Return SKPLUGIN_OK.  Exit on memory allocation error.
 */
skplugin_err_t
skPluginFieldActivate(
    const skplugin_field_t *field);

/**
 *    Deactivate the field 'field'.  All fields start deactivated.
 *    Return SKPLUGIN_OK (always).
 */
skplugin_err_t
skPluginFieldDeactivate(
    const skplugin_field_t *field);

/**
 *    Retrieves a pointer to the constant names of a field.  This is a
 *    NULL-terminated list of strings
 */
skplugin_err_t
skPluginFieldName(
    const skplugin_field_t     *field,
    const char               ***name);

/**
 *    Retrieves a pointer to the constant title of a field.  The
 *    caller should not modify this value.
 */
skplugin_err_t
skPluginFieldTitle(
    const skplugin_field_t     *field,
    const char                **title);

/**
 *    Retrieves a pointer to the constant description of a field.  The
 *    caller should not modify this value.  The description may be
 *    NULL.
 */
skplugin_err_t
skPluginFieldDescription(
    const skplugin_field_t     *field,
    const char                **description);

/**
 *    Retrieves a pointer to the constant path of the plugin which
 *    created the field.  The caller should not modify this value.
 */
skplugin_err_t
skPluginFieldGetPluginName(
    const skplugin_field_t     *field,
    const char                **plugin_name);

/**
 *    Retrieves the length of the binary representation for this
 *    field.  This is the value that was specified in
 *    skplugin_callbacks_t.bin_bytes.  Returns SKPLUGIN_ERR if no
 *    functions that use the binary length were registered for
 *    'field'.
 */
skplugin_err_t
skPluginFieldGetLenBin(
    const skplugin_field_t *field,
    size_t                 *len);

/**
 *    Retrieves the maximum length of text fields (not including
 *    terminating NUL) for this field.  This is the value that was
 *    specified in skplugin_callbacks_t.column_width.  Returns
 *    SKPLUGIN_ERR if no functions that use the textual length were
 *    registered for 'field'.
 */
skplugin_err_t
skPluginFieldGetLenText(
    const skplugin_field_t *field,
    size_t                 *len);

/**
 *    Copies the initial binary value for this field into the bytes
 *    pointed to by 'initial_value'.  This is the value that was
 *    specified in skplugin_callbacks_t.initial.
 */
skplugin_err_t
skPluginFieldGetInitialValue(
    const skplugin_field_t *aggregate,
    uint8_t                *intial_value);


/*********************************************/
/*** Functions to invoke plugin callbacks  ***/
/*********************************************/

/* The following set of functions are invoked by the application, and
 * these functions will call the appropriate function on the
 * registered/active plugins. */

/**
 *    Runs the 'init' routines for the functions and the activated
 *    fields requested.
 *
 *    That is, calls the skplugin_callback_fn_t function:
 *    skplugin_callbacks_t.init(cbdata)
 *
 *    If 'fn_mask' is non-zero, this will only initialize activated
 *    fields for whom 'fn_mask' is a subset of their callback
 *    functions.  If 'fn_mask' will run over activated fields, you
 *    should not run skPluginFieldRunInitialize() on the individual
 *    fields, unless you know the initialization functions will be
 *    idempotent.
 */
skplugin_err_t
skPluginRunInititialize(
    skplugin_fn_mask_t  fn_mask);

/**
 *    Runs the cleanup routines for the activated and activated fields
 *    requested.
 *
 *    That is, calls the skplugin_callback_fn_t function:
 *    skplugin_callbacks_t.cleanup(cbdata)
 *
 *    If 'fn_mask' is non-zero, this will only clean up activated
 *    fields for whom 'fn_mask' is a subset of their callback
 *    functions.  If 'fn_mask' will fun over activated fields, you
 *    should not run skPluginFieldRunCleanup() on the individual
 *    fields, unless you know the cleanup functions will be
 *    idempotent.
 */
skplugin_err_t
skPluginRunCleanup(
    skplugin_fn_mask_t  fn_mask);

/**
 *    Runs a specific plugin field's initialization function.
 */
skplugin_err_t
skPluginFieldRunInitialize(
    const skplugin_field_t *field);

/**
 *    Runs a specific plugin field's cleanup function.
 */
skplugin_err_t
skPluginFieldRunCleanup(
    const skplugin_field_t *field);

/**
 *    Runs the filter functions over the SiLK Flow record 'rec' for
 *    all registered filters.
 *
 *    That is, calls the skplugin_filter_fn_t function:
 *    skplugin_callbacks_t.filter(rec, cbdata, extra)
 *
 *    The 'extra' fields are determined as described in the EXTRA
 *    ARGUMENTS section.
 */
skplugin_err_t
skPluginRunFilterFn(
    const rwRec        *rec,
    void              **extra);

/**
 *    Runs the transform functions over the SiLK Flow record 'rec' for
 *    all registered tranformers.
 *
 *    That is, calls the skplugin_transform_fn_t function:
 *    skplugin_callbacks_t.transform(rec, cbdata, extra)
 *
 *    The 'extra' fields are determined as described in the EXTRA
 *    ARGUMENTS section.
 */
skplugin_err_t
skPluginRunTransformFn(
    rwRec              *rec,
    void              **extra);

/**
 *    Runs the record-to-text function over the SiLK Flow record 'rec'
 *    for the specified field, and puts the value into 'text', where
 *    'text' is an array of 'width' characters.
 *
 *    That is, calls the skplugin_text_fn_t function:
 *    skplugin_callbacks_t.rec_to_text(rec, text. width, cbdata, extra)
 *
 *    The 'extra' fields are determined as described in the EXTRA
 *    ARGUMENTS section.
 */
skplugin_err_t
skPluginFieldRunRecToTextFn(
    const skplugin_field_t     *field,
    char                       *text,
    size_t                      width,
    const rwRec                *rec,
    void                      **extra);

/**
 *    Runs the record-to-bin function over the SiLK Flow record 'rec'
 *    for the specified field, and puts the value into 'bin'.
 *
 *    That is, calls the skplugin_bin_fn_t function:
 *    skplugin_callbacks_t.rec_to_bin(rec, bin, cbdata, extra)
 *
 *    The required size of 'bin' can be determined by a call to
 *    skPluginFieldGetLenBin().
 *
 *    The 'extra' fields are determined as described in the EXTRA
 *    ARGUMENTS section.
 */
skplugin_err_t
skPluginFieldRunRecToBinFn(
    const skplugin_field_t     *field,
    uint8_t                    *bin,
    const rwRec                *rec,
    void                      **extra);

/**
 *    Given a SiLK Flow record 'rec', runs the function that computes
 *    a binary value for this field and merges with (adds to) the
 *    value into currently in 'bin' into 'bin'.  The required size of
 *    'bin' can be determined by a call to skPluginFieldGetLenBin().
 *
 *    That is, calls the skplugin_bin_fn_t function:
 *    skplugin_callbacks_t.add_rec_to_bin(rec, bin, cbdata, extra)
 *
 *    The 'extra' fields are determined as described in the EXTRA
 *    ARGUMENTS section.
 */
skplugin_err_t
skPluginFieldRunAddRecToBinFn(
    const skplugin_field_t     *field,
    uint8_t                    *bin,
    const rwRec                *rec,
    void                      **extra);

/**
 *    Runs the binary-to-text function for the specified field.  The
 *    function takes the binary value 'bin' and puts a textual value
 *    into 'text', an array of 'width' characters.
 *
 *    That is, calls the skplugin_bin_to_text_fn_t function:
 *    skplugin_callbacks_t.bin_to_text(bin, text, width, cbdata)
 */
skplugin_err_t
skPluginFieldRunBinToTextFn(
    const skplugin_field_t *field,
    char                   *text,
    size_t                  width,
    const uint8_t          *bin);

/**
 *    Runs the function that merges two binary values for this field.
 *    The binary value in 'src' is merged with 'dst', and the result
 *    is put back in 'dst'.
 *
 *    That is, calls the skplugin_bin_merge_fn_t function:
 *    skplugin_callbacks_t.bin_merge(dst, src, cbdata)
 */
skplugin_err_t
skPluginFieldRunBinMergeFn(
    const skplugin_field_t *field,
    uint8_t                *dst,
    const uint8_t          *src);

/**
 *    Runs the function that compares two binary values for this
 *    field.  The binary value in 'a' is compared with 'b', and the
 *    result (less than zero, zero, greater than zero) is put in
 *    'val'.
 *
 *    That is, calls the skplugin_bin_cmp_fn_t function:
 *    skplugin_callbacks_t.bin_compare(val, a, b, cbdata)
 */
skplugin_err_t
skPluginFieldRunBinCompareFn(
    const skplugin_field_t *field,
    int                    *val,
    const uint8_t          *a,
    const uint8_t          *b);



/********************************************************************
 *
 *    EXTRA ARGUMENTS
 *
 ********************************************************************/

/*
 *    Extra arguments are sets of extra information that can be passed
 *    to plugin functions on a per-SiLK Flow record (rwrec) basis.
 *    Extra arguments are named, and it is the responsibility of the
 *    application and plugin writers to agree on what type of data
 *    each name is associated with.
 *
 *    Extra arguments are meant to be used when a plugin can make use
 *    of extra information associated with an rwrec that is not in the
 *    rwrec itself.  Some plugins may actually require certain extra
 *    arguments in order to work.  An example: rwptoflow supports a
 *    transform function that requires the original packet data as
 *    context.
 *
 *    Extra arguments are meant to be used as follows:
 *
 *    a) The application registers the set of extra data it can supply
 *       with each record using skPluginSetAppExtraArgs().
 *
 *    b) The plugin gets information about what extra arguments are
 *       available using skpinGetAppExtraArgs().
 *
 *    c) If the plugin wishes to use the any of the extra arguments,
 *       it provides the names of those arguments, and the order in
 *       which is will expect them, as a NULL-terminated list in the
 *       'extra' field of the skplugin_callbacks_t structure.  The
 *       plugin may only include names that it received in the call to
 *       skpinGetAppExtraArgs().  There is less overheaad involved if
 *       the plugin specifies the arguments in the same order specifed
 *       in skpinGetAppExtraArgs().
 *
 *    d) After plugins have been loaded, the application finds out
 *       what extra arguments are being requested by the plugins via
 *       skPluginGetPluginExtraArgs().  These extra arguments MUST be
 *       used by the application, as the plugin will be expecting
 *       them.
 *
 *    e) The application then registers what extra arguments it will
 *       send, and in what order, using the
 *       skPluginSetUsedAppExtraArgs() function.  This set must
 *       include the extra arguments returned by
 *       skPluginGetPluginExtraArgs().
 *
 *    f) The application will hand the extra arguments to calls of
 *       skPluginRun*Fn() and skPluginFieldRun*Fn() in the order
 *       specified in skPluginSetUsedAppExtraArgs().  (Can send NULL
 *       if no extra arguments registered).  The plugins will receive
 *       the extra arguments they asked for in the order specified in
 *       Step (c) above.  The application and its plugins can reduce
 *       the overhead in the skPlugin layer by specifying the same set
 *       of extra arguments in the same order.
 */


/**
 *    Called by the application.  Sets the extra arguments that the
 *    application handles.  'extra' is a NULL terminated array of
 *    strings.  If 'extra' is NULL, no extra arguments are registered.
 *    (This is the default).
 */
void
skPluginSetAppExtraArgs(
    const char        **extra);

/**
 *    Called by the plugin.  Gets the list of extra arguments that the
 *    application specified in skPluginSetAppExtraArgs().  The list is
 *    returned as a NULL-terminated list of strings.
 */
const char **
skpinGetAppExtraArgs(
    void);

/**
 *    Called by the application.  Gets the list of extra arguments
 *    that the plugins support.  The returned array will be a
 *    NULL-terminated list of strings.  The application is obligated
 *    to use all these arguments.
 */
const char **
skPluginGetPluginExtraArgs(
    void);

/**
 *    Called by the application.  Sets which extra arguments the
 *    application will actually use, and the order in which they will
 *    be given.  'extra' is a NULL-terminated array of strings.  If
 *    'extra' is NULL, no extra arguments are registered.
 */
void
skPluginSetUsedAppExtraArgs(
    const char        **extra);

#ifdef __cplusplus
}
#endif
#endif /* _SKPLUGIN_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
