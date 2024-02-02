/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  rwpackerchecker
**
**    Process file(s) or the standard input looking for and reporting
**    on "odd" things:
**
**
**
**    Mark Thomas
**    February 2007
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpackchecker.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skdllist.h>
#include <silk/skipset.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */

/* file handle for --help output */
#define USAGE_FH stdout

/* the checks we can make */
typedef enum {
    BPP_CALC,
    ELAPSED_TIME,
    BYTE_PKT_RATIO,
    BYTE_SEC_RATIO,
    PKT_COUNT,
    BYTE_COUNT,
    ICMP_BPP,
    TCP_BPP,
    UDP_BPP,
    SIP_SET,
    DIP_SET,
    NHIP_SET,
    PROTO,
    TCPFLAGS,
    SNMP_INPUT,
    SNMP_OUTPUT,
    SPORT,
    DPORT
} check_type_t;


/* For 'threshold_t', this is the type of the threshold: a number can
 * be an upper or lower bound; a set can be inclusive or exclusive. */
typedef enum {
    THR_VAL_MAX = 0,
    THR_VAL_MIN,
    THR_SET_IN,
    THR_SET_EX,
    THR_MAP_IN,
    THR_MAP_EX,
    THR_OTHER
} threshold_type_t;

typedef union value_union_un {
    /* the limit of the "range".  whether a min or a max depends on
     * the 't_type' value. */
    uint32_t            num;
    /* a list of IPs */
    skipset_t          *ipset;
    /* a bitmap of values (ports, protos) */
    sk_bitmap_t        *bitmap;
} value_union_t;

typedef struct threshold_st {
    /* title for this threshold */
    const char         *t_title;
    /* option name to enable it or change its value */
    const char         *t_optname;
    /* the number of times we observe the value */
    uint64_t            t_count;
    /* the number of times we can see a value outside the "normal"
     * range before we consider it abnormal. */
    uint64_t            t_allowable;
    /* the value: a number or a set */
    value_union_t       t_value;
    /* whether 't_value' represents an upper or lower threshold or an
     * inclusive or exclusive set */
    threshold_type_t    t_type;
    /* the type of the check */
    check_type_t        t_check;
} threshold_t;


/* LOCAL VARIABLES */

/* fixed tests we always do */
static threshold_t fixed_tests[] = {
    {"BPP Calculation", NULL,
     0,      0, {         0}, THR_OTHER,   BPP_CALC},
    {"Elapsed Time",    NULL,
     0,      0, {      4096}, THR_VAL_MAX, ELAPSED_TIME}
};

/* tests we always do; the user can modify values */
static threshold_t modifiable_tests[] = {
    {"Byte/Packet Ratio",       "min-bpp-ratio",
     0,      0,  {         1}, THR_VAL_MIN, BYTE_PKT_RATIO},
    {"Byte/Packet Ratio",       "max-bpp-ratio",
     0,      0,  {   1 << 14}, THR_VAL_MAX, BYTE_PKT_RATIO},
    {"Byte/Second Ratio",       "min-bps-ratio",
     0,      0,  {         0}, THR_VAL_MIN, BYTE_SEC_RATIO},
    {"Byte/Second Ratio",       "max-bps-ratio",
     0,      0,  {UINT32_MAX}, THR_VAL_MAX, BYTE_SEC_RATIO},
    {"Packet Count",            "min-packets",
     0,      0,  {         1}, THR_VAL_MIN, PKT_COUNT},
    {"Packet Count",            "max-packets",
     0,      0,  {   1 << 26}, THR_VAL_MAX, PKT_COUNT},
    {"Byte Count",              "min-bytes",
     0,      0,  {         1}, THR_VAL_MIN, BYTE_COUNT},
    {"Byte Count",              "max-bytes",
     0,      0,  {UINT32_MAX}, THR_VAL_MAX, BYTE_COUNT},
    {"TCP Byte/Packet Ratio",   "min-tcp-bpp-ratio",
     0,      0,  {         1}, THR_VAL_MIN, TCP_BPP},
    {"TCP Byte/Packet Ratio",   "max-tcp-bpp-ratio",
     0,      0,  {   1 << 14}, THR_VAL_MAX, TCP_BPP},
    {"UDP Byte/Packet Ratio",   "min-udp-bpp-ratio",
     0,      0,  {         1}, THR_VAL_MIN, UDP_BPP},
    {"UDP Byte/Packet Ratio",   "max-udp-bpp-ratio",
     0,      0,  {   1 << 14}, THR_VAL_MAX, UDP_BPP},
    {"ICMP Byte/Packet Ratio",  "min-icmp-bpp-ratio",
     0,      0,  {         1}, THR_VAL_MIN, ICMP_BPP},
    {"ICMP Byte/Packet Ratio",  "max-icmp-bpp-ratio",
     0,      0,  {   1 << 14}, THR_VAL_MAX, ICMP_BPP},
};

/* optional tests the user can choose to run */
static threshold_t optional_tests[] = {
    {"Protocol",                "match-protocol",
     0,      0,  {       0}, THR_MAP_IN, PROTO},
    {"Protocol",                "nomatch-protocol",
     0,      0,  {       0}, THR_MAP_EX, PROTO},
    {"TCP Flag Combination",    "match-flags",
     0,      0,  {       0}, THR_MAP_IN, TCPFLAGS},
    {"TCP Flag Combination",    "nomatch-flags",
     0,      0,  {       0}, THR_MAP_EX, TCPFLAGS},
    {"Source IP",               "match-sip",
     0,      0,  {       0}, THR_SET_IN, SIP_SET},
    {"Source IP",               "nomatch-sip",
     0,      0,  {       0}, THR_SET_EX, SIP_SET},
    {"Destination IP",          "match-dip",
     0,      0,  {       0}, THR_SET_IN, DIP_SET},
    {"Destination IP",          "nomatch-dip",
     0,      0,  {       0}, THR_SET_EX, DIP_SET},
    {"Source Port",             "match-sport",
     0,      0,  {       0}, THR_MAP_IN, SPORT},
    {"Source Port",             "nomatch-sport",
     0,      0,  {       0}, THR_MAP_EX, SPORT},
    {"Destination Port",        "match-dport",
     0,      0,  {       0}, THR_MAP_IN, DPORT},
    {"Destination Port",        "nomatch-dport",
     0,      0,  {       0}, THR_MAP_EX, DPORT},
    {"Next Hop IP",             "match-nhip",
     0,      0,  {       0}, THR_SET_IN, NHIP_SET},
    {"Next Hop IP",             "nomatch-nhip",
     0,      0,  {       0}, THR_SET_EX, NHIP_SET},
    {"SNMP Input",              "match-input",
     0,      0,  {       0}, THR_MAP_IN, SNMP_INPUT},
    {"SNMP Input",              "nomatch-input",
     0,      0,  {       0}, THR_MAP_EX, SNMP_INPUT},
    {"SNMP Output",             "match-output",
     0,      0,  {       0}, THR_MAP_IN, SNMP_OUTPUT},
    {"SNMP Output",             "nomatch-output",
     0,      0,  {       0}, THR_MAP_EX, SNMP_OUTPUT}
};
static sk_bitmap_t *optional_isactive = NULL;


/* string map of potential threshold tests used to during options
 * processing */
static sk_stringmap_t *str_map;

/* ids where the various tests start inside of the string map */
static uint32_t modifiable_first_map_id = UINT32_MAX;
static uint32_t optional_first_map_id = UINT32_MAX;

/* lists of tests to perform; these point to threshold_t objects. */
static sk_dllist_t *tests = NULL;

/* whether to print the entire statistics for a file */
static int print_all = 0;

/* input file processor */
static sk_options_ctx_t *optctx = NULL;


/* OPTIONS */

typedef enum {
    OPT_VALUE, OPT_ALLOWABLE_COUNT,
    OPT_PRINT_ALL
} appOptionsEnum;

static struct option appOptions[] = {
    {"value",           REQUIRED_ARG, 0, OPT_VALUE},
    {"allowable-count", REQUIRED_ARG, 0, OPT_ALLOWABLE_COUNT},
    {"print-all",       NO_ARG,       0, OPT_PRINT_ALL},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Set the value of the named test to the specified value;\n"
     "\tseparate the test name from value by an '='.  Repeat this switch\n"
     "\tfor each value that you wish to set."),
    ("Allow the test to be violated this number of\n"
     "\ttimes before treating it as \"unusual\"; separate the test name\n"
     "\tfrom the count by an '='.  Repeat this switch for each allowable\n"
     "\tcount you wish to set."),
    ("Print the results for all tests, not just those that\n"
     "\tviolated the threshold and allowable count"),
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void thresholdFree(void *v_t);
static int  thresholdInit(void);
static threshold_t *findThreshold(const char *name, int mark_as_seen);
static int  setThreshold(threshold_t *t, const char *opt_arg);
static void thresholdUsage(FILE *fh, const threshold_t *t);
static int  parseFlags(sk_bitmap_t *flag_map, const char *flag_list);
static int  checkFile(skstream_t *stream);


/* FUNCTION DEFINITIONS */

/*
 *  appUsageLong();
 *
 *    Print complete usage information to USAGE_FH.  Pass this
 *    function to skOptionsSetUsageCallback(); skOptionsParse() will
 *    call this funciton and then exit the program when the --help
 *    option is given.
 */
static void
appUsageLong(
    void)
{
#define USAGE_MSG                                                       \
    ("[SWITCHES] [FILES] \n"                                            \
     "\tReads SiLK Flow records from the FILES named on the comamnd\n"  \
     "\tline or from the standard input when no FILES are provided,\n"  \
     "\tand looks for \"unusual\" patterns that may indicate a\n"       \
     "\tcorrupted data file.\n")

    FILE *fh = USAGE_FH;
    size_t i;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsCtxOptionsUsage(optctx, fh);

    fprintf(fh, "\nTEST NAMES\n");
    for (i = 0; i < sizeof(modifiable_tests)/sizeof(threshold_t); ++i) {
        thresholdUsage(fh, &(modifiable_tests[i]));
    }

    fprintf(fh, "\nOPTIONAL TESTS:\n");
    for (i = 0; i < sizeof(optional_tests)/sizeof(threshold_t); ++i) {
        thresholdUsage(fh, &(optional_tests[i]));
    }
}


/*
 *  appTeardown()
 *
 *    Teardown all modules, close all files, and tidy up all
 *    application state.
 *
 *    This function is idempotent.
 */
static void
appTeardown(
    void)
{
    static int teardownFlag = 0;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (optional_isactive) {
        skBitmapDestroy(&optional_isactive);
    }
    if (str_map) {
        skStringMapDestroy(str_map);
        str_map = NULL;
    }
    if (tests) {
        skDLListDestroy(tests);
    }

    skOptionsCtxDestroy(&optctx);
    skAppUnregister();
}


/*
 *  appSetup(argc, argv);
 *
 *    Perform all the setup for this application include setting up
 *    required modules, parsing options, etc.  This function should be
 *    passed the same arguments that were passed into main().
 *
 *    Returns to the caller if all setup succeeds.  If anything fails,
 *    this function will cause the application to exit with a FAILURE
 *    exit status.
 */
static void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    unsigned int optctx_flags;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown hanlder */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* create string map of test names and the list of tests */
    if (thresholdInit()) {
        skAppPrintErr("Unable to initialize threshold tests");
        exit(EXIT_FAILURE);
    }

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names, but we
     * should not consider it a complete failure */
    sksiteConfigure(0);

    return;
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    This function is passed to skOptionsRegister(); it will be called
 *    by skOptionsParse() for each user-specified switch that the
 *    application has registered; it should handle the switch as
 *    required---typically by setting global variables---and return 1
 *    if the switch processing failed or 0 if it succeeded.  Returning
 *    a non-zero from from the handler causes skOptionsParse() to return
 *    a negative value.
 *
 *    The clientData in 'cData' is typically ignored; 'opt_index' is
 *    the index number that was specified as the last value for each
 *    struct option in appOptions[]; 'opt_arg' is the user's argument
 *    to the switch for options that have a REQUIRED_ARG or an
 *    OPTIONAL_ARG.
 */
static int
appOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    threshold_t *t;
    char name[1024];
    char *vp;
    size_t len;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_PRINT_ALL:
        print_all = 1;
        break;

      case OPT_VALUE:
        vp = strchr(opt_arg, '=');
        if (!vp) {
            skAppPrintErr("Missing '=' in argument to --%s switch",
                          appOptions[opt_index].name);
            return 1;
        }
        len = vp - opt_arg;
        ++vp;
        if (len > sizeof(name) - 1) {
            skAppPrintErr("Threshold name is too long in --%s switch",
                          appOptions[opt_index].name);
            return 1;
        }
        strncpy(name, opt_arg, len);
        name[len] = '\0';
        t = findThreshold(name, 1);
        if (t == NULL) {
            skAppPrintErr("Invalid threshold name '%s' in --%s switch",
                          name, appOptions[opt_index].name);
            return 1;
        }
        if (setThreshold(t, vp)) {
            skAppPrintErr("Invalid %s for '%s' threshold",
                          appOptions[opt_index].name, name);
            return 1;
        }
        break;

      case OPT_ALLOWABLE_COUNT:
        vp = strchr(opt_arg, '=');
        if (!vp) {
            skAppPrintErr("Missing '=' in argument to --%s switch",
                          appOptions[opt_index].name);
            return 1;
        }
        len = vp - opt_arg;
        ++vp;
        if (len > sizeof(name) - 1) {
            skAppPrintErr("Threshold name is too long in --%s switch",
                          appOptions[opt_index].name);
            return 1;
        }
        strncpy(name, opt_arg, len);
        name[len] = '\0';
        t = findThreshold(name, 1);
        if (t == NULL) {
            skAppPrintErr("Invalid threshold name '%s' in --%s switch",
                          name, appOptions[opt_index].name);
            return 1;
        }
        rv = skStringParseUint64(&(t->t_allowable), vp, 0, 0);
        if (rv) {
            skAppPrintErr("Invalid %s for '%s' threshold: %s",
                          appOptions[opt_index].name, name,
                          skStringParseStrerror(rv));
            return 1;
        }
        break;

    } /* switch */

    return 0;                   /* OK */
}


/*
 *  thresholdFree(threshold);
 *
 *    Free the state of the threshold_t object 'threshold'.  This
 *    function is invoked by skDLListDestroy().
 */
static void
thresholdFree(
    void               *v_t)
{
    threshold_t *t = (threshold_t*)v_t;

    switch (t->t_type) {
      case THR_SET_IN:
      case THR_SET_EX:
        skIPSetDestroy(&t->t_value.ipset);
        break;
      case THR_MAP_IN:
      case THR_MAP_EX:
        skBitmapDestroy(&t->t_value.bitmap);
        break;
      default:
        break;
    }
}


static int
thresholdInit(
    void)
{
    size_t i;
    threshold_t *t;
    sk_stringmap_id_t map_size;
    sk_stringmap_entry_t entry;

#define CLEAR_SET_AND_BITMAP(t)                 \
    switch ((t)->t_type) {                      \
      case THR_SET_IN:                          \
      case THR_SET_EX:                          \
        (t)->t_value.ipset = NULL;              \
        break;                                  \
      case THR_MAP_IN:                          \
      case THR_MAP_EX:                          \
        (t)->t_value.bitmap = NULL;             \
        break;                                  \
      default:                                  \
        break;                                  \
    }

    /* create the linked list of tests */
    tests = skDLListCreate(thresholdFree);
    if (tests == NULL) {
        return -1;
    }

    /* create the string map */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        return -1;
    }

    /* add each modifiable and optional threshold to the map */
    map_size = 0;

    /* the fixed tests get added to the list of tests but not to the
     * string map */
    for (i = 0, t = fixed_tests;
         i < (sizeof(fixed_tests)/sizeof(threshold_t));
         ++i, ++t)
    {
        CLEAR_SET_AND_BITMAP(t);
        if (skDLListPushTail(tests, t)) {
            return -1;
        }
    }

    /* modifiable thresholds get added to both the tests and to the
     * string map */
    modifiable_first_map_id = map_size;
    for (i = 0, t = modifiable_tests;
         i < (sizeof(modifiable_tests)/sizeof(threshold_t));
         ++i, ++t)
    {
        CLEAR_SET_AND_BITMAP(t);
        if (skDLListPushTail(tests, t)) {
            return -1;
        }
        memset(&entry, 0, sizeof(entry));
        entry.name = t->t_optname;
        entry.id = map_size;
        if (skStringMapAddEntries(str_map, 1, &entry)) {
            return -1;
        }
        ++map_size;
    }

    /* optional thresholds only get added to string map */
    optional_first_map_id = map_size;
    for (i = 0, t = optional_tests;
         i < (sizeof(optional_tests)/sizeof(threshold_t));
         ++i, ++t)
    {
        CLEAR_SET_AND_BITMAP(t);
        memset(&entry, 0, sizeof(entry));
        entry.name = t->t_optname;
        entry.id = map_size;
        if (skStringMapAddEntries(str_map, 1, &entry)) {
            return -1;
        }
        ++map_size;
    }

    /* create a bitmap to note whether an optional test is active */
    if (skBitmapCreate(&optional_isactive,
                       (sizeof(optional_tests)/sizeof(threshold_t))))
    {
        skAppPrintErr("Unable to create test list");
        exit(EXIT_FAILURE);
    }

    return 0;
}


static threshold_t *
findThreshold(
    const char         *name,
    int                 mark_as_seen)
{
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *map_entry;
    uint32_t idx;

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, name, &map_entry);
    if (rv_map != SKSTRINGMAP_OK) {
        switch (rv_map) {
          case SKSTRINGMAP_PARSE_AMBIGUOUS:
            skAppPrintErr("The test name '%s' is ambiguous", name);
            break;

          case SKSTRINGMAP_PARSE_NO_MATCH:
            skAppPrintErr("The test name '%s' is not recognized", name);
            break;

          default:
            skAppPrintErr("Unexpected return value from stringmap parser (%d)",
                          rv_map);
            break;
        }
        return NULL;
    }

    assert(optional_first_map_id > modifiable_first_map_id);

    idx = map_entry->id;
    if (idx >= optional_first_map_id) {
        idx -= optional_first_map_id;
        assert(idx < sizeof(optional_tests)/sizeof(threshold_t));
        if (mark_as_seen) {
            if ( !skBitmapGetBit(optional_isactive, idx)) {
                skBitmapSetBit(optional_isactive, idx);
                if (skDLListPushTail(tests, &optional_tests[idx])) {
                    skAppPrintErr("Unable to add test");
                    return NULL;
                }
            }
        }
        return &optional_tests[idx];
    } else if (idx >= modifiable_first_map_id) {
        idx -= modifiable_first_map_id;
        assert(idx < sizeof(modifiable_tests)/sizeof(threshold_t));
        return &modifiable_tests[idx];
    }

    return NULL;
}


static int
setThreshold(
    threshold_t        *t,
    const char         *opt_arg)
{
    uint32_t val;
    skstream_t *stream = NULL;
    skipset_t *ipset = NULL;
    uint32_t bitmap_size = 65536;
    int rv;

    assert(t);
    switch (t->t_type) {
      case THR_VAL_MIN:
      case THR_VAL_MAX:
        rv = skStringParseUint32(&val, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        t->t_value.num = val;
        break;

      case THR_SET_IN:
      case THR_SET_EX:
        if (t->t_value.ipset) {
            skIPSetDestroy(&(t->t_value.ipset));
        }
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, opt_arg))
            || (rv = skStreamOpen(stream)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            return 1;
        }
        rv = skIPSetRead(&ipset, stream);
        if (rv) {
            if (SKIPSET_ERR_FILEIO == rv) {
                skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                     &skAppPrintErr);
            } else {
                skAppPrintErr("Unable to read %s IPset from '%s': %s",
                              t->t_optname, opt_arg, skIPSetStrerror(rv));
            }
            skStreamDestroy(&stream);
            return 1;
        }
        skStreamDestroy(&stream);
        t->t_value.ipset = ipset;
        break;

      case THR_MAP_IN:
      case THR_MAP_EX:
        if (t->t_check == PROTO || t->t_check == TCPFLAGS) {
            bitmap_size = 256;
        }
        if (t->t_value.bitmap) {
            skBitmapClearAllBits(t->t_value.bitmap);
        } else if (skBitmapCreate(&(t->t_value.bitmap), bitmap_size)) {
            skAppPrintErr("Unable to create bitmap");
            return 1;
        }
        if (t->t_check == TCPFLAGS) {
            if (parseFlags(t->t_value.bitmap, opt_arg)) {
                skAppPrintErr("Unable to parse %s value '%s'",
                              t->t_optname, opt_arg);
                return 1;
            }
        } else {
            rv = skStringParseNumberListToBitmap(t->t_value.bitmap,opt_arg);
            if (rv) {
                goto PARSE_ERROR;
            }
        }
        break;

      case THR_OTHER:
        break;
    }

    return 0;

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  t->t_optname, opt_arg, skStringParseStrerror(rv));
    return 1;
}


static void
thresholdUsage(
    FILE               *fh,
    const threshold_t  *t)
{

    assert(fh);
    assert(t);

    fprintf(fh, "  %s: %s", t->t_optname, t->t_title);
    switch (t->t_type) {
      case THR_VAL_MIN:
        fprintf(fh, (" is less than this value.\n"
                     "\tDef value: %" PRIu32 ".  Allowed count: %" PRIu64),
                t->t_value.num, t->t_allowable);
        break;

      case THR_VAL_MAX:
        fprintf(fh, (" is greater than this value.\n"
                     "\tDef value: %" PRIu32 ".  Allowed count: %" PRIu64),
                t->t_value.num, t->t_allowable);
        break;

      case THR_SET_IN:
        fprintf(fh, (" is present in this IPset.\n"
                     "\tDef set: None.  Allowed count: %" PRIu64),
                t->t_allowable);
        break;

      case THR_SET_EX:
        fprintf(fh, (" is not present in this IPset.\n"
                     "\tDef set: None.  Allowed count: %" PRIu64),
                t->t_allowable);
        break;

      case THR_MAP_IN:
        fprintf(fh, (" is present in this list.\n"
                     "\tDef set: None.  Allowed count: %" PRIu64),
                t->t_allowable);
        break;

      case THR_MAP_EX:
        fprintf(fh, (" is not present in this list.\n"
                     "\tDef set: None.  Allowed count: %" PRIu64),
                t->t_allowable);
        break;

      case THR_OTHER:
        break;
    }
    fprintf(fh, "\n");
}


static int
parseFlags(
    sk_bitmap_t        *flag_map,
    const char         *flag_list)
{
    char buf[32];
    const char *cp;
    const char *sp = flag_list;
    size_t len;
    uint8_t flags;

    while (*sp) {
        cp = strchr(sp, ',');

        if (cp == sp) {
            /* ignore leading or double comma */
            ++sp;
            continue;
        }
        if (cp == NULL) {
            /* move 'cp' to the end of the string */
            cp = &(sp[strlen(sp)]);
        } else {
            /* copy this flag set into 'buf' */
            len = cp - sp;
            if (len > sizeof(buf)-1) {
                return 1;
            }
            strncpy(buf, sp, len);
            buf[len] = '\0';
            sp = buf;

            /* move cp to start of next flagset */
            ++cp;
        }

        if (skStringParseTCPFlags(&flags, sp)) {
            return 1;
        }
        skBitmapSetBit(flag_map, flags);
        sp = cp;
    }

    return 0;
}


/*
 *  status = checkFile(stream);
 *
 *    Check the records in 'stream'.  Return 0 on success, or 1 on
 *    failure.
 */
static int
checkFile(
    skstream_t         *stream)
{
    rwRec rwrec;
    int unusual = 0;
    uint64_t rec_count = 0;
    uint64_t is_bad = 0;
    uint32_t pkts, bytes, ms_dur, bpp, bps;
    sk_dll_iter_t iter;
    threshold_t *t;
    int rv;

    while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
        ++rec_count;

        /* useful ratios */
        pkts = rwRecGetPkts(&rwrec);
        bytes = rwRecGetBytes(&rwrec);
        ms_dur = 1 + rwRecGetElapsed(&rwrec);;
        if (pkts == 0) {
            bpp = UINT32_MAX;
        } else {
            bpp = bytes / pkts;
        }
        bps = bytes / ms_dur * 1000;

        unusual = 0;

        /* run record through each test */
        skDLLAssignIter(&iter, tests);
        while (skDLLIterForward(&iter, (void**)&t) == 0) {
            switch (t->t_check) {
              case BPP_CALC:
#if 0
                if (rwRecGetBpp(&rwrec) != 0) {
                    uint32_t bpp_rec = (rwRecGetBpp(&rwrec) >> 6);
                    if (bpp_rec != bpp) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
#endif /* 0 */
                break;

              case ELAPSED_TIME:
                assert(t->t_type == THR_VAL_MAX);
                if (rwRecGetElapsedSeconds(&rwrec) > t->t_value.num) {
                    ++t->t_count;
                    unusual = 1;
                }
                break;

              case PKT_COUNT:
                if (t->t_type == THR_VAL_MIN) {
                    if (pkts < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (pkts > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case BYTE_COUNT:
                if (t->t_type == THR_VAL_MIN) {
                    if (bytes < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bytes > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case BYTE_PKT_RATIO:
                if (t->t_type == THR_VAL_MIN) {
                    if (bpp < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bpp > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case BYTE_SEC_RATIO:
                if (t->t_type == THR_VAL_MIN) {
                    if (bps < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bps > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case ICMP_BPP:
                if (IPPROTO_ICMP != rwRecGetProto(&rwrec)) {
                    break;
                }
                if (t->t_type == THR_VAL_MIN) {
                    if (bpp < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bpp > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case TCP_BPP:
                if (IPPROTO_TCP != rwRecGetProto(&rwrec)) {
                    break;
                }
                if (t->t_type == THR_VAL_MIN) {
                    if (bpp < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bpp > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case UDP_BPP:
                if (IPPROTO_UDP != rwRecGetProto(&rwrec)) {
                    break;
                }
                if (t->t_type == THR_VAL_MIN) {
                    if (bpp < t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_VAL_MAX);
                    if (bpp > t->t_value.num) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case SIP_SET:
                if (t->t_type == THR_SET_IN) {
                    if (skIPSetCheckRecordSIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_SET_EX);
                    if (!skIPSetCheckRecordSIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case DIP_SET:
                if (t->t_type == THR_SET_IN) {
                    if (skIPSetCheckRecordDIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_SET_EX);
                    if (!skIPSetCheckRecordDIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case NHIP_SET:
                if (t->t_type == THR_SET_IN) {
                    if (skIPSetCheckRecordNhIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_SET_EX);
                    if (!skIPSetCheckRecordNhIP(t->t_value.ipset, &rwrec)) {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case PROTO:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetProto(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetProto(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case TCPFLAGS:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetProto(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetProto(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case SNMP_INPUT:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetInput(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                        rwRecGetInput(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case SNMP_OUTPUT:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetOutput(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                        rwRecGetOutput(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case SPORT:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetSPort(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                        rwRecGetSPort(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;

              case DPORT:
                if (t->t_type == THR_MAP_IN) {
                    if (skBitmapGetBit(t->t_value.bitmap,
                                       rwRecGetDPort(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                } else {
                    assert(t->t_type == THR_MAP_EX);
                    if (!skBitmapGetBit(t->t_value.bitmap,
                                        rwRecGetDPort(&rwrec)))
                    {
                        ++t->t_count;
                        unusual = 1;
                    }
                }
                break;
            } /* switch (t_check) */
        } /* for (each test) */

        if (unusual) {
            ++is_bad;
        }
    } /* skStreamReadRecord() */
    if (SKSTREAM_ERR_EOF == rv) {
        /* what we expect */
        rv = 0;
    } else {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        rv = 1;
    }

    /* if nothing at all was unusual, return unless print_all was
     * requested */
    if (0 == is_bad && 0 == print_all) {
        return rv;
    }

    /* for each test, determine if the number of unusual events is
     * within the allowable range */
    unusual = 0;
    skDLLAssignIter(&iter, tests);
    while (skDLLIterForward(&iter, (void**)&t) == 0) {
        if (t->t_count > t->t_allowable) {
            unusual = 1;
            break;
        }
    }

    /* if everything is within limits, return unless print_all was
     * requested */
    if (0 == unusual && 0 == print_all) {
        return rv;
    }

    printf("%s:\n", skStreamGetPathname(stream));
    printf("%20" PRIu64 "/%" PRIu64 " flows are bad or unusual\n",
           is_bad, rec_count);
    skDLLAssignIter(&iter, tests);
    while (skDLLIterForward(&iter, (void**)&t) == 0) {
        if ((t->t_count <= t->t_allowable) && (print_all == 0)) {
            continue;
        }

        printf("%20" PRIu64 " flows where %s ",
               t->t_count, t->t_title);
        switch (t->t_type) {
          case THR_VAL_MIN:
            printf(("< %" PRIu32), t->t_value.num);
            break;

          case THR_VAL_MAX:
            printf(("> %" PRIu32), t->t_value.num);
            break;

          case THR_SET_IN:
          case THR_MAP_IN:
            printf("inside the match set");
            break;

          case THR_SET_EX:
          case THR_MAP_EX:
            printf("outside the nomatch set");
            break;

          case THR_OTHER:
            switch (t->t_check) {
              case BPP_CALC:
                printf("is incorrect");
                break;

              default:
                skAbortBadCase(t->t_check);
            }
            break;
        }
        printf("\n");
    }

    return unusual;
}


int main(int argc, char ** argv)
{
    skstream_t *stream;
    int exit_status = EXIT_SUCCESS;
    int rv;

    appSetup(argc, argv);

    /* process each input stream/file */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           != 1)
    {
        if (0 != rv) {
            /* error opening file */
            exit_status = EXIT_FAILURE;
            continue;
        }
        if (checkFile(stream)) {
            exit_status = EXIT_FAILURE;
        }
        skStreamDestroy(&stream);
    }

    return exit_status;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
