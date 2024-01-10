/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
 *  rwbag
 *
 *    Build binary Bag files from flow records.
 *
 *
 */


#include <silk/silk.h>

RCSIDENT("$SiLK: rwbag.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skbag.h>
#include <silk/skcountry.h>
#include <silk/skipaddr.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* bagfile_t holds data about each bag file being created.  These are
 * stored in the 'bag_vec' sk_vector_t. */
typedef struct bagfile_st {
    /* the bag object */
    skBag_t                *bag;
    /* where to send the output of the bag */
    skstream_t             *stream;
    /* the command line argument used to create the bag */
    const char             *bag_file_arg;
    /* the prefix map file in which to look up a key */
    const skPrefixMap_t    *pmap;
    /* the key and counter */
    skBagFieldType_t        key;
    skBagFieldType_t        counter;
    /* whether this bag has had an overflow condition in one or more
     * of its counters */
    unsigned                overflow  :1;
} bagfile_t;

/* pmap_data_t holds data about prefix map files.  These are stored in
 * the 'pmap_vec' sk_vector_t. */
struct pmap_data_st {
    /* The prefix map */
    skPrefixMap_t        *pmap;
    /* Name of the pmap */
    char                 *mapname;
};
typedef struct pmap_data_st pmap_data_t;


/* LOCAL VARIABLES */

/* key types that rwbag supports */
static const skBagFieldType_t allowed_key_type[] = {
    SKBAG_FIELD_SIPv4, SKBAG_FIELD_SIPv6,
    SKBAG_FIELD_DIPv4, SKBAG_FIELD_DIPv6,
    SKBAG_FIELD_SPORT, SKBAG_FIELD_DPORT,
    SKBAG_FIELD_PROTO,
    SKBAG_FIELD_PACKETS, SKBAG_FIELD_BYTES,
    SKBAG_FIELD_FLAGS,
    SKBAG_FIELD_STARTTIME,
    SKBAG_FIELD_ELAPSED,
    SKBAG_FIELD_ENDTIME,
    SKBAG_FIELD_SID,
    SKBAG_FIELD_INPUT, SKBAG_FIELD_OUTPUT,
    SKBAG_FIELD_NHIPv4, SKBAG_FIELD_NHIPv6,
    SKBAG_FIELD_INIT_FLAGS, SKBAG_FIELD_REST_FLAGS,
    SKBAG_FIELD_TCP_STATE, SKBAG_FIELD_APPLICATION,
    SKBAG_FIELD_SIP_COUNTRY, SKBAG_FIELD_DIP_COUNTRY,
    SKBAG_FIELD_SIP_PMAP, SKBAG_FIELD_DIP_PMAP,
    SKBAG_FIELD_SPORT_PMAP, SKBAG_FIELD_DPORT_PMAP
};

/* the number of key types that are supported */
static const size_t num_allowed_key_type =
    (sizeof(allowed_key_type) / sizeof(allowed_key_type[0]));

/* counter types that rwbag supports */
static const skBagFieldType_t allowed_counter_type[] = {
    SKBAG_FIELD_RECORDS,
    SKBAG_FIELD_SUM_PACKETS,
    SKBAG_FIELD_SUM_BYTES
};

/* the number of counter types that are supported */
static const size_t num_allowed_counter_type =
    (sizeof(allowed_counter_type) / sizeof(allowed_counter_type[0]));

static const sk_stringmap_entry_t aliases[] = {
    {"scc",     SKBAG_FIELD_SIP_COUNTRY,    NULL, NULL},
    {"dcc",     SKBAG_FIELD_DIP_COUNTRY,    NULL, NULL},
    {"flows",   SKBAG_FIELD_RECORDS,        NULL, NULL},
    {"bytes",   SKBAG_FIELD_SUM_BYTES,      NULL, NULL},
    {"packets", SKBAG_FIELD_SUM_PACKETS,    NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* a vector to hold the --bag-file arguments; the bag contains
 * bagfile_t structures */
static sk_vector_t *bag_vec = NULL;

/* a vector to hold the --pmap-file arguments; the bag contains
 * pmap_data_t structures */
static sk_vector_t *pmap_vec = NULL;

/* the compression method to use when writing the files.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* support for handling inputs */
static sk_options_ctx_t *optctx = NULL;

/* how to handle IPv6 flows */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;

/*
 * stdout_used is set to 1 by parseBagFileOption() when a bag file is
 * to be written to stdout.  ensures only one stream sets uses it.
 */
static int stdout_used = 0;

/* do not record the command line invocation in the generated bag
 * file(s). set by --invocation-strip */
static int invocation_strip = 0;

/* do not copy notes (annoations) from the source files to the
 * generated bag file(s). set by --notes-strip */
static int notes_strip = 0;

/* print help and include legacy bag creation switches */
static int legacy_help = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_LEGACY_HELP,
    OPT_BAG_FILE,
    OPT_PMAP_FILE,
    OPT_INVOCATION_STRIP
} appOptionsEnum;

static struct option appOptions[] = {
    {"legacy-help",         NO_ARG,       0, OPT_LEGACY_HELP},
    {"bag-file",            REQUIRED_ARG, 0, OPT_BAG_FILE},
    {"pmap-file",           REQUIRED_ARG, 0, OPT_PMAP_FILE},
    {"invocation-strip",    NO_ARG,       0, OPT_INVOCATION_STRIP},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    "Print help, including legacy switches, and exit. Def. No",
    ("Given an argument in the form \"KEY,COUNTER,PATH\", create\n"
     "\ta Bag file that sums COUNTERs for each unique KEY and writes the\n"
     "\tresult to PATH. Accepted names for KEY and COUNTER are shown below;\n"
     "\tnames are case insensitive. Repeat the switch and its arguments to\n"
     "\tcreate multiple Bag files."),
    ("Use this prefix map as a key for one or more bag files.\n"
     "\tSpecify as either MAPNAME:PATH or PATH to use map's built-in name.\n"
     "\tUse ':MAPNAME' after key part of the --bag-file switch. This\n"
     "\tmust precede --bag-file switches. Repeat to load multiple maps"),
    ("Strip invocation history from the output bag file(s).\n"
     "\tDef. Record command used to create the file(s)"),
    (char *)NULL
};

typedef enum legacy_bag_type_enum_en {
    /* These MUST be kept in order with the legacy options */
    SIP_FLOWS=0, SIP_PKTS,  SIP_BYTES,
    DIP_FLOWS, DIP_PKTS, DIP_BYTES,
    NHIP_FLOWS, NHIP_PKTS, NHIP_BYTES,
    SPORT_FLOWS, SPORT_PKTS, SPORT_BYTES,
    DPORT_FLOWS, DPORT_PKTS, DPORT_BYTES,
    PROTO_FLOWS, PROTO_PKTS, PROTO_BYTES,
    SID_FLOWS, SID_PKTS, SID_BYTES,
    INPUT_FLOWS, INPUT_PKTS, INPUT_BYTES,
    OUTPUT_FLOWS, OUTPUT_PKTS, OUTPUT_BYTES
} legacy_bag_type_enum;

static struct option legacy_bag_creation_option[] = {
    {"sip-flows",       REQUIRED_ARG, 0, SIP_FLOWS},
    {"sip-packets",     REQUIRED_ARG, 0, SIP_PKTS},
    {"sip-bytes",       REQUIRED_ARG, 0, SIP_BYTES},
    {"dip-flows",       REQUIRED_ARG, 0, DIP_FLOWS},
    {"dip-packets",     REQUIRED_ARG, 0, DIP_PKTS},
    {"dip-bytes",       REQUIRED_ARG, 0, DIP_BYTES},
    {"nhip-flows",      REQUIRED_ARG, 0, NHIP_FLOWS},
    {"nhip-packets",    REQUIRED_ARG, 0, NHIP_PKTS},
    {"nhip-bytes",      REQUIRED_ARG, 0, NHIP_BYTES},
    {"sport-flows",     REQUIRED_ARG, 0, SPORT_FLOWS},
    {"sport-packets",   REQUIRED_ARG, 0, SPORT_PKTS},
    {"sport-bytes",     REQUIRED_ARG, 0, SPORT_BYTES},
    {"dport-flows",     REQUIRED_ARG, 0, DPORT_FLOWS},
    {"dport-packets",   REQUIRED_ARG, 0, DPORT_PKTS},
    {"dport-bytes",     REQUIRED_ARG, 0, DPORT_BYTES},
    {"proto-flows",     REQUIRED_ARG, 0, PROTO_FLOWS},
    {"proto-packets",   REQUIRED_ARG, 0, PROTO_PKTS},
    {"proto-bytes",     REQUIRED_ARG, 0, PROTO_BYTES},
    {"sensor-flows",    REQUIRED_ARG, 0, SID_FLOWS},
    {"sensor-packets",  REQUIRED_ARG, 0, SID_PKTS},
    {"sensor-bytes",    REQUIRED_ARG, 0, SID_BYTES},
    {"input-flows",     REQUIRED_ARG, 0, INPUT_FLOWS},
    {"input-packets",   REQUIRED_ARG, 0, INPUT_PKTS},
    {"input-bytes",     REQUIRED_ARG, 0, INPUT_BYTES},
    {"output-flows",    REQUIRED_ARG, 0, OUTPUT_FLOWS},
    {"output-packets",  REQUIRED_ARG, 0, OUTPUT_PKTS},
    {"output-bytes",    REQUIRED_ARG, 0, OUTPUT_BYTES},
    {0,0,0,0}           /* sentinel entry */
};

/* map from command line switches to types for key/counter.  The order
 * of the entries must be kept in sync with the bag_type_enum. */
static const struct legacy_bag_map_st {
    int                 val;
    const char         *new_arg;
} legacy_bag_map[] = {
    {SIP_FLOWS,    "sIPv4,records"},
    {SIP_PKTS,     "sIPv4,sum-packets"},
    {SIP_BYTES,    "sIPv4,sum-bytes"},
    {DIP_FLOWS,    "dIPv4,records"},
    {DIP_PKTS,     "dIPv4,sum-packets"},
    {DIP_BYTES,    "dIPv4,sum-bytes"},
    {NHIP_FLOWS,   "nhIPv4,records"},
    {NHIP_PKTS,    "nhIPv4,sum-packets"},
    {NHIP_BYTES,   "nhIPv4,sum-bytes"},
    {SPORT_FLOWS,  "sPort,records"},
    {SPORT_PKTS,   "sPort,sum-packets"},
    {SPORT_BYTES,  "sPort,sum-bytes"},
    {DPORT_FLOWS,  "dPort,records"},
    {DPORT_PKTS,   "dPort,sum-packets"},
    {DPORT_BYTES,  "dPort,sum-bytes"},
    {PROTO_FLOWS,  "protocol,records"},
    {PROTO_PKTS,   "protocol,sum-packets"},
    {PROTO_BYTES,  "protocol,sum-bytes"},
    {SID_FLOWS,    "sensor,records"},
    {SID_PKTS,     "sensor,sum-packets"},
    {SID_BYTES,    "sensor,sum-bytes"},
    {INPUT_FLOWS,  "input,records"},
    {INPUT_PKTS,   "input,sum-packets"},
    {INPUT_BYTES,  "input,sum-bytes"},
    {OUTPUT_FLOWS, "output,records"},
    {OUTPUT_PKTS,  "output,sum-packets"},
    {OUTPUT_BYTES, "output,sum-bytes"}
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void appUsageBagFile(FILE *);
static void appUsageLegacyCreationSwitches(FILE *);
static int  legacyOptionsHandler(clientData cData, int opt_index, char *path);
static int  parseBagFileOption(const char *opt_arg);
static int  parsePmapFileOption(const char *opt_arg);


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
#define USAGE_MSG                                                           \
    ("--bag-file=KEY,COUNTER,PATH [--bag-file...] [SWITCHES] [FILES]\n"     \
     "\tRead SiLK Flow records, bin the records by KEY, compute the\n"      \
     "\tCOUNTER for each KEY, and write the binary Bag output to PATH.\n"   \
     "\tMultiple Bag files may be created in a single invocation.  Read\n"  \
     "\tSiLK Flows from named files or from the standard input.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        switch (appOptions[i].val) {
          case OPT_BAG_FILE:
            appUsageBagFile(fh);
            break;

          case OPT_INVOCATION_STRIP:
            /* include the help for --notes before
             * --invocation-strip */
            skOptionsNotesUsage(fh);
            /* FALLTHROUGH */

          default:
            fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                    SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
            break;
        }
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    skCompMethodOptionsUsage(fh);
    sksiteOptionsUsage(fh);

    if (legacy_help) {
        appUsageLegacyCreationSwitches(fh);
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
    bagfile_t *bag;
    pmap_data_t *pmap;
    ssize_t rv;
    size_t i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close all bag files */
    for (i = 0; (bag = (bagfile_t*)skVectorGetValuePointer(bag_vec, i)); ++i) {
        skBagDestroy(&bag->bag);
        if (bag->stream) {
            rv = skStreamClose(bag->stream);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
            }
            skStreamDestroy(&bag->stream);
        }
        memset(bag, 0, sizeof(bagfile_t));
    }
    skVectorDestroy(bag_vec);

    /* destroy the prefix maps */
    if (pmap_vec) {
        for (i = 0;
             (pmap = (pmap_data_t *)skVectorGetValuePointer(pmap_vec, i));
             ++i)
        {
            free(pmap->mapname);
            skPrefixMapDelete(pmap->pmap);
        }
        skVectorDestroy(pmap_vec);
    }
    skCountryTeardown();

    /* close the copy stream */
    skOptionsCtxCopyStreamClose(optctx, &skAppPrintErr);

    skOptionsNotesTeardown();
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
    bagfile_t *bag;
    ssize_t rv;
    size_t i;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize variables */
    bag_vec = skVectorNew(sizeof(bagfile_t));

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES
                    | SK_OPTIONS_CTX_COPY_INPUT);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(
            legacy_bag_creation_option, &legacyOptionsHandler, NULL)
        || skOptionsNotesRegister(&notes_strip)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE)
        || skIPv6PolicyOptionsRegister(&ipv6_policy))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* verify that the user requested output */
    if (skVectorGetCount(bag_vec) == 0) {
        skAppPrintErr("The --%s switch (or a legacy equivalent) is required",
                      appOptions[OPT_BAG_FILE].name);
        skAppUsage();
    }

    /* make certain stdout is not being used for multiple outputs */
    if (stdout_used && skOptionsCtxCopyStreamIsStdout(optctx)) {
        skAppPrintErr("May not use stdout for multiple output streams");
        exit(EXIT_FAILURE);
    }

    /* For each output file, set the compression method and open the file */
    for (i = 0; (bag = (bagfile_t*)skVectorGetValuePointer(bag_vec, i)); ++i) {
        if (bag->stream) {
            rv = skStreamSetCompressionMethod(bag->stream, comp_method);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
                exit(EXIT_FAILURE);
            }
            rv = skStreamOpen(bag->stream);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
                exit(EXIT_FAILURE);
            }
        }
    }

    /* open the --copy-input stream */
    if (skOptionsCtxOpenStreams(optctx, &skAppPrintErr)) {
        exit(EXIT_FAILURE);
    }

    return;                     /* OK */
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
    switch ((appOptionsEnum)opt_index) {
      case OPT_LEGACY_HELP:
        legacy_help = 1;
        appUsageLong();
        exit(EXIT_SUCCESS);

      case OPT_BAG_FILE:
        if (parseBagFileOption(opt_arg)) {
            return 1;
        }
        break;

      case OPT_PMAP_FILE:
        if (parsePmapFileOption(opt_arg)) {
            return 1;
        }
        break;

      case OPT_INVOCATION_STRIP:
        invocation_strip = 1;
        break;
    }

    return 0;                   /* OK */
}


/*
 *    Print the usage for the --bag-file switch to 'fh'.
 */
static void
appUsageBagFile(
    FILE               *fh)
{
    const int indent = 17;
    char field[SKBAG_MAX_FIELD_BUFLEN];
    const char *semi;
    const char *dash = " -";
    const char *key_count[2] = {"KEY", "COUNTER"};
    const skBagFieldType_t *allowed_types[2] = {
        allowed_key_type, allowed_counter_type
    };
    const size_t *num_allowed_types[2] = {
        &num_allowed_key_type, &num_allowed_counter_type
    };
    const sk_stringmap_entry_t *alias;
    skBagFieldType_t t;
    size_t j;
    int i;
    int len;

    fprintf(fh, "--%s %s. %s\n", appOptions[OPT_BAG_FILE].name,
            SK_OPTION_HAS_ARG(appOptions[OPT_BAG_FILE]), appHelp[OPT_BAG_FILE]);

    for (i = 0; i < 2; ++i) {
        len = indent;
        semi = ";";
        j = 0;
        fprintf(fh, "\t%*s%s",
                -(len - 8 - (int)strlen(dash)), key_count[i], dash);
        while (j < *num_allowed_types[i]) {
            t = allowed_types[i][j];
            for (alias = aliases; alias->name != NULL; ++alias) {
                if (alias->id == t) {
                    break;
                }
            }
            skBagFieldTypeAsString(t, field, sizeof(field));
            ++j;
            if (j == *num_allowed_types[i]) {
                semi = "";
            }
            len += 1 + strlen(field) + strlen(semi);
            if (alias->name) {
                len += 2 + strlen(alias->name);
                if (len < 79) {
                    fprintf(fh, " %s, %s%s", field, alias->name, semi);
                } else {
                    len = indent;
                    fprintf(fh, "\n\t%*s %s, %s%s",
                            (len - 8), "", field, alias->name, semi);
                    len += 3 + strlen(field) + strlen(alias->name)
                        + strlen(semi);
                }
            } else {
                if (len < 79) {
                    fprintf(fh, " %s%s", field, semi);
                } else {
                    len = indent;
                    fprintf(fh, "\n\t%*s %s%s", (len - 8), "", field, semi);
                    len += 1 + strlen(field) + strlen(semi);
                }
            }
        }
        fprintf(fh, "\n");
    }
}


/*
 *    Print the usage for the legacy bag-creation switches to 'fh'.
 */
static void
appUsageLegacyCreationSwitches(
    FILE               *fh)
{
    unsigned int i;
    unsigned int j;

    fprintf(fh, "\nLEGACY BAG CREATION SWITCHES (DEPRECATED):\n");
    for (i = 0; legacy_bag_creation_option[i].name != NULL; ++i) {
        for (j = 0; j < sizeof(legacy_bag_map)/sizeof(legacy_bag_map[0]); ++j){
            if (legacy_bag_map[j].val == legacy_bag_creation_option[i].val) {
                fprintf(fh, ("--%s %s. Use --%s=%s,'PATH'\n"
                             "\tin place of --%s='PATH'\n"),
                        legacy_bag_creation_option[i].name,
                        SK_OPTION_HAS_ARG(legacy_bag_creation_option[i]),
                        appOptions[OPT_BAG_FILE].name,
                        legacy_bag_map[j].new_arg,
                        legacy_bag_creation_option[i].name);
                break;
            }
        }
    }
}


/*
 *    Return the prefix map who name is 'mapname', or return NULL if
 *    no such prefix map file is found.
 */
static const skPrefixMap_t *
findPmapByMapname(
    const char         *mapname)
{
    const pmap_data_t *p;
    size_t i;

    if (pmap_vec) {
        for (i = 0;
             (p = (pmap_data_t *)skVectorGetValuePointer(pmap_vec, i)) != NULL;
             ++i)
        {
            if (strcmp(mapname, p->mapname) == 0) {
                return p->pmap;
            }
        }
    }
    return NULL;
}


/*
 *    Parse the [MAPNAME:]PMAP_PATH option and add the result to the
 *    global 'pmap_vec'.  Return 0 on success or -1 on error.
 */
static int
parsePmapFileOption(
    const char         *opt_arg)
{
    skPrefixMapErr_t rv_map;
    skstream_t *stream;
    pmap_data_t pmap_data;
    const char *sep;
    const char *filename;
    int rv;

    memset(&pmap_data, 0, sizeof(pmap_data));
    stream = NULL;
    rv = -1;

    /* Parse the argument into a field name and file name */
    sep = strchr(opt_arg, ':');
    if (NULL == sep) {
        /* no mapname; check for one in the pmap once we read it */
        filename = opt_arg;
    } else if (sep == opt_arg) {
        /* treat a 0-length mapname on the command as having none.
         * Allows use of default mapname for files that contain the
         * separator. */
        filename = sep + 1;
    } else {
        size_t namelen;

        filename = sep + 1;
        /* a mapname was supplied on the command line */
        if (memchr(opt_arg, ',', sep - opt_arg) != NULL) {
            skAppPrintErr("Invalid %s: The map-name may not include a comma",
                          appOptions[OPT_PMAP_FILE].name);
            goto END;
        }
        namelen = sep - opt_arg;
        pmap_data.mapname = (char *)malloc(namelen + 1);
        if (NULL == pmap_data.mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
        strncpy(pmap_data.mapname, opt_arg, namelen);
        pmap_data.mapname[namelen] = '\0';
    }

    /* open the file and read the prefix map */
    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        goto END;
    }
    rv_map = skPrefixMapRead(&pmap_data.pmap, stream);
    if (SKPREFIXMAP_OK != rv_map) {
        if (SKPREFIXMAP_ERR_IO == rv_map) {
            skStreamPrintLastErr(
                stream, skStreamGetLastReturnValue(stream), &skAppPrintErr);
        } else {
            skAppPrintErr("Failed to read the prefix map file '%s': %s",
                          filename, skPrefixMapStrerror(rv_map));
        }
        rv = -1;
        goto END;
    }
    skStreamDestroy(&stream);

    /* set the error flag again */
    rv = -1;

    /* get the mapname from the file when none on command line */
    if (NULL == pmap_data.mapname) {
        if (NULL == skPrefixMapGetMapName(pmap_data.pmap)) {
            skAppPrintErr(("Invalid %s '%s': Prefix map file does not contain"
                           " a map-name and none provided on the command line"),
                appOptions[OPT_PMAP_FILE].name, filename);
            goto END;
        }
        pmap_data.mapname = strdup(skPrefixMapGetMapName(pmap_data.pmap));
        if (NULL == pmap_data.mapname) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }

    if (NULL == pmap_vec) {
        pmap_vec = skVectorNew(sizeof(pmap_data_t));
        if (NULL == pmap_vec) {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }

    /* Verify the mapname is unique */
    if (findPmapByMapname(pmap_data.mapname)) {
        skAppPrintErr("Invalid %s: Multiple pmaps use the map-name '%s'",
                      appOptions[OPT_PMAP_FILE].name, pmap_data.mapname);
        goto END;
    }

    if (skVectorAppendValue(pmap_vec, &pmap_data)) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* The vector owns this */
    memset(&pmap_data, 0, sizeof(pmap_data));
    rv = 0;

  END:
    skStreamDestroy(&stream);
    skPrefixMapDelete(pmap_data.pmap);
    free(pmap_data.mapname);
    return rv;
}


/*
 *    Return a pointer to a static string containing the
 *    KEY,VALUE,PATH that was specified to configure the bagfile_t
 *    'bag'.
 */
static const char *
createBagFileArgument(
    const bagfile_t    *bag)
{
    static char buf[2 * SKBAG_MAX_FIELD_BUFLEN + PATH_MAX];
    char key[SKBAG_MAX_FIELD_BUFLEN];
    char counter[SKBAG_MAX_FIELD_BUFLEN];

    assert(bag);

    key[0] = counter[0] = '\0';
    skBagFieldTypeAsString(bag->key, key, sizeof(key));
    skBagFieldTypeAsString(bag->counter, counter, sizeof(counter));

    snprintf(buf, sizeof(buf), "%s,%s,%s",
             key, counter, skStreamGetPathname(bag->stream));
    return buf;
}


/*
 *    Parse a portion of the --bag-file argument 'opt_arg' where
 *    'field_start' is the current location in that string.  The 'idx'
 *    argument determines whether the KEY (idx==0) or the COUNTER
 *    (idx==1) is expected.
 *
 *    On success, the referent of 'field_type' is set the result of
 *    parsing the field and the start of the next field in 'opt_arg'
 *    is returned.
 *
 *    If a name is invalid or is not ended by a comma, an error is
 *    printed and NULL is returned.
 */
static const char *
parseBagField(
    unsigned int            idx,
    const char             *opt_arg,
    const char             *field_start,
    skBagFieldType_t       *field_type,
    char                   *name,
    size_t                  namelen)
{
    const char *key_count[2] = {"key", "counter"};
    const skBagFieldType_t *allowed_types[2] = {
        allowed_key_type, allowed_counter_type
    };
    const size_t *num_allowed_types[2] = {
        &num_allowed_key_type, &num_allowed_counter_type
    };
    char field[PATH_MAX];
    sk_stringmap_entry_t sm_entry;
    sk_stringmap_entry_t *sm_find;
    const sk_stringmap_entry_t *alias;
    sk_stringmap_status_t sm_err;
    sk_stringmap_t *field_map = NULL;
    skBagFieldType_t t;
    const char *cp;
    size_t i;

    assert(0 == idx || 1 == idx);

    memset(&sm_entry, 0, sizeof(sm_entry));

    /* create a stringmap of the allowed types */
    sm_err = skStringMapCreate(&field_map);
    if (SKSTRINGMAP_OK != sm_err) {
        skAppPrintErr("Unable to create string map: %s",
                      skStringMapStrerror(sm_err));
        goto END;
    }
    for (i = 0; i < *num_allowed_types[idx]; ++i) {
        t = allowed_types[idx][i];
        skBagFieldTypeAsString(t, field, sizeof(field));
        sm_entry.id = t;
        sm_entry.name = field;
        sm_err = skStringMapAddEntries(field_map, 1, &sm_entry);
        if (SKSTRINGMAP_OK != sm_err) {
            skAppPrintErr("Unable to add string map entry: %s",
                          skStringMapStrerror(sm_err));
            goto END;
        }
        /* this is inefficient, but it only happens during setup */
        for (alias = aliases; alias->name != NULL; ++alias) {
            if (alias->id == t) {
                sm_err = skStringMapAddEntries(field_map, 1, alias);
                if (SKSTRINGMAP_OK != sm_err) {
                    skAppPrintErr("Unable to add string map entry: %s",
                                  skStringMapStrerror(sm_err));
                    goto END;
                }
                break;
            }
        }
    }

    /* copy the part of the argument to parse into 'field' */
    sm_err = SKSTRINGMAP_PARSE_UNPARSABLE;
    cp = strchr(field_start, ',');
    if (NULL == cp) {
        skAppPrintErr("Invalid %s: Expected , after %s in '%s'",
                      appOptions[OPT_BAG_FILE].name, key_count[idx], opt_arg);
        goto END;
    }
    if ((size_t)(cp - field_start) >= sizeof(field)) {
        skAppPrintErr(
            "Invalid %s: Expected %s shorter than %d characters in '%s'",
            appOptions[OPT_BAG_FILE].name, key_count[idx],
            (int)sizeof(field), opt_arg);
        goto END;
    }
    strncpy(field, field_start, cp - field_start);
    field[cp - field_start] = '\0';
    ++cp;

    /* attempt to match */
    if (name && namelen) {
        sm_err = skStringMapGetByNameWithAttributes(field_map, field, &sm_find,
                                                    name, namelen);
    } else {
        sm_err = skStringMapGetByName(field_map, field, &sm_find);
    }
    switch (sm_err) {
      case SKSTRINGMAP_OK:
        *field_type = (skBagFieldType_t)sm_find->id;
        break;
      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s: Ambigous %s name '%s'",
                      appOptions[OPT_BAG_FILE].name, key_count[idx], field);
        break;
      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s: Unknown or unsupported %s name '%s'",
                      appOptions[OPT_BAG_FILE].name, key_count[idx], field);
        break;
      case SKSTRINGMAP_PARSE_UNPARSABLE:
        skAppPrintErr("Invalid %s: Cannot parse %s name '%s'",
                      appOptions[OPT_BAG_FILE].name, key_count[idx], field);
        break;
      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      sm_err);
        break;
    }

  END:
    skStringMapDestroy(field_map);
    if (SKSTRINGMAP_OK == sm_err) {
        return cp;
    }
    return NULL;
}


/*
 *    Parse a --bag-file argument "KEY,COUNTER,PATH".  Create the bag
 *    that maps from KEY to COUNTER and create the stream the writes
 *    that bag to PATH.
 *
 *    Ensure that multiple streams are not printed to the standard
 *    output.
 */
static int
parseBagFileOption(
    const char         *opt_arg)
{
    char keyname[SKBAG_MAX_FIELD_BUFLEN] = "";
    char mapname[PATH_MAX] = "";
    bagfile_t bag;
    const char *path;
    ssize_t rv;
    int key_is_ip_pmap = 0;

    memset(&bag, 0, sizeof(bag));

    path = opt_arg;
    path = parseBagField(0, opt_arg, path, &bag.key, mapname, sizeof(mapname));
    if (NULL == path) {
        return -1;
    }
    path = parseBagField(1, opt_arg, path, &bag.counter, NULL, 0);
    if (NULL == path) {
        return -1;
    }

    skBagFieldTypeAsString(bag.key, keyname, sizeof(keyname));
    switch (bag.key) {
      case SKBAG_FIELD_SIP_PMAP:
      case SKBAG_FIELD_DIP_PMAP:
        key_is_ip_pmap = 1;
        /* FALLTHROUGH */
      case SKBAG_FIELD_SPORT_PMAP:
      case SKBAG_FIELD_DPORT_PMAP:
        if ('\0' == mapname[0]) {
            skAppPrintErr(("Invalid %s '%s': Must append :MAP_NAME to %s"
                           " key where MAP_NAME is the map-name of a file"
                           " loaded via --%s"),
                          appOptions[OPT_BAG_FILE].name, opt_arg, keyname,
                          appOptions[OPT_PMAP_FILE].name);
            return -1;
        }
        bag.pmap = findPmapByMapname(mapname);
        if (NULL == bag.pmap) {
            skAppPrintErr("Invalid %s '%s': No prefix map has map-name '%s'",
                          appOptions[OPT_BAG_FILE].name, opt_arg, mapname);
            return -1;
        }
        if ((skPrefixMapGetContentType(bag.pmap) ==SKPREFIXMAP_CONT_PROTO_PORT)
            ? key_is_ip_pmap
            : !key_is_ip_pmap)
        {
            skAppPrintErr(("Invalid %s '%s': Cannot use %s prefix map"
                           " to create a Bag containing %s keys"),
                          appOptions[OPT_BAG_FILE].name, opt_arg,
                          skPrefixMapGetContentName(
                              skPrefixMapGetContentType(bag.pmap)), keyname);
            return -1;
        }
        break;

      case SKBAG_FIELD_SIP_COUNTRY:
      case SKBAG_FIELD_DIP_COUNTRY:
        if (skCountrySetup(NULL, skAppPrintErr)) {
            return -1;
        }
        /* FALLTHROUGH */

      default:
        if (mapname[0]) {
            skAppPrintErr(
                "Invalid %s '%s': May not specify an attribute to %s key",
                appOptions[OPT_BAG_FILE].name, opt_arg, keyname);
            return -1;
        }
        break;
    }

    /* check for multiple streams writing to stdout */
    if (0 == strcmp("stdout", path) || 0 == strcmp("-", path)) {
        if (stdout_used) {
            skAppPrintErr("Invalid %s '%s': Only one output may use stdout",
                          appOptions[OPT_BAG_FILE].name, opt_arg);
            return -1;
        }
        stdout_used = 1;
    }

    /* create the stream */
    if ((rv = skStreamCreate(&bag.stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(bag.stream, path)))
    {
        skStreamPrintLastErr(bag.stream, rv, &skAppPrintErr);
        skStreamDestroy(&bag.stream);
        return -1;
    }

    /* create the bag */
    if (SKBAG_OK != skBagCreateTyped(&bag.bag, bag.key, bag.counter, 0, 0)) {
        skAppPrintErr("Error allocating Bag for %s",
                      createBagFileArgument(&bag));
        skStreamDestroy(&bag.stream);
        return -1;
    }

    skVectorAppendValue(bag_vec, &bag);

    return 0;
}


/*
 *  ok = legacyOptionsHandler(cData, opt_index, pathname);
 *
 *    Map a legacy option to a KEY,COUNTER string pair; fill a buffer
 *    with a "KEY,COUNTER,PATH" triple and parse the result as if it
 *    was an argument to --bag-file.
 */
static int
legacyOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *pathname)
{
    char buf[2 * PATH_MAX];
    unsigned int j;
    ssize_t rv;

    if (!pathname || !pathname[0]) {
        skAppPrintErr("Invalid %s: Missing file name",
                      legacy_bag_creation_option[opt_index].name);
        return 1;
    }
    for (j = 0; j < sizeof(legacy_bag_map)/sizeof(legacy_bag_map[0]); ++j) {
        if (legacy_bag_map[j].val == opt_index) {
            rv = snprintf(buf, sizeof(buf), "%s,%s",
                          legacy_bag_map[j].new_arg, pathname);
            if ((size_t)rv < sizeof(buf)) {
                return parseBagFileOption(buf);
            }
            skAppPrintErr("Invalid %s: File name too long",
                          legacy_bag_creation_option[opt_index].name);
            return 1;
        }
    }

    skAppPrintErr("Unable to find match for legacy_bag_creation_option %d",
                  opt_index);
    skAbort();
}


/*
 *  ok = processFile(stream);
 *
 *    Read the SiLK Flow records from the 'stream' stream---and
 *    potentially create bag files for {sIP,dIP,sPort,dPort,proto} x
 *    {flows,pkts,bytes}.
 *
 *    Return 0 if successful; non-zero otherwise.
 */
static int
processFile(
    skstream_t         *stream)
{
    skBagTypedKey_t key;
    skBagTypedCounter_t counter;
    skBagErr_t err;
    bagfile_t *bag;
    skPrefixMapProtoPort_t pp;
    skipaddr_t ip;
    rwRec rwrec;
    ssize_t rv;
    size_t i;

    /* copy header entries from the source file */
    for (i = 0; (bag = (bagfile_t*)skVectorGetValuePointer(bag_vec, i)); ++i) {
        if (!invocation_strip) {
            rv = skHeaderCopyEntries(skStreamGetSilkHeader(bag->stream),
                                     skStreamGetSilkHeader(stream),
                                     SK_HENTRY_INVOCATION_ID);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
            }
        }
        if (!notes_strip) {
            rv = skHeaderCopyEntries(skStreamGetSilkHeader(bag->stream),
                                     skStreamGetSilkHeader(stream),
                                     SK_HENTRY_ANNOTATION_ID);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
            }
        }
    }

    counter.type = SKBAG_COUNTER_U64;

    while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
        for (i=0; (bag = (bagfile_t*)skVectorGetValuePointer(bag_vec, i)); ++i)
        {
            switch (bag->counter) {
              case SKBAG_FIELD_RECORDS:
                counter.val.u64 = 1;
                break;
              case SKBAG_FIELD_SUM_PACKETS:
                counter.val.u64 = rwRecGetPkts(&rwrec);
                break;
              case SKBAG_FIELD_SUM_BYTES:
                counter.val.u64 = rwRecGetBytes(&rwrec);
                break;
              default:
                skAbortBadCase(bag->counter);
            }

            switch (bag->key) {
              case SKBAG_FIELD_SIPv4:
              case SKBAG_FIELD_SIPv6:
                key.type = SKBAG_KEY_IPADDR;
                rwRecMemGetSIP(&rwrec, &key.val.addr);
                break;
              case SKBAG_FIELD_DIPv4:
              case SKBAG_FIELD_DIPv6:
                key.type = SKBAG_KEY_IPADDR;
                rwRecMemGetDIP(&rwrec, &key.val.addr);
                break;
              case SKBAG_FIELD_NHIPv4:
              case SKBAG_FIELD_NHIPv6:
                key.type = SKBAG_KEY_IPADDR;
                rwRecMemGetNhIP(&rwrec, &key.val.addr);
                break;
              case SKBAG_FIELD_SPORT:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetSPort(&rwrec);
                break;
              case SKBAG_FIELD_DPORT:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetDPort(&rwrec);
                break;
              case SKBAG_FIELD_PROTO:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetProto(&rwrec);
                break;
              case SKBAG_FIELD_PACKETS:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetPkts(&rwrec);
                break;
              case SKBAG_FIELD_BYTES:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetBytes(&rwrec);
                break;
              case SKBAG_FIELD_FLAGS:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetFlags(&rwrec);
                break;
              case SKBAG_FIELD_STARTTIME:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetStartSeconds(&rwrec);
                break;
              case SKBAG_FIELD_ELAPSED:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetElapsedSeconds(&rwrec);
                break;
              case SKBAG_FIELD_ENDTIME:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetEndSeconds(&rwrec);
                break;
              case SKBAG_FIELD_SID:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetSensor(&rwrec);
                break;
              case SKBAG_FIELD_INPUT:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetInput(&rwrec);
                break;
              case SKBAG_FIELD_OUTPUT:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetOutput(&rwrec);
                break;
              case SKBAG_FIELD_INIT_FLAGS:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetInitFlags(&rwrec);
                break;
              case SKBAG_FIELD_REST_FLAGS:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetRestFlags(&rwrec);
                break;
              case SKBAG_FIELD_TCP_STATE:
                key.type = SKBAG_KEY_U32;
                key.val.u32
                    = rwRecGetTcpState(&rwrec) & SK_TCPSTATE_ATTRIBUTE_MASK;
                break;
              case SKBAG_FIELD_APPLICATION:
                key.type = SKBAG_KEY_U32;
                key.val.u32 = rwRecGetApplication(&rwrec);
                break;
              case SKBAG_FIELD_SIP_COUNTRY:
                rwRecMemGetSIP(&rwrec, &ip);
                key.type = SKBAG_KEY_U16;
                key.val.u16 = skCountryLookupCode(&ip);
                break;
              case SKBAG_FIELD_DIP_COUNTRY:
                rwRecMemGetDIP(&rwrec, &ip);
                key.type = SKBAG_KEY_U16;
                key.val.u16 = skCountryLookupCode(&ip);
                break;
              case SKBAG_FIELD_SIP_PMAP:
                rwRecMemGetSIP(&rwrec, &ip);
                key.type = SKBAG_KEY_U32;
                key.val.u32 = skPrefixMapFindValue(bag->pmap, &ip);
                break;
              case SKBAG_FIELD_DIP_PMAP:
                rwRecMemGetDIP(&rwrec, &ip);
                key.type = SKBAG_KEY_U32;
                key.val.u32 = skPrefixMapFindValue(bag->pmap, &ip);
                break;
              case SKBAG_FIELD_SPORT_PMAP:
                pp.proto = rwRecGetProto(&rwrec);
                pp.port  = rwRecGetSPort(&rwrec);
                key.type = SKBAG_KEY_U32;
                key.val.u32 = skPrefixMapFindValue(bag->pmap, &pp);
                break;
              case SKBAG_FIELD_DPORT_PMAP:
                pp.proto = rwRecGetProto(&rwrec);
                pp.port  = rwRecGetDPort(&rwrec);
                key.type = SKBAG_KEY_U32;
                key.val.u32 = skPrefixMapFindValue(bag->pmap, &pp);
                break;
              default:
                skAbortBadCase(bag->counter);
            }

            err = skBagCounterAdd(bag->bag, &key, &counter, NULL);
            switch (err) {
              case SKBAG_OK:
                break;
              case SKBAG_ERR_OP_BOUNDS:
                counter.val.u64 = SKBAG_COUNTER_MAX;
                skBagCounterSet(bag->bag, &key, &counter);
                if (!bag->overflow) {
                    bag->overflow = 1;
                    skAppPrintErr("**WARNING** Overflow for %s=%s",
                                  appOptions[OPT_BAG_FILE].name,
                                  createBagFileArgument(bag));
                }
                break;
              case SKBAG_ERR_MEMORY:
                skAppPrintErr(
                    "Out of memory for %s=%s\n\tCleaning up and exiting",
                    appOptions[OPT_BAG_FILE].name,
                    createBagFileArgument(bag));
                rv = -1;
                goto END;
              default:
                skAppPrintErr("Error setting value for %s=%s: %s",
                              appOptions[OPT_BAG_FILE].name,
                              createBagFileArgument(bag),
                              skBagStrerror(err));
                rv = -1;
                goto END;
            }
        }
    }

    if (rv == SKSTREAM_ERR_EOF) {
        /* Successful if we make it here */
        rv = 0;
    } else {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        rv = -1;
    }

  END:
    return rv;
}


int main(int argc, char **argv)
{
    skstream_t *stream;
    char errbuf[2 * PATH_MAX];
    bagfile_t *bag;
    int had_err = 0;
    skBagErr_t err;
    ssize_t rv;
    size_t i;

    appSetup(argc, argv);                       /* never returns on error */

    /* process input */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        skStreamSetIPv6Policy(stream, ipv6_policy);
        if (0 != processFile(stream)) {
            skAppPrintErr("Error processing input from %s",
                          skStreamGetPathname(stream));
            skStreamDestroy(&stream);
            return EXIT_FAILURE;
        }
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* write the bags */
    for (i = 0; (bag = (bagfile_t*)skVectorGetValuePointer(bag_vec, i)); ++i) {
        assert(bag->bag);
        assert(bag->stream);

        /* add the invocation and notes */
        if (!invocation_strip) {
            rv = skHeaderAddInvocation(skStreamGetSilkHeader(bag->stream),
                                       1, argc, argv);
            if (rv) {
                skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
            }
        }
        rv = skOptionsNotesAddToStream(bag->stream);
        if (rv) {
            skStreamPrintLastErr(bag->stream, rv, &skAppPrintErr);
        }

        err = skBagWrite(bag->bag, bag->stream);
        if (SKBAG_OK == err) {
            rv = skStreamClose(bag->stream);
            if (rv) {
                had_err = 1;
                skStreamLastErrMessage(bag->stream, rv,
                                       errbuf, sizeof(errbuf));
                skAppPrintErr("Error writing %s=%s: %s",
                              appOptions[OPT_BAG_FILE].name,
                              createBagFileArgument(bag),
                              errbuf);
            }
        } else if (SKBAG_ERR_OUTPUT == err) {
            had_err = 1;
            rv = skStreamGetLastReturnValue(bag->stream);
            skStreamLastErrMessage(bag->stream, rv,
                                   errbuf, sizeof(errbuf));
            skAppPrintErr("Error writing %s=%s: %s",
                          appOptions[OPT_BAG_FILE].name,
                          createBagFileArgument(bag),
                          errbuf);
        } else {
            had_err = 1;
            skAppPrintErr("Error writing %s=%s: %s",
                          appOptions[OPT_BAG_FILE].name,
                          createBagFileArgument(bag),
                          skBagStrerror(err));
        }
        skStreamDestroy(&bag->stream);
    }

    /* done */
    return ((had_err) ? EXIT_FAILURE : EXIT_SUCCESS);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
