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
**  rwnetmask
**
**  Read in SiLK Flow records and write out SiLK Flow records, masking
**  the Source IP and Destination IP by the prefix-lengths given on
**  the command line.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwnetmask.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */

/* File handle for --help output */
#define USAGE_FH stdout

/* Number of prefixes supported: sip, dip, nhip */
#define PREFIX_COUNT 3

enum {
    SIP_MASK, DIP_MASK, NHIP_MASK,
    /* next must be last */
    _FINAL_MASK_
};


/* LOCAL VARIABLES */

/* The masks of source/dest/next-hop IP for IPv4 and IPv6, and the
 * number of bits in each mask. */
static struct net_mask_st {
    uint8_t     mask6[16];
    uint32_t    mask4;
    uint8_t     bits6;
    uint8_t     bits4;
} net_mask[PREFIX_COUNT];

/* support for looping over input files */
static sk_options_ctx_t *optctx = NULL;

/* Where to write the output */
static const char *output_path = NULL;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* how to handle IPv6 flows */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;


/* OPTIONS */

typedef enum {
    OPT_4SIP_PREFIX_LENGTH, OPT_4DIP_PREFIX_LENGTH, OPT_4NHIP_PREFIX_LENGTH,
#if SK_ENABLE_IPV6
    OPT_6SIP_PREFIX_LENGTH, OPT_6DIP_PREFIX_LENGTH, OPT_6NHIP_PREFIX_LENGTH,
#endif
    OPT_OUTPUT_PATH
}  appOptionsEnum;

static struct option appOptions[] = {
    {"4sip-prefix-length",  REQUIRED_ARG, 0, OPT_4SIP_PREFIX_LENGTH},
    {"4dip-prefix-length",  REQUIRED_ARG, 0, OPT_4DIP_PREFIX_LENGTH},
    {"4nhip-prefix-length", REQUIRED_ARG, 0, OPT_4NHIP_PREFIX_LENGTH},
#if SK_ENABLE_IPV6
    {"6sip-prefix-length",  REQUIRED_ARG, 0, OPT_6SIP_PREFIX_LENGTH},
    {"6dip-prefix-length",  REQUIRED_ARG, 0, OPT_6DIP_PREFIX_LENGTH},
    {"6nhip-prefix-length", REQUIRED_ARG, 0, OPT_6NHIP_PREFIX_LENGTH},
#endif
    {"output-path",         REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    /* add help strings here for the applications options */
    "High bits of source IPv4 to keep. Def 32",
    "High bits of destination IPv4 to keep. Def 32",
    "High bits of next-hop IPv4 to keep. Def 32",
#if SK_ENABLE_IPV6
    "High bits of source IPv6 to keep. Def 128",
    "High bits of destination IPv6 to keep. Def 128",
    "High bits of next-hop IPv6 to keep. Def 128",
#endif
    "Write the output to this stream or file. Def. stdout",
    (char *)NULL
};

/* for compatibility */
static struct option legacyOptions[] = {
    {"sip-prefix-length",           REQUIRED_ARG, 0, OPT_4SIP_PREFIX_LENGTH},
    {"source-prefix-length",        REQUIRED_ARG, 0, OPT_4SIP_PREFIX_LENGTH},
    {"dip-prefix-length",           REQUIRED_ARG, 0, OPT_4DIP_PREFIX_LENGTH},
    {"destination-prefix-length",   REQUIRED_ARG, 0, OPT_4DIP_PREFIX_LENGTH},
    {"d",                           REQUIRED_ARG, 0, OPT_4DIP_PREFIX_LENGTH},
    {"nhip-prefix-length",          REQUIRED_ARG, 0, OPT_4NHIP_PREFIX_LENGTH},
    {"next-hop-prefix-length",      REQUIRED_ARG, 0, OPT_4NHIP_PREFIX_LENGTH},
    {0,0,0,0}                       /* sentinel entry */
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);


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
#define USAGE_MSG                                                          \
    ("<PREFIX_SWITCH> [<PREFIX_SWITCH>...] [SWITCHES] [FILES]\n"           \
     "\tRead SiLK Flow records from FILES named on the command line or\n"  \
     "\tfrom the standard input, keep the specified number of most\n"      \
     "\tsignificant bits for each IP address, and write the modified\n"    \
     "\trecords to the specified output file or to the standard output.\n")

    FILE *fh = USAGE_FH;
    int i, j;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);

    fprintf(fh, "\nPREFIX SWITCHES:\n");
    /* print everything before --output-path */
    for (i=0; appOptions[i].name && appOptions[i].val < OPT_OUTPUT_PATH; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    /* print the first three switches again as aliases---use a
     * different variable!! */
    for (j = 0;
         appOptions[j].name && appOptions[j].val <= OPT_4NHIP_PREFIX_LENGTH;
         ++j)
    {
        fprintf(fh, "--%s %s. Alias for --%s\n", appOptions[j].name + 1,
                SK_OPTION_HAS_ARG(appOptions[j]), appOptions[j].name);
    }

    /* print remaining options */
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for ( ; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }

    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    skCompMethodOptionsUsage(fh);
    skOptionsNotesUsage(fh);
    sksiteOptionsUsage(fh);
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
    int rv;
    int i;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    assert(PREFIX_COUNT == _FINAL_MASK_);

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize variables */
    memset(net_mask, 0, sizeof(net_mask));

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsRegister(legacyOptions, &appOptionsHandler, NULL)
        || skIPv6PolicyOptionsRegister(&ipv6_policy)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
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

    /* make certain at least one mask was specified */
    for (i = 0; i < PREFIX_COUNT; ++i) {
        if (net_mask[i].bits6 || net_mask[i].bits4) {
            break;
        }
    }
    if (i == PREFIX_COUNT) {
        skAppPrintErr("Must specify at least one prefix length option");
        skAppUsage();
    }

    /* check the output */
    if (output_path == NULL) {
        output_path = "-";
    }
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
#if SK_ENABLE_IPV6
    uint32_t j;
#endif
    uint32_t n;
    uint32_t i;
    int rv;

    /* Store the address of the prefix to set in the switch(), then
     * set the referenced value below the switch() */
    switch ((appOptionsEnum)opt_index) {
      case OPT_4SIP_PREFIX_LENGTH:
      case OPT_4DIP_PREFIX_LENGTH:
      case OPT_4NHIP_PREFIX_LENGTH:
        /* Which mask to change */
        i = (opt_index - OPT_4SIP_PREFIX_LENGTH);
        /* Parse value */
        rv = skStringParseUint32(&n, opt_arg, 1, 32);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (net_mask[i].bits4) {
            skAppPrintErr(("The %s value was given multiple times;\n"
                           "\tusing final value %lu"),
                          appOptions[opt_index].name, (unsigned long)n);
        }
        net_mask[i].bits4 = (uint8_t)n;
        net_mask[i].mask4 = ~((n == 32) ? 0 : (UINT32_MAX >> n));
        break;

#if SK_ENABLE_IPV6
      case OPT_6SIP_PREFIX_LENGTH:
      case OPT_6DIP_PREFIX_LENGTH:
      case OPT_6NHIP_PREFIX_LENGTH:
        /* Which mask to change */
        i = (opt_index - OPT_6SIP_PREFIX_LENGTH);
        /* Parse value */
        rv = skStringParseUint32(&n, opt_arg, 1, 128);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (net_mask[i].bits6) {
            skAppPrintErr(("The %s value was given multiple times;\n"
                           "\tusing final value %lu"),
                          appOptions[opt_index].name, (unsigned long)n);
        }
        net_mask[i].bits6 = (uint8_t)n;
        /* byte in the uint8_t[16] where the change occurs */
        j = n >> 3;
        memset(&net_mask[i].mask6[0], 0xFF, j);
        if (n < 128) {
            net_mask[i].mask6[j] = ~(0xFF >> (n & 0x07));
            memset(&net_mask[i].mask6[j+1], 0, (15 - j));
        }
        break;
#endif  /* SK_ENABLE_IPV6 */

      case OPT_OUTPUT_PATH:
        if (output_path) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        output_path = opt_arg;
        break;
    }

    return 0;                   /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  maskInput(in_stream, out_stream);
 *
 *    Read SiLK Flow records from the 'in_stream' stream, mask off the
 *    source, destination, and/or next-hop IP addresses, and print the
 *    records to the 'out_stream' stream.
 */
static int
maskInput(
    skstream_t         *in_stream,
    skstream_t         *out_stream)
{
    rwRec rwrec;
    int rv;

    /* read the records and mask the IP addresses */
    while ((rv = skStreamReadRecord(in_stream, &rwrec)) == SKSTREAM_OK) {
#if SK_ENABLE_IPV6
        if (rwRecIsIPv6(&rwrec)) {
            if (net_mask[SIP_MASK].bits6) {
                rwRecApplyMaskSIPv6(&rwrec, net_mask[SIP_MASK].mask6);
            }
            if (net_mask[DIP_MASK].bits6) {
                rwRecApplyMaskDIPv6(&rwrec, net_mask[DIP_MASK].mask6);
            }
            if (net_mask[NHIP_MASK].bits6) {
                rwRecApplyMaskNhIPv6(&rwrec, net_mask[NHIP_MASK].mask6);
            }
        } else
#endif  /* SK_ENABLE_IPV6 */
        {
            if (net_mask[SIP_MASK].bits4) {
                rwRecApplyMaskSIPv4(&rwrec, net_mask[SIP_MASK].mask4);
            }
            if (net_mask[DIP_MASK].bits4) {
                rwRecApplyMaskDIPv4(&rwrec, net_mask[DIP_MASK].mask4);
            }
            if (net_mask[NHIP_MASK].bits4) {
                rwRecApplyMaskNhIPv4(&rwrec, net_mask[NHIP_MASK].mask4);
            }
        }

        rv = skStreamWriteRecord(out_stream, &rwrec);
        if (SKSTREAM_ERROR_IS_FATAL(rv)) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            return rv;
        }
    }

    if (SKSTREAM_ERR_EOF != rv) {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
    }
    return SKSTREAM_OK;
}


int main(int argc, char **argv)
{
    skstream_t *stream_in;
    skstream_t *stream_out;
    int rv;

    appSetup(argc, argv);       /* never returns on error */

    /* Open the output file */
    if ((rv = skStreamCreate(&stream_out, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(stream_out, output_path))
        || (rv = skStreamSetCompressionMethod(stream_out, comp_method))
        || (rv = skOptionsNotesAddToStream(stream_out))
        || (rv = skStreamOpen(stream_out))
        || (rv = skStreamWriteSilkHeader(stream_out)))
    {
        skStreamPrintLastErr(stream_out, rv, &skAppPrintErr);
        skStreamDestroy(&stream_out);
        exit(EXIT_FAILURE);
    }

    /* Process each input file */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream_in, skAppPrintErr))
           == 0)
    {
        skStreamSetIPv6Policy(stream_in, ipv6_policy);
        maskInput(stream_in, stream_out);
        skStreamDestroy(&stream_in);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* Close output */
    rv = skStreamClose(stream_out);
    if (rv) {
        skStreamPrintLastErr(stream_out, rv, &skAppPrintErr);
    }
    skStreamDestroy(&stream_out);

    /* done */
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
