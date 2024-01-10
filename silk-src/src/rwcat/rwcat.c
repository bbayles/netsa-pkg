/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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
**  rwcat.c
**
**  12/13/2002
**
**  Suresh L. Konda
**
**  Stream out a bunch of input files--given on the command
**  line--and/or stdin to stdout or given file Path
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcat.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */

/* file handle for --help output */
#define USAGE_FH stdout

/* file handle to use for --print-filenames output */
#define FILENAMES_FH stderr

/* LOCAL VARIABLES */

/* handles input streams */
static sk_options_ctx_t *optctx = NULL;

/* output stream */
static skstream_t *out_stream = NULL;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* byte order of the files we generate; default is to write files in
 * the native byte order */
static silk_endian_t byte_order = SILK_ENDIAN_ANY;

/* how to handle IPv6 flows. the --ipv4-output switch will set this to
 * SK_IPV6POLICY_ASV4 */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;


/* OPTIONS SETUP */

typedef enum {
    OPT_OUTPUT_PATH, OPT_BYTE_ORDER, OPT_IPV4_OUTPUT
} appOptionsEnum;

static struct option appOptions[] = {
    {"output-path",     REQUIRED_ARG, 0, OPT_OUTPUT_PATH},
    {"byte-order",      REQUIRED_ARG, 0, OPT_BYTE_ORDER},
    {"ipv4-output",     NO_ARG,       0, OPT_IPV4_OUTPUT},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Write the output to this stream or file. Def. stdout",
    ("Write the output in this byte order. Def. 'native'.\n"
     "\tChoices: 'native', 'little', 'big'"),
    ("Force the output to contain only IPv4 addresses. Def. no"),
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  byteOrderParse(const char *endian_string);


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
     "\tline, or from the standard input when no FILES are provided,\n" \
     "\tand writes the SiLK records to the specified output file or\n"  \
     "\tto the standard output if it is not connected to a terminal.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsCtxOptionsUsage(optctx, fh);
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
    static uint8_t teardownFlag = 0;
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close output file */
    if (out_stream) {
        rv = skStreamClose(out_stream);
        if (rv && rv != SKSTREAM_ERR_NOT_OPEN) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&out_stream);
    }

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
    sk_file_header_t *out_hdr = NULL;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
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

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* create output stream to stdout if no --output-path was given */
    if (out_stream == NULL) {
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, "-")))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skStreamDestroy(&out_stream);
            exit(EXIT_FAILURE);
        }
    }

    /* get the output file's header */
    out_hdr = skStreamGetSilkHeader(out_stream);

#if SK_ENABLE_IPV6
    /* write an RWGENERIC file if we know there will be no IPv6 flows */
    if (ipv6_policy < SK_IPV6POLICY_MIX) {
        rv = skHeaderSetFileFormat(out_hdr, FT_RWGENERIC);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skStreamDestroy(&out_stream);
            exit(EXIT_FAILURE);
        }
    }
#endif  /* SK_ENABLE_IPV6 */

    /* set the header, add the notes (if given), open output, and
     * write header */
    if ((rv = skHeaderSetCompressionMethod(out_hdr, comp_method))
        || (rv = skHeaderSetByteOrder(out_hdr, byte_order))
        || (rv = skOptionsNotesAddToStream(out_stream))
        || (rv = skStreamOpen(out_stream))
        || (rv = skStreamWriteSilkHeader(out_stream)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&out_stream);
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
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_OUTPUT_PATH:
        if (out_stream != NULL) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        if ((rv = skStreamCreate(&out_stream,SK_IO_WRITE,SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(out_stream, opt_arg)))
        {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            skStreamDestroy(&out_stream);
            return 1;
        }
        break;

      case OPT_BYTE_ORDER:
        if (byteOrderParse(opt_arg)) {
            return 1;
        }
        break;

      case OPT_IPV4_OUTPUT:
        ipv6_policy = SK_IPV6POLICY_ASV4;
        break;
    } /* switch */

    return 0;                     /* OK */
}


/*
 *  ok = byteOrderParse(argument)
 *
 *    Parse the argument to the --byte-order switch and set the global
 *    variable 'byte_order'.
 */
static int
byteOrderParse(
    const char         *endian_string)
{
    static int option_seen = 0;
    int i;
    size_t len;
    /* Options for byte-order switch */
    struct {
        const char     *name;
        silk_endian_t   value;
    } byte_order_opts[] = {
        {"native", SILK_ENDIAN_NATIVE},
        {"little", SILK_ENDIAN_LITTLE},
        {"big",    SILK_ENDIAN_BIG},
        {NULL,     SILK_ENDIAN_ANY} /* sentinel */
    };

    /* only process option one time */
    if (option_seen != 0) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }
    option_seen = 1;

    len = strlen(endian_string);
    if (len == 0) {
        skAppPrintErr("Invalid %s: Empty string",
                      appOptions[OPT_BYTE_ORDER].name);
        return 1;
    }

    /* parse user's input */
    for (i = 0; byte_order_opts[i].name; ++i) {
        if ((len <= strlen(byte_order_opts[i].name))
            && (0 == strncmp(byte_order_opts[i].name, endian_string, len)))
        {
            byte_order = byte_order_opts[i].value;
            option_seen = 2;
            break;
        }
    }

    if (option_seen != 2) {
        skAppPrintErr("Invalid %s '%s': Unrecognized value",
                      appOptions[OPT_BYTE_ORDER].name, endian_string);
        return 1;
    }

    if (byte_order == SILK_ENDIAN_NATIVE) {
#if SK_LITTLE_ENDIAN
        byte_order = SILK_ENDIAN_LITTLE;
#else
        byte_order = SILK_ENDIAN_BIG;
#endif
    }

    return 0;
}


/*
 *  catFile(in_stream);
 *
 *    Write all the records from 'in_stream' to out_stream.
 */
static void
catFile(
    skstream_t         *in_stream)
{
    rwRec rwrec;
    uint64_t in_count = 0;
    uint64_t out_count = 0;
    FILE *print_filenames;
    int in_rv;
    int rv = SKSTREAM_OK;

    skStreamSetIPv6Policy(in_stream, ipv6_policy);

    while ((in_rv = skStreamReadRecord(in_stream, &rwrec)) == SKSTREAM_OK) {
        in_count++;
        rv = skStreamWriteRecord(out_stream, &rwrec);
        if (SKSTREAM_OK != rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                break;
            }
        }
        out_count++;
    }
    if ((in_rv != SKSTREAM_ERR_EOF) && (in_rv != SKSTREAM_OK)) {
        skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
    }

    print_filenames = skOptionsCtxGetPrintFilenames(optctx);
    if (print_filenames) {
        fprintf(FILENAMES_FH, ("Read %" PRIu64 " Wrote %" PRIu64 "\n"),
                in_count, out_count);
    }
}


int main(int argc, char **argv)
{
    skstream_t *stream;
    int rv = 0;

    appSetup(argc, argv);

    /* process input */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        catFile(stream);
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
