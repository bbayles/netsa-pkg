/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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
 * rwswapbytes
 *
 * Read any rw file (rwpacked file, rwfilter output, etc) and output a
 * file in the specified byte order.
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwswapbytes.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* MACROS AND TYPEDEFS */

/* File handle for --help output */
#define USAGE_FH stdout

typedef enum rwswapOptions {
    RWSW_BIG = 128, RWSW_LITTLE, RWSW_NATIVE, RWSW_SWAP,
    RWSW_UNSET = 1
} rwswapOptions_t;

#if SK_LITTLE_ENDIAN
#  define RWSW_NATIVE_FORMAT "little"
#else
#  define RWSW_NATIVE_FORMAT "big"
#endif


/* LOCAL VARIABLES */

static rwswapOptions_t out_endian = RWSW_UNSET;
static const char *in_path;
static const char *out_path;


/* OPTIONS */

typedef enum {
    OPT_BIG_ENDIAN, OPT_LITTLE_ENDIAN, OPT_NATIVE_ENDIAN, OPT_SWAP_ENDIAN
} appOptionsEnum;

static struct option appOptions[] = {
    {"big-endian",       NO_ARG,       0, OPT_BIG_ENDIAN},
    {"little-endian",    NO_ARG,       0, OPT_LITTLE_ENDIAN},
    {"native-endian",    NO_ARG,       0, OPT_NATIVE_ENDIAN},
    {"swap-endian",      NO_ARG,       0, OPT_SWAP_ENDIAN},
    {0,0,0,0}            /* sentinel entry */
};

static const char *appHelp[] = {
    "Write output in big-endian format (network byte-order)",
    "Write output in little-endian format",
    ("Write output in this machine's native format [" RWSW_NATIVE_FORMAT "]"),
    "Unconditionally swap the byte-order of the input",
    (char *)NULL
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
#define USAGE_MSG                                                             \
    ("ENDIAN_SWITCH [SWITCHES] [INPUT_FILE [OUTPUT_FILE]]\n"                  \
     "\tChange the byte-order of the SiLK Flow records in INPUT_FILE as\n"    \
     "\tspecified by ENDIAN_SWITCH and write the result to OUTPUT_FILE.\n"    \
     "\tUse 'stdin' or '-' for INPUT_FILE to read from the standard input;\n" \
     "\tuse 'stdout' or '-' for OUTPUT_FILE to write to the standard\n"       \
     "\toutput. INPUT_FILE and OUTPUT_FILE default to 'stdin' and 'stdout'.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    skOptionsNotesUsage(fh);
    fprintf(fh, "\nENDIAN_SWITCH:\n");
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s: %s\n", appOptions[i].name, appHelp[i]);
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

    skOptionsNotesTeardown();
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
    int arg_index;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL))
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
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* Check that a swapping option was given */
    if (RWSW_UNSET == out_endian) {
        skAppPrintErr("You must specify the output byte order.");
        skAppUsage();
    }

    /* default is to read from stdin and write to stdout */
    in_path = "-";
    out_path = "-";

    /* process files named on the command line */
    switch (argc - arg_index) {
      case 2:
        in_path = argv[arg_index++];
        out_path = argv[arg_index++];
        break;
      case 1:
        in_path = argv[arg_index++];
        break;
      case 0:
        break;
      default:
        skAppPrintErr("Too many arguments;"
                      " a maximum of two files may be specified");
        skAppUsage();
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
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    rwswapOptions_t e;

    SK_UNUSED_PARAM(cData);
    SK_UNUSED_PARAM(opt_arg);

    switch ((appOptionsEnum)opt_index) {
      case OPT_BIG_ENDIAN:
      case OPT_LITTLE_ENDIAN:
      case OPT_NATIVE_ENDIAN:
      case OPT_SWAP_ENDIAN:
        e = (rwswapOptions_t)(RWSW_BIG + (opt_index - OPT_BIG_ENDIAN));
        if (RWSW_UNSET == out_endian) {
            out_endian = e;
        } else if (e != out_endian) {
            skAppPrintErr("Invalid %s: The --%s switch was already specified",
                          appOptions[opt_index].name,
                          appOptions[out_endian - RWSW_BIG].name);
            return 1;
        }
        break;
    }

    return 0;                   /* OK */
}


/*
 *  is_ok = rwswap_file(input_file, output_file, endian);
 *
 *    Byte swap the file named 'input_file' and write it to
 *    'output_file' using the 'endian' to determine the byte-order of
 *    'output_file'.
 */
static int
rwswap_file(
    const char         *in_file,
    const char         *out_file,
    rwswapOptions_t     endian)
{
    silk_endian_t byte_order;
    skstream_t *in_stream;
    skstream_t *out_stream;
    sk_file_header_t *in_hdr;
    sk_file_header_t *out_hdr;
    rwRec rwrec;
    int in_rv = SKSTREAM_OK;
    int rv = 0;

    assert(RWSW_UNSET != endian);

    /* Create and bind the output file */
    if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(out_stream, out_file)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        return 1;
    }

    /* Open input file */
    in_rv = skStreamOpenSilkFlow(&in_stream, in_file, SK_IO_READ);
    if (in_rv) {
        skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
        skStreamDestroy(&in_stream);
        skStreamDestroy(&out_stream);
        return 1;
    }

    in_hdr = skStreamGetSilkHeader(in_stream);

    switch (endian) {
      case RWSW_BIG:
        byte_order = SILK_ENDIAN_BIG;
        break;
      case RWSW_LITTLE:
        byte_order = SILK_ENDIAN_LITTLE;
        break;
      case RWSW_NATIVE:
        byte_order = SILK_ENDIAN_NATIVE;
        break;
      case RWSW_SWAP:
        switch (skHeaderGetByteOrder(in_hdr)) {
          case SILK_ENDIAN_BIG:
            byte_order = SILK_ENDIAN_LITTLE;
            break;
          case SILK_ENDIAN_LITTLE:
            byte_order = SILK_ENDIAN_BIG;
            break;
          default:
            skAbortBadCase(skHeaderGetByteOrder(in_hdr));
        }
        break;
      default:
        skAbortBadCase(endian);
    }

    /* Copy the headers from the source file to the output file
     * modifying the byte order, output the output stream, and write
     * its header */
    out_hdr = skStreamGetSilkHeader(out_stream);
    if ((rv = skHeaderCopy(out_hdr, in_hdr,
                           (SKHDR_CP_ALL & ~SKHDR_CP_ENDIAN)))
        || (rv = skHeaderSetByteOrder(out_hdr, byte_order))
        || (rv = skOptionsNotesAddToStream(out_stream))
        || (rv = skStreamOpen(out_stream))
        || (rv = skStreamWriteSilkHeader(out_stream)))
    {
        goto END;
    }

    /* read and write the data until we encounter an error */
    while ((in_rv = skStreamReadRecord(in_stream, &rwrec)) == SKSTREAM_OK) {
        rv = skStreamWriteRecord(out_stream, &rwrec);
        if (SKSTREAM_ERROR_IS_FATAL(rv)) {
            goto END;
        }
    }

    /* input error */
    if (in_rv != SKSTREAM_ERR_EOF) {
        skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
    }

    if (rv == SKSTREAM_OK) {
        rv = skStreamClose(out_stream);
    }

  END:
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }
    skStreamDestroy(&out_stream);
    skStreamDestroy(&in_stream);

    return rv;
}


int main(int argc, char **argv)
{
    int rv;

    appSetup(argc, argv);

    rv = rwswap_file(in_path, out_path, out_endian);

    /* done */
    return ((0 == rv) ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
