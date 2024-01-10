/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
 *  Read rwrec input and write the output to every known SiLK Flow
 *  record file format.
 *
 */


#include <silk/silk.h>

RCSIDENT("$SiLK: rwallformats.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* basename of outputs.  Will append -{B,L}-<type>-<version>.dat to this. */
static const char *base_name = NULL;

/* if non-zero, do not include invocation in the output file.  I added
 * this to deal with libtool since, when running within the build
 * directory, the command name may or may not include an "lt-" prefix,
 * and this makes comparing complete files impossible. */
static int no_invocation = 0;

/* where to write the records as they are read to avoid having to open
 * many file handles */
static const char *temp_directory = NULL;

/* file handle to temporary file */
static FILE *tmpf = NULL;

/* support for input files */
static sk_options_ctx_t *optctx = NULL;

/* reference to argc and argv for filter output */
static int g_argc;
static char **g_argv;

/* file formats to output */
static unsigned int stream_format[] = {
    FT_FLOWCAP,
    FT_RWAUGMENTED,
    FT_RWAUGROUTING,
    FT_RWAUGWEB,
    FT_RWAUGSNMPOUT,
    FT_RWFILTER,
    FT_RWGENERIC,
    FT_RWIPV6,
    FT_RWIPV6ROUTING,
    FT_RWNOTROUTED,
    FT_RWROUTED,
    FT_RWSPLIT,
    FT_RWWWW
};


/* OPTIONS SETUP */

typedef enum {
    OPT_BASENAME, OPT_NO_INVOCATION
} appOptionsEnum;

static struct option appOptions[] = {
    {"basename",                REQUIRED_ARG, 0, OPT_BASENAME},
    {"no-invocation",           NO_ARG,       0, OPT_NO_INVOCATION},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    "Begin each output file with this text",
    "Do not include command line invocation in output",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static FILE *openTempFile(void);
static size_t openOutput(skstream_t **out_stream, const rwRec *rwrec);


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
    ("[SWITCHES] [FILES]\n"                                             \
     "\tRead SiLK Flow records as input and write them to files using\n" \
     "\tevery known SiLK Flow file format and byte order.  Files are\n" \
     "\tnamed FT_<format>-v<version>-c<compmethod>-{B,L}.dat, where\n"  \
     "\t<version> is file version, <compmethod> is the compression\n"   \
     "\tmethod, and {B,L} is the byte order (big,little).  The names will\n" \
     "\tbe prefixed by \"<basename>-\" when --basename is given.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsCtxOptionsUsage(optctx, fh);
    skOptionsTempDirUsage(fh);
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

    if (tmpf) {
        fclose(tmpf);
        tmpf = NULL;
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

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW
                    | SK_OPTIONS_CTX_ALLOW_STDIN);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skOptionsTempDirRegister(&temp_directory)
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

    /* parse the options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();
    }

    /* ensure the site config is available */
    if (sksiteConfigure(1)) {
        exit(EXIT_FAILURE);
    }

    /* open a temporary file */
    tmpf = openTempFile();
    if (tmpf == NULL) {
        exit(EXIT_FAILURE);
    }

    return;  /* OK */
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
      case OPT_BASENAME:
        base_name = opt_arg;
        break;

      case OPT_NO_INVOCATION:
        no_invocation = 1;
        break;
    }

    return 0;  /* OK */
}


/*
 *  fp = openTempFile();
 *
 *    Open a temporary file; the file is immediately unlinked, so it
 *    will be removed when the program exits.
 */
static FILE *
openTempFile(
    void)
{
    static char temp_name[PATH_MAX];
    int len;
    int fd;
    FILE *fp;

    temp_directory = skTempDir(temp_directory, &skAppPrintErr);
    if (temp_directory == NULL) {
        return NULL;
    }

    /* attempt to open a temp file, then remove it */
    len = snprintf(temp_name, sizeof(temp_name), "%s/%s.XXXXXXXX",
                   temp_directory, skAppName());
    if (len < 0 || (size_t)len > sizeof(temp_name)) {
        skAppPrintErr("Error creating temp file name");
        return NULL;
    }
    fd = mkstemp(temp_name);
    if (fd == -1) {
        skAppPrintSyserror("Cannot create temp file %s", temp_name);
        return NULL;
    }
    fp = fdopen(fd, "wb+");
    if (fp == NULL) {
        skAppPrintSyserror("Cannot reopen temp file %s", temp_name);
        return NULL;
    }
    if (unlink(temp_name)) {
        skAppPrintSyserror("Cannot remove temp file '%s'", temp_name);
        fclose(fp);
        return NULL;
    }

    return fp;
}


/*
 *  status = openOutput(&stream, rwrec);
 *
 *    Open an output stream for every known type-version-endian
 *    combination.  The files are opened one at a time; a different
 *    file is opened each time this function is called.  The caller
 *    should skStreamClose() the file when finished with it.  The newly
 *    opened file is placed into the memory pointed at by 'stream'.
 *    The 'rwrec' is used to write headers to the file.
 */
static size_t
openOutput(
    skstream_t        **out_stream,
    const rwRec        *first_rec)
{
    const size_t num_formats = (sizeof(stream_format)/sizeof(unsigned int));
    const silk_endian_t endians[] = {SILK_ENDIAN_BIG, SILK_ENDIAN_LITTLE};
    const char *endian_name[] = {"B", "L"};

    static unsigned int num_compmethod = 0;
    static unsigned int f, e, c;
    static sk_file_version_t v;

    silk_endian_t byte_order;
    skstream_t *stream;
    sk_file_header_t *hdr;
    int rv = SKSTREAM_OK;
    char path[PATH_MAX];
    char format_name[SK_MAX_STRLEN_FILE_FORMAT+1];

    if (num_compmethod == 0) {
        /* need to initialize */

        /* find the number of compression methods */
        for (num_compmethod = 0;
             skCompMethodCheck(num_compmethod);
             ++num_compmethod)
            ; /* no-op */

        c = 0;
        f = 0;
        v = 0;
        e = 0;
    }

    /* loop over compression methods */
    for ( ; c < num_compmethod; ++c) {
        if (SK_COMPMETHOD_IS_AVAIL != skCompMethodCheck(c)) {
            continue;
        }

        /* loop over formats */
        for ( ; f < num_formats; ++f) {
            /* loop over versions of that format */
            for (;;) {
                /* only RWGENERIC supports v=0 */
                if (v == 0) {
                    if (stream_format[f] != FT_RWGENERIC) {
                        goto NEXT_VERSION;
                    }
                }
                if (stream_format[f] == FT_FLOWCAP && v < 2) {
                    goto NEXT_VERSION;
                }

                /* loop over byte-orders */
                while (e < 2) {
                    byte_order = endians[e];

                    skFileFormatGetName(format_name, sizeof(format_name),
                                        stream_format[f]);
                    if ((size_t)snprintf(path, sizeof(path),
                                         "%s%s%s-v%d-c%u-%s.dat",
                                         ((base_name != NULL) ? base_name :""),
                                         ((base_name != NULL) ? "-" : ""),
                                         format_name, v, c, endian_name[e])
                        >= sizeof(path))
                    {
                        skAppPrintErr("File name overflow");
                        return -1;
                    }

                    /* create and open the file */
                    hdr = NULL;
                    rv = SKSTREAM_OK;
                    if ( !rv) {
                        rv = skStreamCreate(&stream, SK_IO_WRITE,
                                            SK_CONTENT_SILK_FLOW);
                    }
                    if ( !rv) {
                        rv = skStreamBind(stream, path);
                    }
                    if ( !rv) {
                        hdr = skStreamGetSilkHeader(stream);
                        rv = skHeaderSetFileFormat(hdr, stream_format[f]);
                    }
                    if ( !rv) {
                        rv = skHeaderSetRecordVersion(hdr, v);
                    }
                    if ( !rv) {
                        rv = skHeaderSetByteOrder(hdr, byte_order);
                    }
                    if ( !rv) {
                        rv = skHeaderSetCompressionMethod(hdr, c);
                    }
#if 0
                    if ( !rv) {
                        /* force output to be in IPv4 for comparison
                         * with formats that do not support IPv6 */
                        rv = skStreamSetIPv6Policy(stream, SK_IPV6POLICY_ASV4);
                    }
#endif  /* 0 */
                    if ( !rv) {
                        rv = skHeaderAddProbename(hdr, "DUMMY_PROBE");
                    }
                    if ( !rv) {
                        rv=skHeaderAddPackedfile(hdr,
                                                 rwRecGetStartTime(first_rec),
                                                 rwRecGetFlowType(first_rec),
                                                 rwRecGetSensor(first_rec));
                    }
                    if ( !rv && !no_invocation) {
                        rv = skHeaderAddInvocation(hdr, 1, g_argc, g_argv);
                    }
                    if ( !rv) {
                        rv = skStreamOpen(stream);
                    }
                    if ( !rv) {
                        rv = skStreamWriteSilkHeader(stream);
                    }

                    if (rv) {
                        if (rv == SKSTREAM_ERR_UNSUPPORT_VERSION) {
                            /* Reached max version for this type.  Try
                             * next type. */
                            skStreamDestroy(&stream);
                            if (skFileExists(path)) {
                                unlink(path);
                            }
                            goto NEXT_TYPE;
                        }

                        /* Unexpected error.  Bail */
                        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
                        skAppPrintErr("Error opening '%s'\n", path);
                        skStreamDestroy(&stream);
                        return -1;
                    }

                    /* increment 'e' for the next run */
                    ++e;

                    /* and return */
                    *out_stream = stream;
                    return 0;

                } /* for e */

              NEXT_VERSION:
                ++v;
                e = 0;
            } /* while 1 */
          NEXT_TYPE:
            v = 0;
            e = 0;
        } /* for f */
        f = 0;
        v = 0;
        e = 0;
    } /* for c */

    return 1;
}


/*
 *  writeOutputs();
 *
 *    Writes the records stored in the global 'tmpf' to a file in
 *    every know file format, version, compression method, and byte
 *    order.  The openOutput() function is called to open the next
 *    file, then the records in tmpf are written there.
 */
static void
writeOutputs(
    void)
{
    skstream_t *stream;
    rwRec rwrec;
    int rv;

    /* write each real output file */
    for (;;) {
        if (fseek(tmpf, 0, SEEK_SET) == -1) {
            skAppPrintSyserror("Cannot seek in temp file");
            exit(EXIT_FAILURE);
        }
        if (!fread(&rwrec, sizeof(rwRec), 1, tmpf)) {
            skAppPrintErr("Cannot read from temp file");
            exit(EXIT_FAILURE);
        }

        rv = openOutput(&stream, &rwrec);
        if (rv != 0) {
            if (rv == 1) {
                /* done */
                break;
            }
            /* error */
            exit(EXIT_FAILURE);
        }

        do {
            rv = skStreamWriteRecord(stream, &rwrec);
            if (SKSTREAM_OK != rv) {
                skStreamPrintLastErr(stream, rv, &skAppPrintErr);
                if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                    break;
                }
            }
        } while (fread(&rwrec, sizeof(rwRec), 1, tmpf));

        rv = skStreamClose(stream);
        if (SKSTREAM_OK != rv) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        }
        skStreamDestroy(&stream);
    }
}


/*
 *  status = readFileToTemp(input_path);
 *
 *    Append the contents of input_path to the temporary file.
 */
static int
readFileToTemp(
    skstream_t         *in_stream)
{
    rwRec rwrec;
    int rv;

    while ((rv = skStreamReadRecord(in_stream, &rwrec)) == SKSTREAM_OK) {
        if (!fwrite(&rwrec, sizeof(rwRec), 1, tmpf)) {
            skAppPrintSyserror("Cannot write to temp file");
            return -1;
        }
    }
    if (SKSTREAM_ERR_EOF != rv) {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
    }

    return 0;
}


int main(int argc, char **argv)
{
    skstream_t *stream;
    int rv = 0;

    g_argc = argc;
    g_argv = argv;

    appSetup(argc, argv);                       /* never returns on error */

    /* process input */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        if (readFileToTemp(stream)) {
            skStreamDestroy(&stream);
            exit(EXIT_FAILURE);
        }
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* Write the records from the temp file to each output file */
    writeOutputs();

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
