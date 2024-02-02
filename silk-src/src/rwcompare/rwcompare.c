/*
** Copyright (C) 2009-2023 by Carnegie Mellon University.
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
**  rwcompare.c
**
**    Compare SiLK files to determine if they contain the same data.
**
**    Mark Thomas
**    April 2009
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwcompare.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLE DEFINITIONS */

/* index into argv */
static int arg_index;

/* whether to print the record that differs or just exit quietly */
static int quiet = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_QUIET
} appOptionsEnum;

static struct option appOptions[] = {
    {"quiet",           NO_ARG,     0, OPT_QUIET},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Do not print any output",
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
    ("[SWITCHES] FILE1 FILE2\n"                                               \
     "\tCompare the SiLK Flow records in FILE1 and FILE2.  Print nothing\n"   \
     "\tand exit with status 0 if the SiLK Flow records in the two files\n"   \
     "\tare identical.  Else, print the record where files differ and exit\n" \
     "\twith status 1.  Use 'stdin' or '-' for either FILE1 or FILE2 to\n"    \
     "\tread from the standard input.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
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
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* arg_index is looking at first file name to process */
    if (arg_index + 2 != argc) {
        skAppPrintErr("Expected two file names on the command line");
        skAppUsage();       /* never returns */
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
    char        UNUSED(*opt_arg))
{
    switch ((appOptionsEnum)opt_index) {
      case OPT_QUIET:
        quiet = 1;
        break;
    }

    return 0;  /* OK */
}


#ifdef RWCOMPARE_VERBOSE

#define RWCOMPARE_BUFSIZ    64
#if RWCOMPARE_BUFSIZ < SKIPADDR_STRLEN
#error "Buffer size is smaller than SKIPADDR_STRLEN"
#endif
#if RWCOMPARE_BUFSIZ < SKTIMESTAMP_STRLEN
#error "Buffer size is smaller than SKTIMESTAMP_STRLEN"
#endif

/* Width of the name column */
#define WIDTH_NAME  11

/* Width of value columns */
#define WIDTH_VALUE 33

#define DIFF_STRING "***"

static void
compareStrings(
    const char         *title,
    const char          str[][RWCOMPARE_BUFSIZ])
{
    char buf[16];
    int width = WIDTH_NAME - strlen(DIFF_STRING);

    if (0 == strcmp(str[0], str[1])) {
        printf("%*.*s|%*s|%*s|\n",
               WIDTH_NAME, WIDTH_NAME, title,
               WIDTH_VALUE, str[0], WIDTH_VALUE, str[1]);
        return;
    }

    snprintf(buf, sizeof(buf), "%*.*s%s",
             width, width, title, DIFF_STRING);
    printf("%*s|%*s|%*s|\n",
           WIDTH_NAME, buf, WIDTH_VALUE, str[0], WIDTH_VALUE, str[1]);
}

static void
compareNumbers(
    const char         *title,
    const uint32_t      num[])
{
    char buf[16];
    int width = WIDTH_NAME - strlen(DIFF_STRING);

    if (num[0] == num[1]) {
        printf("%*.*s|%*" PRIu32 "|%*" PRIu32 "|\n",
               WIDTH_NAME, WIDTH_NAME, title,
               WIDTH_VALUE, num[0], WIDTH_VALUE, num[1]);
        return;
    }

    snprintf(buf, sizeof(buf), "%*.*s%s",
             width, width, title, DIFF_STRING);
    printf("%*s|%*" PRIu32 "|%*" PRIu32 "|\n",
           WIDTH_NAME, buf, WIDTH_VALUE, num[0], WIDTH_VALUE, num[1]);
}

static void
printRecords(
    const rwRec         rec[])
{
    char starttime[2][RWCOMPARE_BUFSIZ];
    uint32_t elapsed[2];
    uint32_t sport[2];
    uint32_t dport[2];
    uint32_t proto[2];
    uint32_t flowtype[2];
    uint32_t sensor[2];
    uint32_t flags[2];
    uint32_t initflags[2];
    uint32_t restflags[2];
    uint32_t tcpstate[2];
    uint32_t application[2];
    uint32_t memo[2];
    uint32_t input[2];
    uint32_t output[2];
    uint32_t pkts[2];
    uint32_t bytes[2];
    char sip[2][RWCOMPARE_BUFSIZ];
    char dip[2][RWCOMPARE_BUFSIZ];
    char nhip[2][RWCOMPARE_BUFSIZ];
    skipaddr_t ip;
    unsigned i;

    for (i = 0; i < 2; ++i) {
        sktimestamp_r(
            starttime[i], rwRecGetStartTime(&rec[i]), SKTIMESTAMP_EPOCH);
        elapsed[i] = rwRecGetElapsed(&rec[i]);
        sport[i] = rwRecGetSPort(&rec[i]);
        dport[i] = rwRecGetDPort(&rec[i]);
        proto[i] = rwRecGetProto(&rec[i]);
        flowtype[i] = rwRecGetFlowType(&rec[i]);
        sensor[i] = rwRecGetSensor(&rec[i]);
        flags[i] = rwRecGetFlags(&rec[i]);
        initflags[i] = rwRecGetInitFlags(&rec[i]);
        restflags[i] = rwRecGetRestFlags(&rec[i]);
        tcpstate[i] = rwRecGetTcpState(&rec[i]);
        application[i] = rwRecGetApplication(&rec[i]);
        memo[i] = rwRecGetMemo(&rec[i]);
        input[i] = rwRecGetInput(&rec[i]);
        output[i] = rwRecGetOutput(&rec[i]);
        pkts[i] = rwRecGetPkts(&rec[i]);
        bytes[i] = rwRecGetBytes(&rec[i]);
        rwRecMemGetSIP(&rec[i], &ip);
        skipaddrString(sip[i], &ip, SKIPADDR_HEXADECIMAL);
        rwRecMemGetDIP(&rec[i], &ip);
        skipaddrString(dip[i], &ip, SKIPADDR_HEXADECIMAL);
        rwRecMemGetNhIP(&rec[i], &ip);
        skipaddrString(nhip[i], &ip, SKIPADDR_HEXADECIMAL);
    }

    compareStrings("StartTime", starttime);
    compareNumbers("Elapsed", elapsed);
    compareNumbers("SPort", sport);
    compareNumbers("DPort", dport);
    compareNumbers("Proto", proto);
    compareNumbers("FlowType", flowtype);
    compareNumbers("Sensor", sensor);
    compareNumbers("Flags", flags);
    compareNumbers("InitFlags", initflags);
    compareNumbers("RestFlags", restflags);
    compareNumbers("TcpState", tcpstate);
    compareNumbers("Application", application);
    compareNumbers("Memo", memo);
    compareNumbers("Input", input);
    compareNumbers("Output", output);
    compareNumbers("Pkts", pkts);
    compareNumbers("Bytes", bytes);
    compareStrings("SIP", sip);
    compareStrings("DIP", dip);
    compareStrings("NhIP", nhip);
}
#endif  /* RWCOMPARE_VERBOSE */


static int
compareFiles(
    char              **file)
{
    skstream_t *stream[2] = {NULL, NULL};
    rwRec rec[2];
    int i;
    int rv;
    int status = 2;
    uint64_t rec_count = 0;
    int eof = -1;

    memset(stream, 0, sizeof(stream));
    memset(rec, 0, sizeof(rec));

    for (i = 0; i < 2; ++i) {
        if ((rv = skStreamCreate(&stream[i], SK_IO_READ, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(stream[i], file[i]))
            || (rv = skStreamOpen(stream[i]))
            || (rv = skStreamReadSilkHeader(stream[i], NULL)))
        {
            /* Give up if we can't read the beginning of the silk header */
            if (rv != SKSTREAM_OK) {
                if (!quiet) {
                    skStreamPrintLastErr(stream[i], rv, &skAppPrintErr);
                }
                goto END;
            }
        }
    }

    while ((rv = skStreamReadRecord(stream[0], &rec[0])) == SKSTREAM_OK) {
        rv = skStreamReadRecord(stream[1], &rec[1]);
        if (rv != SKSTREAM_OK) {
            if (rv == SKSTREAM_ERR_EOF) {
                /* file 0 longer than file 1 */
                status = 1;
                eof = 1;
            } else {
                if (!quiet) {
                    skStreamPrintLastErr(stream[1], rv, &skAppPrintErr);
                }
                status = -1;
            }
            goto END;
        }

        ++rec_count;
        if (0 != memcmp(&rec[0], &rec[1], sizeof(rwRec))) {
            status = 1;
            goto END;
        }
    }

    if (rv != SKSTREAM_ERR_EOF) {
        if (!quiet) {
            skStreamPrintLastErr(stream[0], rv, &skAppPrintErr);
        }
    } else {
        rv = skStreamReadRecord(stream[1], &rec[1]);
        switch (rv) {
          case SKSTREAM_OK:
            /* file 1 longer than file 0 */
            status = 1;
            eof = 0;
            break;

          case SKSTREAM_ERR_EOF:
            /* files identical */
            status = 0;
            break;

          default:
            if (!quiet) {
                skStreamPrintLastErr(stream[1], rv, &skAppPrintErr);
            }
            break;
        }
    }

  END:
    for (i = 0; i < 2; ++i) {
        skStreamDestroy(&stream[i]);
    }
    if (1 == status && !quiet) {
        if (eof != -1) {
            printf("%s %s differ: EOF %s\n",
                   file[0], file[1], file[eof]);
        } else {
            printf(("%s %s differ: record %" PRIu64 "\n"),
                   file[0], file[1], rec_count);
#ifdef RWCOMPARE_VERBOSE
            printRecords(rec);
#endif
        }
    }

    return status;
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);                       /* never returns on error */

    return compareFiles(&argv[arg_index]);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
