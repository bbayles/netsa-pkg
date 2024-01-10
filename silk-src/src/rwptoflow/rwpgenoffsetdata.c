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
** Take a tcpdump capture file as input, and output the same file, but
** with timestamps skewed by 0-4 milliseconds.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwpgenoffsetdata.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwppacketheaders.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

static pcap_t *g_pkt_input = NULL;
static pcap_t *g_output;
static pcap_dumper_t *g_output_dumper = NULL;


/* OPTION SETUP */

typedef enum {
    OPT_HELP /* remove this when real options added */
} appOptionsEnum;


static struct option appOptions[] = {
    {0, 0, 0, 0}         /* sentinel entry */
};


static const char *appHelp[] = {
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData  cData, int opt_index, char *opt_arg);


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
#define USAGE_MSG                                                            \
    ("<TCPDUMP_FILE>\n"                                                      \
     "\tOpens TCPDUMP_FILE, offsets the times in the packets, and writes\n"  \
     "\tthe resulting packets in TCPDUMP format to the standard output,\n"   \
     "\twhich must not be connected to a terminal.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* Close all files */
    if (g_pkt_input) {
        pcap_close(g_pkt_input);
    }
    if (g_output_dumper) {
        pcap_dump_close(g_output_dumper);
    }
    if (g_output) {
        pcap_close(g_output);
    }

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
    char errbuf[PCAP_ERRBUF_SIZE];
    int arg_index;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char*)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
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
        skAppUsage(); /* never returns */
    }

    /* verify input file */
    if (arg_index >= argc) {
        skAppPrintErr("No input packet file found");
        skAppUsage();             /* never returns */
    }

    /* verify output is not a terminal */
    if (FILEIsATty(stdout)) {
        skAppPrintErr("stdout is connected to a terminal");
        skAppUsage();             /* never returns */
    }

    /* open input file */
    g_pkt_input = pcap_open_offline(argv[arg_index], errbuf);
    if (g_pkt_input == NULL) {
        skAppPrintErr("Unable to open input file %s: %s",
                      argv[arg_index], errbuf);
        exit(EXIT_FAILURE);
    }

    /* open output file (tcpdump format packet file) */
    g_output = pcap_open_dead(pcap_datalink(g_pkt_input),
                              pcap_snapshot(g_pkt_input));
    if (g_output == NULL) {
        skAppPrintErr("Error opening stdout: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    g_output_dumper = pcap_dump_open(g_output, "-");
    if (g_output_dumper == NULL) {
        skAppPrintErr("Error opening stdout: %s", pcap_geterr(g_output));
        exit(EXIT_FAILURE);
    }

    return; /* OK */
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
      case OPT_HELP: /* remove this when options are added */
        assert(0);
        skAbort();
        break;
    }

    return 0; /* OK */
}



int main(int argc, char **argv)
{
    int offset = 0;
    struct pcap_pkthdr next_pkt_hdr;
    const u_char *next_pkt_data = NULL;

    appSetup(argc, argv);

    while ((next_pkt_data = pcap_next(g_pkt_input, &next_pkt_hdr)) != NULL) {
        next_pkt_hdr.ts.tv_usec += offset % 5000;
        pcap_dump((u_char *) g_output_dumper, &next_pkt_hdr,
                  next_pkt_data);
        offset += 1000;
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
