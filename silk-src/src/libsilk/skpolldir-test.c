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
**  Simple tester for the skpolldir library
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skpolldir-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skpolldir.h>
#include <silk/sklog.h>
#include <silk/utils.h>


static skPollDir_t *pd = NULL;


/*
 *  appHandleSignal(signal_value)
 *
 *    Stop polling the directory
 */
static void
appHandleSignal(
    int          UNUSED(sig))
{
    if (pd) {
        skPollDirStop(pd);
    }
}


/*
 *    Prefix any error messages from skpolldir with the program name
 *    and an abbreviated time instead of the standard logging tag.
 */
static size_t
logprefix(
    char               *buffer,
    size_t              bufsize)
{
    time_t t;
    struct tm ts;

    t = time(NULL);
    localtime_r(&t, &ts);

    return (size_t)snprintf(buffer, bufsize, "%s: %2d:%02d:%02d: ",
                            skAppName(), ts.tm_hour, ts.tm_min, ts.tm_sec);
}


int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    const char *dirname;
    uint32_t interval = 5;
    char path[PATH_MAX];
    char *file;
    int logmask;

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    /* make certain there are enough args.  If first arg begins with
     * hyphen, print usage. */
    if (argc < 2 || argc > 3 || argv[1][0] == '-') {
        fprintf(stderr, "Usage: %s <dirname> [<poll-interval>]\n",
                skAppName());
        return EXIT_FAILURE;
    }

    /* get directory to poll */
    dirname = argv[1];
    if (!skDirExists(dirname)) {
        skAppPrintErr("Polling dir '%s' does not exist", dirname);
        return EXIT_FAILURE;
    }

    /* get interval if given */
    if (argc == 3) {
        int rv = skStringParseUint32(&interval, argv[2], 1, 0);
        if (rv != 0) {
            skAppPrintErr("Invalid interval '%s': %s",
                          argv[2], skStringParseStrerror(rv));
            return EXIT_FAILURE;
        }
    }

    /* set signal handler to clean up temp files on SIGINT, SIGTERM, etc */
    if (skAppSetSignalHandler(&appHandleSignal)) {
        exit(EXIT_FAILURE);
    }

    /* Must enable the logger */
    sklogSetup(0);
    sklogSetDestination("stderr");
    sklogSetStampFunction(&logprefix);
    /* set level to "warning" to avoid the "Started logging" message */
    logmask = sklogGetMask();
    sklogSetLevel("warning");
    sklogOpen();
    sklogSetMask(logmask);

    pd = skPollDirCreate(dirname, interval);
    if (pd == NULL) {
        skAppPrintErr("Failed to set up polling for directory %s", dirname);
        return EXIT_FAILURE;
    }

    printf("%s: Polling '%s' every %" PRIu32 " seconds\n",
           skAppName(), dirname, interval);
    while (PDERR_NONE == skPollDirGetNextFile(pd, path, &file)) {
        printf("%s\n", file);
    }

    skPollDirDestroy(pd);
    pd = NULL;

    /* set level to "warning" to avoid the "Stopped logging" message */
    sklogSetLevel("warning");
    sklogTeardown();
    skAppUnregister();

    return EXIT_SUCCESS;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
