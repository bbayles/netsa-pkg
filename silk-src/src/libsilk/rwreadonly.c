/*
** Copyright (C) 2010-2023 by Carnegie Mellon University.
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
**  rwreadonly.c
**
**    Read SiLK Flow records from files listed on the command line.
**    Use a file name of "-" to read records from the standard input.
**
**    This is a test program to that can be used for library timings.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwreadonly.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skstream.h>
#include <silk/utils.h>

#define PLURAL(s) (((s) == 1) ? "" : "s")


int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int64_t ticks = 0;
    rwRec rwrec;
    uint64_t rec_count = 0;
    skstream_t *stream;
    int exit_val = 0;
    int rv;
    unsigned int i;

    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    for (i = 1; i < (unsigned int)argc; ++i) {
        stream = NULL;
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(stream, argv[i]))
            || (rv = skStreamOpen(stream))
            || (rv = skStreamReadSilkHeader(stream, NULL)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            exit_val = 1;
            break;
        }
        ticks -= clock();
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            ++rec_count;
        }
        ticks += clock();
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            exit_val = 1;
            break;
        }
        skStreamDestroy(&stream);
    }

    fprintf(stderr, ("%s: Read %" PRIu64 " record%s from %d file%s"
                     " in %.4f seconds\n"),
            skAppName(), rec_count, PLURAL(rec_count),
            (i - 1), PLURAL(i - 1), (double)ticks / CLOCKS_PER_SEC);

    skAppUnregister();
    return exit_val;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
