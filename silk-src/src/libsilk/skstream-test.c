/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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
**  skstream-test.c
**
**    Test the binary capability of the skstream functions.
**
**  Mark Thomas
**  June 2007
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skstream-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sksite.h>
#include <silk/utils.h>
#include <silk/skstream.h>


int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    uint8_t buffer[1 << 15];
    skstream_t *s_in = NULL;
    skstream_t *s_out = NULL;
    int rv;
    ssize_t got;
    ssize_t put;
    off_t len;
    int i;

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <source> <dest>\n", skAppName());
        exit(EXIT_FAILURE);
    }

    if ((rv = (skStreamCreate(&s_in, SK_IO_READ, SK_CONTENT_OTHERBINARY)))
        || (rv = skStreamBind(s_in, argv[1]))
        || (rv = skStreamOpen(s_in)))
    {
        skStreamPrintLastErr(s_in, rv, &skAppPrintErr);
        goto END;
    }

    if ((rv = (skStreamCreate(&s_out, SK_IO_WRITE, SK_CONTENT_OTHERBINARY)))
        || (rv = skStreamBind(s_out, argv[2]))
        || (rv = skStreamOpen(s_out)))
    {
        skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
        goto END;
    }

    do {
        got = skStreamRead(s_in, buffer, sizeof(buffer));
        if (got > 0) {
            put = skStreamWrite(s_out, buffer, got);
            if (got != put) {
                if (put < 0) {
                    skStreamPrintLastErr(s_out, put, &skAppPrintErr);
                } else {
                    skAppPrintErr("Warning: read %ld bytes and wrote %ld bytes",
                                  (long)got, (long)put);
                }
            }
        }
    } while (got > 0);

    if (got < 0) {
        skStreamPrintLastErr(s_in, got, &skAppPrintErr);
    }

    if (skStreamIsSeekable(s_out)) {
        /* get the current position in the output, write the buffer to
         * the output a couple of times, then truncate the output to
         * the current position */
        if ((rv = skStreamFlush(s_out))
            || ((len = skStreamTell(s_out)) == (off_t)-1))
        {
            skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
            goto END;
        }

        memset(buffer, 0x55, sizeof(buffer));
        got = sizeof(buffer);

        for (i = 0; i < 2; ++i) {
            put = skStreamWrite(s_out, buffer, got);
            if (got != put) {
                skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
                skAppPrintErr("Warning: have %ld bytes and wrote %ld bytes",
                              (long)got, (long)put);
            }
        }

        rv = skStreamTruncate(s_out, len);
        if (rv) {
            skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
        }
    }

  END:
    rv = skStreamDestroy(&s_in);
    if (rv) {
        skStreamPrintLastErr(s_in, rv, &skAppPrintErr);
    }
    rv = skStreamClose(s_out);
    if (rv) {
        skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
    }
    rv = skStreamDestroy(&s_out);
    if (rv) {
        skStreamPrintLastErr(s_out, rv, &skAppPrintErr);
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
