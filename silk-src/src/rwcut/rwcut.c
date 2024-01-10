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
** rwcut.c
**
**      cut fields/records from the given input file(s) using field
**      specifications from here, record filter specifications from
**      module libfilter
**
** 1/15/2002
**
** Suresh L. Konda
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwcut.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwcut.h"


/* TYPEDEFS AND MACROS */

/* When --copy-input is active but the required 'num_recs' records
 * have been printed, skStreamSkipRecords() is used to read data from
 * all remaining input streams.  This specifies the record-count
 * parameter to pass to that function. */
#define CUT_SKIP_COUNT 65536

/* EXPORTED VARIABLES */

/* The object to convert the record to text; includes pointer to the
 * file handle where the records are written */
rwAsciiStream_t *ascii_str = NULL;

/* handle input streams */
sk_options_ctx_t *optctx = NULL;

/* number records to print */
uint64_t num_recs = 0;

/* number of records to skip before printing */
uint64_t skip_recs = 0;

/* number of records to "tail" */
uint64_t tail_recs = 0;

/* buffer used for storing 'tail_recs' records */
rwRec *tail_buf = NULL;

/* how to handle IPv6 flows */
sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;


/* LOCAL VARIABLES */

/* current position in the 'tail_buf' */
static rwRec *tail_buf_cur;

/* whether we read more than 'tail_recs' records. 1==yes */
static int tail_buf_full = 0;


/* FUNCTION DEFINITIONS */

/*
 *  status = tailFile(stream);
 *
 *    Read SiLK flow records from the file at 'stream' and store the
 *    most recent 'tail_recs' number of records in the 'tail_buf'
 *    buffer.
 *
 *    Return -1 on read error, or 0 otherwise.
 */
static int
tailFile(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;

    while ((rv = skStreamReadRecord(stream, tail_buf_cur)) == SKSTREAM_OK) {
        ++tail_buf_cur;
        if (tail_buf_cur == &tail_buf[tail_recs]) {
            tail_buf_cur = tail_buf;
            tail_buf_full = 1;
        }
    }
    if (SKSTREAM_ERR_EOF != rv) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        return -1;
    }

    return 0;
}


/*
 *  printTailBuffer();
 *
 *    Print the SiLK Flow records that are in the global 'tail_buf'
 *    buffer.
 */
static void
printTailBuffer(
    void)
{
    uint64_t avail_recs;

    /* determine number of records available to print; if 'tail_buf'
     * is not full, move 'tail_buf_cur' to the first record.  When the
     * buffer is full; 'tail_buf_cur' is already sitting on the first
     * record to print. */
    if (tail_buf_full) {
        avail_recs = tail_recs;
    } else {
        avail_recs = tail_buf_cur - tail_buf;
        tail_buf_cur = tail_buf;
    }

    /* determine number of records to print */
    if (0 == num_recs) {
        num_recs = avail_recs;
    } else if (avail_recs < num_recs) {
        num_recs = avail_recs;
    }

    rwAsciiPrintTitles(ascii_str);

    while (num_recs) {
        rwAsciiPrintRec(ascii_str, tail_buf_cur);
        --num_recs;
        ++tail_buf_cur;
        if (tail_buf_cur == &tail_buf[tail_recs]) {
            tail_buf_cur = tail_buf;
        }
    }
}


/*
 *  status = cutFile(stream);
 *
 *    Read SiLK flow records from the file at 'stream' and maybe print
 *    them according the values in 'skip_recs' and 'num_recs'.
 *
 *    Return -1 on error.  Return 1 if all requested records have been
 *    printed and processing should stop.  Return 0 if processing
 *    should continue.
 */
static int
cutFile(
    skstream_t         *stream)
{
    static int copy_input_only = 0;
    rwRec rwrec;
    int rv = SKSTREAM_OK;
    size_t num_skipped;
    int ret_val = 0;

    /* handle case where all requested records have been printed, but
     * we need to write all records to the --copy-input stream. */
    if (copy_input_only) {
        while ((rv = skStreamSkipRecords(stream, CUT_SKIP_COUNT, NULL))
               == SKSTREAM_OK)
            ;  /* empty */

        if (SKSTREAM_ERR_EOF != rv) {
            ret_val = -1;
        }
        goto END;
    }

    /* skip any leading records */
    if (skip_recs) {
        rv = skStreamSkipRecords(stream, skip_recs, &num_skipped);
        switch (rv) {
          case SKSTREAM_OK:
            skip_recs -= num_skipped;
            break;
          case SKSTREAM_ERR_EOF:
            skip_recs -= num_skipped;
            goto END;
          default:
            ret_val = -1;
            goto END;
        }
    }

    if (0 == num_recs) {
        /* print all records */
        while ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
            rwAsciiPrintRec(ascii_str, &rwrec);
        }
        if (SKSTREAM_ERR_EOF != rv) {
            ret_val = -1;
        }
    } else {
        while (num_recs
               && ((rv = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK))
        {
            rwAsciiPrintRec(ascii_str, &rwrec);
            --num_recs;
        }
        switch (rv) {
          case SKSTREAM_OK:
          case SKSTREAM_ERR_EOF:
            break;
          default:
            ret_val = -1;
            goto END;
        }
        if (0 == num_recs) {
            if (0 == skOptionsCtxCopyStreamIsActive(optctx)) {
                /* we're done */
                ret_val = 1;
            } else {
                /* send all remaining records to copy-input */
                copy_input_only = 1;
                while ((rv = skStreamSkipRecords(stream, CUT_SKIP_COUNT, NULL))
                       == SKSTREAM_OK)
                    ;  /* empty */
                if (SKSTREAM_ERR_EOF != rv) {
                    ret_val = -1;
                }
            }
        }
    }

  END:
    if (-1 == ret_val) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
    }
    return ret_val;
}


int main(int argc, char **argv)
{
    skstream_t *stream;
    int rv = 0;

    appSetup(argc, argv);                 /* never returns on error */

    if (tail_buf) {
        assert(tail_recs);
        tail_buf_cur = tail_buf;

        /* Process the files from command line or stdin */
        while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
               == 0)
        {
            skStreamSetIPv6Policy(stream, ipv6_policy);
            rv = tailFile(stream);
            skStreamDestroy(&stream);
            if (-1 == rv) {
                exit(EXIT_FAILURE);
            }
        }
        if (rv < 0) {
            exit(EXIT_FAILURE);
        }
        printTailBuffer();
    } else {
        /* Process the files on command line or records from stdin */

        /* get first file */
        rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr);
        if (rv < 0) {
            exit(EXIT_FAILURE);
        }

        /* print title line */
        rwAsciiPrintTitles(ascii_str);

        if (1 == rv) {
            /* xargs with no input; we are done */
            appTeardown();
            return 0;
        }

        do {
            skStreamSetIPv6Policy(stream, ipv6_policy);
            rv = cutFile(stream);
            skStreamDestroy(&stream);
            if (-1 == rv) {
                exit(EXIT_FAILURE);
            }
            if (1 == rv) {
                break;
            }
        } while ((rv =skOptionsCtxNextSilkFile(optctx, &stream,&skAppPrintErr))
                 == 0);
        if (rv < 0) {
            exit(EXIT_FAILURE);
        }
    }

    /* done */
    appTeardown();

    return 0;
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
