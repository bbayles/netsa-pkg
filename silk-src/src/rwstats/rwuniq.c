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
**  rwuniq.c
**
**  Implementation of the rwuniq application.
**
**  rwuniq reads SiLK flow records---from files listed on the command
**  line or from the standard input when no filenames are given---and
**  bins those flows by a key composed of user-selected fields of an
**  rwRec, or by fields generated from a plug-in.  For each bin, a
**  user-selected combination of bytes, packets, flows, earliest
**  start-time, latest end-time, distinct sIPs, and/or distinct dIPs
**  may be computed.
**
**  Once the input is read, the keys fields and computed values are
**  printed for each bin that meets the user-specified minimum and
**  maximum.
**
**  Normally, rwuniq uses the hashlib hash table to store the
**  key-volume pairs for each bin.  If this hash table runs out of
**  memory, the contents of the table are sorted and then saved to
**  disk in a temporary file.  More records are then read into a fresh
**  hash table.  The process repeats until all records are read or the
**  maximum number of temp files is reached.  The on-disk files are
**  then merged to produce the final output.
**
**  When the --presorted-input switch is given, rwuniq assumes rwsort
**  has been used to sort the data with the same --fields value that
**  rwuniq is using.  In this case, the hash table is not used.
**  Instead, rwuniq just watches for the key to change, and prints the
**  key-volume when it does.
**
**  For the --presorted-input case or when more than one distinct IP
**  count is requested for the unsorted case, an IPSet is used to keep
**  track of the IPs we have seen.  Since IPSets do not yet support
**  IPv6, this limits rwuniq's ability when IPv6 is active.  Also,
**  these IPSets can exhaust the ram, which would lead to an incorrect
**  count of IPs.  Could consider using a hashlib instead of an IPSet
**  for the values to get around the IPv6 issue.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwuniq.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwstats.h"


/* EXPORTED VARIABLES */

/* is this rwstats or rwuniq? */
const statsuniq_program_t this_program = STATSUNIQ_PROGRAM_UNIQ;


/* FUNCTION DEFINITIONS */

/* dummy functions needed for linking with rwstatssetup.c */
int
protoStatsOptionsRegister(
    void)
{
    skAbort();
    return 0;                   /* NOTREACHED */
}
void
protoStatsOptionsUsage(
    FILE               *fh)
{
    SK_UNUSED_PARAM(fh);
    skAbort();
}
int
legacyOptionsSetup(
    clientData          cData)
{
    SK_UNUSED_PARAM(cData);
    skAbort();
    return 0;                   /* NOTREACHED */
}
void
legacyOptionsUsage(
    FILE               *fh)
{
    SK_UNUSED_PARAM(fh);
    skAbort();
}


/*
 *  writeColTitles();
 *
 *    Enable the pager, and print the column titles to the global
 *    'output.fp'.
 */
static void
writeColTitles(
    void)
{
    setOutputHandle();
    rwAsciiPrintTitles(ascii_str);
}


/*
 *  uniqRandom();
 *
 *    Main control function that creates a hash table, processes the
 *    input (files or stdin), and prints the results.
 */
static void
uniqRandom(
    void)
{
    sk_unique_iterator_t *iter;
    uint8_t *outbuf[3];
    skstream_t *stream;
    rwRec rwrec;
    int rv = 0;

    while (0 == (rv = appNextInput(&stream))) {
        while (SKSTREAM_OK == (rv = readRecord(stream, &rwrec))) {
            if (0 != skUniqueAddRecord(uniq, &rwrec)) {
                appExit(EXIT_FAILURE);
            }
        }
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            return;
        }
        skStreamDestroy(&stream);
    }
    if (rv == -1) {
        /* error reading file */
        appExit(EXIT_FAILURE);
    }

    /* Write out the headings */
    writeColTitles();

    skUniquePrepareForOutput(uniq);

    /* create the iterator */
    rv = skUniqueIteratorCreate(uniq, &iter);
    if (rv) {
        skAppPrintErr("Unable to create iterator; err = %d", rv);
        appExit(EXIT_FAILURE);
    }

    if (app_flags.check_limits) {
        while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
               == SK_ITERATOR_OK)
        {
            checkLimitsWriteRecord(outbuf);
        }
    } else {
        while (skUniqueIteratorNext(iter, &outbuf[0], &outbuf[2], &outbuf[1])
               == SK_ITERATOR_OK)
        {
            writeAsciiRecord(outbuf);
        }
    }

    skUniqueIteratorDestroy(&iter);

    return;
}


static int
presortedCheckLimitsCallback(
    const uint8_t          *key,
    const uint8_t          *distinct,
    const uint8_t          *value,
    void            UNUSED(*callback_data))
{
    uint8_t *outbuf[3];

    outbuf[0] = (uint8_t*)key;
    outbuf[1] = (uint8_t*)value;
    outbuf[2] = (uint8_t*)distinct;

    checkLimitsWriteRecord(outbuf);
    return 0;
}

static int
presortedEntryCallback(
    const uint8_t          *key,
    const uint8_t          *distinct,
    const uint8_t          *value,
    void            UNUSED(*callback_data))
{
    uint8_t *outbuf[3];

    outbuf[0] = (uint8_t*)key;
    outbuf[1] = (uint8_t*)value;
    outbuf[2] = (uint8_t*)distinct;

    writeAsciiRecord(outbuf);
    return 0;
}


/*
 *  uniqPresorted();
 *
 *    Main control function that reads presorted flow records from
 *    files or stdin and prints the results.
 */
static void
uniqPresorted(
    void)
{
    /* Write the headings */
    writeColTitles();

    if (app_flags.check_limits) {
        if (skPresortedUniqueProcess(
                ps_uniq, presortedCheckLimitsCallback, NULL))
        {
            skAppPrintErr("Unique processing failed");
        }
    } else {
        if (skPresortedUniqueProcess(ps_uniq, presortedEntryCallback, NULL)) {
            skAppPrintErr("Unique processing failed");
        }
    }
}


int main(int argc, char **argv)
{
    /* Global setup */
    appSetup(argc, argv);

    if (app_flags.presorted_input) {
        uniqPresorted();
    } else {
        uniqRandom();
    }

    /* Done, do cleanup */
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
