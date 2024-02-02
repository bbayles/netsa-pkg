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
**  rwdedupe.h
**
**    Common declarations needed by rwdedupe.  See rwdedupe.c for
**    implementation details.
*/
#ifndef _RWDEDUPE_H
#define _RWDEDUPE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWDEDUPE_H, "$SiLK: rwdedupe.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skstream.h>
#include <silk/sktempfile.h>
#include <silk/utils.h>

/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    The default buffer size to use, unless the user selects a
 *    different value with the --buffer-size switch.
 *
 *    Support of a buffer of almost 2GB.
 */
#define DEFAULT_BUFFER_SIZE     "1920m"

/*
 *    We do not allocate the buffer at once, but use realloc() to grow
 *    the buffer linearly to the maximum size.  The following is the
 *    number of steps to take to reach the maximum size.  The number
 *    of realloc() calls will be once less than this value.
 *
 *    If the initial allocation fails, the number of chunks is
 *    incremented---making the size of the initial malloc()
 *    smaller---and allocation is attempted again.
 */
#define NUM_CHUNKS  6

/*
 *    Do not allocate more than this number of bytes at a time.
 *
 *    If dividing the buffer size by NUM_CHUNKS gives a chunk size
 *    larger than this; determine the number of chunks by dividing the
 *    buffer size by this value.
 *
 *    Use a value of 1g
 */
#define MAX_CHUNK_SIZE      ((size_t)(0x40000000))

/*
 *    If we cannot allocate a buffer that will hold at least this many
 *    records, give up.
 */
#define MIN_IN_CORE_RECORDS     1000

/*
 *    Maximum number of files to attempt to merge-sort at once.
 */
#define MAX_MERGE_FILES         1024

/*
 *    Size of a node is constant: the size of a complete rwRec.
 */
#define NODE_SIZE               sizeof(rwRec)

/*
 *    The maximum buffer size is the maximum size we can allocate.
 */
#define MAXIMUM_BUFFER_SIZE     ((size_t)(SIZE_MAX))

/*
 *    The minium buffer size.
 */
#define MINIMUM_BUFFER_SIZE     (NODE_SIZE * MIN_IN_CORE_RECORDS)


/*
 *    Number of delta fields
 */
#define RWDEDUP_DELTA_FIELD_COUNT  4

typedef struct flow_delta_st {
    int64_t     d_stime;
    uint32_t    d_elapsed;
    uint32_t    d_packets;
    uint32_t    d_bytes;
} flow_delta_t;



/* VARIABLES */

/* number of fields to sort over */
extern uint32_t num_fields;

/* IDs of the fields to sort over; values are from the
 * rwrec_printable_fields_t enum. */
extern uint32_t sort_fields[RWREC_PRINTABLE_FIELD_COUNT];

/* output stream */
extern skstream_t *out_stream;

/* temp file context */
extern sk_tempfilectx_t *tmpctx;

/* maximum amount of RAM to attempt to allocate */
extern size_t buffer_size;

/* differences to allow between flows */
extern flow_delta_t delta;


/* FUNCTIONS */

void
appExit(
    int                 status)
    NORETURN;
void
appSetup(
    int                 argc,
    char              **argv);
int
appNextInput(
    skstream_t        **stream);


#ifdef __cplusplus
}
#endif
#endif /* _RWDEDUPE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
