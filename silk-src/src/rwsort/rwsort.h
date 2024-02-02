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
**  rwsort reads SiLK Flow Records from the standard input or from
**  named files and sorts them on one or more user-specified fields.
**
**  See rwsort.c for implementation details.
**
*/
#ifndef _RWSORT_H
#define _RWSORT_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWSORT_H, "$SiLK: rwsort.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skplugin.h>
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
 *    different value with the --sort-buffer-size switch.
 *
 *    Support of a buffer of almost 2GB.
 */
#define DEFAULT_SORT_BUFFER_SIZE    "1920m"

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
 *    Maximum number of fields that can come from plugins.  Allow four
 *    per plug-in.
 */
#define MAX_PLUGIN_KEY_FIELDS   32

/*
 *    Maximum bytes allotted to a "node", which is the complete rwRec
 *    and the bytes required by all keys that can come from plug-ins.
 *    Allow 8 bytes per field, plus enough space for an rwRec.
 */
#define MAX_NODE_SIZE ((size_t)(8 * MAX_PLUGIN_KEY_FIELDS + SK_MAX_RECORD_SIZE))

/*
 *    The maximum buffer size is the maximum size we can allocate.
 */
#define MAXIMUM_SORT_BUFFER_SIZE    ((size_t)(SIZE_MAX))

/*
 *    The minium buffer size.
 */
#define MINIMUM_SORT_BUFFER_SIZE ((size_t)(MAX_NODE_SIZE * MIN_IN_CORE_RECORDS))


/* for key fields that come from plug-ins, this struct will hold
 * information about a single field */
typedef struct key_field_st {
    /* The plugin field handle */
    skplugin_field_t *kf_field_handle;
    /* the byte-offset for this field */
    size_t            kf_offset;
    /* the byte-width of this field */
    size_t            kf_width;
} key_field_t;



/* VARIABLES */

/* number of fields to sort over; skStringMapParse() sets this */
extern uint32_t num_fields;

/* IDs of the fields to sort over; skStringMapParse() sets it; values
 * are from the rwrec_printable_fields_t enum and from values that
 * come from plug-ins. */
extern uint32_t *sort_fields;

/* the size of a "node".  Because the output from rwsort are SiLK
 * records, the node size includes the complete rwRec, plus any binary
 * fields that we get from plug-ins to use as the key.  This node_size
 * value may increase when we parse the --fields switch. */
extern size_t node_size;

/* the columns that make up the key that come from plug-ins */
extern key_field_t key_fields[MAX_PLUGIN_KEY_FIELDS];

/* the number of these key_fields */
extern size_t key_num_fields;

/* output stream */
extern skstream_t *out_stream;

/* temp file context */
extern sk_tempfilectx_t *tmpctx;

/* whether the user wants to reverse the sort order */
extern int reverse;

/* whether to treat the input files as already sorted */
extern int presorted_input;

/* maximum amount of RAM to attempt to allocate */
extern size_t sort_buffer_size;

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
#endif /* _RWSORT_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
