/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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
**  pdufilereader.c
**
**    Helper file for rwflowpack.
**
**    Specify the functions that are used to read PDU (NetFlow v5)
**    records from a single file where the name of the file is
**    provided as a command line argument.
**
**    This input_mode_type should only be used for the 'pdufile'
**    input-mode.
**
**    The file's length must be an integer multiple of 1464 bytes,
**    where each 1464-byte block contains the 24-byte NetFlow v5
**    header and space for thirty 48-byte flow records.  For a block
**    holding fewer than 30 NetFlow records, the block should be
**    padded to 1464 bytes.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: pdufilereader.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwflowpack_priv.h"


/* LOCAL MACROS AND TYPEDEFS */

#define INPUT_MODE_TYPE_NAME "PDU File Reader"


/* FUNCTION DECLARATIONS */

static void readerPrintStats(flow_proc_t *fproc);


/* FUNCTION DEFINITIONS */

/*
 *  status = readerGetRecord(&out_rwrec, &out_probe, flow_processor);
 *
 *    Invoked by input_mode_type->get_record_fn();
 */
static fp_get_record_result_t
readerGetRecord(
    rwRec                  *out_rwrec,
    const skpc_probe_t    **out_probe,
    flow_proc_t            *fproc)
{
    skPDUSource_t *pdu_src = (skPDUSource_t*)fproc->flow_src;
    const char *filename;

    if (0 == skPDUSourceGetGeneric(pdu_src, out_rwrec)) {
        /* got a record */
        *out_probe = fproc->probe;

        /* When reading from a file, should only stop at the end of a
         * file. */
        return FP_RECORD;
    }

    /* At end of file */

    /* print stats for file */
    readerPrintStats(fproc);

    /* archive file if requested */
    filename = skpcProbeGetFileSource(fproc->probe);
    archiveDirectoryInsertOrRemove(filename, NULL);

    /* We can stop here. */
    return FP_END_STREAM;
}


/*
 *  status = readerStart(flow_processor)
 *
 *    Invoked by input_mode_type->start_fn();
 */
static int
readerStart(
    flow_proc_t        *fproc)
{
    const char *filename = skpcProbeGetFileSource(fproc->probe);
    skPDUSource_t *pdu_src;
    skFlowSourceParams_t params;

    /* if a pdu_src already exists, just return. */
    if (fproc->flow_src != NULL) {
        return 0;
    }

    if (filename == NULL) {
        ERRMSG("Probe %s not configured for reading from file",
               skpcProbeGetName(fproc->probe));
        return -1;
    }

    params.path_name = filename;
    pdu_src = skPDUSourceCreate(fproc->probe, &params);
    if (pdu_src == NULL) {
        ERRMSG("'%s': Could not create PDU source from file '%s'",
               skpcProbeGetName(fproc->probe), filename);
        errorDirectoryInsertFile(filename);
        return -1;
    }

    /* zero counts */
    fproc->rec_count_total = 0;
    fproc->rec_count_bad = 0;

    fproc->flow_src = pdu_src;
    return 0;
}


/*
 *  readerStop(flow_processor);
 *
 *    Invoked by input_mode_type->stop_fn();
 */
static void
readerStop(
    flow_proc_t        *fproc)
{
    if (fproc->flow_src) {
        skPDUSourceStop((skPDUSource_t*)fproc->flow_src);
    }
}


/*
 *  readerFree(flow_processor);
 *
 *    Invoked by input_mode_type->free_fn();
 */
static void
readerFree(
    flow_proc_t        *fproc)
{
    if (fproc->flow_src) {
        skPDUSourceDestroy((skPDUSource_t*)fproc->flow_src);
        fproc->flow_src = NULL;
    }
}


/*
 *  readerPrintStats(flow_processor);
 *
 *    Invoked by input_mode_type->print_stats_fn();
 */
static void
readerPrintStats(
    flow_proc_t        *fproc)
{
    skPDUSource_t *pdu_src = (skPDUSource_t*)fproc->flow_src;

    if (pdu_src) {
        skPDUSourceLogStatsAndClear(pdu_src);
    }
    if (fproc->rec_count_bad) {
        INFOMSG(("'%s': Records categorized %" PRIu64 ", dropped %" PRIu64),
                skpcProbeGetFileSource(fproc->probe),
                (fproc->rec_count_total - fproc->rec_count_bad),
                fproc->rec_count_bad);
    }
}


/*
 *  status = readerSetup(&out_daemon_mode, probe_vector, options);
 *
 *    Invoked by input_mode_type->setup_fn();
 */
static int
readerSetup(
    fp_daemon_mode_t   *is_daemon,
    const sk_vector_t  *probe_vec,
    reader_options_t   *options)
{
    size_t count = skVectorGetCount(probe_vec);
    const char *netflow_file = options->pdu_file.netflow_file;
    skpc_probe_t *p;

    /* this function should only be called if we actually have probes
     * to process */
    if (count == 0) {
        skAppPrintErr("readerSetup() called with zero length probe vector");
        return 1;
    }

    if (count > 1) {
        skAppPrintErr("The " INPUT_MODE_TYPE_NAME
                      "only supports one file-based probe.");
        return -1;
    }

    if (NULL != netflow_file) {
        /* Modify the probe to have the file name given on the command
         * line. */
        if (0 == skVectorGetValue(&p, probe_vec, 0)) {
            if (skpcProbeSetFileSource(p, netflow_file)) {
                skAppPrintErr("Cannot change file source of probe");
                return 1;
            }
        }
    }

    /* Not a deamon */
    *is_daemon = FP_DAEMON_OFF;

    return 0;
}


/*
 *  yes_or_no = readerWantProbe(probe);
 *
 *    Invoked by input_mode_type->want_probe_fn();
 */
static int
readerWantProbe(
    skpc_probe_t       *probe)
{
    /* This is what we expect, a NetFlow v5 based file reader */
    if ((NULL != skpcProbeGetFileSource(probe))
        && (PROBE_ENUM_NETFLOW_V5 == skpcProbeGetType(probe)))
    {
        return 1;
    }

    return 0;
}


/*
 *  status = pduFileReaderInitialize(input_mode_type);
 *
 *    Fill in the name and the function pointers for the input_mode_type.
 */
int
pduFileReaderInitialize(
    input_mode_type_t  *input_mode_type)
{
    /* Set my name */
    input_mode_type->reader_name = INPUT_MODE_TYPE_NAME;

    /* Set function pointers */
    input_mode_type->free_fn       = &readerFree;
    input_mode_type->get_record_fn = &readerGetRecord;
    input_mode_type->setup_fn      = &readerSetup;
    input_mode_type->start_fn      = &readerStart;
    input_mode_type->stop_fn       = &readerStop;
    input_mode_type->want_probe_fn = &readerWantProbe;

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
