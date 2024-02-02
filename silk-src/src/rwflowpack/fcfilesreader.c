/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
**  fcfilesreader.c
**
**    Helper file for rwflowpack.
**
**    Specify the functions that are used to poll a directory for
**    files that were created by the flowcap daemon.
**
**    This input_mode_type is used by the 'fcfilesreader' input-mode.
**
**    Files created by flowcap contain a header that specifies the
**    probe name where the flows were collected.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: fcfilesreader.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skpolldir.h>
#include <silk/skstream.h>
#include "rwflowpack_priv.h"


/* MACROS AND TYPEDEFS */

/* A name for this input mode. */
#define INPUT_MODE_TYPE_NAME  "FlowCap Files Reader"


/* PRIVATE VARIABLES */

/* The directory flowcap files mode will poll for new flowcap
 * files to process */
static const char *incoming_directory = NULL;

/* Directory polling information */
static skPollDir_t     *polldir = NULL;
static uint32_t         polling_interval;


/* FUNCTION DEFINITIONS */

/*
 *    Helper function that opens the flowcap file at 'path'.  The
 *    handle to the file is put in the location specified by 'stream'.
 *    The name of the probe is read from the file's header, and the
 *    probe object is put into 'probe'.  Returns 0 on success, or -1
 *    on the following error conditions:
 *
 *    -- 'path' is NULL.
 *    -- unable to open file
 *    -- file is not a valid SiLK file
 *    -- file does not contain a Probename Header
 *    -- the probe_name does not map to a valid probe in probeconf
 *
 *    NOTES:
 *
 *    Flowcap V16 files have the probe name in the header.
 *
 *    Flowcap Files V2-V5 have the sensor name and probe name in the
 *    header.  When these are processed in SiLK 1.0, these get mapped
 *    to the probe name "<sensor>_<probe>".
 *
 *    Flowcap Files V1 have no probe information and are no longer
 *    supported.
 */
static int
flowcapSourceCreateFromFile(
    const char         *path,
    skstream_t        **stream,
    skpc_probe_t      **probe)
{
    sk_file_header_t *hdr;
    sk_header_entry_t *sp_hdr;
    const char *probe_name;
    int rv;

    /* Argument checking */
    if (path == NULL) {
        ERRMSG("NULL path passed to flowcapSourceCreateFromFile.");
        return -1;
    }

    /* Valid file checking */
    rv = skStreamOpenSilkFlow(stream, path, SK_IO_READ);
    if (rv) {
        CRITMSG("Unable to open '%s' for reading.", path);
        skStreamPrintLastErr(*stream, rv, &ERRMSG);
        goto error;
    }

    /*
     * File should have a Probename header
     *
     * Flowcap V16 files have the probe name in the header.
     *
     * Flowcap Files V2-V5 have a separate sensor name and probe name
     * in the header.  In SiLK 1.0, these get mapped to the single
     * probe name "<sensor>_<probe>".
     *
     * Flowcap Files V1 have no probe information and are not
     * supported.
     */
    hdr = skStreamGetSilkHeader(*stream);
    sp_hdr = skHeaderGetFirstMatch(hdr, SK_HENTRY_PROBENAME_ID);
    if (sp_hdr == NULL) {
        CRITMSG("No probename header in %s.", path);
        goto error;
    }

    probe_name = skHentryProbenameGetProbeName(sp_hdr);
    if (probe_name == NULL || probe_name[0] == '\0') {
        CRITMSG("Unable to get probename from flowcap file '%s'.",
                path);
        goto error;
    }

    /* Use the probe_name to find the skpc_probe_t object. */
    *probe = (skpc_probe_t*)skpcProbeLookupByName(probe_name);
    if (*probe == NULL) {
        CRITMSG("The sensor configuration file does not define probe '%s'",
                probe_name);
        goto error;
    }

    /* Verify that the probe has sensors associated with it */
    if (skpcProbeGetSensorCount(*probe) == 0) {
        CRITMSG("Probe '%s' is not associated with a sensor", probe_name);
        goto error;
    }

    /* File has been validated.  We're done. */
    return 0;

  error:
    skStreamDestroy(stream);
    return -1;
}


/*
 *  readerGetNextValidFile(&fc_src);
 *
 *    Pull the next file name off of the valid-queue and create a
 *    flowsource object to read the flowcap records in it.  Fills
 *    'fproc' with the new flowcap-source object and probe.
 *
 *    Return 0 on success.  Return -1 if getting the file name fails.
 *    If unable to open the file or file not of correct form, return
 *    -2 unless the --error-dir is set, in which case move the file
 *    there and try the next file.
 */
static int
readerGetNextValidFile(
    flow_proc_t        *fproc)
{
    skstream_t *fcfile = NULL;
    skpc_probe_t *probe = NULL;
    skPollDirErr_t pderr;
    char *filename;
    char path[PATH_MAX];
    int rv;

    do {
        /* Get next file from the directory poller */
        pderr = skPollDirGetNextFile(polldir, path, &filename);
        if (pderr != PDERR_NONE) {
            if (pderr == PDERR_STOPPED) {
                return -1;
            }
            CRITMSG("Fatal polldir error ocurred: %s",
                    ((pderr == PDERR_SYSTEM)
                     ? strerror(errno)
                     : skPollDirStrError(pderr)));
            skAbort();
        }

        INFOMSG((INPUT_MODE_TYPE_NAME " processing %s"), filename);

        /* open the file to create a source of records */
        rv = flowcapSourceCreateFromFile(path, &fcfile, &probe);
        if (rv) {
            rv = errorDirectoryInsertFile(path);
            if (rv != 0) {
                /* either no --error-dir (rv == 1) or problem moving
                 * the file (rv == -1).  either way, return an error
                 * code to the caller. */
                return -2;
            }
        }
    } while (fcfile == NULL);

    fproc->flow_src = fcfile;
    fproc->probe = probe;

    return 0;
}


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
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    skstream_t *fcfile;
    const char *filename;
    fp_get_record_result_t retVal = FP_GET_ERROR;
    int rv;

    pthread_mutex_lock(&mutex);

    /* If we don't have a source, get a file from the directory poller
     * and start processing it. */
    if (fproc->flow_src == NULL) {
        switch (readerGetNextValidFile(fproc)) {
          case 0:
            /* Success */
            break;
          case -1:
            /* Error getting file name (maybe in shutdown?) */
            goto END;
          case -2:  /* Error opening file */
          default:  /* Unexpected value */
            retVal = FP_FATAL_ERROR;
            goto END;
        }
    }
    fcfile = (skstream_t*)fproc->flow_src;

    /* Assume we can get a record from the probe. */
    retVal = FP_RECORD;
    *out_probe = fproc->probe;

    /* Try to get a record */
    rv = skStreamReadRecord(fcfile, out_rwrec);
    if (rv) {
        /* get failed: either at EOF or got an error. */
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(fcfile, rv, &WARNINGMSG);
        }

        retVal = FP_FILE_BREAK;
        *out_probe = NULL;

        /* Print results for the file we just processed. */
        filename = skStreamGetPathname(fcfile);
        INFOMSG("Processed file %s, %" PRIu64 " records.",
                filename, skStreamGetRecordCount(fcfile));

        skStreamClose(fcfile);

        /* Either archive the file or remove it */
        archiveDirectoryInsertOrRemove(filename, NULL);

        /* All done with the flow source */
        skStreamDestroy(&fcfile);
        fproc->flow_src = NULL;
        fproc->probe = NULL;
    }

  END:
    pthread_mutex_unlock(&mutex);

    return retVal;
}


/*
 *  status = readerStart(flow_processor);
 *
 *    Invoked by input_mode_type->start_fn();
 */
static int
readerStart(
    flow_proc_t UNUSED(*fproc))
{
    /* Create the polldir object for directory polling */
    INFOMSG(("Creating " INPUT_MODE_TYPE_NAME " directory poller for '%s'"),
            incoming_directory);

    polldir = skPollDirCreate(incoming_directory, polling_interval);
    if (NULL == polldir) {
        CRITMSG("Could not initiate polling for %s", incoming_directory);
        return 1;
    }

    return 0;
}


/*
 *  readerStop(flow_processor);
 *
 *    Invoked by input_mode_type->stop_fn();
 */
static void
readerStop(
    flow_proc_t UNUSED(*fproc))
{
    if (polldir) {
        DEBUGMSG("Stopping " INPUT_MODE_TYPE_NAME " directory poller");
        skPollDirStop(polldir);
    }
}


/*
 *  status = readerSetup(&out_daemon_mode, probe_vector, options);
 *
 *    Invoked by input_mode_type->setup_fn();
 */
static int
readerSetup(
    fp_daemon_mode_t           *is_daemon,
    const sk_vector_t   UNUSED(*probe_vec),
    reader_options_t           *options)
{
    /* pull values out of options */
    incoming_directory   = options->fcfiles.incoming_directory;
    polling_interval     = options->fcfiles.polling_interval;

    *is_daemon = FP_DAEMON_ON;

    return 0;
}


/*
 *  readerCleanup();
 *
 *    Invoked by input_mode_type->cleanup_fn();
 */
static void
readerCleanup(
    void)
{
    /* End the file thread. */
    if (polldir) {
        DEBUGMSG("Destroying " INPUT_MODE_TYPE_NAME " directory poller");
        skPollDirDestroy(polldir);
        polldir = NULL;
    }
}


/*
 *  status = fcFilesReaderInitialize(input_mode_type);
 *
 *    Fill in the name and the function pointers for the input_mode_type.
 */
int
fcFilesReaderInitialize(
    input_mode_type_t  *input_mode_type)
{
    /* Set my name */
    input_mode_type->reader_name = INPUT_MODE_TYPE_NAME;

    /* Set function pointers */
    input_mode_type->cleanup_fn    = &readerCleanup;
    input_mode_type->get_record_fn = &readerGetRecord;
    input_mode_type->setup_fn      = &readerSetup;
    input_mode_type->start_fn      = &readerStart;
    input_mode_type->stop_fn       = &readerStop;

    return 0;                     /* OK */
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
