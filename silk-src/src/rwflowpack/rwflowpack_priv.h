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
#ifndef _RWFLOWPACK_PRIV_H
#define _RWFLOWPACK_PRIV_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWFLOWPACK_PRIV_H, "$SiLK: rwflowpack_priv.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  rwflowpack_priv.h
**
**    Private definitions and prototypes for rwflowpack.
*/

#include <silk/libflowsource.h>
#include <silk/probeconf.h>
#include <silk/rwflowpack.h>
#include <silk/rwrec.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include "rwflow_utils.h"


/*
 *    These values indicate whether the flow reader operates as a
 *    daemon.  When acting as a daemon, rwflowpack will fork().
 */
typedef enum {
    FP_DAEMON_OFF, FP_DAEMON_ON
} fp_daemon_mode_t;


/*
 *    These values give information back to the caller of the
 *    get_record_fn as to whether the function worked, and whether it
 *    is safe to stop pulling data.
 */
typedef enum {
    FP_FATAL_ERROR = -2,    /* A critical error occured */
    FP_GET_ERROR = -1,      /* An error occured */
    FP_BREAK_POINT = 0,     /* You may stop before processing the record */
    FP_FILE_BREAK,          /* You may stop before processing the record */
    FP_RECORD,              /* You may NOT stop after processing record */
    FP_END_STREAM           /* You must stop.  There is no record. */
} fp_get_record_result_t;


/*
 *    A structure to pass options between the rwflowpack and the
 *    input_mode_types.  Defined below.
 */
typedef union reader_options_un reader_options_t;


/*
 *    rwflowpack uses the input_mode_type_t structure to communicate
 *    with the individual files that support each
 *    input_mode_type---for a definition of the input_mode_type, see
 *    rwflowpack.c.  These files are named "*reader.c".
 *
 *    rwflowpack has an array of initialization functions.  rwflowpack
 *    invokes each initialization function with a input_mode_type_t
 *    object; the initialization function should set the name and
 *    function pointers for that input_mode_type.
 *
 *    The input_mode_type_t structure is defined below.
 */
typedef struct input_mode_type_st input_mode_type_t;

/*
 *    The flow_proc_t is a structure for an individual flow processor,
 *    which can be thought of as an instance of the input_mode_type_t.
 *    It is defined below.
 */
typedef struct flow_proc_st flow_proc_t;


struct input_mode_type_st {
    /* The name of this input_mode_type, for printing in --help output
     * and log messages. */
    const char *reader_name;

    /* The list of probes assigned to this input_mode_type.  A probe
     * is assigned to the input_mode_type when the input_mode_type's
     * want_probe_fn() returns a TRUE value for a probe. */
    sk_vector_t *probes;

    /* When rwflowpack is running in 'stream' input-mode and
     * collecting flow records, this function will be called for every
     * probe defined in the sensor.conf file.  This function should
     * return 1 if this input_mode_type knows how to process the
     * probe, or 0 otherwise.  rwflowpack will indicate an error when
     * more than one input_mode_type wants to process a probe.
     *
     * For input_mode_types that rwflowpack handles specially, this
     * function pointer may be NULL, in which case no probes are
     * assigned to input_mode_type.
     */
    int       (*want_probe_fn)(skpc_probe_t *probe);

    /* Once all the probes have been assigned to exactly one
     * input_mode_type, the setup_fn() function is called for any
     * input_mode_type that said it wanted to process a probe---via
     * the call to its want_probe_fn().  The list of probes is given
     * to the input_mode_type in the ''probe_vec' vector.
     *
     * The options specific to the particular input-mode are passed to
     * the input_mode_type in 'options'.  The input_mode_type should
     * validate, process, or store any command line options that
     * partain to it.
     *
     * The 'setup_fn' should set the 'is_daemon' variable depending on
     * whether the main processing loop in rwflowpack should
     * daemon-ize itself.
     *
     * This function is the last time the input_mode_type has to do
     * any processing or setup prior to rwflowpack daemonizing
     * itself,spawning threads, and starting to process records.
     *
     * The function should return 0 on successful set-up, or non-zero
     * if there was an error.
     */
    int       (*setup_fn)(fp_daemon_mode_t     *is_daemon,
                          const sk_vector_t    *probe_vec,
                          reader_options_t     *options);

    /* The start_fn() is the function rwflowpack calls to tell each
     * active input_mode_type to start processing records.  Each
     * invocation of the start_fn() will occur in a separate thread.
     * For input_mode_types that operate in stream input-mode, the
     * start_fn() will be called multiple times, once for each
     * probe--the probe is available from the 'fproc' structure.  For
     * other input_mode_types, the start_fn() is called once.  The
     * function should returns 0 on success, or non-zero on
     * failure. */
    int       (*start_fn)(flow_proc_t *fproc);

    /* Once all flow processors have been created, rwflowpack will
     * call get_record_fn() in each active thread.  This function
     * should block until a record is ready, or until
     * input_mode_type's stop_fn() is called.  The get_record_fn()
     * function should set 'out_rec' to the SiLK Flow record collected
     * from the source, and set 'out_probe' to the probe where the
     * record was collected.
     *
     * The get_record_fn() return value indicates what actions are
     * safe after retrieving the value; specifically, whether it is
     * safe for rwflowpack to shutdown, if it has been signaled to do
     * so.  (See the definition for fp_get_record_result_t above) */
    fp_get_record_result_t (*get_record_fn)(rwRec               *out_rec,
                                            const skpc_probe_t **out_probe,
                                            flow_proc_t         *fproc);

    /* rwflowpack will periodically call print_stats_fn(); the
     * function should log information about the number of records
     * processed by the flow processor. */
    void      (*print_stats_fn)(flow_proc_t *fproc);

    /* When rwflowpack has been signaled to terminate, it will call
     * the stop_fn() to stop the flow processor.  This function must
     * also unblock a any call to get_record_fn(). */
    void      (*stop_fn)(flow_proc_t *fproc);

    /* Once all flow processors have stopped collecting and their
     * threads have terminated, rwflowpack calls the free_fn() to have
     * the input_mode_type destroy the flow processor.  This function
     * pointer may be NULL. */
    void      (*free_fn)(flow_proc_t *fproc);

    /* rwflowpack calls the cleanup_fn() once for each
     * input_mode_type.  This function can perform any final cleanup.
     * This is the final function called for each input mode type.
     * This function pointer may be NULL. */
    void      (*cleanup_fn)(void);
};


struct flow_proc_st {
    /* Total number of records processed */
    uint64_t            rec_count_total;

    /* Number of bad records processed */
    uint64_t            rec_count_bad;

    /* The class of this processor */
    input_mode_type_t      *input_mode_type;

    /* The probe and flow_src are where the processor gets its data.
     * The flow_src is created based on settings in the probe. */
    const skpc_probe_t *probe;
    void               *flow_src;

    /* A flow processor is associated with a single thread. */
    pthread_t           thread;
};


/*
 *    The reader_options_t union is used to pass options between the
 *    rwflowpack and the functions for each input_mode_type.  Which
 *    part of the union is valid depends on --input-mode.
 *
 */
union reader_options_un {
    /* for --input-mode=pdufile */
    struct pdu_file_st {
        const char *netflow_file;
    } pdu_file;
#if 0
    struct silk_file_st {
        const char *pathname;
    } silk_file;
#endif

    /* for --input-mode=fcfiles */
    struct fcfiles_st {
        /* The directory flowcap files mode will poll for new flowcap
         * files to process */
        const char *incoming_directory;

        /* Polling interval (in seconds) for the incoming directory */
        uint32_t polling_interval;
    } fcfiles;

    /* for --input-mode=respool */
    struct respool_st {
        /* The directory respool mode will poll for new silk files to
         * process */
        const char *incoming_directory;

        /* Polling interval (in seconds) for the incoming directory */
        uint32_t polling_interval;
    } respool;

    /* for --input-mode=stream */
    struct stream_polldir_st {
        /* Polling interval (in seconds) for PDU/SiLK files. */
        uint32_t polling_interval;
    } stream_polldir;
};


/*
 *    Functions in rwflowpack.c to limit the number of incoming files
 *    the directory polling threads can have open.
 */
int
flowpackAcquireFileHandle(
    void);
void
flowpackReleaseFileHandle(
    void);


/*
 *    The initialization functions for each input_mode_type_t.  These
 *    are defined in the *readers.c files.  These could be specified
 *    in a header file for each input_mode_type, but it seems like
 *    overkill to have a header for a single function declaration.
 *
 *    These functions are passed the input_mode_type structure; the
 *    functions should set the name of the input mode type and the
 *    function pointers.
 */
extern int
pduReaderInitialize(
    input_mode_type_t  *input_mode_type);
extern int
pduFileReaderInitialize(
    input_mode_type_t  *input_mode_type);
extern int
dirReaderInitialize(
    input_mode_type_t  *input_mode_type);
/* extern int  silkFileReaderInitialize(input_mode_type_t *input_mode_type); */
extern int
fcFilesReaderInitialize(
    input_mode_type_t  *input_mode_type);
extern int
respoolReaderInitialize(
    input_mode_type_t  *input_mode_type);
#if SK_ENABLE_IPFIX
extern int
ipfixReaderInitialize(
    input_mode_type_t  *input_mode_type);
#endif


/* Declare function to initialize rwflowpack for respooling */
int
packLogicRespoolInitialize(
    packlogic_plugin_t *);

#ifdef __cplusplus
}
#endif
#endif /* _RWFLOWPACK_PRIV_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
