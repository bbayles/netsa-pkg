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
#ifndef _FLOWCAP_H
#define _FLOWCAP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_FLOWCAP_H, "$SiLK: flowcap.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  flowcap.h
**
**  Common information between flowcap objects
**
**/

#include <silk/probeconf.h>
#include <silk/skdaemon.h>
#include <silk/sklog.h>
#include <silk/skstream.h>
#include <silk/skvector.h>
#include <silk/utils.h>


/* Max timestamp length (YYYYMMDDhhmmss) */
#define FC_TIMESTAMP_MAX 15
/* Maximum sensor size (including either trailing zero or preceeding hyphen) */
#define FC_SENSOR_MAX (SK_MAX_STRLEN_SENSOR + 1)
/* Maximum probe size (including either trailing zero or preceeding hyphen) */
#define FC_PROBE_MAX (SK_MAX_STRLEN_SENSOR + 1)
/* Size of uniquness extension */
#define FC_UNIQUE_MAX 7
/* Previous two, plus hyphen */
#define FC_NAME_MAX                                     \
    (FC_TIMESTAMP_MAX + FC_SENSOR_MAX +                 \
     FC_PROBE_MAX + FC_UNIQUE_MAX)


/* Minimum flowcap version */
/* We no longer support flowcap version 1 */
#define FC_VERSION_MIN 2

/* Maximum flowcap version */
#define FC_VERSION_MAX 5

/* Default version of flowcap to produce */
#define FC_VERSION_DEFAULT 5

/* minimum number of bytes to leave free on the data disk.  File
 * distribution will stop when the freespace on the disk reaches or
 * falls below this mark.  This value is parsed by
 * skStringParseHumanUint64(). */
#define DEFAULT_FREESPACE_MINIMUM   "1g"

/* maximum percentage of disk space to take */
#define DEFAULT_SPACE_MAXIMUM_PERCENT  ((double)98.00)


/* Where to write files */
extern const char *destination_dir;

/* Compression method for output files */
extern sk_compmethod_t comp_method;

/* The version of flowcap to produce */
extern uint8_t flowcap_version;

/* To ensure records are sent along in a timely manner, the files are
 * closed when a timer fires or once they get to a certain size.
 * These variables define those values. */
extern uint32_t write_timeout;
extern uint32_t max_file_size;

/* Timer base (0 if none) from which we calculate timeouts */
extern sktime_t clock_time;

/* Amount of disk space to allow for a new file when determining
 * whether there is disk space available. */
extern uint64_t alloc_file_size;

/* Probes the user wants to flowcap process */
extern sk_vector_t *probe_vec;

#ifdef SK_HAVE_STATVFS
/* leave at least this much free space on the disk; specified by
 * --freespace-minimum */
extern int64_t freespace_minimum;

/* take no more that this amount of the disk; as a percentage.
 * specified by --space-maximum-percent */
extern double space_maximum_percent;
#endif /* SK_HAVE_STATVFS */


void
appSetup(
    int                 argc,
    char              **argv);
void
appTeardown(
    void);

int
createReaders(
    void);

#ifdef __cplusplus
}
#endif
#endif /* _FLOWCAP_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
