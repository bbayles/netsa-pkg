/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  rwgroup.h
**
**    See rwgroup.c for description.
**
*/
#ifndef _RWGROUP_H
#define _RWGROUP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWGROUP_H, "$SiLK: rwgroup.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skplugin.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */


/*
 *    Maximum size of the --rec-treshold
 */
#define MAX_THRESHOLD 65535

/*
 *    Value indicating the delta_field value is unset
 */
#define DELTA_FIELD_UNSET   UINT32_MAX

/*
 *    Maximum number of fields that can come from plugins.  Allow four
 *    per plug-in.
 */
#define MAX_PLUGIN_KEY_FIELDS  32

/*
 *    Maximum bytes allotted to a "node", which is the complete rwRec
 *    and the bytes required by all keys that can come from plug-ins.
 *    Allow 8 bytes per field, plus enough space for an rwRec.
 */
#define MAX_NODE_SIZE  (256 + SK_MAX_RECORD_SIZE)

/* for key fields that come from plug-ins, this struct will hold
 * information about a single field */
typedef struct key_field_st {
    /* The plugin field handle, if kf_fxn is null */
    skplugin_field_t *kf_field_handle;
    /* the byte-offset for this field */
    size_t            kf_offset;
    /* the byte-width of this field */
    size_t            kf_width;
} key_field_t;


/* VARIABLES */

/* number of fields to group by; skStringMapParse() sets this */
extern uint32_t num_fields;

/* IDs of the fields to group by; skStringMapParse() sets it; values
 * are from the rwrec_printable_fields_t enum and from values that
 * come from plugins. */
extern uint32_t *id_fields;

/* the size of a "node".  Because the output from rwgroup is SiLK
 * records, the node size includes the complete rwRec, plus any binary
 * fields that we get from plug-ins to use as the key.  This node_size
 * value may increase when we parse the --fields switch. */
extern uint32_t node_size;

/* the columns that make up the key that come from plug-ins */
extern key_field_t key_fields[MAX_PLUGIN_KEY_FIELDS];

/* the number of these key_fields */
extern size_t key_num_fields;

/* input stream */
extern skstream_t *in_stream;

/* output stream */
extern skstream_t *out_stream;

/* the id of the field to match with fuzzy-ness */
extern uint32_t delta_field;

/* the amount of fuzzy-ness allowed */
extern uint64_t delta_value;

/* for IPv6, use a delta_value that is an skipaddr_t */
extern skipaddr_t delta_value_ip;

/* number of records to that must be in a group before the group is
 * printed. */
extern uint32_t threshold;

/* where to store the records while waiting to meet the threshold */
extern rwRec *thresh_buf;

/* the value to write into the next hop IP field */
extern skipaddr_t group_id;

/* whether the --summarize switch was given */
extern int summarize;

/* whether the --objective switch was given */
extern int objective;


void
appTeardown(
    void);
void
appSetup(
    int                 argc,
    char              **argv);


#ifdef __cplusplus
}
#endif
#endif /* _RWGROUP_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
