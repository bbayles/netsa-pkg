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
** rwgroup
**
** rwgroup is a 'fuzzy uniq' utility that can be used to group together
** records into 'groups' of fields; to work properly, it
** requires a sorted set of fields, because it can only do record-record
** comparison.
**
** command arguments:
**
** --id-fields: id fields are fields which have to be identical to
**   define a group.
** --delta-field: delta field is the field which is allowed to have a
**   delta value
** --delta-value: This is the maximum value by which two consecutive records
**   can differ before they're considered parts of different groups.  It
**   Is an integer, and represents an inclusive value, so if delta is 1 and
**   the field is stime, then records which are a second apart will be
**   considered part of the same group.
** --threshold: minimum number of records to output
** --summarize: Instead of printing out a record with a grouped id, this will
**              print out a summarized record with stime=min time,
**              etime=max time, bytes and packets summarized.
**
** The way that this application works is as follows: a 'group' is
** a set of records where the id-fields are identical, and the
** delta-field changes within delta.  Each group is identified by a
** unique group id stored in next hop ip; group id's start at 0
** and continue on from there.
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwgroup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwgroup.h"


/* TYPEDEFS AND DEFINES */

/* File handle for --help output */
#define USAGE_FH stdout

#define MAX_THRESH 65535


/* EXPORTED VARIABLES */

/* number of fields to group by; skStringMapParse() sets this */
uint32_t num_fields = 0;

/* IDs of the fields to group by; skStringMapParse() sets it; values
 * are from the rwrec_printable_fields_t enum and from values that
 * come from plug-ins. */
uint32_t *id_fields = NULL;

/* the size of a "node".  Because the output from rwgroup is SiLK
 * records, the node size includes the complete rwRec, plus any binary
 * fields that we get from plug-ins to use as the key.  This node_size
 * value may increase when we parse the --fields switch. */
uint32_t node_size = sizeof(rwRec);

/* the columns that make up the key that come from plug-ins */
key_field_t key_fields[MAX_PLUGIN_KEY_FIELDS];

/* the number of these key_fields */
size_t key_num_fields = 0;

/* input stream */
skstream_t *in_stream = NULL;

/* output stream */
skstream_t *out_stream = NULL;

/* the id of the field to match with fuzzy-ness */
uint32_t delta_field = DELTA_FIELD_UNSET;

/* the amount of fuzzy-ness allowed */
uint64_t delta_value = 0;

/* for IPv6, use a delta_value that is an skipaddr_t */
skipaddr_t delta_value_ip;

/* number of records to that must be in a group before the group is
 * printed. */
uint32_t threshold = 0;

/* where to store the records while waiting to meet the threshold */
rwRec *thresh_buf = NULL;

/* the value to write into the next hop IP field */
skipaddr_t group_id;

/* whether the --summarize switch was given */
int summarize = 0;

/* whether the --objective switch was given */
int objective = 0;



/* LOCAL FUNCTION PROTOTYPES */



/* FUNCTION DEFINITIONS */

/* Define our raw sorting functions */
#define RETURN_IF_SORTED(func, rec_a, rec_b)                    \
    {                                                           \
        if (func((rwRec*)(rec_a)) < func((rwRec*)(rec_b))) {    \
            return -1;                                          \
        }                                                       \
        if (func((rwRec*)(rec_a)) > func((rwRec*)(rec_b))) {    \
            return 1;                                           \
        }                                                       \
    }

#define RETURN_IF_SORTED_IPS(func, rec_a, rec_b)        \
    {                                                   \
        skipaddr_t ipa, ipb;                            \
        int cmp;                                        \
        func((rwRec*)(rec_a), &ipa);                    \
        func((rwRec*)(rec_b), &ipb);                    \
        cmp = skipaddrCompare(&ipa, &ipb);              \
        if (cmp != 0) {                                 \
            return (cmp);                               \
        }                                               \
    }

#define RETURN_IF_VALUE_OUTSIDE_DELTA(func, rec_a, rec_b)       \
    {                                                           \
        uint64_t val_a = func((rwRec*)(rec_a));                 \
        uint64_t val_b = func((rwRec*)(rec_b));                 \
        if (val_a < val_b) {                                    \
            if ((val_b - val_a) > delta_value) {                \
                return -2;                                      \
            }                                                   \
        } else if (val_a > val_b) {                             \
            if ((val_a - val_b) > delta_value) {                \
                return 2;                                       \
            }                                                   \
        }                                                       \
    }

#if !SK_ENABLE_IPV6
/* compare two IPv4 addresses masked by same value */
#define RETURN_IF_IPS_OUTSIDE_DELTA(func, rec_a, rec_b) \
    {                                                   \
        uint32_t val_a, val_b;                          \
        val_a = delta_value & func((rwRec*)(rec_a));    \
        val_b = delta_value & func((rwRec*)(rec_b));    \
        if (val_a < val_b) {                            \
            return -2;                                  \
        } else if (val_a > val_b) {                     \
            return 2;                                   \
        }                                               \
    }
#else
/* compare two skipaddr_t's masked by an skipaddr_t */
#define RETURN_IF_IPS_OUTSIDE_DELTA(func, rec_a, rec_b) \
    {                                                   \
        skipaddr_t ipa, ipb;                            \
        int cmp;                                        \
        func((rwRec*)(rec_a), &ipa);                    \
        func((rwRec*)(rec_b), &ipb);                    \
        skipaddrMask(&ipa, &delta_value_ip);            \
        skipaddrMask(&ipb, &delta_value_ip);            \
        cmp = skipaddrCompare(&ipa, &ipb);              \
        if (cmp != 0) {                                 \
            return (cmp);                               \
        }                                               \
    }
#endif  /* SK_ENABLE_IPV6 */


static uint8_t
getIcmpType(
    const void         *rec)
{
    if (rwRecIsICMP((rwRec*)rec)) {
        return rwRecGetIcmpType((rwRec*)rec);
    }
    return 0;
}

static uint8_t
getIcmpCode(
    const void         *rec)
{
    if (rwRecIsICMP((rwRec*)rec)) {
        return rwRecGetIcmpCode((rwRec*)rec);
    }
    return 0;
}

/*
 *  rwrecCompare(a, b);
 *
 *     Returns an ordering on the recs pointed to `a' and `b' by
 *     comparing the fields listed in the id_fields[] array.
 */
static int
rwrecCompare(
    const uint8_t      *a,
    const uint8_t      *b)
{
    key_field_t *key = key_fields;
    skplugin_err_t err;
    uint32_t i;
    int rv;

    for (i = 0; i < num_fields; i++) {
        switch (id_fields[i]) {
          case RWREC_FIELD_SIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetSIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetSIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_DIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetDIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetDIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_NHIP:
#if !SK_ENABLE_IPV6
            RETURN_IF_SORTED(rwRecGetNhIPv4, a, b);
#else
            RETURN_IF_SORTED_IPS(rwRecMemGetNhIP, a, b);
#endif /* SK_ENABLE_IPV6 */
            break;

          case RWREC_FIELD_SPORT:
            RETURN_IF_SORTED(rwRecGetSPort, a, b);
            break;

          case RWREC_FIELD_DPORT:
            RETURN_IF_SORTED(rwRecGetDPort, a, b);
            break;

          case RWREC_FIELD_PROTO:
            RETURN_IF_SORTED(rwRecGetProto, a, b);
            break;

          case RWREC_FIELD_PKTS:
            RETURN_IF_SORTED(rwRecGetPkts, a, b);
            break;

          case RWREC_FIELD_BYTES:
            RETURN_IF_SORTED(rwRecGetBytes, a, b);
            break;

          case RWREC_FIELD_FLAGS:
            RETURN_IF_SORTED(rwRecGetFlags, a, b);
            break;

          case RWREC_FIELD_STIME:
          case RWREC_FIELD_STIME_MSEC:
            RETURN_IF_SORTED(rwRecGetStartTime, a, b);
            break;

          case RWREC_FIELD_ELAPSED:
          case RWREC_FIELD_ELAPSED_MSEC:
            RETURN_IF_SORTED(rwRecGetElapsed, a, b);
            break;

          case RWREC_FIELD_ETIME:
          case RWREC_FIELD_ETIME_MSEC:
            RETURN_IF_SORTED(rwRecGetEndTime, a, b);
            break;

          case RWREC_FIELD_SID:
            RETURN_IF_SORTED(rwRecGetSensor, a, b);
            break;

          case RWREC_FIELD_INPUT:
            RETURN_IF_SORTED(rwRecGetInput, a, b);
            break;

          case RWREC_FIELD_OUTPUT:
            RETURN_IF_SORTED(rwRecGetOutput, a, b);
            break;

          case RWREC_FIELD_INIT_FLAGS:
            RETURN_IF_SORTED(rwRecGetInitFlags, a, b);
            break;

          case RWREC_FIELD_REST_FLAGS:
            RETURN_IF_SORTED(rwRecGetRestFlags, a, b);
            break;

          case RWREC_FIELD_TCP_STATE:
            RETURN_IF_SORTED(rwRecGetTcpState, a, b);
            break;

          case RWREC_FIELD_APPLICATION:
            RETURN_IF_SORTED(rwRecGetApplication, a, b);
            break;

          case RWREC_FIELD_FTYPE_CLASS:
          case RWREC_FIELD_FTYPE_TYPE:
            RETURN_IF_SORTED(rwRecGetFlowType, a, b);
            break;

          case RWREC_FIELD_ICMP_TYPE:
            RETURN_IF_SORTED(getIcmpType, a, b);
            break;

          case RWREC_FIELD_ICMP_CODE:
            RETURN_IF_SORTED(getIcmpCode, a, b);
            break;

          default:
            /* we go through the fields in the same way they were
             * added, and 'key' should always be pointing to the
             * current plugin. */
            assert((size_t)(key - key_fields) < key_num_fields);
            err = skPluginFieldRunBinCompareFn(key->kf_field_handle, &rv,
                                               &(a[key->kf_offset]),
                                               &(b[key->kf_offset]));
            if (err != SKPLUGIN_OK) {
                const char **name;
                skPluginFieldName(key->kf_field_handle, &name);
                skAppPrintErr(("Plugin-based field %s failed "
                               "comparing binary values "
                               "with error code %d"), name[0], err);
                exit(EXIT_FAILURE);
            }
            ++key;
            if (rv != 0) {
                return rv;
            }
            break;
        }
    }

    if (DELTA_FIELD_UNSET == delta_field) {
        return 0;
    }

    switch (delta_field) {
      case RWREC_FIELD_SIP:
#if !SK_ENABLE_IPV6
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecGetSIPv4, a, b);
#else
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecMemGetSIP, a, b);
#endif /* SK_ENABLE_IPV6 */
        break;

      case RWREC_FIELD_DIP:
#if !SK_ENABLE_IPV6
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecGetDIPv4, a, b);
#else
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecMemGetDIP, a, b);
#endif /* SK_ENABLE_IPV6 */
        break;

      case RWREC_FIELD_NHIP:
#if !SK_ENABLE_IPV6
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecGetNhIPv4, a, b);
#else
        RETURN_IF_IPS_OUTSIDE_DELTA(rwRecMemGetNhIP, a, b);
#endif /* SK_ENABLE_IPV6 */
        break;

      case RWREC_FIELD_SPORT:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetSPort, a, b);
        break;

      case RWREC_FIELD_DPORT:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetDPort, a, b);
        break;

      case RWREC_FIELD_PROTO:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetProto, a, b);
        break;

      case RWREC_FIELD_PKTS:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetPkts, a, b);
        break;

      case RWREC_FIELD_BYTES:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetBytes, a, b);
        break;

      case RWREC_FIELD_FLAGS:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetFlags, a, b);
        break;

      case RWREC_FIELD_STIME:
      case RWREC_FIELD_STIME_MSEC:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetStartTime, a, b);
        break;

      case RWREC_FIELD_ELAPSED:
      case RWREC_FIELD_ELAPSED_MSEC:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetElapsed, a, b);
        break;

      case RWREC_FIELD_ETIME:
      case RWREC_FIELD_ETIME_MSEC:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetEndTime, a, b);
        break;

      case RWREC_FIELD_SID:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetSensor, a, b);
        break;

      case RWREC_FIELD_INPUT:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetInput, a, b);
        break;

      case RWREC_FIELD_OUTPUT:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetOutput, a, b);
        break;

      case RWREC_FIELD_INIT_FLAGS:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetInitFlags, a, b);
        break;

      case RWREC_FIELD_REST_FLAGS:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetRestFlags, a, b);
        break;

      case RWREC_FIELD_TCP_STATE:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetTcpState, a, b);
        break;

      case RWREC_FIELD_APPLICATION:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetApplication, a, b);
        break;

      case RWREC_FIELD_FTYPE_CLASS:
      case RWREC_FIELD_FTYPE_TYPE:
        RETURN_IF_VALUE_OUTSIDE_DELTA(rwRecGetFlowType, a, b);
        break;

      case RWREC_FIELD_ICMP_TYPE:
        RETURN_IF_VALUE_OUTSIDE_DELTA(getIcmpType, a, b);
        break;

      case RWREC_FIELD_ICMP_CODE:
        RETURN_IF_VALUE_OUTSIDE_DELTA(getIcmpCode, a, b);
        break;

      default:
        break;
    }

    return 0;
}


/*
 * int process_recs
 * Called on all records except the first; it compares the
 * new records against the group and generates a group
 * number as necessary.
 *
 * flags: current_rec: the record that we're actually processing
 * force: instead of processing the record, output whatever we would
 *        at this time.  force handles the terminal corner case and
 *        makes sure we print out all records in the file.
 */
static int
groupInput(
    void)
{
#define WRITE_REC(r)                                                    \
    {                                                                   \
        rv = skStreamWriteRecord(out_stream, (rwRec*)(r));              \
        if (rv) {                                                       \
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);       \
            return -1;                                                  \
        }                                                               \
    }

    uint32_t thresh_count;
    uint32_t summary_thresh;
    key_field_t *key;
    skplugin_err_t err;
    size_t j;
    int unsorted_warning = 0;
    int cmp;
    int rv;

#ifndef SK_HAVE_ALIGNED_ACCESS_REQUIRED
    uint8_t rec_buf[3][MAX_NODE_SIZE];
    rwRec *summary_rec = (rwRec*)rec_buf[0];
    uint8_t *last_rec = rec_buf[1];
    uint8_t *cur_rec = rec_buf[2];

    memset(rec_buf, 0, sizeof(rec_buf));
#else
    /* ugh.  force the record buffer to be aligned on 8-byte
     * boundary to keep 64bit solaris happy */
    union rec_buf_un {
        uint8_t  rb_buf[3][MAX_NODE_SIZE];
        uint64_t rb_64;
    } rec_buf;
    rwRec *summary_rec = (rwRec*)rec_buf.rb_buf[0];
    uint8_t *last_rec = rec_buf.rb_buf[1];
    uint8_t *cur_rec =  rec_buf.rb_buf[2];

    memset(&rec_buf, 0, sizeof(rec_buf));
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */

    /* number of records in the current group, used to see if we have
     * met the threshold, and used as index into the thresh_buf when
     * we are not summarizing */
    thresh_count = 0;

    /* if a summary record overflows and we haven't met the threshold
     * yet, store the current summary_rec in thresh_buf.  this var is
     * an index into the thresh_buf when summarizing */
    summary_thresh = 0;

    /* read the first record, it begins a new group */
    rv = skStreamReadRecord(in_stream, (rwRec*)last_rec);
    if (rv) {
        /* end of file or error getting record */
        if (SKSTREAM_ERR_EOF == rv) {
            return 0;
        }
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        return -1;
    }

    /* lookup data from plug-in */
    for (j = 0, key = key_fields; j < key_num_fields; ++j, ++key) {
        err = skPluginFieldRunRecToBinFn(key->kf_field_handle,
                                         &(last_rec[key->kf_offset]),
                                         (rwRec*)last_rec, NULL);
        if (err != SKPLUGIN_OK) {
            const char **name;
            skPluginFieldName(key->kf_field_handle, &name);
            skAppPrintErr(("Plugin-based field %s failed "
                           "converting record to binary "
                           "with error code %d"), name[0], err);
            exit(EXIT_FAILURE);
        }
    }

    /* set group id on the record */
    rwRecMemSetNhIP((rwRec*)last_rec, &group_id);
    if (summarize) {
        /* use this record as basis for summary_rec */
        RWREC_COPY(summary_rec, (rwRec*)last_rec);
    } else if (threshold) {
        /* add record to threshold buffer */
        RWREC_COPY(&thresh_buf[0], (rwRec*)last_rec);
    } else {
        /* write it */
        WRITE_REC(last_rec);
    }
    thresh_count = 1;

    /* read the remaining records */
    while ((rv = skStreamReadRecord(in_stream, (rwRec*)cur_rec))
           == SKSTREAM_OK)
    {
        /* lookup data from plug-in */
        for (j = 0, key = key_fields; j < key_num_fields; ++j, ++key) {
            err = skPluginFieldRunRecToBinFn(key->kf_field_handle,
                                             &(cur_rec[key->kf_offset]),
                                             (rwRec*)cur_rec, NULL);
            if (err != SKPLUGIN_OK) {
                const char **name;
                skPluginFieldName(key->kf_field_handle, &name);
                skAppPrintErr(("Plugin-based field %s failed "
                               "converting record to binary "
                               "with error code %d"), name[0], err);
                exit(EXIT_FAILURE);
            }
        }

        cmp = rwrecCompare(last_rec, cur_rec);
        if (!objective || 0 != cmp) {
            /* cur_rec becomes the last_rec unless the records match
             * and --objective was specified. */
            memcpy(last_rec, cur_rec, node_size);
        }
        if (0 == cmp) {
            if (!summarize) {
                rwRecMemSetNhIP((rwRec*)cur_rec, &group_id);
                if (thresh_count >= threshold) {
                    /* write the record */
                    WRITE_REC(cur_rec);
                } else if (thresh_count + 1 == threshold) {
                    /* write the contents of the threshold buffer */
                    for (j = 0; j < thresh_count; ++j) {
                        WRITE_REC(&thresh_buf[j]);
                    }

                    /* write the record we just read */
                    WRITE_REC(cur_rec);
                } else {
                    /* add record to threshold buffer */
                    RWREC_COPY(&thresh_buf[thresh_count], (rwRec*)cur_rec);
                }
            } else {
                /* add record to summary_rec, handling overflow */
                sktime_t sttime = 0, summary_etime = 0, cur_etime;
                uint32_t bytes = 0, pkts = 0;
                int overflow = 0;

                /* use a do{}while(0) so we can break on the first
                 * sign of an overflow */
                do {
                    /* check for overflow in bytes, most likely place
                     * for an overflow to occur */
                    bytes = rwRecGetBytes((rwRec*)cur_rec);
                    if (UINT32_MAX - bytes < rwRecGetBytes(summary_rec)) {
                        overflow = 1;
                        break;
                    }
                    bytes += rwRecGetBytes(summary_rec);

                    /* set 'summary_etime' to the later end time */
                    summary_etime = rwRecGetEndTime(summary_rec);
                    cur_etime = rwRecGetEndTime((rwRec*)cur_rec);
                    if (summary_etime < cur_etime) {
                        summary_etime = cur_etime;
                    }

                    /* set 'sttime' to the earlier start time */
                    if (rwRecGetStartTime((rwRec*)cur_rec)
                        < rwRecGetStartTime(summary_rec))
                    {
                        sttime = rwRecGetStartTime((rwRec*)cur_rec);
                    } else {
                        sttime = rwRecGetStartTime(summary_rec);
                    }

                    /* make certain elapsed time won't overflow */
                    if ((sktime_t)UINT32_MAX < (summary_etime - sttime)) {
                        overflow = 1;
                        break;
                    }

                    /* check for overflow in packets.  should never
                     * happen since we should have bytes > packets */
                    pkts = rwRecGetPkts((rwRec*)cur_rec);
                    if (UINT32_MAX - pkts < rwRecGetPkts(summary_rec)) {
                        overflow = 1;
                        break;
                    }
                    pkts += rwRecGetPkts(summary_rec);
                } while (0);

                if (0 == overflow) {
                    /* nothing overflowed.  update summary_rec */
                    rwRecSetBytes(summary_rec, bytes);
                    rwRecSetPkts(summary_rec, pkts);
                    rwRecSetStartTime(summary_rec, sttime);
                    rwRecSetElapsed(summary_rec,
                                    (uint32_t)(summary_etime - sttime));

                    /* handle flags */
                    rwRecSetFlags(summary_rec,
                                  (rwRecGetFlags(summary_rec)
                                   | rwRecGetFlags((rwRec*)cur_rec)));
                    rwRecSetRestFlags(summary_rec,
                                      (rwRecGetRestFlags(summary_rec)
                                       | rwRecGetRestFlags((rwRec*)cur_rec)));
                } else {
                    /* we overflowed.  if we haven't reached the
                     * threshold yet, store current summary_rec in the
                     * thresh_buf. */
                    if (thresh_count + 1 < threshold) {
                        /* add record to threshold buffer */
                        RWREC_COPY(&thresh_buf[summary_thresh], summary_rec);
                        ++summary_thresh;
                    } else {
                        /* write anything in the thresh_buf, then print
                         * the current summary_rec */
                        for (j = 0; j < summary_thresh; ++j) {
                            WRITE_REC(&thresh_buf[j]);
                        }
                        summary_thresh = 0;

                        WRITE_REC(summary_rec);
                    }

                    /* the cur_rec becomes new basis for summary */
                    RWREC_COPY(summary_rec, cur_rec);
                }
            }
            ++thresh_count;

        } else {
            /* cur_rec is start of a new group */

            /* warn (just once) if data appears to be unsorted */
            if (cmp > 0 && !unsorted_warning) {
                skAppPrintErr("Your input data appears to be unsorted");
                unsorted_warning = 1;
            }

            /* increment the group id */
            skipaddrIncrement(&group_id);
            rwRecMemSetNhIP((rwRec*)cur_rec, &group_id);

            if (!summarize) {
                if (threshold) {
                    /* add record to threshold buffer */
                    RWREC_COPY(&thresh_buf[0], (rwRec*)cur_rec);
                } else {
                    /* print the record */
                    WRITE_REC(cur_rec);
                }
            } else {
                /* handle the summary_rec */
                if (thresh_count >= threshold) {
                    /* write any summary records that overflowed */
                    for (j = 0; j < summary_thresh; ++j) {
                        WRITE_REC(&thresh_buf[j]);
                    }
                    /* print summary_rec */
                    WRITE_REC(summary_rec);
                }
                summary_thresh = 0;

                RWREC_COPY(summary_rec, (rwRec*)cur_rec);
            }
            thresh_count = 1;
        }
    }

    if (SKSTREAM_ERR_EOF == rv) {
        rv = SKSTREAM_OK;
    } else {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
    }

    /* print final summary_rec */
    if (summarize && thresh_count >= threshold) {
        /* write any summary records that overflowed */
        for (j = 0; j < summary_thresh; ++j) {
            WRITE_REC(&thresh_buf[j]);
        }
        summary_thresh = 0;

        WRITE_REC(summary_rec);
    }

    return ((rv == 0) ? 0 : -1);
}


int main(int argc, char **argv)
{
    int rv;

    appSetup(argc, argv);                 /* never returns on error */

    rv = groupInput();
    if (rv) {
        exit(EXIT_FAILURE);
    }

    /* close the output file */
    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }
    skStreamDestroy(&out_stream);

    /* done */
    appTeardown();

    return ((rv == 0) ? 0 : 1);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
