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
#ifndef _RWSTATS_H
#define _RWSTATS_H
#ifdef __cplusplus
extern "C" {
#endif

/*
**  rwstats.h
**
**    Common declarations for the rwstats and rwuniq applications.
**    See rwstats,c and rwuniq.c for descriptions of the applications.
**
*/

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWSTATS_H, "$SiLK: rwstats.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/hashlib.h>
#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skplugin.h>
#include <silk/skipaddr.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include "skunique.h"


/* TYPEDEFS AND DEFINES */

/* whether the program is rwstats or rwuniq */
typedef enum {
    STATSUNIQ_PROGRAM_STATS = 1,
    STATSUNIQ_PROGRAM_UNIQ  = 2,
    STATSUNIQ_PROGRAM_BOTH  = 3
} statsuniq_program_t;

/* symbol names for whether this is a top-N or bottom-N */
typedef enum {
    RWSTATS_DIR_TOP, RWSTATS_DIR_BOTTOM
} rwstats_direction_t;

/* what type of cutoff to use; keep these in same order as appOptionsEnum */
typedef enum {
    /* specify the N for a Top-N or Bottom-N */
    RWSTATS_COUNT = 0,
    /* output bins whose value is at-least/no-more-than this value */
    RWSTATS_THRESHOLD = 1,
    /* output bins whose value relative to the total across all bins
     * is at-least/no-more-than this percentage */
    RWSTATS_PERCENTAGE = 2,
    /* there is no limit; print all (enabled by --count=0) */
    RWSTATS_ALL = 3
} rwstats_limit_type_t;

/* number of limit types; used for sizing arrays */
#define NUM_RWSTATS_LIMIT_TYPE      4

/* builtin_field_t declaration; defined in rwstatssetup.c */
typedef struct builtin_field_st builtin_field_t;

/* struct to hold information about the first value field.  That field
 * is used to sort and limit the number of rows printed. */
typedef struct rwstats_limit_st {
    char                    title[256];
    /* values that correspond to rwstats_limit_type_t.  the double
     * value is used for RWSTATS_PERCENTAGE; the uint64_t otherwise */
    union value_un {
        double      d;
        uint64_t    u64;
    }                       value[NUM_RWSTATS_LIMIT_TYPE];
    /* number of entries in the hash table */
    uint64_t                entries;
    /* handles to the field to limit */
    sk_fieldentry_t        *fl_entry;
    skplugin_field_t       *pi_field;
    builtin_field_t        *bf_value;
    sk_fieldid_t            fl_id;
    /* count, threshold, percentage, or all */
    rwstats_limit_type_t    type;
    /* did user provide a stopping condition? (1==yes) */
    unsigned                seen    :1;
    /* is this an aggregate value(0) or a distinct(1)? */
    unsigned                distinct:1;
} rwstats_limit_t;

/* flags set by user options */
typedef struct app_flags_st {
    unsigned presorted_input    :1;      /* Assume input is sorted */
    unsigned no_percents        :1;      /* Whether to include the % cols */
    unsigned sort_output        :1;      /* uniq: Whether to sort output */
    unsigned print_filenames    :1;
    unsigned no_columns         :1;
    unsigned no_titles          :1;
    unsigned no_final_delimiter :1;
    unsigned integer_sensors    :1;
    unsigned integer_tcp_flags  :1;
    unsigned check_limits       :1;      /* Whether output must meet limits */
} app_flags_t;

/* names for the columns */
enum width_type {
    WIDTH_KEY, WIDTH_VAL, WIDTH_INTVL, WIDTH_PCT
};

#define RWSTATS_COLUMN_WIDTH_COUNT 4

/* used to handle legacy switches */
typedef struct rwstats_legacy_st {
    const char *fields;
    const char *values;
} rwstats_legacy_t;


/* VARIABLE DECLARATIONS */

/* which program is being run */
extern const statsuniq_program_t this_program;

/* non-zero when --overall-stats or --detail-proto-stats is given */
extern int proto_stats;

extern sk_unique_t *uniq;
extern sk_sort_unique_t *ps_uniq;

extern sk_fieldlist_t *key_fields;
extern sk_fieldlist_t *value_fields;
extern sk_fieldlist_t *distinct_fields;

/* whether this is a top-n or bottom-n */
extern rwstats_direction_t direction;

/* hold the value of the N for top-N,bottom-N */
extern rwstats_limit_t limit;

/* to convert the key fields (as an rwRec) to ascii */
extern rwAsciiStream_t *ascii_str;

/* the output */
extern sk_fileptr_t output;

/* flags set by the user options */
extern app_flags_t app_flags;

/* output column widths.  mapped to width_type */
extern int width[RWSTATS_COLUMN_WIDTH_COUNT];

/* delimiter between output columns */
extern char delimiter;

/* the final delimiter on each line */
extern char final_delim[];

/* number of records read */
extern uint64_t record_count;

/* Summation of whatever value (bytes, packets, flows) we are using.
 * When counting flows, this will be equal to record_count. */
extern uint64_t value_total;

/* CIDR block mask for sIPs and dIPs.  If 0, use all bits; otherwise,
 * the IP address should be bitwised ANDed with this value. */
extern uint32_t cidr_sip;
extern uint32_t cidr_dip;


/* FUNCTION DECLARATIONS */

/* rwstatssetup.c */

void
appSetup(
    int                 argc,
    char              **argv);
void
appTeardown(
    void);
void
appExit(
    int                 status)
    NORETURN;
int
readRecord(
    skstream_t         *stream,
    rwRec              *rwrec);
int
appNextInput(
    skstream_t        **stream);
void
setOutputHandle(
    void);
void
writeAsciiRecord(
    uint8_t           **outbuf);
void
checkLimitsWriteRecord(
    uint8_t           **outbuf);


/* rwstatsproto.c: Functions for detailed protocol statistics.
 * rwuniq.c provides dummy versions of these. */

int
protoStatsOptionsRegister(
    void);
void
protoStatsOptionsUsage(
    FILE               *fh);
int
protoStatsMain(
    void);


/* from rwstatslegacy.c. rwuniq.c provides dummy versions of these. */

int
legacyOptionsSetup(
    clientData          cData);
void
legacyOptionsUsage(
    FILE               *fh);

#ifdef __cplusplus
}
#endif
#endif /* _RWSTATS_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
