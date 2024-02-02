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
#ifndef _RWCOUNT_H
#define _RWCOUNT_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWCOUNT_H, "$SiLK: rwcount.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>

/*
 *  rwcount.h
 *
 *    Header file for the rwcount utility.
 */


/* DEFINES AND TYPEDEFS */

/* bin loading schemata */
typedef enum {
    LOAD_MEAN=0, LOAD_START, LOAD_END, LOAD_MIDDLE,
    LOAD_DURATION, LOAD_MAXIMUM, LOAD_MINIMUM
} bin_load_scheme_enum_t;

#define MAX_LOAD_SCHEME LOAD_MINIMUM

#define DEFAULT_LOAD_SCHEME LOAD_DURATION


/* default size of bins, in milliseconds */
#define DEFAULT_BINSIZE 30000

/* Values to use for the start_time and end_time to denote that they
 * are not set */
#define RWCO_UNINIT_START 0
#define RWCO_UNINIT_END   INT64_MAX


/* counting data structure */
typedef struct count_bin_st {
    double bytes;
    double pkts;
    double flows;
} count_bin_t;


typedef struct count_data_st {
    /* size of each bin, in milliseconds */
    int64_t     size;
    /* total number of bins that are allocated */
    uint64_t    count;
    /* time on the first bin, in UNIX epoch milliseconds */
    sktime_t    window_min;
    /* one millisecond after the final bin, in UNIX epoch milliseconds */
    sktime_t    window_max;
    /* range of dates for printing of data in UNIX epoch milliseconds */
    sktime_t    start_time;
    sktime_t    end_time;

    /* the data */
    count_bin_t *data;
} count_data_t;


typedef struct count_flags_st {
    /* how to label timestamps */
    uint32_t    timeflags;

    /* bin loading scheme */
    bin_load_scheme_enum_t  load_scheme;

    /* delimiter between columns */
    char        delimiter;

    /* when non-zero, print row label with bin's index value */
    unsigned    label_index         :1;

    /* when non-zero, do not print column titles */
    unsigned    no_titles           :1;

    /* when non-zero, suppress the final delimiter */
    unsigned    no_final_delimiter  :1;

    /* when non-zero, do not print bins with zero counts */
    unsigned    skip_zeroes         :1;

    /* when non-zero, do not print column titles */
    unsigned    no_columns          :1;
} count_flags_t;


/* FUNCTIONS */

void
appSetup(
    int                 argc,
    char              **argv);
void
appTeardown(
    void);
FILE *
getOutputHandle(
    void);


/* VARIABLES */

extern sk_options_ctx_t *optctx;

/* the data */
extern count_data_t bins;

/* flags */
extern count_flags_t flags;

#ifdef __cplusplus
}
#endif
#endif /* _RWCOUNT_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
