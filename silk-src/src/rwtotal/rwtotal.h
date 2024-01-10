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
#ifndef _RWTOTAL_H
#define _RWTOTAL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWTOTAL_H, "$SiLK: rwtotal.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/*
 * rwtotal.h
 *
 * Various handy header information for rwtotal.
 */

/* number of things to compute (used to compute size of count_array[]) */
#define NUM_TOTALS 3

/* offsets into the count_array[] array */
#define C_RECS  0
#define C_BYTES 1
#define C_PKTS  2



/* define the options; also these determine how to compute the key for
 * each bin */
typedef enum {
    OPT_SIP_FIRST_8=0, OPT_SIP_FIRST_16,  OPT_SIP_FIRST_24,
    OPT_SIP_LAST_8,    OPT_SIP_LAST_16,
    OPT_DIP_FIRST_8,   OPT_DIP_FIRST_16,  OPT_DIP_FIRST_24,
    OPT_DIP_LAST_8,    OPT_DIP_LAST_16,
    OPT_SPORT,         OPT_DPORT,
    OPT_PROTO,
    OPT_PACKETS,
    OPT_BYTES,
    OPT_DURATION,
    OPT_ICMP_CODE,

    /* above map to count-modes; below control output */

    OPT_SUMMATION,
    OPT_MIN_BYTES, OPT_MIN_PACKETS, OPT_MIN_RECORDS,
    OPT_MAX_BYTES, OPT_MAX_PACKETS, OPT_MAX_RECORDS,
    OPT_SKIP_ZEROES,
    OPT_NO_TITLES,
    OPT_NO_COLUMNS,
    OPT_COLUMN_SEPARATOR,
    OPT_NO_FINAL_DELIMITER,
    OPT_DELIMITED,
    OPT_OUTPUT_PATH,
    OPT_PAGER
} appOptionsEnum;


#define COUNT_MODE_UNSET     -1

/* which of the above is the maximum possible count_mode */
#define COUNT_MODE_MAX_OPTION OPT_ICMP_CODE

/* which of the above is final value to handle IP addresses.  used for
 * ignoring IPv6 addresses */
#define COUNT_MODE_FINAL_ADDR  OPT_DIP_LAST_16

/* which count mode to use */
extern int count_mode;

extern sk_options_ctx_t *optctx;

extern int  summation;
extern int  no_titles;
extern int  no_columns;
extern int  no_final_delimiter;
extern char delimiter;

/* array that holds the counts */
extern uint64_t *count_array;

extern uint64_t bounds[2 * NUM_TOTALS];

void
appTeardown(
    void);
void
appSetup(
    int                 argc,
    char              **argv);
FILE *
getOutputHandle(
    void);


#ifdef __cplusplus
}
#endif
#endif /* _RWTOTAL_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
