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
**  rwsynackfin.c
**
**    Pass web traffic and fail all other traffic.  For web traffic,
**    keep a count of the number/types of flags seen, and print
**    summary to stderr once processing is complete.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsynackfin.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skplugin.h>
#include <silk/rwrec.h>


/* DEFINES AND TYPEDEFS */

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0


/* LOCAL VARIABLES */

static uint32_t fin_count, ack_count, rst_count, syn_count;


/* FUNCTION DECLARATIONS */

static skplugin_err_t check(const rwRec *rwrec, void *cbdata, void **extra);
static skplugin_err_t summary(void *cbdata);


/* FUNCTION DEFINITIONS */

/* the registration function called by skplugin.c */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*pi_data))
{
    skplugin_err_t rv;
    skplugin_callbacks_t regdata;

    /* Check API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    syn_count = fin_count = ack_count = rst_count = 0;

    /* Register the function to use for filtering */
    memset(&regdata, 0, sizeof(regdata));
    regdata.cleanup = summary;
    regdata.filter = check;
    return skpinRegFilter(NULL, &regdata, NULL);
}


/*
 *  status = check(rwrec, data, NULL);
 *
 *    Check whether 'rwrec' passes the filter.  Return
 *    SKPLUGIN_FILTER_PASS if it does; SKPLUGIN_FILTER_FAIL otherwise.
 *
 *    Pass the filter if 80/tcp or 443/tcp
 */
static skplugin_err_t
check(
    const rwRec            *rwrec,
    void            UNUSED(*cbdata),
    void           UNUSED(**extra))
{
    if (rwRecGetProto(rwrec) != 6) {
        return SKPLUGIN_FILTER_FAIL;
    }
    if (rwRecGetDPort(rwrec) != 80 && rwRecGetDPort(rwrec) != 443) {
        return SKPLUGIN_FILTER_FAIL;
    }

    if (rwRecGetFlags(rwrec) == ACK_FLAG
        && rwRecGetPkts(rwrec) == 1
        && rwRecGetBytes(rwrec) == 40)
    {
        ack_count++;
        return SKPLUGIN_FILTER_PASS;
    }

    if (rwRecGetFlags(rwrec) & FIN_FLAG) {
        fin_count++;
    }
    if (rwRecGetFlags(rwrec) & RST_FLAG) {
        rst_count++;
    }
    if (rwRecGetFlags(rwrec) & SYN_FLAG) {
        syn_count++;
    }
    return SKPLUGIN_FILTER_PASS;
}


/*
 *  status = summary(cbdata);
 *
 *    Print a summary of the flows we've seen to stderr.
 */
static skplugin_err_t
summary(
    void        UNUSED(*cbdata))
{
    fprintf(stderr, ("WEB SYN %" PRIu32 "  FIN %" PRIu32
                     "  RST %" PRIu32 "  ACK %" PRIu32 "\n"),
            syn_count, fin_count, rst_count, ack_count);

    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
