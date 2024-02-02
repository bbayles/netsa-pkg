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
#ifndef _UDPSOURCE_H
#define _UDPSOURCE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_UDPSOURCE_H, "$SiLK: udpsource.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>

struct skUDPSource_st;
typedef struct skUDPSource_st skUDPSource_t;


/**
 *    Signature of callback function.
 *
 *    The UDP source calls this function for each packet it collects
 *    from network or reads from a file.  The function is called with
 *    the length of the packet, the packet's data, and a
 *    'callback_data' object supplied by the caller.
 *
 *    If the function returns non-zero, the packet is rejected.  If
 *    the function returns 0, the packet is stored until request by
 *    the caller via the skUDPSourceNext() function.
 */
typedef int (*udp_source_reject_fn)(
    ssize_t         recv_data_len,
    void           *recv_data,
    void           *callback_data);


/**
 *    Creates and returns a UDP source representing the connectivity
 *    information in 'probe' and 'params'.
 *
 *    'itemsize' is the maximum size of an individual packet.
 *
 *    'reject_pkt_fn' is a function that will be called for every
 *    packet the UDP source receives, and 'fn_callback_data' is a
 *    parameter passed to that function.  If the 'reject_pkt_fn'
 *    returns a true value, the packet will be ignored.
 *
 *    Returns the UDP source on success, or NULL on failure.
 */
skUDPSource_t *
skUDPSourceCreate(
    const skpc_probe_t         *probe,
    const skFlowSourceParams_t *params,
    uint32_t                    itemsize,
    udp_source_reject_fn        reject_pkt_fn,
    void                       *fn_callback_data);


/**
 *    Tell the UDP Source to stop processing data.
 */
void
skUDPSourceStop(
    skUDPSource_t      *source);


/**
 *    Free all memory associated with the UDP Source.  Does nothing if
 *    'source' is NULL.
 */
void
skUDPSourceDestroy(
    skUDPSource_t      *source);


/**
 *    Get the next piece of data collected/read by the UDP Source.
 */
uint8_t *
skUDPSourceNext(
    skUDPSource_t      *source);

#ifdef __cplusplus
}
#endif
#endif /* _UDPSOURCE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
