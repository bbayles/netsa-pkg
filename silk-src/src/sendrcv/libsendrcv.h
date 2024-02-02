/*
** Copyright (C) 2012-2023 by Carnegie Mellon University.
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
#ifndef _LIBSENDRCV_H
#define _LIBSENDRCV_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_LIBSENDRCV_H, "$SiLK: libsendrcv.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  libsendrcv.h
**
**  Maintenance macros for the libsendrcv convenience library
*/

/*
 *  ENABLING DEBUGGING
 *
 *    Setting the SENDRCV_DEBUG macro (below) to an bitmask of the
 *    following flags turns on specific types of debug output for
 *    rwsender/rwreceiver.  To see the messages in the running
 *    application, you MUST run with --log-level=debug.
 *
 *    The bit flags are:
 *
 *    0x0001 DEBUG_SKMSG_OTHER -- Logs messages for channel
 *    creation/destruction, network connection issues, and thread
 *    start/stop in skmsg.c.
 *
 *    0x0002 DEBUG_RWTRANSFER_PROTOCOL -- Logs messages regarding the
 *    higher-level protocol between rwsender and rwreceiver and thread
 *    start/stop in rwtransfer.c, rwsender.c, rwreceiver.c.
 *
 *    0x0004 DEBUG_RWTRANSFER_CONTENT -- Logs messages consisting of
 *    offset and length information for each message sent between the
 *    sender and receiver that is part of the actual file being
 *    transferred.  Generally used to debug file corruption.
 *
 *    0x0008 DEBUG_RWRECEIVER_DISKFREE -- Logs a message reporting
 *    disk usage each time rwreceiver asks about the amount of free
 *    space available on the disk.
 *
 *    0x0010 DEBUG_SKMSG_POLL_TIMEOUT -- Logs a message once a second
 *    when the call to poll() times out---this includes reading on the
 *    internal channel, which mostly waits for events.
 *
 *    The following are mostly used to debug lock-ups:
 *
 *    0x0100 DEBUG_SKMSG_MUTEX -- Logs a message for each mutex
 *    lock/unlock in skmsg.c
 *
 *    0x0200 DEBUG_RWTRANSFER_MUTEX -- Logs a message for each mutex
 *    lock/unlock in rwtransfer.c, rwsender.c, rwreceiver.c
 *
 *    0x0400 DEBUG_MULTIQUEUE_MUTEX -- Logs a message for each mutex
 *    lock/unlock in multiqueue.c
 *
 *    0x0800 DEBUG_INTDICT_MUTEX -- Logs a message for each mutex
 *    lock/unlock in intdict.c
 *
 *    0x1000 DEBUG_SKMSG_FN -- Logs a message for each function entry
 *    and function return in skmsg.c
 *
 *
 */

#define DEBUG_SKMSG_OTHER           0x0001
#define DEBUG_RWTRANSFER_PROTOCOL   0x0002
#define DEBUG_RWTRANSFER_CONTENT    0x0004
#define DEBUG_RWRECEIVER_DISKFREE   0x0008

#define DEBUG_SKMSG_POLL_TIMEOUT    0x0010

#define DEBUG_SKMSG_MUTEX           0x0100
#define DEBUG_RWTRANSFER_MUTEX      0x0200
#define DEBUG_MULTIQUEUE_MUTEX      0x0400
#define DEBUG_INTDICT_MUTEX         0x0800

#define DEBUG_SKMSG_FN              0x1000


/* #define SENDRCV_DEBUG 0 */
#ifndef SENDRCV_DEBUG
#  if defined(GLOBAL_TRACE_LEVEL) && GLOBAL_TRACE_LEVEL == 9
#    define SENDRCV_DEBUG 0xffff
#  else
#    define SENDRCV_DEBUG 0
#  endif
#endif


#ifdef __cplusplus
}
#endif
#endif /* _LIBSENDRCV_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
