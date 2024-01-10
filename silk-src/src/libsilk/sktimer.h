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

/*
**  sktimer.h
**
**    Generic timers which will run callback functions in a separate
**    thread context after a given amount of time.
**
*/
#ifndef _SKTIMER_H
#define _SKTIMER_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKTIMER_H, "$SiLK: sktimer.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>

/**
 *  @file
 *
 *    Implemention of a timer.
 *
 *    This file is part of libsilk-thrd.
 *
 *    Each timer runs in a separate thread.  The timer invokes the
 *    specified callback functions after a given amount of time unless
 *    the timer is destroyed before the timeout occurs.  The return
 *    status of the callback specifies whether the timer should repeat
 *    or end.
 */


/**
 *    The return type of 'skTimer_fn's.  This value indicates whether
 *    the timer should stop, or repeat.
 */
typedef enum {
    SK_TIMER_END, SK_TIMER_REPEAT
} skTimerRepeat_t;

/**
 *    The type of callback functions for timers.  The function will be
 *    called after the timer has waited for the desired duration.  The
 *    'client_data' value passed into the timer creation function will
 *    be passed to the callback.  The return value of the callback is
 *    of type skTimerContinue_t and determines whether the timer
 *    repeats or not.
 */
typedef skTimerRepeat_t (*skTimerFn_t)(
    void       *client_data);


/**
 *    The type of timer handles.
 */
typedef struct sk_timer_st *skTimer_t;


/**
 *    Creates a timer.  The timer starts at time 'start'.  After the
 *    number of seconds determined by the parameter 'secs' has passed,
 *    the callback function 'call_back' will be executed with
 *    'client_data' passed as an argument to it.
 *
 *    Based on the return value of the callback, the timer will repeat
 *    or stop.  The timer handle is passed back as the 'timer' value.
 *    Returns zero on success, non-zero on failure.
 */
int
skTimerCreateAtTime(
    skTimer_t          *timer,
    uint32_t            secs,
    sktime_t            start,
    skTimerFn_t         callback,
    void               *client_data);

/**
 *    Creates a timer.  The timer starts immediately after creation.
 *    After the number of seconds determined by the parameter 'secs'
 *    has passed, the callback function 'call_back' will be executed
 *    with 'client_data' passed as an argument to it.
 *
 *    Based on the return value of the callback, the timer will repeat
 *    or stop.  The timer handle is passed back as the 'timer' value.
 *    Returns zero on success, non-zero on failure.
 */
int
skTimerCreate(
    skTimer_t          *timer,
    uint32_t            secs,
    skTimerFn_t         callback,
    void               *client_data);


/**
 *    Stops and destroys a timer. Returns zero on success, non-zero on
 *    failure.  Does nothing if 'timer' is NULL.
 */
int
skTimerDestroy(
    skTimer_t           timer);

#ifdef __cplusplus
}
#endif
#endif /* _SKTIMER_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
