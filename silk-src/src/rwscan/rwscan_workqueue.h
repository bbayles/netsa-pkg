/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
#ifndef _RWSCAN_WORKQUEUE_H
#define _RWSCAN_WORKQUEUE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWSCAN_WORKQUEUE_H, "$SiLK: rwscan_workqueue.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");


typedef struct work_queue_node_st {
    struct work_queue_node_st *next;       /* next request in queue */
} work_queue_node_t;

/*
 * This threaded queue structure is specialized for a
 * producer/consumer design in two ways.  First, queues can be created
 * with a maximum queue depth parameter, which governs how large the
 * queue can grow in size.  Second, the queue can be "deactivated" to
 * shut down producer threads when the program exits.
 *
 * The queue just maintains node pointers; it does not manage node
 * memory in any way.
 *
 */
typedef struct work_queue_st {
    work_queue_node_t *head;        /* pointer to first node */
    work_queue_node_t *tail;        /* pointer to last node */

    pthread_mutex_t    mutex;       /* master queue lock mutex */
    pthread_cond_t     cond_posted; /* used to wake up a consumer */
    pthread_cond_t     cond_avail;  /* used to signal a producer */

    int                depth;       /* number of items in queue */
    int                maxdepth;    /* max items allowed in queue */
    int                pending;     /* numitems being processed */
    int                active;      /* if work queue has been activated */
#ifdef RWSCN_WORKQUEUE_DEBUG
    int                consumed;    /* num items consumed */
    int                produced;    /* num items posted by producers */
    int                peakdepth;   /* highest queue depth */
#endif
} work_queue_t;


/* Public work queue API */
work_queue_t *
workqueue_create(
    uint32_t            maxdepth);
int
workqueue_put(
    work_queue_t       *q,
    work_queue_node_t  *newnode);
int
workqueue_get(
    work_queue_t       *q,
    work_queue_node_t **retnode);
int
workqueue_depth(
    work_queue_t       *q);

#if 1
int
workqueue_pending(
    work_queue_t       *q);
#endif
int
workqueue_activate(
    work_queue_t       *q);
int
workqueue_deactivate(
    work_queue_t       *q);
void
workqueue_destroy(
    work_queue_t       *q);

#ifdef __cplusplus
}
#endif
#endif /* _RWSCAN_WORKQUEUE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
