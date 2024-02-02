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

#include <silk/silk.h>

RCSIDENT("$SiLK: rwscan_workqueue.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwscan_workqueue.h"



work_queue_t *
workqueue_create(
    uint32_t            maxdepth)
{
    work_queue_t *q;

    q = (work_queue_t *) calloc(1, sizeof(work_queue_t));
    if (q == NULL) {
        return (work_queue_t *) NULL;
    }

    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_posted, NULL);
    pthread_cond_init(&q->cond_avail, NULL);

    q->maxdepth = maxdepth;
    q->active   = 1;

    return q;
}

int
workqueue_activate(
    work_queue_t       *q)
{
    if (pthread_mutex_lock(&q->mutex)) {
        return 0;
    }
    q->active = 1;
    pthread_mutex_unlock(&q->mutex);
    pthread_cond_broadcast(&q->cond_posted);
    return 1;
}

int
workqueue_deactivate(
    work_queue_t       *q)
{
    if (pthread_mutex_lock(&q->mutex)) {
        return 0;
    }
    q->active = 0;
    pthread_mutex_unlock(&q->mutex);
    pthread_cond_broadcast(&q->cond_posted);
    return 1;
}



void
workqueue_destroy(
    work_queue_t       *q)
{
    if (q == NULL) {
        return;
    }

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_posted);
    pthread_cond_destroy(&q->cond_avail);
    free(q);
}


int
workqueue_put(
    work_queue_t       *q,
    work_queue_node_t  *newnode)
{
    if (newnode == NULL || q == NULL) {
        return -1;
    }

    pthread_mutex_lock(&q->mutex);

    while ((q->maxdepth > 0) && (q->depth + q->pending >= q->maxdepth)) {
        /* queue is full - wait on cond var for notification that a slot has
         * become open */
        pthread_cond_wait(&q->cond_avail, &q->mutex);
    }

    if (q->tail == NULL) {
        q->tail = q->head = newnode;
    } else {
        q->tail->next = newnode;
        q->tail       = newnode;
    }

    newnode->next = NULL;

    q->depth++;

    /* release queue mutex and signal consumer that an item is ready */
    pthread_mutex_unlock(&q->mutex);
    pthread_cond_signal(&q->cond_posted);


#ifdef RWSCN_WORKQUEUE_DEBUG
    /* update the peak depth, if needed */
    if (q->depth > q->peakdepth) {
        q->peakdepth = q->depth;
    }

    q->produced++;
#endif

    return q->depth;
}


int
workqueue_get(
    work_queue_t       *q,
    work_queue_node_t **retnode)
{
    work_queue_node_t *node;

    if (q->head == NULL || q->depth == 0) {
        retnode = NULL;
        return -1;
    }

    node = q->head;
    if (node->next) {
        q->head = node->next;
    } else {
        q->head = NULL;
        q->tail = q->head = NULL;
    }

    node->next = NULL;
    *retnode   = node;

    q->depth--;
    q->pending++;

#ifdef RWSCN_WORKQUEUE_DEBUG
    q->consumed++;
#endif

    return 0;
}

int
workqueue_depth(
    work_queue_t       *q)
{
    return q->depth;
}

int
workqueue_pending(
    work_queue_t       *q)
{
    return q->pending;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
