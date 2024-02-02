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

#include <silk/silk.h>

RCSIDENT("$SiLK: skdeque.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skdeque.h>


/*
 *  Deque API
 *
 *    A deque is a thread-safe double-ended queue.
 *
 *    There are two types of deques:
 *
 *    --A standard deque is a double-ended queue of objects.
 *
 *    --A merged deque is a deque of deques.  It is a pseudo-deque
 *    which acts like a deque with all the elements of deque-1 in
 *    front of deque-2.  deque-1 and deque-2 behave normally.
 *
 *    Aside from the create function, the functions for the two deques
 *    are implemented using function pointers.
 *
 */


/* typedef struct sk_deque_st *skDeque_t;  // skdeque.h  */

/* Deque data structure */
typedef struct sk_deque_st {
    struct methods_st {
        skDQErr_t (*block)(skDeque_t self, uint8_t flag);
        skDQErr_t (*destroy)(skDeque_t self);
        skDQErr_t (*peek)(skDeque_t self, void **item, uint8_t front);
        skDQErr_t (*pop)(skDeque_t self, void **item, uint8_t block,
                         uint8_t front, uint32_t seconds);
        skDQErr_t (*push)(skDeque_t self, void *item, uint8_t front);
        uint32_t  (*size)(skDeque_t self);
        skDQErr_t (*status)(skDeque_t self);
    }                   methods;

    pthread_mutex_t     mutex_data; /* mutex storage */
    pthread_mutex_t    *mutex;      /* mutex */
    pthread_cond_t      cond_data;  /* condition variable storage */
    pthread_cond_t     *cond;       /* condition variable */
    void               *data;       /* data (NULL == destroyed) */
    uint8_t             ref;        /* reference count */
} sk_deque_t;

/* Deque item */
typedef struct skdq_item_st skdq_item_t;
struct skdq_item_st {
    void           *item;
    skdq_item_t    *dir[2];      /* 0 == back, 1 == front */
};



/*
 *  Functions for the standard deque
 *  ******************************************************************
 */

/* Standard deque */
typedef struct skdq_std_st {
    skdq_item_t    *dir[2];     /* 0 == back, 1 == front */
    uint32_t        size;
    uint8_t         blocked;
} skdq_std_t;

static skDQErr_t
std_block(
    skDeque_t           self,
    uint8_t             flag)
{
    skdq_std_t *q = (skdq_std_t *)self->data;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    q->blocked = flag;
    if (!flag) {
        pthread_cond_broadcast(self->cond);
    }

    return SKDQ_SUCCESS;
}

static uint32_t
std_size(
    skDeque_t           self)
{
    skdq_std_t *q = (skdq_std_t *)self->data;

    return q->size;
}

static skDQErr_t
std_status(
    skDeque_t           self)
{
    skdq_std_t *q = (skdq_std_t *)self->data;

    if (q == NULL) {
        return SKDQ_ERROR;
    }
    if (q->dir[0] == NULL) {
        return SKDQ_EMPTY;
    }
    return SKDQ_SUCCESS;
}

static skDQErr_t
std_peek(
    skDeque_t           self,
    void              **item,
    uint8_t             front)
{
    skdq_std_t *q = (skdq_std_t *)self->data;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    if (q->dir[0] == NULL) {
        return SKDQ_EMPTY;
    }

    *item = q->dir[front]->item;

    return SKDQ_SUCCESS;
}

static skDQErr_t
std_pop(
    skDeque_t           self,
    void              **item,
    uint8_t             block,
    uint8_t             f,
    uint32_t            seconds)
{
    skdq_std_t *q = (skdq_std_t *)self->data;
    skdq_item_t *t;
    uint8_t b;
    int rv;
    struct timeval now;
    struct timespec to;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    if (block) {
        gettimeofday(&now, NULL);
        to.tv_sec = now.tv_sec + seconds;
        to.tv_nsec = now.tv_usec * 1000;
        while (self->data && q->dir[0] == NULL && q->blocked) {
            if (seconds) {
                rv = pthread_cond_timedwait(self->cond, self->mutex, &to);
                if (rv == ETIMEDOUT) {
                    return SKDQ_TIMEDOUT;
                }
            } else {
                pthread_cond_wait(self->cond, self->mutex);
            }
        }
        if (self->data && !q->blocked) {
            return SKDQ_UNBLOCKED;
        }
    }
    if (self->data == NULL) {
        return SKDQ_DESTROYED;
    }
    if (q->dir[0] == NULL) {
        return SKDQ_EMPTY;
    }

    b = 1 - f;

    t = q->dir[f];
    *item = t->item;

    q->dir[f] = t->dir[b];
    if (q->dir[f]) {
        q->dir[f]->dir[f] = NULL;
    } else {
        q->dir[b] = NULL;
    }

    q->size--;

    free(t);

    return SKDQ_SUCCESS;
}

static skDQErr_t
std_push(
    skDeque_t           self,
    void               *item,
    uint8_t             f)
{
    skdq_std_t *q = (skdq_std_t *)self->data;
    skdq_item_t *t;
    uint8_t b;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    if ((t = (skdq_item_t *)malloc(sizeof(skdq_item_t))) == NULL) {
        return SKDQ_ERROR;
    }

    t->item = item;

    b = 1 - f;

    t->dir[f] = NULL;
    t->dir[b] = q->dir[f];
    q->dir[f] = t;
    if (q->dir[b]) {
        t->dir[b]->dir[f] = t;
    } else {
        q->dir[b] = t;
        pthread_cond_broadcast(self->cond);
    }

    q->size++;

    return SKDQ_SUCCESS;
}

static skDQErr_t
std_destroy(
    skDeque_t           self)
{
    skdq_std_t *q = (skdq_std_t *)self->data;
    skdq_item_t *t, *x;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    for (t = q->dir[1]; t; t = x) {
        x = t->dir[0];
        free(t);
    }

    free(q);

    self->data = NULL;

    return SKDQ_SUCCESS;
}

/* Create a standard deque */
skDeque_t
skDequeCreate(
    void)
{
    skDeque_t deque;
    skdq_std_t *data;

    /* memory allocation */
    if ((deque = (skDeque_t)malloc(sizeof(sk_deque_t))) == NULL) {
        return NULL;
    }
    if ((data = (skdq_std_t *)malloc(sizeof(skdq_std_t))) == NULL) {
        free(deque);
        return NULL;
    }

    /* Initialize data */
    data->dir[0] = data->dir[1] = NULL;
    data->size = 0;
    data->blocked = 1;

    /* Initialize deque */
    deque->ref = 1;
    pthread_mutex_init(&deque->mutex_data, NULL);
    pthread_cond_init(&deque->cond_data, NULL);
    deque->mutex = &deque->mutex_data;
    deque->cond = &deque->cond_data;
    deque->methods.status = std_status;
    deque->methods.pop = std_pop;
    deque->methods.peek = std_peek;
    deque->methods.push = std_push;
    deque->methods.destroy = std_destroy;
    deque->methods.block = std_block;
    deque->methods.size = std_size;
    deque->data = (void *)data;

    return deque;
}



/*
 *  Functions for a deque of deques (a merged deque)
 *  ******************************************************************
 */

typedef struct skdq_merged_st {
    skDeque_t q[2];             /* 0 == back, 1 == front */
} skdq_merged_t;

static skDQErr_t
merged_block(
    skDeque_t           self,
    uint8_t             flag)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;
    skDQErr_t err = SKDQ_SUCCESS;
    uint8_t i;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    for (i = 0; i <= 1 && err == SKDQ_SUCCESS; i++) {
        err = q->q[i]->methods.block(q->q[i], flag);
    }

    return err;
}

static uint32_t
merged_size(
    skDeque_t           self)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;

    return (q->q[0]->methods.size(q->q[0]) + q->q[1]->methods.size(q->q[1]));
}

static skDQErr_t
merged_status(
    skDeque_t           self)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;
    skDQErr_t retval;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    if ((retval = q->q[0]->methods.status(q->q[0])) == SKDQ_EMPTY) {
        retval = q->q[1]->methods.status(q->q[1]);
    }

    return retval;
}

static skDQErr_t
merged_peek(
    skDeque_t           self,
    void              **item,
    uint8_t             f)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;
    skDQErr_t retval;
    uint8_t b;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    b = 1 - f;

    if ((retval = q->q[f]->methods.peek(q->q[f], item, f)) == SKDQ_EMPTY) {
        retval = q->q[b]->methods.peek(q->q[b], item, f);
    }

    return retval;
}

static skDQErr_t
merged_pop(
    skDeque_t           self,
    void              **item,
    uint8_t             block,
    uint8_t             f,
    uint32_t            seconds)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;
    skDQErr_t retval = SKDQ_SUCCESS;
    uint8_t b;
    int rv;
    struct timeval now;
    struct timespec to;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    if (block) {
        gettimeofday(&now, NULL);
        to.tv_sec = now.tv_sec + seconds;
        to.tv_nsec = now.tv_usec * 1000;
        while (self->data && merged_status(self) == SKDQ_EMPTY) {
            if (seconds) {
                rv = pthread_cond_timedwait(self->cond, self->mutex, &to);
                if (rv == ETIMEDOUT) {
                    return SKDQ_TIMEDOUT;
                }
            } else {
                pthread_cond_wait(self->cond, self->mutex);
            }
        }
    }

    if (self->data == NULL) {
        return SKDQ_DESTROYED;
    }

    if ((retval = merged_status(self)) != SKDQ_SUCCESS) {
        return retval;
    }

    b = 1 - f;

    retval = q->q[f]->methods.pop(q->q[f], item, 0, f, 0);
    if (retval == SKDQ_EMPTY) {
        retval = q->q[b]->methods.pop(q->q[b], item, 0, f, 0);
    }

    return retval;
}

static skDQErr_t
merged_push(
    skDeque_t           self,
    void               *item,
    uint8_t             f)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    return q->q[f]->methods.push(q->q[f], item, f);
}

static skDQErr_t
merged_destroy(
    skDeque_t           self)
{
    skdq_merged_t *q = (skdq_merged_t *)self->data;
    uint8_t i;

    if (q == NULL) {
        return SKDQ_ERROR;
    }

    for (i = 0; i <= 1; i++) {
        q->q[i]->mutex = &q->q[i]->mutex_data;
        q->q[i]->cond = &q->q[i]->cond_data;
        skDequeDestroy(q->q[i]);
    }

    free(q);

    return SKDQ_SUCCESS;
}

/* Creates a new pseudo-deque which acts like a deque with all the
 * elements of q1 in front of q2.  q1 and q2 continue behaving
 * normally. */
skDeque_t
skDequeCreateMerged(
    skDeque_t           q1,
    skDeque_t           q2)
{
    volatile skDeque_t deque;
    skdq_merged_t *data;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
    uint8_t i;

    if (q1 == NULL || q2 == NULL ||
        q1->data == NULL || q2->data == NULL) {
        return NULL;
    }

    /* memory allocation */
    if ((deque = (skDeque_t)malloc(sizeof(sk_deque_t))) == NULL) {
        return NULL;
    }
    if ((data = (skdq_merged_t *)malloc(sizeof(skdq_merged_t))) == NULL) {
        free(deque);
        return NULL;
    }

    /* Initialize data */
    if ((data->q[1] = skDequeCopy(q1)) == NULL) {
        free(data);
        free(deque);
        return NULL;
    }
    if ((data->q[0] = skDequeCopy(q2)) == NULL) {
        skDequeDestroy(data->q[1]);
        free(data);
        free(deque);
        return NULL;
    }

    /* Initialize deque */
    deque->ref = 1;
    pthread_mutex_init(&deque->mutex_data, NULL);
    pthread_cond_init(&deque->cond_data, NULL);
    deque->mutex = &deque->mutex_data;
    deque->cond = &deque->cond_data;
    deque->methods.status = merged_status;
    deque->methods.pop = merged_pop;
    deque->methods.peek = merged_peek;
    deque->methods.push = merged_push;
    deque->methods.destroy = merged_destroy;
    deque->methods.block = merged_block;
    deque->methods.size = merged_size;
    deque->data = (void *)data;

    /** Reorganize subdeques' mutexes and condition variables **/

    /* Lock our own */
    pthread_mutex_lock(deque->mutex);

    for (i = 0; i <= 1; ++i) {
        /* Grab q[i] */
        pthread_mutex_lock(data->q[i]->mutex);
        mutex = data->q[i]->mutex;
        cond = data->q[i]->cond;
        /* Fix its mutex and condition variable to be ours */
        data->q[i]->mutex = deque->mutex;
        data->q[i]->cond = deque->cond;
        /* Wake up anything waiting on it so they pick up the new
         * condition variable. */
        pthread_cond_broadcast(cond);
        /* Unlock */
        pthread_mutex_unlock(mutex);
    }

    pthread_mutex_unlock(deque->mutex);

    return deque;
}



/*
 *  Generic Functions that operate on any deque
 *  ******************************************************************
 */

/* Creates a copy of a deque.  Operations on both deques will affect
 * each other. */
skDeque_t
skDequeCopy(
    volatile skDeque_t  deque)
{
    int die = 0;

    if (deque == NULL || deque->data == NULL) {
        return NULL;
    }
    pthread_mutex_lock(deque->mutex);
    if (deque->data == NULL) {
        die = 1;
    } else {
        deque->ref++;
    }
    pthread_mutex_unlock(deque->mutex);

    if (die) {
        return NULL;
    }
    return deque;
}


/* Destroy and free a deque.  (Not reponsible for freeing the elements
 * within the deque). */
skDQErr_t
skDequeDestroy(
    skDeque_t           deque)
{
    int destroy;

    if (deque == NULL) {
        return SKDQ_ERROR;
    }

    pthread_mutex_lock(deque->mutex);

    if ((destroy = (--deque->ref == 0))) {
        /* Call destructor method */
        deque->methods.destroy(deque);

        /* Mark as destroyed */
        deque->data = NULL;

        /* Give all the condition waiting threads a chance to exit. */
        pthread_cond_broadcast(deque->cond);
    }

    pthread_mutex_unlock(deque->mutex);

    if (destroy) {
        while (pthread_mutex_destroy(deque->mutex) == EBUSY)
            ; /* empty */
        while (pthread_cond_destroy(deque->cond) == EBUSY) {
            pthread_cond_broadcast(deque->cond);
        }
        free(deque);
    }

    return SKDQ_SUCCESS;
}


skDQErr_t
skDequeBlock(
    skDeque_t           deque)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.block(deque, 1);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}

skDQErr_t
skDequeUnblock(
    skDeque_t           deque)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.block(deque, 0);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}


/* Return the size of a deque. */
uint32_t
skDequeSize(
    skDeque_t           deque)
{
    uint32_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.size(deque);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}


/* Return the status of a deque. */
skDQErr_t
skDequeStatus(
    skDeque_t           deque)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.status(deque);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}


/* Peek at an element from a deque. */
static skDQErr_t
sk_deque_peek(
    skDeque_t           deque,
    void              **item,
    uint8_t             front)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.peek(deque, item, front);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}

/* Return the first or last element of a deque without removing it, or
 * SKDQ_EMPTY if the deque is empty.  */
skDQErr_t
skDequeFront(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_peek(deque, item, 1);
}
skDQErr_t
skDequeBack(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_peek(deque, item, 0);
}


/* Pop an element from a deque.  */
static skDQErr_t
sk_deque_pop(
    skDeque_t           deque,
    void              **item,
    uint8_t             block,
    uint8_t             front,
    uint32_t            seconds)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.pop(deque, item, block, front, seconds);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}

/*
 *  Pop an element from a deque.
 *
 *  skDequePop{Front,Back} will block until an item is available in
 *  the deque.  skDequePop{Front,Back}NB will return SKDQ_EMPTY if the
 *  deque is empty instead.
 */
skDQErr_t
skDequePopFront(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_pop(deque, item, 1, 1, 0);
}
skDQErr_t
skDequePopFrontNB(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_pop(deque, item, 0, 1, 0);
}
skDQErr_t
skDequePopFrontTimed(
    skDeque_t           deque,
    void              **item,
    uint32_t            seconds)
{
    return sk_deque_pop(deque, item, 1, 1, seconds);
}
skDQErr_t
skDequePopBack(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_pop(deque, item, 1, 0, 0);
}
skDQErr_t
skDequePopBackNB(
    skDeque_t           deque,
    void              **item)
{
    return sk_deque_pop(deque, item, 0, 0, 0);
}
skDQErr_t
skDequePopBackTimed(
    skDeque_t           deque,
    void              **item,
    uint32_t            seconds)
{
    return sk_deque_pop(deque, item, 1, 0, seconds);
}


/* Push an element onto a deque. */
static skDQErr_t
sk_deque_push(
    skDeque_t           deque,
    void               *item,
    uint8_t             front)
{
    skDQErr_t retval;

    pthread_mutex_lock(deque->mutex);

    retval = deque->methods.push(deque, item, front);

    pthread_mutex_unlock(deque->mutex);

    return retval;
}

/* Push an item onto a deque. */
skDQErr_t
skDequePushFront(
    skDeque_t           deque,
    void               *item)
{
    return sk_deque_push(deque, item, 1);
}
skDQErr_t
skDequePushBack(
    skDeque_t           deque,
    void               *item)
{
    return sk_deque_push(deque, item, 0);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
