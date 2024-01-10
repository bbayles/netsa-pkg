/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  picq.c
 *  General pickable queue implementation
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

/**
 * @file
 *
 * Generic Pickable Queue. A pickable queue's elements may be removed from any
 * point in the queue, and added to the queue's head or tail. Together with a
 * hash table to locate mid-queue elements, this can be used to implement idle
 * timeout of its elements.
 *
 * Where present, a <tt>vq</tt> argument is a void pointer to a queue. A
 * queue's first two members must be a pointer to the tail (last node) of the
 * queue and a pointer to the head (first node) of the queue.
 *
 * Where present, a <tt>vn</tt> argument is a void pointer to a queue node.
 * A queue node's first two elements must be a pointer to the previous node
 * in the queue and a pointer to the next node in the queue.
 */

/* idem hack */
#ifndef _YAF_PICQ_H_
#define _YAF_PICQ_H_
#include <yaf/autoinc.h>


/**
 * Pick a node from a given pickable queue. The node is removed from the queue,
 * and its previous and next pointers are set to NULL. It is assumed that the
 * node is actually an element of the given queue; undefined behavior may
 * result if this is not the case.
 *
 * @param vq queue to remove from
 * @param vn node to remove
 */
void
piqPick(
    void  *vq,
    void  *vn);

/**
 * Enqueue a node at the head of a given pickable queue. The node must not be
 * an element in another queue; that is, its own previous and next pointers
 * must be NULL. To move a node from one queue to another, use piqPick()
 * first.
 *
 * @param vq queue to enqueue to
 * @param vn node to enqueue
 */
void
piqEnQ(
    void  *vq,
    void  *vn);

/**
 * Enqueue a node at the tail of a given pickable queue. The node must not be
 * an element in another queue; that is, its own previous and next pointers
 * must be NULL. To move a node from one queue to another, use piqPick()
 * first.
 *
 * @param vq queue to enqueue to
 * @param vn node to enqueue
 */
void
piqUnshift(
    void  *vq,
    void  *vn);

/**
 * Dequeue a node from the head of a given pickable queue. Analogous to finding
 * the head, picking it, then returning it. The node is removed from the queue,
 * and its previous and next pointers are set to NULL. Returns NULL if the
 * queue is empty.
 *
 * @param vq queue to remove from
 * @return the dequeued head of the queue, or NULL if empty.
 */
void *
piqShift(
    void  *vq);

/**
 * Dequeue a node from the tail of a given pickable queue. Analogous to finding
 * the tail, picking it, then returning it. The node is removed from the queue,
 * and its previous and next pointers are set to NULL. Returns NULL if the
 * queue is empty.
 *
 * @param vq queue to remove from
 * @return the dequeued tail of the queue, or NULL if empty.
 */
void *
piqDeQ(
    void  *vq);

#endif /* ifndef _YAF_PICQ_H_ */
