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
#ifndef _CIRCBUF_H
#define _CIRCBUF_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_CIRCBUF_H, "$SiLK: circbuf.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  circbuf.h
**
**    Circular buffer API
**
**    A circular buffer is a thread-safe FIFO with a maximum memory
**    size.
*/

/*
 *    The type for the circular buffer.
 */
struct sk_circbuf_st;
typedef struct sk_circbuf_st sk_circbuf_t;


/*
 *    The normal maximum size (in bytes) of a single chunk in a
 *    circular buffer.  (Circular buffers are allocated in chunks, as
 *    neeeded.)  A single chunk will will always be at least 3 times
 *    the item_size, regardless of the value of
 *    SK_CIRCBUF_CHUNK_MAX_SIZE.
 */
#define SK_CIRCBUF_CHUNK_MAX_SIZE 0x20000   /* 128k */


/*
 *    Status codes returned by the sk_circbuf_t functions.
 */
enum sk_circbuf_status_en {
    /*  Success */
    SK_CIRCBUF_OK = 0,
    /*  Memory allocation error */
    SK_CIRCBUF_E_ALLOC,
    /*  Bad parameter to function */
    SK_CIRCBUF_E_BAD_PARAM,
    /*  The sk_circbuf_t is stopped. */
    SK_CIRCBUF_E_STOPPED
};
typedef enum sk_circbuf_status_en sk_circbuf_status_t;


/*
 *    Creates a circular buffer which can contain at least
 *    'item_count' items each of size 'item_size' and stores the
 *    circular buffer at the location specified by 'buf'.
 *
 *    Returns SK_CIRCBUF_E_BAD_PARAM if 'buf' is NULL, if either
 *    numeric parameter is 0, or if 'item_size' is larger than 85MiB.
 *    Returns SK_CIRCBUF_E_ALLOC if there is not enough memory.  The
 *    created circular buffer may contain space for more than
 *    'item_count' items, up to the size of a circular buffer chunk.
 */
int
skCircBufCreate(
    sk_circbuf_t      **buf,
    uint32_t            item_size,
    uint32_t            item_count);

/*
 *    Causes all threads waiting on the circular buffer 'buf' to
 *    return.
 */
void
skCircBufStop(
    sk_circbuf_t       *buf);

/*
 *    Destroys the circular buffer 'buf'.  For proper clean-up, the
 *    caller should call skCircBufStop() before calling this function.
 *    Does nothing if 'buf' is NULL.
 */
void
skCircBufDestroy(
    sk_circbuf_t       *buf);

/*
 *    Sets the location referenced by 'writer_pos'--which should be a
 *    pointer-pointer---to an empty memory block in the circular
 *    buffer 'buf' and returns SK_CIRCBUF_OK.  When 'item_count' is
 *    not NULL, the location it references is set to number of items
 *    currently in 'buf' (the returned block is included in the item
 *    count).
 *
 *    This block should be used to add data to the circular buffer.
 *    The size of the block is the 'item_size' specified when 'buf'
 *    was created.
 *
 *    This call blocks if the buffer is full. The function returns
 *    SK_CIRCBUF_E_STOPPED if skCircBufStop() or skCircBufDestroy()
 *    are called while waiting.  The function returns
 *    SK_CIRCBUF_E_ALLOC when an attempt to allocate a new chunk
 *    fails.
 *
 *    When the function returns a value other than SK_CIRCBUF_OK, the
 *    pointer referenced by 'writer_pos' is set to NULL and the value
 *    in 'item_count' is not defined.
 *
 *    The circular buffer considers the returned block locked by the
 *    caller.  The block is not made available for use by
 *    skCircBufGetReaderBlock() until skCircBufGetWriterBlock() is
 *    called again.
 */
int
skCircBufGetWriterBlock(
    sk_circbuf_t       *buf,
    void               *writer_pos,
    uint32_t           *item_count);

/*
 *    Sets the location referenced by 'reader_pos'--which should be a
 *    pointer-pointer---to a full memory block in the circular buffer
 *    'buf' and returns SK_CIRCBUF_OK.  When 'item_count' is not NULL,
 *    the location it references is set to number of items currently
 *    in 'buf' (the returned item is included in the item count).
 *
 *    This block should be used to get data from the circular buffer.
 *    The size of the block is the 'item_size' specified when 'buf'
 *    was created.  The block is the least recently added item from a
 *    call to skCircBufGetWriterBlock().
 *
 *    This call blocks if the buffer is full. The function returns
 *    SK_CIRCBUF_E_STOPPED if skCircBufStop() or skCircBufDestroy()
 *    are called while waiting.
 *
 *    When the function returns a value other than SK_CIRCBUF_OK, the
 *    pointer referenced by 'reader_pos' is set to NULL and the value
 *    in 'item_count' is not defined.
 *
 *    The circular buffer considers the returned block locked by the
 *    caller.  The block is not made available for use by
 *    skCircBufGetWriterBlock() until skCircBufGetReaderBlock() is
 *    called again.
 */
int
skCircBufGetReaderBlock(
    sk_circbuf_t       *buf,
    void               *reader_pos,
    uint32_t           *item_count);

#ifdef __cplusplus
}
#endif
#endif /* _CIRCBUF_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
