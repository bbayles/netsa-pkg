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

RCSIDENT("$SiLK: circbuf.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sklog.h>
#include "circbuf.h"

#ifdef CIRCBUF_TRACE_LEVEL
#define TRACEMSG_LEVEL 1
#endif
#define TRACEMSG( msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>

/* Minimum number of items which should be storable in a chunk */
#define SK_CIRCBUF_MINIMUM_ITEMS_PER_CHUNK 3

/* Maximum possible size of a single item */
#define SK_CIRCBUF_CHUNK_MAXIMUM_ITEM_SIZE                 \
    ((1 << 28) / SK_CIRCBUF_MINIMUM_ITEMS_PER_CHUNK)


/*
 *    The sk_circbuf_t hands cells to the writing thread which that
 *    thread fills.  The sk_circbuf_t holds onto these cells until the
 *    reading thread requests them.  The maxinum number of cells a
 *    sk_circbuf_t may allocate is specified at creatation time.
 *    However, the cells are not allocated as one block of memory.
 *    Instead, the sk_circbuf_t allocates smaller blocks of memory
 *    called chunks.  All chunks are the same size.  To summarize, the
 *    sk_circbuf_t is composed of multiple chunks, and a chunk is
 *    composed of multiple cells.
 *
 *    For each chunk, the 'writer' member points to the cell currently
 *    in use by the writing thread, and the 'reader' member points to
 *    the cell currently in use by the reading thread.
 *
 *    All cells "between" the 'reader' and the 'writer' have data.  In
 *    the diagram below, the 'writer' has wrapped around, and all
 *    cells with 'D' have data.  'W' is where the writing thread is
 *    currently writing data, and 'R' is where the reading thread is
 *    reading.
 *
 *        _ _ _ _ _ _ _ _ _ _ _ _
 *       |D|D|W|_|_|_|_|_|R|D|D|D|
 *            A A         A A
 *            | |         | |
 *            | next_wtr  | next_rdr
 *            |           |
 *            writer      reader
 *
 *    When the writing thread or reading thread finishes with a cell,
 *    it calls the appropriate "get next" function which releases the
 *    current cell and moves the thread to the next cell.
 *
 *    If a chunk becomes full and the number of cells is not at the
 *    maximum, a new chunk is allocated and the writer starts using
 *    cells from the new chunk.  Depending on the chunk size and
 *    maximum number of cells allowed, there may be multiple chunks in
 *    the chunk list between the writer and the reader.
 *
 *    Once the reading thread finishes with all the cells in the
 *    current chunk, the reader moves to the first cell of the next
 *    chunk in the chunk list, and the chunk the reader just completed
 *    is discarded.  The sk_circbuf_t is circular within a chunk, but
 *    like a linked list between multiple chunks.
 *
 *    The first time the sk_circbuf_t has a chunk to discard, the
 *    sk_circbuf_t stores the chunk as spare (instead of deallocating
 *    the chunk).  When a chunk needs to be discard and the
 *    sk_circbuf_t already has a spare chunk, the chunk is
 *    deallocated.
 *
 */
typedef struct circbuf_chunk_st circbuf_chunk_t;
struct circbuf_chunk_st {
    /* Next chunk in chunk list */
    circbuf_chunk_t *next;
    /* Next writer cell index */
    uint32_t         next_writer;
    /* Current writer cell index */
    uint32_t         writer;
    /* Next reader cell index */
    uint32_t         next_reader;
    /* Current reader cell index */
    uint32_t         reader;
    /* Buffer containing cells */
    uint8_t         *data;
    /* True if all cells are used */
    unsigned         full   :1;
};


/* sk_circbuf_t */
struct sk_circbuf_st {
    /* Maximum number of cells */
    uint32_t         maxcells;
    /* Current number of cells in use, across all chunks */
    uint32_t         cellcount;
    /* Size of a single cell */
    uint32_t         cellsize;
    /* Number of cells per chunk */
    uint32_t         cells_per_chunk;
    /* Writer chunk */
    circbuf_chunk_t *writer_chunk;
    /* Rreader chunk */
    circbuf_chunk_t *reader_chunk;
    /* Spare chunk */
    circbuf_chunk_t *spare_chunk;
    /* Mutex */
    pthread_mutex_t  mutex;
    /* Condition variable */
    pthread_cond_t   cond;
    /* Number of threads waiting on this buf */
    uint32_t         wait_count;
    /* True if the buf has been stopped */
    unsigned         destroyed : 1;
};
/* typedef struct sk_circbuf_st sk_circbuf_t; */


/* Allocate a new chunk */
static circbuf_chunk_t *
circbuf_alloc_chunk(
    sk_circbuf_t       *buf)
{
    circbuf_chunk_t *chunk;

    if (buf->spare_chunk) {
        /* If there is a spare chunk, use it.  We maintain a spare
         * chunk to avoid reallocating frequently when items are
         * removed more quickly then they are added. */
        chunk = buf->spare_chunk;
        buf->spare_chunk = NULL;
        chunk->next_writer = chunk->reader = 0;
    } else {
        /* Otherwise, allocate a new chunk. */
        chunk = (circbuf_chunk_t*)calloc(1, sizeof(circbuf_chunk_t));
        if (chunk == NULL) {
            return NULL;
        }
        chunk->data = (uint8_t*)malloc(buf->cells_per_chunk * buf->cellsize);
        if (chunk->data == NULL) {
            free(chunk);
            return NULL;
        }
    }
    chunk->writer = buf->cells_per_chunk - 1;
    chunk->next_reader = 1;
    chunk->next = NULL;

    return chunk;
}


int
skCircBufCreate(
    sk_circbuf_t      **buf_out,
    uint32_t            item_size,
    uint32_t            item_count)
{
    sk_circbuf_t *buf;
    uint32_t chunks;

    if (NULL == buf_out) {
        return SK_CIRCBUF_E_BAD_PARAM;
    }
    *buf_out = NULL;

    if (item_count == 0
        || item_size == 0
        || item_size > SK_CIRCBUF_CHUNK_MAXIMUM_ITEM_SIZE)
    {
        return SK_CIRCBUF_E_BAD_PARAM;
    }

    buf = (sk_circbuf_t*)calloc(1, sizeof(sk_circbuf_t));
    if (buf == NULL) {
        return SK_CIRCBUF_E_ALLOC;
    }

    buf->cellsize = item_size;

    buf->cells_per_chunk = SK_CIRCBUF_CHUNK_MAX_SIZE / item_size;
    if (buf->cells_per_chunk < SK_CIRCBUF_MINIMUM_ITEMS_PER_CHUNK) {
        buf->cells_per_chunk = SK_CIRCBUF_MINIMUM_ITEMS_PER_CHUNK;
    }

    /* Number of chunks required to handle item_count cells */
    chunks = 1 + (item_count - 1) / buf->cells_per_chunk;
    buf->maxcells = buf->cells_per_chunk * chunks;

    /* Create the initial chunk */
    buf->reader_chunk = buf->writer_chunk = circbuf_alloc_chunk(buf);
    if (buf->reader_chunk == NULL) {
        free(buf);
        return SK_CIRCBUF_E_ALLOC;
    }
    /* The initial chunk needs to pretend that its reader starts at -1
     * instead of 0, because its reader is not coming from a previous
     * chunk.  This is a special case that should only happen once. */
    buf->reader_chunk->reader = buf->cells_per_chunk - 1;
    buf->reader_chunk->next_reader = 0;

    pthread_mutex_init(&buf->mutex, NULL);
    pthread_cond_init(&buf->cond, NULL);
    *buf_out = buf;
    return SK_CIRCBUF_OK;
}


int
skCircBufGetWriterBlock(
    sk_circbuf_t       *buf,
    void               *writer_pos,
    uint32_t           *out_item_count)
{
    int retval;

    assert(buf);
    assert(writer_pos);

    pthread_mutex_lock(&buf->mutex);

    ++buf->wait_count;

    /* Wait for an empty cell */
    while (!buf->destroyed && (buf->cellcount == buf->maxcells)) {
        TRACEMSG((("skCircBufGetWriterBlock() full, count is %" PRIu32),
                  buf->cellcount));
        pthread_cond_wait(&buf->cond, &buf->mutex);
    }

    if (buf->cellcount <= 1) {
        /* If previously, the buffer was empty, signal waiters */
        pthread_cond_broadcast(&buf->cond);
    }

    /* Increment the cell count */
    ++buf->cellcount;

    if (out_item_count) {
        *out_item_count = buf->cellcount;
    }

    if (buf->destroyed) {
        *(uint8_t**)writer_pos = NULL;
        retval = SK_CIRCBUF_E_STOPPED;
        pthread_cond_broadcast(&buf->cond);
    } else {
        /* Get the writer chunk */
        circbuf_chunk_t *chunk = buf->writer_chunk;

        /* If the writer chunk is full */
        if (chunk->full) {
            assert(chunk->next == NULL);
            chunk->next = circbuf_alloc_chunk(buf);
            if (chunk->next == NULL) {
                *(uint8_t**)writer_pos = NULL;
                retval = SK_CIRCBUF_E_ALLOC;
                goto END;
            }

            /* Make the next chunk the new writer chunk*/
            chunk = chunk->next;
            assert(chunk->next == NULL);
            buf->writer_chunk = chunk;
        }
        /* Return value is the next writer position */
        *(uint8_t**)writer_pos = &chunk->data[chunk->next_writer
                                              * buf->cellsize];
        retval = SK_CIRCBUF_OK;

        /* Increment the current writer and the next_writer,
         * accounting for wrapping of the next_writer */
        chunk->writer = chunk->next_writer;
        ++chunk->next_writer;
        if (chunk->next_writer == buf->cells_per_chunk) {
            chunk->next_writer = 0;
        }

        /* Check to see if we have filled this chunk */
        if (chunk->next_writer == chunk->reader) {
            chunk->full = 1;
        }
    }

  END:

    --buf->wait_count;

    pthread_mutex_unlock(&buf->mutex);

    return retval;
}


int
skCircBufGetReaderBlock(
    sk_circbuf_t       *buf,
    void               *reader_pos,
    uint32_t           *out_item_count)
{
    int retval;

    assert(buf);
    assert(reader_pos);

    pthread_mutex_lock(&buf->mutex);

    ++buf->wait_count;

    /* Wait for a full cell */
    while (!buf->destroyed && (buf->cellcount <= 1)) {
        pthread_cond_wait(&buf->cond, &buf->mutex);
    }

    /* If previously, the buffer was full, signal waiters */
    if (buf->cellcount == buf->maxcells) {
        pthread_cond_broadcast(&buf->cond);
    }

    if (out_item_count) {
        *out_item_count = buf->cellcount;
    }

    /* Decrement the cell count */
    --buf->cellcount;

    if (buf->destroyed) {
        *(uint8_t**)reader_pos = NULL;
        retval = SK_CIRCBUF_E_STOPPED;
        pthread_cond_broadcast(&buf->cond);
    } else {
        /* Get the reader chunk */
        circbuf_chunk_t *chunk = buf->reader_chunk;

        /* Mark the chunk as not full */
        chunk->full = 0;

        /* Increment the reader and the next_reader, accounting for
         * wrapping of the next_reader */
        chunk->reader = chunk->next_reader;
        ++chunk->next_reader;
        if (chunk->next_reader == buf->cells_per_chunk) {
            chunk->next_reader = 0;
        }

        /* Move to next chunk if we have emptied this one (and not last) */
        if (chunk->reader == chunk->next_writer) {
            circbuf_chunk_t *next_chunk;

            next_chunk = chunk->next;

            /* Free the reader chunk.  Save as spare_chunk if empty */
            if (buf->spare_chunk) {
                free(chunk->data);
                free(chunk);
            } else {
                buf->spare_chunk = chunk;
            }

            chunk = buf->reader_chunk = next_chunk;
            assert(chunk);
        }

        /* Return value is the current reader position */
        *(uint8_t**)reader_pos = &chunk->data[chunk->reader * buf->cellsize];
        retval = SK_CIRCBUF_OK;
    }

    --buf->wait_count;

    pthread_mutex_unlock(&buf->mutex);

    return retval;
}


void
skCircBufStop(
    sk_circbuf_t       *buf)
{
    pthread_mutex_lock(&buf->mutex);
    buf->destroyed = 1;
    pthread_cond_broadcast(&buf->cond);
    while (buf->wait_count) {
        pthread_cond_wait(&buf->cond, &buf->mutex);
    }
    pthread_mutex_unlock(&buf->mutex);
}


void
skCircBufDestroy(
    sk_circbuf_t       *buf)
{
    circbuf_chunk_t *chunk;
    circbuf_chunk_t *next_chunk;

    if (!buf) {
        return;
    }
    pthread_mutex_lock(&buf->mutex);
    if (!buf->destroyed) {
        buf->destroyed = 1;
        pthread_cond_broadcast(&buf->cond);
        while (buf->wait_count) {
            pthread_cond_wait(&buf->cond, &buf->mutex);
        }
    }
    TRACEMSG((("skCircBufDestroy(): Buffer has %" PRIu32 " records"),
              buf->cellcount));
    pthread_mutex_unlock(&buf->mutex);

    pthread_mutex_destroy(&buf->mutex);
    pthread_cond_destroy(&buf->cond);

    chunk = buf->reader_chunk;
    while (chunk) {
        next_chunk = chunk->next;
        free(chunk->data);
        free(chunk);
        chunk = next_chunk;
    }

    if (buf->spare_chunk) {
        free(buf->spare_chunk->data);
        free(buf->spare_chunk);
    }

    free(buf);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
