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
#ifndef _RWTRANSFER_H
#define _RWTRANSFER_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWTRANSFER_H, "$SiLK: rwtransfer.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  rwtransfer.h
**
**  Message definitions for rwsender and rwreceiver.
**
*/

#include <silk/redblack.h>
#include "libsendrcv.h"
#include "multiqueue.h"
#include "skmsg.h"

/* SENDRCV_DEBUG is defined in libsendrcv.h */
#if (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_MUTEX
#  define SKTHREAD_DEBUG_MUTEX 1
#endif
#include <silk/skthread.h>

/* Maximum error message length */
#define MAX_ERROR_MESSAGE 8096

/* Password env postfix */
#define PASSWORD_ENV_POSTFIX "_TLS_PASSWORD"

/* Internal and external messages */
#define EXTERNAL 0
#define INTERNAL 1

/* Keepalive timeout (in seconds) */
#define KEEPALIVE_TIMEOUT 60

/* SENDRCV_DEBUG is defined in libsendrcv.h */
#if (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL
#define DEBUG_PRINT1(x)           SKTHREAD_DEBUG_PRINT1(x)
#define DEBUG_PRINT2(x, y)        SKTHREAD_DEBUG_PRINT2(x, y)
#define DEBUG_PRINT3(x, y, z)     SKTHREAD_DEBUG_PRINT3(x, y, z)
#define DEBUG_PRINT4(x, y, z, zz) SKTHREAD_DEBUG_PRINT4(x, y, z, zz)
#else
#define DEBUG_PRINT1(x)
#define DEBUG_PRINT2(x, y)
#define DEBUG_PRINT3(x, y, z)
#define DEBUG_PRINT4(x, y, z, zz)
#endif  /* (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL */

/* SENDRCV_DEBUG is defined in libsendrcv.h */
#if (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_CONTENT
/* log message consisting of offset and length information for each
 * message sent between the rwsender and rwreceiver that is part of
 * the actual file being transferred. */
#define DEBUG_CONTENT_PRINT(x, y, z) DEBUG_PRINT3(x, y, z)
#else
#define DEBUG_CONTENT_PRINT(x, y, z)
#endif


#define CHECK_ALLOC(x)                                                  \
    if (x) { /* ok */ } else {                                          \
        skAppPrintOutOfMemory(NULL);                                    \
        exit(EXIT_FAILURE);                                             \
    }

#define ASSERT_ABORT(x)                         \
    if (x) { /* ok */ } else {                  \
        assert(x);                              \
        skAbort();                              \
    }


/* Protocol messages for a primary connection between a sender and a
 * receiver.  ** Always add new messages for future protocol versions
 * to the end, so as to not change the values of the enumerations with
 * respect to previous protocol versions.  Also, never remove any of
 * these messages in future protocol versions unless you do not intend
 * to keep backwards compatibility. **
 */
typedef enum {
    CONN_SENDER_VERSION,
    CONN_RECEIVER_VERSION,
    CONN_IDENT,
    CONN_READY,
    CONN_DISCONNECT_RETRY,
    CONN_DISCONNECT,
    CONN_NEW_FILE,
    CONN_NEW_FILE_READY,
    CONN_FILE_BLOCK,
    CONN_FILE_COMPLETE,
    CONN_DUPLICATE_FILE,
    CONN_REJECT_FILE,

    CONN_NUMBER_OF_CONNECTION_MESSAGES
} connection_msg_t;


typedef struct file_info_st {
    uint32_t high_filesize;
    uint32_t low_filesize;
    uint32_t block_size;
    uint32_t mode;
    char     filename[1];
} file_info_t;


typedef struct block_info_st {
    uint32_t high_offset;
    uint32_t low_offset;
    uint8_t  block[1];
} block_info_t;

typedef struct file_map_st {
    void           *map;
    size_t          map_size;
    uint64_t        count;
    pthread_mutex_t mutex;
} file_map_t;

typedef struct sender_block_info_st {
    uint32_t    high_offset;
    uint32_t    low_offset;
    file_map_t *ref;
} sender_block_info_t;

typedef struct transfer_st {
    char                *ident;
    sk_sockaddr_array_t *addr;
    pthread_t            thread;
    skm_channel_t        channel;
    uint32_t             remote_version;

    unsigned             disconnect     : 1;
    unsigned             address_exists : 1;
    unsigned             thread_exists  : 1;
    unsigned             channel_exists : 1;

    union {
        struct receiver_st {
            regex_t            filter;
            mq_multi_t        *queue;
            mq_queue_t        *high;
            mq_queue_t        *low;
            unsigned           filter_exists  : 1;
        } r;
        struct sender_st {
            char               dummy;
        } s;
    } app;
} transfer_t;


void
transferUsageLong(
    FILE               *fh,
    const char         *usage,
    struct option       options[],
    const char         *help[]);

int
transferSetup(
    void);
int
transferVerifyOptions(
    void);

transfer_t *
initTemp(
    void);
void
clearTemp(
    void);

int
checkIdent(
    const char         *ident,
    const char         *switch_name);

struct rbtree *
transferIdentTreeCreate(
    void);

int
startTransferDaemon(
    void);

int
handleDisconnect(
    sk_msg_t           *msg,
    const char         *type);

void
transferShutdown(
    void);
void
transferTeardown(
    void);

int
sendString(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    int                 internal,
    skm_type_t          type,
    int                 log_level,
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(6, 7);

void
threadExit(
    int                 status,
    void               *retval);

#ifdef TEST_PRINTF_FORMATS
/* test the string and format we pass to sendString().  Requires C99 */
#define sendString(q, channel, internal, type, log_level, ...)          \
    (fprintf(stderr, __VA_ARGS__) &&                                    \
     sendString((q), (channel), (internal), (type), (log_level), __VA_ARGS__))
#endif


int
checkMsg(
    sk_msg_t           *msg,
    sk_msg_queue_t     *q,
    connection_msg_t    type);


#define MSG_FROMTYPE(msg, type) *(type *)skMsgMessage(msg)
#define MSG_UINT32(msg) ntohl(MSG_FROMTYPE(msg, uint32_t))
#define MSG_CHARP(msg) ((char *)skMsgMessage(msg))


extern connection_msg_t local_version_check;
extern connection_msg_t remote_version_check;
extern struct rbtree *transfers;
extern volatile int shuttingdown;

/* Return -1 on fatal error, 1 if at least one file was transferred, 0
 * otherwise */
int
transferFiles(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    transfer_t         *rcvr);
int
transferUnblock(
    transfer_t         *item);

extern const char *password_env;
extern int main_retval;


#ifdef __cplusplus
}
#endif
#endif /* _RWTRANSFER_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
