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

/*
**  skmsg.h
**
**    Two-sided message queues over sockets
**
*/
#ifndef _SKMSG_H
#define _SKMSG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKMSG_H, "$SiLK: skmsg.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>

/*
 *    The number of bytes of network overhead when sending a message.
 */
#define SKMSG_MESSAGE_OVERHEAD 6

/*
 *    The control channel
 */
#define SKMSG_CHANNEL_CONTROL 0xFFFF

/*
 *    The message type of non-user-defined error messages.
 */
#define SKMSG_TYPE_ERROR      0xFFFF


/*** Control channel messages ***/

/*
 *    New connection: Contains the channel ID of the initial channel
 *    for the new connection.
 */
#define SKMSG_CTL_NEW_CONNECTION 0

/*
 *    Channel died.  Contains the channel ID if the channel that
 *    died.
 */
#define SKMSG_CTL_CHANNEL_DIED   1


/*
 *    Use for getting a single channel id out of a message
 */
#define SKMSG_CTL_MSG_GET_CHANNEL(x) ntohs(*(uint16_t *)skMsgMessage(x))


/*** Fundamental types ***/

/*
 *    The type of message queues
 */
struct sk_msg_queue_st;
typedef struct sk_msg_queue_st sk_msg_queue_t;

/*
 *    The type of messages
 */
struct sk_msg_st;
typedef struct sk_msg_st sk_msg_t;

/*
 *    Type of channel IDs
 */
typedef uint16_t skm_channel_t;

/*
 *    Type of message types
 */
typedef uint16_t skm_type_t;

/*
 *    Type of message lengths
 */
typedef uint16_t skm_len_t;

/*
 *    Type of address info for new channels
 */
typedef struct sk_new_channel_info_st {
    skm_channel_t   channel;
    sk_sockaddr_t   addr;
    /* Whether 'addr' is usable */
    unsigned        known : 1;
} sk_new_channel_info_t;


/*** Message queue API ***/

/*
 *    Create a message queue
 */
int
skMsgQueueCreate(
    sk_msg_queue_t    **queue);

/*
 *    Start a listener
 */
int
skMsgQueueBind(
    sk_msg_queue_t             *queue,
    const sk_sockaddr_array_t  *addr);

/*
 *    Connect to a listening message queue
 */
int
skMsgQueueConnect(
    sk_msg_queue_t     *queue,
    struct sockaddr    *addr,
    socklen_t           addrlen,
    skm_channel_t      *channel);

/*
 *    Clean up after GNU TLS initialization allocations.  Only
 *    necessary during shutdown if TLS functions have been used.  Is
 *    safe to call even if TLS functions were not used.
 */
void
skMsgGnuTLSTeardown(
    void);

/*
 *    Shut down a message queue
 */
void
skMsgQueueShutdown(
    sk_msg_queue_t     *queue);

/*
 *    Shut down all associated message queues
 */
void
skMsgQueueShutdownAll(
    sk_msg_queue_t     *queue);

/*
 *    Destroy a message queue
 */
void
skMsgQueueDestroy(
    sk_msg_queue_t     *queue);

/*
 *    Send a message of size length to the remote message queue.  A
 *    copy of the message is made; to avoid making this copy, use
 *    skMsgQueueSendMessageNoCopy() instead.
 */
int
skMsgQueueSendMessage(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_type_t          type,
    const void         *message,
    skm_len_t           length);

/*
 *    Inject a message of size length (into this message queue).  A
 *    copy of the message is made; to avoid making this copy, use
 *    skMsgQueueInjectMessageNoCopy() instead.
 */
int
skMsgQueueInjectMessage(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_type_t          type,
    const void         *message,
    skm_len_t           length);

/*
 *    Send a message to the remote message queue.  Message is always
 *    freed with free_fn, even if the message cannot be added to the
 *    message queue.  Do not call this function with a NULL free_fn;
 *    use skMsgQueueSendMessage() instead.
 */
int
skMsgQueueSendMessageNoCopy(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    void              (*free_fn)(void *));

/*
 *    Send a message scattered across multiple pointers to the remote
 *    message queue.  Data is always freed with free_fn, even if the
 *    message cannot be added to the message queue.  Do not call this
 *    function with a NULL free_fn.
 */
int
skMsgQueueScatterSendMessageNoCopy(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_type_t          type,
    uint16_t            num_sections,
    struct iovec       *sections,
    void              (*free_fn)(uint16_t, struct iovec *));


/*
 *    Inject a message (into this message queue). Message is always
 *    freed with free_fn, even if the message cannot be added to the
 *    message queue.  Do not call this function with a NULL free_fn;
 *    use skMsgQueueInjectMessage() instead.
 */
int
skMsgQueueInjectMessageNoCopy(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    void              (*free_fn)(void *));

/*
 *    Create a new stream from a channel
 */
int
skMsgChannelNew(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    skm_channel_t      *new_channel);

/*
 *    Split a channel onto a new queue
 */
int
skMsgChannelSplit(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    sk_msg_queue_t    **new_queue);

/*
 *    Move a channel to a different queue
 */
int
skMsgChannelMove(
    skm_channel_t       channel,
    sk_msg_queue_t     *queue);

/*
 *    Shut down a channel
 */
int
skMsgChannelKill(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel);

/*
 *    Get the next message
 */
int
skMsgQueueGetMessage(
    sk_msg_queue_t     *queue,
    sk_msg_t          **msg);

/*
 *    Get the next message from a specific channel
 */
int
skMsgQueueGetMessageFromChannel(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    sk_msg_t          **msg);

/*
 *    Get a channel's remote ID
 */
int
skMsgGetRemoteChannelID(
    sk_msg_queue_t     *queue,
    skm_channel_t       lchannel,
    skm_channel_t      *rchannel);

/*
 *    Fill a string with information about the connection associated
 *    with a channel.  Return -1 on error.  Return the number of
 *    characters it wrote or would have written (not counting
 *    terminating null) on success.
 */
int
skMsgGetConnectionInformation(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    char               *buffer,
    size_t              buffer_size);

/*
 *    Fill 'port' with the local port associated with a channel.
 */
int
skMsgGetLocalPort(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    uint16_t           *port);

/*
 *    Free a message
 */
void
skMsgDestroy(
    sk_msg_t           *msg);

/*
 *    Set the keepalive timeout for a connection (in seconds).  Use a
 *    keepalive of 0 to disable keepalive messages.  By default, there
 *    are no keepalive messages.
 */
int
skMsgSetKeepalive(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    uint16_t            keepalive);

/**
 *    Register the command line switches related to TLS, where
 *    'passwd_env_name' is the name of the environment variable
 *    containing the password for the PKCS12 file.
 *
 *    Return 0 on success and non-zero on failure.  Do nothing and
 *    return 0 if GnuTLS support is not available.
 */
int
skMsgTlsOptionsRegister(
    const char         *passwd_env_name);

/**
 *    Print the usage/help for each of the command line switches
 *    related to TLS.  Do nothing if GnuTLS support is not available.
 */
void
skMsgTlsOptionsUsage(
    FILE               *fh);

/**
 *    Verify that user either provided no TLS switches or correctly
 *    provided a set of switches (i.e., there are no conflicting
 *    switches).  Return 0 if there is no conflict/error, and non-zero
 *    if there is.  When `tls_available` is provided, its referent is
 *    set to 0 if TLS is not being used and 1 if it is.
 */
int
skMsgTlsOptionsVerify(
    unsigned int       *tls_available);


/*
 *    Accessor functions on messages
 */
skm_channel_t
skMsgChannel(
    const sk_msg_t     *msg);
skm_type_t
skMsgType(
    const sk_msg_t     *msg);
skm_len_t
skMsgLength(
    const sk_msg_t     *msg);
const void *
skMsgMessage(
    const sk_msg_t     *msg);

#ifdef __cplusplus
}
#endif
#endif /* _SKMSG_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
