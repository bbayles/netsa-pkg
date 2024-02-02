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
**  SiLK message functions
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skmsg.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "intdict.h"
#include "multiqueue.h"
#include "skmsg.h"
#include "libsendrcv.h"
#include <silk/skdeque.h>
#include <silk/sklog.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>
#include <poll.h>
#if SK_ENABLE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>
#endif  /* SK_ENABLE_GNUTLS */

/* SENDRCV_DEBUG is defined in libsendrcv.h */
#if (SENDRCV_DEBUG) & DEBUG_SKMSG_MUTEX
#  define SKTHREAD_DEBUG_MUTEX 1
#endif
#include <silk/skthread.h>


/* Define Constants */

/* Maximum number of CA certs that can be in the CA cert file */
#define MAX_CA_CERTS 32

/* GnuTLS minimum version */
#define MIN_GNUTLS_VERISON      "2.12.0"

/* Maximum GnuTLS logging level accepted by gnutls_global_set_log_level */
#define MAX_TLS_DEBUG_LEVEL     99

/* Keepalive timeout for the control channel */
#define SKMSG_CONTROL_KEEPALIVE_TIMEOUT 60 /* seconds */

/* Time used by connections without keepalive times to determine how
 * whether the connection is stagnant. */
#define SKMSG_DEFAULT_STAGNANT_TIMEOUT (2 * SKMSG_CONTROL_KEEPALIVE_TIMEOUT)

/* Time used to determine how often to check to see if the connection
 * is still alive. */
#define SKMSG_MINIMUM_READ_SELECT_TIMEOUT SKMSG_CONTROL_KEEPALIVE_TIMEOUT

/* Read and write sides of control pipes */
#define READ 0
#define WRITE 1

#define SKMERR_MEMORY  -1
#define SKMERR_PIPE    -2
#define SKMERR_MUTEX   -3
#define SKMERR_PTHREAD -4
#define SKMERR_ERROR   -5
#define SKMERR_ERRNO   -6
#define SKMERR_CLOSED  -7
#define SKMERR_SHORT   -8
#define SKMERR_PARTIAL -9
#define SKMERR_EMPTY   -10
#define SKMERR_GNUTLS  -11

#define LISTENQ 5

#define SKMSG_CTL_CHANNEL_ANNOUNCE  0xFFFE
#define SKMSG_CTL_CHANNEL_REPLY     0xFFFD
#define SKMSG_CTL_CHANNEL_KILL      0xFFFC
#define SKMSG_CTL_CHANNEL_KEEPALIVE 0xFFFA
#define SKMSG_WRITER_UNBLOCKER      0xFFFB

#define SKMSG_MINIMUM_SYSTEM_CTL_CHANNEL 0xFFFA

/* Default security level. */
#define TLS_SECURITY_DEFAULT    "medium"

/* TLS read timeout, in milliseconds */
#define TLS_POLL_TIMEOUT 1000

/* IO thread check timeout, in milliseconds*/
#define SKMSG_IO_POLL_TIMEOUT 1000

/* Whether to use the custom tls_pull, tls_push */
#ifndef SK_TLS_USE_CUSTOM_PULL_PUSH
#define SK_TLS_USE_CUSTOM_PULL_PUSH 0
#endif


/* Define Macros */

/*
 *  this macro is used when the extra-level debugging statements write
 *  to the log, since we do not want the result of the log's printf()
 *  to trash the value of 'errno'
 */
#define WRAP_ERRNO(x)                                           \
    do { int _saveerrno = errno; x; errno = _saveerrno; }       \
    while (0)

/* SENDRCV_DEBUG is defined in libsendrcv.h */
#if 0 == ((SENDRCV_DEBUG) & DEBUG_SKMSG_OTHER)
#define DEBUG_PRINT1(x)
#define DEBUG_PRINT2(x, y)
#define DEBUG_PRINT3(x, y, z)
#define DEBUG_PRINT4(x, y, z, q)
#else
#define DEBUG_PRINT1(x)          WRAP_ERRNO(SKTHREAD_DEBUG_PRINT1(x))
#define DEBUG_PRINT2(x, y)       WRAP_ERRNO(SKTHREAD_DEBUG_PRINT2(x, y))
#define DEBUG_PRINT3(x, y, z)    WRAP_ERRNO(SKTHREAD_DEBUG_PRINT3(x, y, z))
#define DEBUG_PRINT4(x, y, z, q) WRAP_ERRNO(SKTHREAD_DEBUG_PRINT4(x, y, z, q))
#endif  /* (SENDRCV_DEBUG) & DEBUG_SKMSG_OTHER */


/*
 *  Logging messages for function entry/exit.
 *
 *    Use DEBUG_ENTER_FUNC at the beginning of every function.  Use
 *    RETURN(x) for functions that return a value, and RETURN_VOID for
 *    functions that have no return value.
 *
 *    SENDRCV_DEBUG is defined in libsendrcv.h.  DEBUG_SKMSG_FN turns
 *    on function entry/exit debug print macros.
 */
#if 0 == ((SENDRCV_DEBUG) & DEBUG_SKMSG_FN)
#  define DEBUG_ENTER_FUNC
#  define RETURN(x)         return x
#  define RETURN_VOID       return
#else
#  define DEBUG_ENTER_FUNC                                      \
    WRAP_ERRNO(SKTHREAD_DEBUG_PRINT2("Entering %s", __func__))

#  define RETURN(x)                                                     \
    do {                                                                \
        WRAP_ERRNO(SKTHREAD_DEBUG_PRINT2("Exiting %s", __func__));      \
        return x;                                                       \
    } while (0)

#  define RETURN_VOID                                                   \
    do {                                                                \
        WRAP_ERRNO(SKTHREAD_DEBUG_PRINT2("Exiting %s", __func__));      \
        return;                                                         \
    } while (0)

#endif  /* ((SENDRCV_DEBUG) & DEBUG_SKMSG_FN) */


/* MUTEX_* macros are defined in skthread.h */

/* Mutex accessor */
#define QUEUE_MUTEX(q)      (&(q)->root->mutex)

/* Queue lock */
#define QUEUE_LOCK(q)       MUTEX_LOCK(QUEUE_MUTEX(q))

/* Queue unlock */
#define QUEUE_UNLOCK(q)     MUTEX_UNLOCK(QUEUE_MUTEX(q))

/* Queue wait */
#define QUEUE_WAIT(cond, q) MUTEX_WAIT(cond, QUEUE_MUTEX(q))

/* Queue locked assert */
#define ASSERT_QUEUE_LOCK(q)                                    \
    assert(pthread_mutex_trylock(QUEUE_MUTEX(q)) == EBUSY)


/* Any place an XASSERT occurs could be replaced with better error
   handling at some point in time. */
#define XASSERT(x) do {                                                 \
    if (!(x)) {                                                         \
        CRITMSG("Unhandled error at " __FILE__ ":%" PRIu32 " \"" #x "\"", \
                __LINE__);                                              \
        skAbort();                                                      \
    }                                                                   \
    } while (0)
#define MEM_ASSERT(x) do {                                              \
    if (!(x)) {                                                         \
        CRITMSG(("Memory allocation error creating \"" #x "\" at "      \
                 __FILE__ ":%" PRIu32), __LINE__);                      \
        abort();                                                        \
    }                                                                   \
    } while (0)

/* Macros to deal with thread creation and destruction */
#define QUEUE_TINFO(q) ((q)->root->tinfo)

#define THREAD_INFO_INIT(q)                             \
    do {                                                \
        pthread_cond_init(&QUEUE_TINFO(q).cond, NULL);  \
        QUEUE_TINFO(q).count = 0;                       \
    } while (0)

#define THREAD_INFO_DESTROY(q) pthread_cond_destroy(&QUEUE_TINFO(q).cond)


#define THREAD_START(name, rv, q, loc, fn, arg)                 \
    do {                                                        \
        DEBUG_PRINT1("THREAD_START");                           \
        ASSERT_QUEUE_LOCK(q);                                   \
        QUEUE_TINFO(q).count++;                                 \
        (rv) = skthread_create(name, (loc), (fn), (arg));       \
        if ((rv) != 0) {                                        \
            QUEUE_TINFO(q).count--;                             \
        }                                                       \
    } while (0)

#define THREAD_END(q)                                           \
    do {                                                        \
        DEBUG_PRINT1("THREAD_END");                             \
        ASSERT_QUEUE_LOCK(q);                                   \
        assert(QUEUE_TINFO(q).count != 0);                      \
        QUEUE_TINFO(q).count--;                                 \
        DEBUG_PRINT2("THREAD END COUNT decremented to %d",      \
                     QUEUE_TINFO(q).count);                     \
        MUTEX_BROADCAST(&QUEUE_TINFO(q).cond);                  \
    } while (0)

#define THREAD_WAIT_END(q, state)                               \
    do {                                                        \
        DEBUG_PRINT1("WAITING FOR THREAD_END");                 \
        ASSERT_QUEUE_LOCK(q);                                   \
        while ((state) != SKM_THREAD_ENDED) {                   \
            QUEUE_WAIT(&QUEUE_TINFO(q).cond, q);                \
        }                                                       \
        DEBUG_PRINT1("FINISHED WAITING FOR THREAD_END");        \
    } while (0)

#define THREAD_WAIT_ALL_END(q)                                  \
    do {                                                        \
        DEBUG_PRINT1("WAITING FOR ALL THREAD_END");             \
        ASSERT_QUEUE_LOCK(q);                                   \
        while (QUEUE_TINFO(q).count != 0) {                     \
            DEBUG_PRINT2("THREAD ALL END WAIT COUNT == %d",     \
                         QUEUE_TINFO(q).count);                 \
            QUEUE_WAIT(&QUEUE_TINFO(q).cond, q);                \
        }                                                       \
        DEBUG_PRINT1("FINISHED WAITING FOR ALL THREAD_END");    \
    } while (0)


/*
 *  is_stagnat = CONNECTION_STAGNANT(conn, t);
 *
 *    Compare current time 't' with time the last message was received
 *    for connection 'conn'; return 1 if the time difference is larger
 *    than the timeout or 0 otherwise.
 */
#define CONNECTION_STAGNANT(conn, t)                                    \
    (difftime(t, (conn)->last_recv) > ((conn)->keepalive                \
                                       ? (2.0 * (conn)->keepalive)      \
                                       : SKMSG_DEFAULT_STAGNANT_TIMEOUT))

/* return a string for a received event from poll() */
#define SK_POLL_EVENT_STR(ev_)                          \
    (((ev_) & POLLHUP) ? "POLLHUP"                      \
     : (((ev_) & POLLERR) ? "POLLERR"                   \
        : (((ev_) & POLLNVAL) ? "POLLNVAL" : "")))


/*
 *  ASSERT_RESULT(ar_func_args, ar_type, ar_expected);
 *
 *    ar_func_args  -- is a function and any arugments it requires
 *    ar_type       -- is the type that ar_func_args returns
 *    ar_expected   -- is the expected return value from ar_func_args
 *
 *    If assert() is disabled, simply call 'ar_func_args'.
 *
 *    If assert() is enabled, call 'ar_func_args', capture its result,
 *    and assert() that its result is 'ar_expected'.
 */
#ifdef  NDEBUG
/* asserts are disabled; just call the function */
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)  ar_func_args
#else
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)       \
    do {                                                        \
        ar_type ar_rv = (ar_func_args);                         \
        assert(ar_rv == (ar_expected));                         \
    } while(0)
#endif  /* #else of #ifdef NDEBUG */



/*** Local types ***/

/* The type of message headers */
typedef struct sk_msg_hdr_st {
    skm_channel_t channel;
    skm_type_t    type;
    skm_len_t     size;
} sk_msg_hdr_t;

/* The type of messages */
/* typedef struct sk_msg_st sk_msg_t;  // from skmsg.h */
struct sk_msg_st {
    sk_msg_hdr_t hdr;
    void       (*free_fn)(uint16_t, struct iovec *);
    void       (*simple_free)(void *);
    uint16_t     segments;
    struct iovec segment[1];
};

/* Buffer for reading an sk_msg_t; used to support partial reads */
typedef struct sk_msg_read_buf_st {
    /* The message being read */
    sk_msg_t *msg;
    /* Location to read into */
    uint8_t  *loc;
    /* Number of bytes still to read */
    uint16_t  count;
} sk_msg_read_buf_t;

/* Buffer for writing an sk_msg_t; used to support partial writes */
typedef struct sk_msg_write_buf_st {
    /* The message being written */
    sk_msg_t   *msg;
    /* Number of bytes of the message remaining to write */
    ssize_t     msg_size;
    /* The index of the iov segment currently being sent */
    uint16_t    cur_seg;
    /* Number of bytes of the current segment that have been sent */
    uint16_t    seg_offset;
} sk_msg_write_buf_t;


/* Allow tracking of thread entance and exits. */
typedef struct sk_thread_info_st {
    pthread_cond_t  cond;
    uint32_t        count;
} sk_thread_info_t;

typedef enum {
    SKM_THREAD_BEFORE,
    SKM_THREAD_RUNNING,
    SKM_THREAD_SHUTTING_DOWN,
    SKM_THREAD_ENDED
} sk_thread_state_t;

/* The type of a message queue root */
typedef struct sk_msg_root_st {
    /* Global mutex for message queue */
    pthread_mutex_t     mutex;

    /* The next channel number to try to allocate */
    skm_channel_t       next_channel;

    /* Information about active threads */
    sk_thread_info_t    tinfo;

    /* Map of channel-id to channels */
    int_dict_t         *channel;
    /* Map of read socket to connections */
    int_dict_t         *connection;
    /* Map of channel-ids to queues */
    int_dict_t         *groups;

    /* The information for binding and listening for connections */
    struct pollfd      *pfd;
    nfds_t              pfd_len;
    pthread_t           listener;
    /* The listener state */
    sk_thread_state_t   listener_state;
    /* Listener condition variable */
    pthread_cond_t      listener_cond;

    sk_msg_queue_t     *shutdownqueue;

#if SK_ENABLE_GNUTLS
    /* Auth/Encryption credentials */
    gnutls_certificate_credentials_t cred;
#endif

    unsigned            shuttingdown: 1;
    /* whether GnuTLS credentials have been set */
    unsigned            cred_set: 1;
    /* whether this connection uses TLS */
    unsigned            bind_tls: 1;
} sk_msg_root_t;


/* The type of a message queue */
/* typedef struct sk_msg_queue_st sk_msg_queue_t; */
struct sk_msg_queue_st {
    sk_msg_root_t      *root;
    /* Map of channels */
    int_dict_t         *channel;
    /* Queue group for all channels */
    mq_multi_t         *group;
    pthread_cond_t      shutdowncond;
    unsigned            shuttingdown: 1;
};


/* States for connections and channels */
typedef enum {
    SKM_CREATED,
    SKM_CONNECTING,
    SKM_CONNECTED,
    SKM_CLOSED
} sk_msg_state_t;

/* States for threads */
typedef enum {
    SKM_SEND_INTERNAL,
    SKM_SEND_REMOTE,
    SKM_SEND_CONTROL
} sk_send_type_t;

/* The type of connection to use */
typedef enum {
    CONN_TCP,
    CONN_TLS
} skm_conn_t;

/* TLS connections */
typedef enum {
    SKM_TLS_NONE,
    SKM_TLS_CLIENT,
    SKM_TLS_SERVER
} skm_tls_type_t;


/* Forward declarations; these strucures reference each other */
typedef struct sk_msg_channel_queue_st sk_msg_channel_queue_t;
typedef struct sk_msg_conn_queue_st sk_msg_conn_queue_t;

/* Represents a connected socket or pipe */
/* typedef struct sk_msg_conn_queue_st sk_msg_conn_queue_t; */
struct sk_msg_conn_queue_st {
    /* Read socket */
    int                     rsocket;
    /* Write socket */
    int                     wsocket;

    /* Address of connection */
    struct sockaddr        *addr;
    /* Length of address of connection */
    socklen_t               addrlen;

    /* Transport type */
    skm_conn_t              transport;

    /* Channel map */
    int_dict_t             *channelmap;
    /* Channel refcount */
    uint16_t                refcount;

    /* Current state of connection */
    sk_msg_state_t          state;

    /* Outgoing write queue */
    skDeque_t               queue;
    /* Writer thread handle */
    pthread_t               writer;
    /* State */
    sk_thread_state_t       writer_state;
    /* Condition variable for thread */
    pthread_cond_t          writer_cond;

    /* The reader thread */
    pthread_t               reader;
    /* The reader state */
    sk_thread_state_t       reader_state;
    /* Reader condition variable */
    pthread_cond_t          reader_cond;

    /* Most recent error from read/write; paired with SKMERR_ERRNO and
     * SKMERR_GNUTLS return values */
    int                     last_errnum;

    /* Keepalive timeout */
    uint16_t                keepalive;
    /* Time of last received data */
    time_t                  last_recv;

    /* Buffer to support partial read of incoming messages */
    sk_msg_read_buf_t       msg_read_buf;

    /* Pre-connected initial channel */
    sk_msg_channel_queue_t *first_channel;

#if SK_ENABLE_GNUTLS
    gnutls_session_t        session;
    unsigned                use_tls : 1;
#endif  /* SK_ENABLE_GNUTLS */
};


/* Represents a channel */
/* typedef struct sk_msg_channel_queue_st sk_msg_channel_queue_t; */
struct sk_msg_channel_queue_st {
    /* channel's queue */
    mq_queue_t            *queue;
    /* local channel ID */
    skm_channel_t          channel;
    /* remote channel ID */
    skm_channel_t          rchannel;
    /* channel state */
    sk_msg_state_t         state;
    /* associated connection */
    sk_msg_conn_queue_t   *conn;
    /* group associated with this channel */
    sk_msg_queue_t        *group;
    /* pending condition variable */
    pthread_cond_t         pending;
    /* whether we are waiting for connection */
    unsigned               is_pending: 1;
    unsigned               flushing: 1;
};

/* Used for passing data to a writer thread */
typedef struct sk_queue_and_conn_st {
    sk_msg_queue_t         *q;
    sk_msg_conn_queue_t    *conn;
} sk_queue_and_conn_t;


/* Used to represent a local/remote channel pair */
typedef struct sk_channel_pair_st {
    skm_channel_t   lchannel;
    skm_channel_t   rchannel;
} sk_channel_pair_t;



/*** Local function prototypes ***/

static void *reader_thread(void *);
static void *writer_thread(void *);
static void *listener_thread(void *);

static int
destroy_connection(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn);

static int
send_message(
    sk_msg_queue_t     *q,
    skm_channel_t       lchannel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    sk_send_type_t      send_type,
    int                 no_copy,
    void              (*free_fn)(void *));

static int
send_message_internal(
    sk_msg_channel_queue_t *chan,
    sk_msg_t               *msg,
    sk_send_type_t          send_type);


/*** Local variables ***/

#if SK_ENABLE_GNUTLS
#if GNUTLS_VERSION_NUMBER < 0x030300
#define GNUTLS_SEC_PARAM_MEDIUM GNUTLS_SEC_PARAM_NORMAL
#endif

/* Mutex to control access to GnuTLS global state */
static pthread_mutex_t sk_msg_gnutls_mutex = PTHREAD_MUTEX_INITIALIZER;
static int sk_msg_gnutls_initialized = 0;

/* Local handle to the name of environment variable holding the
 * password for the PKCS12 file. */
static const char *password_env_name = NULL;

/* Encryption and authentication files */
static const char *tls_ca_file     = NULL;
static const char *tls_cert_file   = NULL;
static const char *tls_key_file    = NULL;
static const char *tls_pkcs12_file = NULL;
static const char *tls_crl_file    = NULL;

/* GnuTLS debugging log level */
static int tls_debug_level = 0;

/* The priority string the user provides for GnuTLS priority, used to
 * fill tls_priority_cache. */
static const char *tls_priority = NULL;

/* GnuTLS priority cache passed to gnutls_priority_set(), based on
 * tls_priority.  If NULL, the default priority is used. */
static gnutls_priority_t tls_priority_cache = NULL;

/* The level the user provides for the GnuTLS security parameter
 * level.  If not provided, defaults to TLS_SECURITY_DEFAULT. */
static const char *tls_security = NULL;

/* The GnuTLS security parameter level based on 'tls_security'. */
static gnutls_sec_param_t tls_security_param;

/* Potential values for tls_security */
static const sk_stringmap_entry_t tls_security_levels[] = {
    {"low",             GNUTLS_SEC_PARAM_LOW,       NULL,   NULL},
    {"medium",          GNUTLS_SEC_PARAM_MEDIUM,    NULL,   NULL},
    {"high",            GNUTLS_SEC_PARAM_HIGH,      NULL,   NULL},
    {"ultra",           GNUTLS_SEC_PARAM_ULTRA,     NULL,   NULL},
    SK_STRINGMAP_SENTINEL
};

typedef enum {
    OPT_TLS_CA,
    OPT_TLS_CERT,
    OPT_TLS_KEY,
    OPT_TLS_PKCS12,
    OPT_TLS_SECURITY,
    OPT_TLS_PRIORITY,
    OPT_TLS_CRL,
    OPT_TLS_DEBUG_LEVEL
} sk_tls_options_enum;

/* Command line switches for encryption/authentication files */
static struct option sk_tls_options[] = {
    {"tls-ca",          REQUIRED_ARG, 0, OPT_TLS_CA},
    {"tls-cert",        REQUIRED_ARG, 0, OPT_TLS_CERT},
    {"tls-key",         REQUIRED_ARG, 0, OPT_TLS_KEY},
    {"tls-pkcs12",      REQUIRED_ARG, 0, OPT_TLS_PKCS12},
    {"tls-security",    REQUIRED_ARG, 0, OPT_TLS_SECURITY},
    {"tls-priority",    REQUIRED_ARG, 0, OPT_TLS_PRIORITY},
    {"tls-crl",         REQUIRED_ARG, 0, OPT_TLS_CRL},
    {"tls-debug-level", REQUIRED_ARG, 0, OPT_TLS_DEBUG_LEVEL},
    {0, 0, 0, 0}        /* sentinel */
};

/* Usage text for each command line switch */
static const char *sk_tls_options_help[] = {
    ("Load the Certificate Authority from the file in PEM format\n"
     "\tlocated at this complete path. Def. None. Either --tls-pkcs12 or\n"
     "\tboth --tls-key and --tls-key must also be specified"),
    ("Load the encryption cert and any intermediate certs from\n"
     "\tthe file in PEM format located at this complete path. Def. None.\n"
     "\tRequires that --tls-ca and --tls-key are also specified"),
    ("Load the encryption key from the file in PEM format\n"
     "\tlocated at this complete path. Def. None. Requires that --tls-ca\n"
     "\tand --tls-cert are also specified"),
    ("Load the encryption cert and key and any intermediate\n"
     "\tcerts from the file in PKCS#12 format located at this complete path.\n"
     "\tDef. None. Requires that --tls-ca is also specified"),
    ("Specify the security level to use when the required\n"
     "\tfile options are provided. Def. '" TLS_SECURITY_DEFAULT "'.\n"
     "\tChoices:"),
    ("Specify the priorities for ciphers, key exchange\n"
     "\tmethods, message authentication codes, and compression methods.\n"
     "\tSee the GnuTLS documentation of \"Priority Strings\" for the details\n"
     "\tabout the format of the argument. Def. 'NORMAL'"),
    ("Load the Certificate Revocation List from the file in PEM\n"
     "\tformat located at this complete path. Def. None"),
    ("Set TLS debugging level to the specified value.\n"
     "\tDef. 0. Range: 0-"),
    (char *)NULL
};


#endif /* SK_ENABLE_GNUTLS */

/* Type of connections to use.  Set to TLS when the required files are
 * specified on the command line. */
static skm_conn_t connection_type = CONN_TCP;


/* Utility functions */


static sk_msg_channel_queue_t *
find_channel(
    sk_msg_queue_t     *q,
    skm_channel_t       channel)
{
    sk_msg_channel_queue_t **chan;

    DEBUG_ENTER_FUNC;

    chan = (sk_msg_channel_queue_t **)int_dict_get(q->root->channel,
                                                   channel, NULL);

    RETURN(chan ? *chan : NULL);
}


static void
msg_simple_free(
    uint16_t            n,
    struct iovec       *iov)
{
    while (n > 0) {
        --n;
        free(iov[n].iov_base);
    }
}


static void
sk_destroy_report_message(
    void               *vmsg)
{
    sk_msg_t *msg = (sk_msg_t *)vmsg;

    DEBUG_ENTER_FUNC;

    DEBUG_PRINT3("Queue (destroy): chan=%#x type=%#x",
                 msg->hdr.channel, msg->hdr.type);

    skMsgDestroy(msg);

    RETURN_VOID;
}


static void
set_nonblock(
    int                 fd)
{
    int flags, rv;

    DEBUG_ENTER_FUNC;

    flags = fcntl(fd, F_GETFL, 0);
    XASSERT(flags != -1);
    flags |= O_NONBLOCK;
    rv = fcntl(fd, F_SETFL, flags);
    XASSERT(rv != -1);

    RETURN_VOID;
}


static const char *
skmerr_strerror(
    const sk_msg_conn_queue_t  *conn,
    int                         retval)
{
    static char buf[256];

    switch (retval) {
      case SKMERR_MEMORY:
        return "Memory allocation failure";
      case SKMERR_PIPE:
        return "Failed to create pipe";
      case SKMERR_MUTEX:
        return "Failed to initialize pthread mutex or condition variable";
      case SKMERR_PTHREAD:
        return "Error with pthread";
      case SKMERR_ERROR:
        return "Generic error";
      case SKMERR_ERRNO:
        if (conn) {
            return strerror(conn->last_errnum);
        }
        return strerror(errno);
      case SKMERR_CLOSED:
        return "Connection is closed";
      case SKMERR_SHORT:
        return "Short read or write (fail)";
      case SKMERR_PARTIAL:
        return "Partial read or write (will retry)";
      case SKMERR_EMPTY:
        return "Empty read (will retry)";
      case SKMERR_GNUTLS:
#if SK_ENABLE_GNUTLS
        if (conn) {
            return gnutls_strerror(conn->last_errnum);
        }
#endif  /* SK_ENABLE_GNUTLS */
        return "GnuTLS error";
    }

    snprintf(buf, sizeof(buf), "Unknown SKMERR_ error code value %d", retval);
    return buf;
}



#if SK_ENABLE_GNUTLS
/*
 *  file_exists = optionsFileCheck(opt_name, opt_arg);
 *
 *    Verify that the file in 'opt_arg' exists and that we have a full
 *    path to the file.  Verify that the length is shorter than
 *    PATH_MAX.  If so, return 0; otherwise, print an error that the
 *    option named by 'opt_name' was bad and return -1.
 */
static int
optionsFileCheck(
    const char         *opt_name,
    const char         *opt_arg)
{
    if (!opt_arg || !opt_arg[0]) {
        skAppPrintErr("Invalid %s: The argument empty", opt_name);
        return -1;
    }

    if (strlen(opt_arg)+1 >= PATH_MAX) {
        skAppPrintErr("Invalid %s: Path is too long", opt_name);
        return -1;
    }

    if (!skFileExists(opt_arg)) {
        skAppPrintErr(("Invalid %s:"
                       " File '%s' does not exist or is not a regular file"),
                      opt_name, opt_arg);
        return -1;
    }

    if (opt_arg[0] != '/') {
        skAppPrintErr(("Invalid %s: Must use complete path"
                       " ('%s' does not begin with slash)"),
                      opt_name, opt_arg);
        return -1;
    }

    return 0;
}


/**
 *    Handle a single command line argument.
 */
static int
skMsgTlsOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    uint32_t tmp32;
    int rv;

    SK_UNUSED_PARAM(cData);

#define SET_FILE_OPTION(variable)                                       \
    if (variable) {                                                     \
        skAppPrintErr("Invalid %s: Switch used multiple times",         \
                      sk_tls_options[opt_index].name);                  \
    }                                                                   \
    if (optionsFileCheck(sk_tls_options[opt_index].name, opt_arg)) {    \
        return 1;                                                       \
    }                                                                   \
    variable = opt_arg


    switch ((sk_tls_options_enum)opt_index) {
      case OPT_TLS_CA:
        SET_FILE_OPTION(tls_ca_file);
        break;

      case OPT_TLS_CERT:
        SET_FILE_OPTION(tls_cert_file);
        break;

      case OPT_TLS_KEY:
        SET_FILE_OPTION(tls_key_file);
        break;

      case OPT_TLS_PKCS12:
        SET_FILE_OPTION(tls_pkcs12_file);
        break;

      case OPT_TLS_CRL:
        SET_FILE_OPTION(tls_crl_file);
        break;

      case OPT_TLS_PRIORITY:
        if (tls_priority) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          sk_tls_options[opt_index].name);
        }
        tls_priority = opt_arg;
        break;

      case OPT_TLS_SECURITY:
        if (tls_security) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          sk_tls_options[opt_index].name);
        }
        tls_security = opt_arg;
        break;

      case OPT_TLS_DEBUG_LEVEL:
        rv = skStringParseUint32(&tmp32, opt_arg, 0, MAX_TLS_DEBUG_LEVEL);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          sk_tls_options[opt_index].name, opt_arg,
                          skStringParseStrerror(rv));
            return 1;
        }
        tls_debug_level = (int)tmp32;
        break;
    }

    return 0;
}


/* Register the switches and their handler function */
int
skMsgTlsOptionsRegister(
    const char         *passwd_env_name)
{
    password_env_name = passwd_env_name;
    return skOptionsRegister(sk_tls_options, &skMsgTlsOptionsHandler, NULL);
}

/* Print usage for the switches */
void
skMsgTlsOptionsUsage(
    FILE               *fh)
{
    unsigned int i, j;

    fprintf(fh, "\nTransport encryption switches:\n");
    for (i = 0; sk_tls_options[i].name; ++i) {
        fprintf(fh, "--%s %s. %s", sk_tls_options[i].name,
                SK_OPTION_HAS_ARG(sk_tls_options[i]),
                sk_tls_options_help[i]);
        switch (sk_tls_options[i].val) {
#if GNUTLS_VERSION_NUMBER >= 0x030400
          case OPT_TLS_PRIORITY:
            {
                const unsigned int flag = GNUTLS_PRIORITY_LIST_INIT_KEYWORDS;
                const char *s;
                fprintf(fh, ".\n\tValues:");
                for (j = 0; (s = gnutls_priority_string_list(j, flag)); ++j) {
                    if (*s) {
                        fprintf(fh, "%s %s", ((0 == j) ? "" : ","), s);
                    }
                }
            }
            break;
#endif  /* GNUTLS_VERSION_NUMBER >= 0x030400 */
          case OPT_TLS_SECURITY:
            for (j = 0; tls_security_levels[j].name; ++j) {
                fprintf(fh, "%s %s",
                        ((0 == j) ? "" : ","), tls_security_levels[j].name);
            }
            break;
          case OPT_TLS_DEBUG_LEVEL:
            fprintf(fh, "%d", MAX_TLS_DEBUG_LEVEL);
            break;
          default:
            break;
        }
        fprintf(fh, "\n");
    }
}

/* Verify the switches. */
int
skMsgTlsOptionsVerify(
    unsigned int       *tls_available)
{
    sk_stringmap_t *field_map = NULL;
    sk_stringmap_entry_t *sm_entry;
    sk_stringmap_status_t sm_err;
    int rv = 0;

    if (NULL == tls_security) {
        tls_security = TLS_SECURITY_DEFAULT;
    }

    /* create a stringmap */
    if ((sm_err = skStringMapCreate(&field_map))
        || (sm_err = skStringMapAddEntries(field_map, -1, tls_security_levels)))
    {
        skAppPrintErr("Unable to create string map: %s",
                      skStringMapStrerror(sm_err));
        rv = 1;
        goto END;
    }

    /* attempt to match */
    sm_err = skStringMapGetByName(field_map, tls_security, &sm_entry);
    switch (sm_err) {
      case SKSTRINGMAP_OK:
        tls_security_param = (gnutls_sec_param_t)sm_entry->id;
        break;
      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s: Field '%s' is ambiguous",
                      sk_tls_options[OPT_TLS_SECURITY].name, tls_security);
        rv = 1;
        break;
      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s: Field '%s' is not recognized",
                      sk_tls_options[OPT_TLS_SECURITY].name, tls_security);
        rv = 1;
        break;
      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      sm_err);
        rv = 1;
        break;
    }

    if (tls_ca_file || tls_cert_file || tls_key_file || tls_pkcs12_file) {
        if (!tls_ca_file) {
            skAppPrintErr("A certificate authority file must be specified"
                          " with --%s when using encryption",
                          sk_tls_options[OPT_TLS_CA].name);
            rv = 1;
        }
        if (0 == ((tls_cert_file && tls_key_file) ^ (!!tls_pkcs12_file))) {
            skAppPrintErr("When using encryption, you must specify --%s and "
                          "--%s, or just --%s",
                          sk_tls_options[OPT_TLS_CERT].name,
                          sk_tls_options[OPT_TLS_KEY].name,
                          sk_tls_options[OPT_TLS_PKCS12].name);
            rv = 1;
        }
    }

    if (tls_ca_file && 0 == rv) {
        connection_type = CONN_TLS;
    }
    if (tls_available) {
        *tls_available = (CONN_TLS == connection_type);
    }

  END:
    skStringMapDestroy(field_map);
    return rv;
}

#endif  /* SK_ENABLE_GNUTLS */


/*** TCP functions ***/

/*
 *    Use standard TCP functions to write (send) a message.
 *
 *    Either this function or tls_send() is used in the
 *    writer_thread() to write a message.  The 'transport' member of
 *    the sk_msg_conn_queue_t determines which function is used.
 *
 *    tcp_recv() is the matching function for receiving a message.
 */
static int
tcp_send(
    sk_msg_conn_queue_t    *conn,
    sk_msg_write_buf_t     *write_buf)
{
    uint8_t *seg_base = NULL;
    sk_msg_t *msg;
    int retval = 0;
    ssize_t rv;

    DEBUG_ENTER_FUNC;

    assert(write_buf);
    msg = write_buf->msg;

    assert(msg);
    assert(conn);
    assert(msg->segments);
    assert(msg->segment[0].iov_base == &msg->hdr);
    assert(msg->segment[0].iov_len  == sizeof(msg->hdr));

    DEBUG_PRINT3("Sending chan=%#x type=%#x",
                 ntohs(msg->hdr.channel), ntohs(msg->hdr.type));

    if (write_buf->seg_offset) {
        /* there is a partially written segment; move iov_base to
         * start of unwritten data and adjust length of segment  */
        assert(msg->segment[write_buf->cur_seg].iov_len
               > write_buf->seg_offset);
        seg_base = (uint8_t*)msg->segment[write_buf->cur_seg].iov_base;
        msg->segment[write_buf->cur_seg].iov_base
            = seg_base + write_buf->seg_offset;
        msg->segment[write_buf->cur_seg].iov_len -= write_buf->seg_offset;
    }

    /* Write the message */
    while ((rv = writev(conn->wsocket, msg->segment + write_buf->cur_seg,
                        msg->segments - write_buf->cur_seg))
           != write_buf->msg_size)
    {
        if (rv == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                DEBUG_PRINT1("send: writev returned EAGAIN");
                retval = SKMERR_PARTIAL;
                break;
            }
            if (errno == EPIPE || errno == ECONNRESET) {
                DEBUG_PRINT3("send: Connection closed due to %d [%s]",
                             errno, strerror(errno));
                retval = SKMERR_CLOSED;
                break;
            }
            conn->last_errnum = errno;
            DEBUG_PRINT3("send: System error %d [%s]", errno, strerror(errno));
            retval = SKMERR_ERRNO;
            break;
        }
        if (rv == 0) {
            DEBUG_PRINT1("send: Connection closed due to write returning 0");
            retval = SKMERR_CLOSED;
            break;
        }
        assert(rv < write_buf->msg_size);
        DEBUG_PRINT3("send: Handling short write (%" SK_PRIdZ "/%" SK_PRIdZ ")",
                     rv, write_buf->msg_size);
        retval = SKMERR_PARTIAL;
        write_buf->msg_size -= rv;
        if (seg_base) {
            msg->segment[write_buf->cur_seg].iov_base = seg_base;
            seg_base = NULL;
            if (msg->segment[write_buf->cur_seg].iov_len > (size_t)rv) {
                /* did not complete writing this segment */
                msg->segment[write_buf->cur_seg].iov_len
                    += write_buf->seg_offset;
                write_buf->seg_offset += rv;
                break;
            }
            /* finished this segment */
            rv -= msg->segment[write_buf->cur_seg].iov_len;
            msg->segment[write_buf->cur_seg].iov_len += write_buf->seg_offset;
            ++write_buf->cur_seg;
        }
        while (rv > 0
               && msg->segment[write_buf->cur_seg].iov_len <= (size_t)rv)
        {
            rv -= msg->segment[write_buf->cur_seg].iov_len;
            ++write_buf->cur_seg;
        }
        /* partial write for this segment */
        write_buf->seg_offset = rv;
        break;
    }

    if (seg_base) {
        msg->segment[write_buf->cur_seg].iov_base = seg_base;
        msg->segment[write_buf->cur_seg].iov_len += write_buf->seg_offset;
    }

    RETURN(retval);
}


/*
 *    Use standard TCP functions to read (receive) a message.
 *
 *    Either this function or tls_recv() is used in the
 *    reader_thread() to read a message.  The 'transport' member of
 *    the sk_msg_conn_queue_t determines which function is used.
 *
 *    tcp_send() is the matching function for sending a message.
 */
static int
tcp_recv(
    sk_msg_conn_queue_t    *conn,
    sk_msg_t              **message)
{
    ssize_t             rv;
    sk_msg_read_buf_t  *buffer;
    int                 retval;
    int                 new_msg;

    DEBUG_ENTER_FUNC;

    assert(message);
    assert(conn);

    buffer = &conn->msg_read_buf;
    new_msg = (buffer->msg == NULL);
    if (new_msg) {
        /* Starting to read a new message. */

        sk_msg_hdr_t    *hdr;
        sk_msg_t        *msg;
        uint8_t         *hdr_buf;
        ssize_t          hdr_len;

        /* Create a message structure */
        buffer->msg = (sk_msg_t*)malloc(sizeof(sk_msg_t)
                                        + sizeof(struct iovec));
        msg = buffer->msg;
        MEM_ASSERT(msg != NULL);
        msg->segments = 1;
        msg->simple_free = NULL;
        msg->free_fn = msg_simple_free;
        hdr = &msg->hdr;
        msg->segment[0].iov_base = hdr;
        msg->segment[0].iov_len = sizeof(*hdr);
        memset(hdr, 0, sizeof(*hdr));

        /* Read a header */
        hdr_buf = (uint8_t*)hdr;
        hdr_len = (ssize_t)sizeof(*hdr);
        while ((rv = read(conn->rsocket, hdr_buf, hdr_len))
               != hdr_len)
        {
            /* Did not get all of the data we expected to get */
            if (rv > 0) {
                /* Partial read, reduce number of expected bytes and
                 * try again. */
                DEBUG_PRINT3("recv: Partial read of header; trying again"
                             " (%" SK_PRIdZ "/%" SK_PRIuZ ")",
                             rv, hdr_len);
                hdr_buf += rv;
                hdr_len -= rv;
                continue;
            }
            if (rv == -1) {
                /* Error.  Close connection unless interrupt. */
                if (errno == EINTR) {
                    continue;
                }
                if (errno != EAGAIN) {
                    conn->last_errnum = errno;
                    DEBUG_PRINT3("recv: System error %d [%s]",
                                 errno, strerror(errno));
                    retval = SKMERR_ERRNO;
                } else if (sizeof(*hdr) == (size_t)hdr_len) {
                    /* Handle EAGAIN on a completely unread header
                     * specially. This can happen if poll() says data
                     * is available when it actually is not, which can
                     * happen on Linux ("spurious readiness") */
                    DEBUG_PRINT1("recv: EAGAIN on unread header");
                    retval = SKMERR_EMPTY;
                } else {
                    /* Handle EAGAIN after we have read part of the
                     * header as a short read error. */
                    DEBUG_PRINT3("recv: Short read (%" SK_PRIdZ
                                 "/%" SK_PRIuZ ") [EAGAIN]",
                                 (sizeof(*hdr) - hdr_len), sizeof(*hdr));
                    retval = SKMERR_SHORT;
                }
            } else if (sizeof(*hdr) == (size_t)hdr_len) {
                /* This read() returned 0, and we do not have any of
                 * the header; assume connection is closed. */
                DEBUG_PRINT1("recv: Connection closed due to attempted"
                             " read of header returning 0");
                retval = SKMERR_CLOSED;
            } else {
                /* This read() returned 0, but we got part of the
                 * header on a previous read(); treat as error. */
                DEBUG_PRINT3("recv: Short read (%" SK_PRIdZ "/%" SK_PRIuZ ")",
                             (sizeof(*hdr) - hdr_len), sizeof(*hdr));
                retval = SKMERR_SHORT;
            }
            goto error;
        }

        /* Convert network byte order to host byte order */
        hdr->channel = ntohs(hdr->channel);
        hdr->type    = ntohs(hdr->type);
        hdr->size    = ntohs(hdr->size);

        DEBUG_PRINT4("Receiving chan=%#x type=%#x size=%d",
                     hdr->channel, hdr->type, hdr->size);

        if (hdr->size == 0) {
            /* If the size is zero, the message is complete */
            *message = msg;
            buffer->msg = NULL;
            RETURN(0);
        }
        /* Allocate space for the body of the message */
        msg->segment[1].iov_base = malloc(hdr->size);
        MEM_ASSERT(msg->segment[1].iov_base);
        msg->segment[1].iov_len = hdr->size;
        msg->segments++;

        /* Maintain state for re-entrant call */
        buffer->count = hdr->size;
        buffer->loc = (uint8_t*)msg->segment[1].iov_base;

        /* Fall through to read the rest of the message.  NOTE: Do not
         * fail if the next read() returns 0, since maybe the header
         * was the only thing available to read. */
    }
    /* else, the previous call to recv was a partial read of the
     * message. */

    assert(buffer->count);
    rv = read(conn->rsocket, buffer->loc, buffer->count);
    if (rv == -1) {
        if (errno == EINTR || errno == EAGAIN) {
            DEBUG_PRINT3("Failed to read %u bytes; return PARTIAL [%s]",
                         buffer->count, strerror(errno));
            RETURN(SKMERR_PARTIAL);
        }
        conn->last_errnum = errno;
        DEBUG_PRINT3("Failed to read %u bytes; return ERRNO [%s]",
                     buffer->count, strerror(errno));
        retval = SKMERR_ERRNO;
        goto error;
    } else if (rv == 0 && !new_msg) {
        /* Fail: poll() said data was available, and this first
         * attempt to read() data returned 0 bytes. */
        DEBUG_PRINT2("Failed to read %u bytes; return CLOSED [EOF]",
                     buffer->count);
        retval = SKMERR_CLOSED;
        goto error;
    }

    buffer->count -= rv;
    buffer->loc   += rv;

    if (buffer->count != 0) {
        /* We've read the available data but the message is not yet
         * complete; return to reader_thread() and call poll()
         * again */
        DEBUG_PRINT2("PARTIAL message, %u bytes remaining", buffer->count);
        RETURN(SKMERR_PARTIAL);
    }
    /* else, message is complete */

    *message = buffer->msg;
    buffer->msg = NULL;
    RETURN(0);

  error:
    if (buffer->msg) {
        skMsgDestroy(buffer->msg);
        buffer->msg = NULL;
    }
    RETURN(retval);
}


#if SK_ENABLE_GNUTLS

/*** TLS functions ***/

/*
 *    Use GnuTLS to write (send) a message.
 *
 *    Either this function or tcp_send() is used in the
 *    writer_thread() to write a message.  The 'transport' member of
 *    the sk_msg_conn_queue_t determines which function is used.
 *
 *    tls_recv() is the matching function for receiving a message.
 *
 *    The call to gnutls_record_send() in this function invokes the
 *    tls_push() callback defined below.
 */
static int
tls_send(
    sk_msg_conn_queue_t    *conn,
    sk_msg_write_buf_t     *write_buf)
{
    sk_msg_t *msg;
    ssize_t rv;
    uint16_t i;

    DEBUG_ENTER_FUNC;

    assert(write_buf);
    msg = write_buf->msg;

    assert(msg);
    assert(conn);
    assert(conn->use_tls);
    assert(msg->segments);
    assert(msg->segment[0].iov_base == &msg->hdr);
    assert(msg->segment[0].iov_len  == sizeof(msg->hdr));

    DEBUG_PRINT3("Sending chan=%#x type=%#x",
                 ntohs(msg->hdr.channel), ntohs(msg->hdr.type));

    for (i = 0; i < msg->segments; i++) {
        size_t remaining = msg->segment[i].iov_len;
        uint8_t *loc = (uint8_t*)msg->segment[i].iov_base;

        /* Write the message */
        while (remaining) {
            DEBUG_PRINT2("calling gnutls_record_send (%d)",
                         (skm_len_t)msg->segment[i].iov_len);
            rv = gnutls_record_send(conn->session, loc, remaining);
            DEBUG_PRINT2("gnutls_record_send -> %" SK_PRIdZ, rv);
            if (rv < 0) {
                if (rv == GNUTLS_E_INTERRUPTED || rv == GNUTLS_E_AGAIN) {
                    continue;
                }
                if (rv == GNUTLS_E_PUSH_ERROR) {
                    if (errno == EPIPE || errno == ECONNRESET) {
                        RETURN(SKMERR_CLOSED);
                    }
                    conn->last_errnum = errno;
                    RETURN(SKMERR_ERRNO);
                }
                conn->last_errnum = rv;
                RETURN(SKMERR_GNUTLS);
            } else if (rv == 0) {
                DEBUG_PRINT1("send: Connection closed"
                             " due to write returning 0");
                RETURN(SKMERR_CLOSED);
            } else {
                remaining -= rv;
                loc += rv;
            }
        }
    }

    RETURN(0);
}


/*
 *    Use GnuTLS to read (receive) a message.
 *
 *    Either this function or tcp_recv() is used in the
 *    reader_thread() to read a message.  The 'transport' member of
 *    the sk_msg_conn_queue_t determines which function is used.
 *
 *    tls_send() is the matching function for sending a message.
 *
 *    The call to gnutls_record_recv() in this function invokes the
 *    tls_pull() callback defined below.
 */
static int
tls_recv(
    sk_msg_conn_queue_t    *conn,
    sk_msg_t              **message)
{
    ssize_t             rv;
    sk_msg_read_buf_t  *buffer;
    int                 retval;
    int                 new_msg;

    DEBUG_ENTER_FUNC;

    assert(message);
    assert(conn);

    buffer = &conn->msg_read_buf;
    new_msg = (buffer->msg == NULL);
    if (new_msg) {
        /* Starting to read a new message */

        sk_msg_hdr_t    *hdr;
        sk_msg_t        *msg;
        uint8_t         *hdr_buf;
        ssize_t          hdr_len;

        /* Create a message structure */
        buffer->msg = (sk_msg_t*)malloc(sizeof(sk_msg_t)
                                        + sizeof(struct iovec));
        msg = buffer->msg;
        MEM_ASSERT(msg != NULL);
        msg->segments = 1;
        msg->simple_free = NULL;
        msg->free_fn = msg_simple_free;
        hdr = &msg->hdr;
        msg->segment[0].iov_base = hdr;
        msg->segment[0].iov_len = sizeof(*hdr);
        memset(hdr, 0, sizeof(*hdr));

        /* Read a header */
        hdr_buf = (uint8_t*)hdr;
        hdr_len = (ssize_t)sizeof(*hdr);
        DEBUG_PRINT2("calling gnutls_record_recv (%" SK_PRIdZ ")", hdr_len);
        while ((rv = gnutls_record_recv(conn->session, hdr_buf, hdr_len))
               != hdr_len)
        {
            DEBUG_PRINT2("gnutls_record_recv -> %" SK_PRIdZ, rv);
            if (rv > 0) {
                /* Partial read, reduce number of expected bytes and
                 * try again. */
                DEBUG_PRINT3("recv: Partial read of header; trying again"
                             " (%" SK_PRIdZ "/%" SK_PRIdZ ")",
                             rv, hdr_len);
                hdr_buf += rv;
                hdr_len -= rv;
                DEBUG_PRINT2("calling gnutls_record_recv (%" SK_PRIdZ ")",
                             hdr_len);
                continue;
            }
            if (rv < 0) {
                if (rv == GNUTLS_E_INTERRUPTED || rv == GNUTLS_E_AGAIN) {
                    DEBUG_PRINT2("calling gnutls_record_recv (%" SK_PRIdZ ")",
                                 hdr_len);
                    continue;
                }
                if (rv == GNUTLS_E_PULL_ERROR) {
                    conn->last_errnum = errno;
                    retval = SKMERR_ERRNO;
                } else {
                    /* it seems that GnuTLS 2.x returns
                     * GNUTLS_E_UNEXPECTED_PACKET_LENGTH when read()
                     * in the tls_pull() function returns 0.  Perhaps
                     * we ought to treat that as an ordinary close to
                     * avoid an odd error msg in the log file. */
                    conn->last_errnum = rv;
                    retval = SKMERR_GNUTLS;
                }
            } else if (sizeof(*hdr) == (size_t)hdr_len) {
                /* This read() returned 0, and we do not have any of
                 * the header; assume connection is closed. */
                DEBUG_PRINT1("recv: Connection closed due to attempted"
                             " read of header returning 0");
                retval = SKMERR_CLOSED;
            } else {
                /* This read() returned 0, but we got part of the
                 * header on a previous read(); treat as error. */
                DEBUG_PRINT3("recv: Short read (%" SK_PRIdZ "/%" SK_PRIuZ ")",
                             (sizeof(*hdr) - hdr_len), sizeof(*hdr));
                retval = SKMERR_SHORT;
            }
            goto error;
        }
        DEBUG_PRINT2("gnutls_record_recv -> %" SK_PRIdZ, rv);

        /* Convert network byte order to host byte order */
        hdr->channel = ntohs(hdr->channel);
        hdr->type    = ntohs(hdr->type);
        hdr->size    = ntohs(hdr->size);

        DEBUG_PRINT4("Receiving chan=%#x type=%#x size=%d",
                     hdr->channel, hdr->type, hdr->size);

        if (hdr->size == 0) {
            /* If the size is zero, the message is complete */
            *message = msg;
            buffer->msg = NULL;
            RETURN(0);
        }
        /* Allocate space for the body of the message */
        msg->segment[1].iov_base = malloc(hdr->size);
        MEM_ASSERT(msg->segment[1].iov_base);
        msg->segment[1].iov_len = hdr->size;
        msg->segments++;

        /* Maintain state for re-entrant call */
        buffer->count = hdr->size;
        buffer->loc = (uint8_t*)msg->segment[1].iov_base;

        /* Fall through to read the rest of the message.  NOTE: Do not
         * fail if the next gnutls_record_recv() returns 0, since
         * maybe the header was the only thing available. */
    }
    /* else, the previous call to recv was a partial read of the
     * message. */

    assert(buffer->count);
    DEBUG_PRINT2("calling gnutls_record_recv (%d)", buffer->count);
    while ((rv = gnutls_record_recv(conn->session, buffer->loc, buffer->count))
           < 0)
    {
        DEBUG_PRINT2("gnutls_record_recv -> %" SK_PRIdZ, rv);
        if (rv == GNUTLS_E_INTERRUPTED || rv == GNUTLS_E_AGAIN) {
            DEBUG_PRINT2("calling gnutls_record_recv (%d)", buffer->count);
            continue;
        }
        if (rv == GNUTLS_E_PULL_ERROR) {
            conn->last_errnum = errno;
            retval = SKMERR_ERRNO;
            DEBUG_PRINT3("read failure: %d [%s]", errno, strerror(errno));
        } else {
            conn->last_errnum = rv;
            retval = SKMERR_GNUTLS;
            DEBUG_PRINT2("read failure: [%s]", gnutls_strerror(rv));
        }
        goto error;
    }
    DEBUG_PRINT2("gnutls_record_recv -> %" SK_PRIdZ, rv);

    if (rv == 0 && !new_msg) {
        /* Fail: poll() said data was available, but this first
         * attempt to use gnutls_record_recv() returned 0 bytes. */
        DEBUG_PRINT1("read ended: [EOF]");
        retval = SKMERR_CLOSED;
        goto error;
    }

    buffer->count -= rv;
    buffer->loc   += rv;

    if (buffer->count != 0) {
        /* we've read the available data but the message is not yet
         * complete; return to reader_thread() and call poll()
         * again */
        RETURN(SKMERR_PARTIAL);
    }
    /* else, message is complete */

    *message = buffer->msg;
    buffer->msg = NULL;
    RETURN(0);

  error:
    if (buffer->msg) {
        skMsgDestroy(buffer->msg);
        buffer->msg = NULL;
    }
    RETURN(retval);
}

#endif /* SK_ENABLE_GNUTLS */


#if SK_ENABLE_GNUTLS
/*
 *    Since we cannot be certain that GnuTLS was built with pthread
 *    support (hello redhat), define our own functions that are copies
 *    of the functions gnutls_system_mutex_init(), etc, with
 *    pthread-support found in gnutls-3.x/lib/system/threads.c.
 */

/*    Initialize a mutex. */
static int
skMsgGnuTLSMutexInit(
    void             **priv)
{
    pthread_mutex_t *lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));

    *priv = lock;
    if (NULL == lock) {
        return GNUTLS_E_MEMORY_ERROR;
    }
    if (pthread_mutex_init(lock, NULL)) {
        free(lock);
        *priv = NULL;
        return GNUTLS_E_LOCKING_ERROR;
    }
    return 0;
}

/*    Destroy/Free a mutex. */
static int
skMsgGnuTLSMutexDeinit(
    void             **priv)
{
    pthread_mutex_destroy((pthread_mutex_t *)*priv);
    free(*priv);
    *priv = NULL;
    return 0;
}

/*    Lock a mutex. */
static int
skMsgGnuTLSMutexLock(
    void             **priv)
{
    if (pthread_mutex_lock((pthread_mutex_t *)*priv)) {
        return GNUTLS_E_LOCKING_ERROR;
    }
    return 0;
}

/*    Unlock a mutex. */
static int
skMsgGnuTLSMutexUnlock(
    void             **priv)
{
    if (pthread_mutex_unlock((pthread_mutex_t *)*priv)) {
        return GNUTLS_E_LOCKING_ERROR;
    }
    return 0;
}
#endif  /* SK_ENABLE_GNUTLS */


/***********************************************************************/


#if SK_ENABLE_GNUTLS

/* Callback function used for debugging messages */
static void
skMsgGnuTLSDebugLog(
    int                 level,
    const char         *msg)
{
    INFOMSG("GnuTLS[%d] %s", level, msg);
}

#if GNUTLS_VERSION_NUMBER >= 0x030000
/* Callback function used for audit messages */
static void
skMsgGnuTLSAuditLog(
    gnutls_session_t    session,
    const char         *msg)
{
    SK_UNUSED_PARAM(session);
    NOTICEMSG("GnuTLS audit: %s", msg);
}
#endif  /* GNUTLS_VERSION_NUMBER >= 0x030000 */

#if GNUTLS_VERSION_NUMBER < 0x030406
/* Callback function to verify the peer's certificate during the TLS
 * handshake. */
static int
skMsgGnuTLSVerifyPeer(
    gnutls_session_t    session)
{
    int rv;
    unsigned int status;
    char reasonbuf[256];
    const char *reason;

    DEBUG_ENTER_FUNC;

    status = 0;
    rv = gnutls_certificate_verify_peers2(session, &status);
    if (0 == rv && 0 == status) {
        RETURN(0);
    }
    if (rv < 0) {
        NOTICEMSG("Failed to verify peer's certificate: %s",
                  gnutls_strerror(rv));
        RETURN(GNUTLS_E_CERTIFICATE_ERROR);
    }

    if (status & GNUTLS_CERT_REVOKED) {
        reason = "Certificate is revoked by its authority.";
    } else if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
        reason = "Certificate's issuer is not known.";
    } else if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
        reason = "Certificate's signer is not a CA.";
    } else if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
        reason = "Certificate is signed using an insecure algorithm";
    } else if (status & GNUTLS_CERT_NOT_ACTIVATED) {
        reason = "Certificate is not yet activated.";
    } else if (status & GNUTLS_CERT_EXPIRED) {
        reason = "Certificate has expired.";
    } else if (status & GNUTLS_CERT_INVALID) {
        reason = ("Certificate is not signed by a known authority"
                  " or the signature is invalid");
    } else {
        snprintf(reasonbuf, sizeof(reasonbuf), "Other reason [%#x]",
                 status);
        reason = reasonbuf;
    }

    NOTICEMSG("Certificate verification failed: %s", reason);
    RETURN(GNUTLS_E_CERTIFICATE_ERROR);
}
#endif  /* GNUTLS_VERSION_NUMBER < 0x030406 */

/*
 *    If authentication and encryption files were provided, read and
 *    load them into the message queue's credentials.
 *
 *    Do global initialization of GnuTLS if it has not occurred yet.
 */
static int
skMsgQueueInitializeGnuTLS(
    sk_msg_queue_t     *queue)
{
#if GNUTLS_VERSION_NUMBER < 0x030506
    static gnutls_dh_params_t dh_params;
    unsigned int bits;
#endif  /* GNUTLS_VERSION_NUMBER < 0x030506 */
    int rv = 0;

    DEBUG_ENTER_FUNC;

    assert(queue);
    assert(queue->root);

    pthread_mutex_lock(&sk_msg_gnutls_mutex);
    if (NULL == tls_ca_file) {
        assert(NULL == tls_cert_file);
        assert(NULL == tls_key_file);
        assert(NULL == tls_pkcs12_file);
        DEBUGMSG("Skipping GnuTLS initialization since not in use");
        goto END;
    }
    assert((tls_cert_file && tls_key_file) ^ (!!tls_pkcs12_file));

    if (NULL == gnutls_check_version(MIN_GNUTLS_VERISON)) {
        CRITMSG("GnuTLS version is less than required %s", MIN_GNUTLS_VERISON);
        goto END;
    }

    if (!sk_msg_gnutls_initialized) {
        gnutls_global_set_mutex(skMsgGnuTLSMutexInit, skMsgGnuTLSMutexDeinit,
                                skMsgGnuTLSMutexLock, skMsgGnuTLSMutexUnlock);
        rv = gnutls_global_init();
        if (rv < 0) {
            WARNINGMSG("Unable to initialize gnutls: %s", gnutls_strerror(rv));
            goto END;
        }
        if (tls_debug_level) {
            gnutls_global_set_log_function(skMsgGnuTLSDebugLog);
            gnutls_global_set_log_level(tls_debug_level);
        }
        if (tls_priority) {
            const char *err_pos = NULL;
            rv = gnutls_priority_init(&tls_priority_cache, tls_priority,
                                      &err_pos);
            if (rv != GNUTLS_E_SUCCESS) {
                if (rv != GNUTLS_E_INVALID_REQUEST || NULL == err_pos) {
                    CRITMSG("Unable to initialize gnutls priority: %s",
                            gnutls_strerror(rv));
                } else {
                    CRITMSG("Invalid %s: Error at '%s'",
                            sk_tls_options[OPT_TLS_PRIORITY].name, err_pos);
                }
                goto END;
            }
        }
#if GNUTLS_VERSION_NUMBER >= 0x030000
        gnutls_global_set_audit_log_function(skMsgGnuTLSAuditLog);
#endif
#if GNUTLS_VERSION_NUMBER < 0x030506
        /* Generate Diffie-Hellman parameters */
        bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, tls_security_param);
        if (0 == bits) {
            CRITMSG(("Programmer error: Unable to determine number of bits"
                     " for algorithm %u at security level %u in"
                     " GnuTLS version %s"),
                    GNUTLS_PK_DH, tls_security_param,
                    gnutls_check_version(NULL));
            rv = -1;
            goto END;
        }
        rv = gnutls_dh_params_init(&dh_params);
        if (rv < 0) {
            CRITMSG("Unable to initialize Diffie-Hellman parameters: %s",
                    gnutls_strerror(rv));
            goto END;
        }
        INFOMSG("Generating Diffie-Hellman parameters...");
        INFOMSG("This could take some time...");
        rv = gnutls_dh_params_generate2(dh_params, bits);
        if (rv < 0) {
            CRITMSG("Unable to generate Diffie-Hellman parameters: %s",
                    gnutls_strerror(rv));
            goto END;
        }
        INFOMSG("Finished generating Diffie-Hellman parameters");
#endif  /* GNUTLS_VERSION_NUMBER < 0x030506 */
        sk_msg_gnutls_initialized = 1;
    }

    /* allocate credentials and set Diffie-Hellman parameters */
    if (!queue->root->cred_set) {
        rv = gnutls_certificate_allocate_credentials(&queue->root->cred);
        if (rv < 0) {
            WARNINGMSG("Unable to allocate credentials: %s",
                       gnutls_strerror(rv));
            goto END;
        }
#if GNUTLS_VERSION_NUMBER < 0x030506
        gnutls_certificate_set_dh_params(queue->root->cred, dh_params);
#else
        rv = (gnutls_certificate_set_known_dh_params(
                  queue->root->cred, GNUTLS_SEC_PARAM_MEDIUM));
        if (rv < 0) {
            WARNINGMSG(
                "Unable to set credentials' Diffie-Hellman parameters: %s",
                gnutls_strerror(rv));
            goto END;
        }
#endif  /* GNUTLS_VERSION_NUMBER < 0x030506 */
    }

    /* add the trusted CAs from 'tls_ca_file'; the file should
     * be in PEM format. */
    rv = (gnutls_certificate_set_x509_trust_file(
              queue->root->cred, tls_ca_file, GNUTLS_X509_FMT_PEM));
    if (rv < 0) {
        CRITMSG("Invalid Certificate Authority file '%s': %s",
                tls_ca_file, gnutls_strerror(rv));
        goto END;
    }

    /* add the revocation file from 'tls_crl_file' if provided; the
     * file should be in PEM format. */
    if (tls_crl_file) {
        rv = (gnutls_certificate_set_x509_crl_file(
                  queue->root->cred, tls_crl_file, GNUTLS_X509_FMT_PEM));
        if (rv < 0) {
            CRITMSG("Invalid Certificate Revocation List file '%s': %s",
                    tls_crl_file, gnutls_strerror(rv));
            goto END;
        }
    }

#if  GNUTLS_VERSION_NUMBER < 0x030406
    /* set the callback function used to verify the peers'
     * certificates */
    gnutls_certificate_set_verify_function(
        queue->root->cred, &skMsgGnuTLSVerifyPeer);
#endif  /* GNUTLS_VERSION_NUMBER < 0x030406 */

    /* add either the PKCS12 file or the certificate and key files */
    if (tls_pkcs12_file) {
        const char *password = getenv(password_env_name);
        rv = (gnutls_certificate_set_x509_simple_pkcs12_file(
                  queue->root->cred, tls_pkcs12_file,
                  GNUTLS_X509_FMT_DER, password));
        if (rv < 0) {
            CRITMSG("Invalid encryption cert file '%s': %s",
                    tls_pkcs12_file, gnutls_strerror(rv));
            goto END;
        }
    } else {
        /* set a certificate/private-key pair in the credential from
         * separate certificate and key files, each in PEM format. */
        rv = (gnutls_certificate_set_x509_key_file(
                  queue->root->cred, tls_cert_file, tls_key_file,
                  GNUTLS_X509_FMT_PEM));
        if (rv < 0) {
            CRITMSG("Invalid encryption cert or key file '%s', '%s': %s",
                    tls_cert_file, tls_key_file, gnutls_strerror(rv));
            goto END;
        }
    }

    if (!queue->root->cred_set) {
        queue->root->cred_set = 1;
        ++sk_msg_gnutls_initialized;
    }

    rv = 0;

  END:
    if (0 != rv) {
        rv = -1;
        if (queue->root->cred_set) {
            gnutls_certificate_free_credentials(queue->root->cred);
            queue->root->cred_set = 0;
        }
    }
    pthread_mutex_unlock(&sk_msg_gnutls_mutex);
    RETURN(rv);
}


void
skMsgGnuTLSTeardown(
    void)
{
    DEBUG_ENTER_FUNC;

    pthread_mutex_lock(&sk_msg_gnutls_mutex);

    if (tls_priority_cache) {
        gnutls_priority_deinit(tls_priority_cache);
        tls_priority_cache = NULL;
    }
    if (sk_msg_gnutls_initialized) {
        gnutls_global_deinit();
        sk_msg_gnutls_initialized = 0;
    }

    pthread_mutex_unlock(&sk_msg_gnutls_mutex);
    RETURN_VOID;
}

#endif /* SK_ENABLE_GNUTLS */


/* Create a channel within a message queue. */
static sk_msg_channel_queue_t *
create_channel(
    sk_msg_queue_t     *q)
{
    sk_msg_channel_queue_t *chan;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    ASSERT_QUEUE_LOCK(q);

    /* Allocate space for a new channel */
    chan = (sk_msg_channel_queue_t *)calloc(1, sizeof(*chan));
    MEM_ASSERT(chan != NULL);

    chan->queue = mqCreateQueue(q->group);
    MEM_ASSERT(chan->queue != NULL);

    /* Assign a local channel number and add the channel to the
       message queue */
    do {
        chan->channel = q->root->next_channel++;
        rv = int_dict_set(q->root->channel, chan->channel, &chan);
    } while (rv == 1);
    MEM_ASSERT(rv == 0);

    /* Channel is created, rchannel is unset */
    chan->state = SKM_CREATED;
    chan->rchannel = SKMSG_CHANNEL_CONTROL;
    rv = pthread_cond_init(&chan->pending, NULL);
    XASSERT(rv == 0);
    chan->is_pending = 0;

    rv = int_dict_set(q->root->groups, chan->channel, &q);
    MEM_ASSERT(rv == 0);
    rv = int_dict_set(q->channel, chan->channel, &chan);
    MEM_ASSERT(rv == 0);
    chan->group = q;

    DEBUG_PRINT2("create_channel() = %#x", chan->channel);

    RETURN(chan);
}


/* Attach a channel to a connection object. */
static int
set_channel_connecting(
    sk_msg_queue_t         *q,
    sk_msg_channel_queue_t *chan,
    sk_msg_conn_queue_t    *conn)
{
    int rv;

    DEBUG_ENTER_FUNC;
    SK_UNUSED_PARAM(q);

    assert(q);
    assert(chan);
    assert(conn);
    ASSERT_QUEUE_LOCK(q);
    assert(chan->state == SKM_CREATED);
    assert(conn->state != SKM_CLOSED);

    DEBUG_PRINT2("set_channel_connecting(%#x)", chan->channel);

    /* Set the channel's communication stream, set it to
       half-connected, and up the refcount on the connection
       object. */
    chan->conn = conn;
    chan->state = SKM_CONNECTING;

    /* Add an entry in the connections's channel map for the
       channel. */
    rv = int_dict_set(conn->channelmap, chan->channel, &chan);
    MEM_ASSERT(rv != -1);
    assert(rv == 0);

    conn->state = SKM_CONNECTED;
    conn->refcount++;

    RETURN(0);
}


/* Return 1 if the connection was destroyed, zero otherwise */
static int
set_channel_closed(
    sk_msg_queue_t         *q,
    sk_msg_channel_queue_t *chan,
    int                     no_destroy)
{
    sk_msg_conn_queue_t *conn;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(chan);
    ASSERT_QUEUE_LOCK(q);
    assert(chan->conn);
    if (chan->state == SKM_CLOSED) {
        RETURN(0);
    }
    assert(chan->conn->refcount > 0);
    assert(chan->state == SKM_CONNECTING ||
           chan->state == SKM_CONNECTED);

    DEBUG_PRINT2("set_channel_closed(%#x)", chan->channel);

    conn = chan->conn;

    if (chan->state == SKM_CONNECTED &&
        chan->channel != SKMSG_CHANNEL_CONTROL)
    {
        skm_channel_t lchannel = htons(chan->channel);
        DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_DIED (Internal)");
        send_message(q, SKMSG_CHANNEL_CONTROL,
                     SKMSG_CTL_CHANNEL_DIED,
                     &lchannel, sizeof(lchannel), SKM_SEND_INTERNAL,
                     0, NULL);
    }

    ASSERT_RESULT(int_dict_del(conn->channelmap, chan->channel),
                  int, 0);

    chan->state = SKM_CLOSED;
    conn->refcount--;

    /* Notify people waiting on this channel to complete connecting
       that it is dead. */
    MUTEX_BROADCAST(&chan->pending);

    if (conn->refcount == 0 && !no_destroy) {
        RETURN(destroy_connection(q, conn));
    }

    RETURN(0);
}


static int
set_channel_connected(
    sk_msg_queue_t         *q,
    sk_msg_channel_queue_t *chan,
    skm_channel_t           rchannel)
{
    DEBUG_ENTER_FUNC;
    SK_UNUSED_PARAM(q);

    assert(q);
    assert(chan);
    ASSERT_QUEUE_LOCK(q);
    assert(chan->state == SKM_CONNECTING);

    DEBUG_PRINT2("set_channel_connected(%#x)", chan->channel);

    chan->rchannel = rchannel;

    chan->state = SKM_CONNECTED;
    RETURN(0);
}


static void
destroy_channel(
    sk_msg_queue_t         *q,
    sk_msg_channel_queue_t *chan)
{
    DEBUG_ENTER_FUNC;

    assert(q);
    assert(chan);
    ASSERT_QUEUE_LOCK(q);

    DEBUG_PRINT2("destroy_channel(%#x)", chan->channel);

    if (chan->state == SKM_CONNECTED &&
        chan->channel != SKMSG_CHANNEL_CONTROL)
    {
        skm_channel_t rchannel = htons(chan->rchannel);
        DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_KILL (Ext-control)");
        send_message(q, chan->channel, SKMSG_CTL_CHANNEL_KILL,
                     &rchannel, sizeof(rchannel), SKM_SEND_CONTROL,
                     0, NULL);
    }
    if (chan->state == SKM_CONNECTED || chan->state == SKM_CONNECTING) {
        set_channel_closed(q, chan, 0);
    }

    assert(chan->state == SKM_CLOSED);

    ASSERT_RESULT(int_dict_del(q->root->channel, chan->channel), int, 0);

    ASSERT_RESULT(int_dict_del(q->root->groups, chan->channel), int, 0);
    ASSERT_RESULT(int_dict_del(chan->group->channel, chan->channel), int, 0);

    ASSERT_RESULT(pthread_cond_destroy(&chan->pending), int, 0);

    /* Disable adding to the queue (it will be destroyed when the
       group is destroyed) */
    mqQueueDisable(chan->queue, MQ_ADD);

    free(chan);

    RETURN_VOID;
}


#if SK_ENABLE_GNUTLS
#if SK_TLS_USE_CUSTOM_PULL_PUSH
/*
 *    A callback function used by GnuTLS for receiving (reading) data.
 *
 *    This callback is invoked by gnutls_record_recv(), which is
 *    called by the tls_recv() function, which is called by the
 *    reader_thread().
 */
static ssize_t
tls_pull(
    gnutls_transport_ptr_t  fd,
    void                   *buf,
    size_t                  len)
{
    struct pollfd pfd;
    ssize_t       rv;

    pfd.fd = (intptr_t)fd;
    pfd.events = POLLIN;

    rv = poll(&pfd, 1, TLS_POLL_TIMEOUT);
    if (0 == rv) {
        /* poll() timed out.  According to GnuTLS docs, this function
         * should act like recv(2) in that case and set errno to
         * EAGAIN and return -1 */
        errno = EAGAIN;
        rv = -1;
    } else if (1 == rv) {
        rv = read(pfd.fd, buf, len);

#if (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL
        if (pfd.revents & (POLLERR | POLLNVAL | POLLHUP)) {
            /* Log but ignore poll error events for now (allow the
             * read to fail).  */
            DEBUG_PRINT2("Poll returned %s", SK_POLL_EVENT_STR(pfd.revents));
        }
        if (-1 == rv) {
            DEBUG_PRINT2("Returning -1 from tls_pull (read()) [errno = %d]",
                         errno);
        } else if (0 == rv) {
            DEBUG_PRINT1("Returning 0 from tls_pull (read())");
        }
    } else {
        if (-1 == rv) {
            DEBUG_PRINT2("Returning -1 from tls_pull (poll()) [errno = %d]",
                         errno);
        } else {
            DEBUG_PRINT2("Returning %" SK_PRIdZ " from tls_pull (poll())", rv);
        }
#endif  /*  (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL */
    }
    return rv;
}

/*
 *    A callback function used by GnuTLS for sending (writing) data.
 *
 *    This callback is invoked by gnutls_record_send(), which is
 *    called by our tls_send() function, which is called by the
 *    writer_thread().
 */
static ssize_t
tls_push(
    gnutls_transport_ptr_t  fd,
    const void             *buf,
    size_t                  len)
{
    struct pollfd pfd;
    ssize_t       rv;

    pfd.fd = (intptr_t)fd;
    pfd.events = POLLOUT;

    rv = poll(&pfd, 1, TLS_POLL_TIMEOUT);
    if (1 == rv) {
        rv = write(pfd.fd, buf, len);

#if (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL
        if (pfd.revents & (POLLERR | POLLNVAL | POLLHUP)) {
            /* Log but ignore poll error events for now (allow the
             * write to fail).  */
            DEBUG_PRINT2("Poll returned %s", SK_POLL_EVENT_STR(pfd.revents));
        }
        if (-1 == rv) {
            DEBUG_PRINT2("Returning -1 from tls_push (write()) [errno = %d]",
                         errno);
        } else if (0 == rv) {
            DEBUG_PRINT1("Returning 0 from tls_push (write())");
        }
    } else {
        if (-1 == rv) {
            DEBUG_PRINT2("Returning -1 from tls_push (poll()) [errno = %d]",
                         errno);
        } else {
            DEBUG_PRINT2("Returning %" SK_PRIdZ " from tls_push (poll())", rv);
        }
#endif  /* (SENDRCV_DEBUG) & DEBUG_RWTRANSFER_PROTOCOL */
    }
    /* What should happen if result of poll() is 0 (timed out)?
     * Currently we just return 0, as if there was a zero write.
     * Possibly we should return -1 with an errno of EAGAIN. */
    return rv;
}
#endif  /* SK_TLS_USE_CUSTOM_PULL_PUSH */

static int
setup_tls(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn,
    int                     rsocket,
    int                     wsocket,
    skm_tls_type_t          tls)
{
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(conn);
    assert(q->root->cred_set);

    /* initialize the TLS session object depending on whether it is
     * the client or the server */
    switch (tls) {
      case SKM_TLS_CLIENT:
#if GNUTLS_VERSION_NUMBER < 0x030000
        rv = gnutls_init(&conn->session, GNUTLS_CLIENT);
#else
        rv = gnutls_init(&conn->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
#endif  /* #else of GNUTLS_VERSION_NUMBER < 0x030000 */
        break;
      case SKM_TLS_SERVER:
#if GNUTLS_VERSION_NUMBER < 0x030000
        rv = gnutls_init(&conn->session, GNUTLS_SERVER);
#else
        rv = gnutls_init(&conn->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
#endif  /* #else of GNUTLS_VERSION_NUMBER < 0x030000 */
        break;
      default:
        skAbortBadCase(tls);
    }
    if (rv < 0) {
        ERRMSG("Unable to initialize TLS in the session: %s",
               gnutls_strerror(rv));
        RETURN(-1);
    }

    /* tell the session to use the public/private keys loaded earlier */
    rv = gnutls_credentials_set(conn->session, GNUTLS_CRD_CERTIFICATE,
                                q->root->cred);
    if (rv < 0) {
        ERRMSG("Unable to set TLS credentials in the session: %s",
               gnutls_strerror(rv));
        RETURN(-1);
    }

    /* set the priority */
    if (tls_priority_cache) {
        rv = gnutls_priority_set(conn->session, tls_priority_cache);
    } else {
        /* use "NORMAL" priority */
        rv = gnutls_set_default_priority(conn->session);
    }
    if (rv < 0) {
        ERRMSG("Unable to initialize TLS priority in the session: %s",
               gnutls_strerror(rv));
        RETURN(-1);
    }

    if (rsocket != wsocket) {
        WARNINGMSG("Unexpected found read socket %d != write socket %d",
                   rsocket, wsocket);
        gnutls_transport_set_ptr2(conn->session,
                                  (gnutls_transport_ptr_t)(intptr_t)rsocket,
                                  (gnutls_transport_ptr_t)(intptr_t)wsocket);
    } else {
        gnutls_transport_set_ptr(conn->session,
                                 (gnutls_transport_ptr_t)(intptr_t)rsocket);
    }

#if SK_TLS_USE_CUSTOM_PULL_PUSH
    /* tell TLS to use our read and write functions (tls_pull,
     * tls_push) instead of the defaults.  The call to set_ptr2()
     * controls what will be passed to tls_pull() and tls_push(). */
    gnutls_transport_set_pull_function(conn->session, tls_pull);
    gnutls_transport_set_push_function(conn->session, tls_push);
#endif  /* SK_TLS_USE_CUSTOM_PULL_PUSH */
#if GNUTLS_VERSION_NUMBER < 0x030000
    /* Used to set the low water value in order for select() to check
     * if there are data pending to be read from the socket buffer. */
    gnutls_transport_set_lowat(conn->session, 0);
#endif  /* GNUTLS_VERSION_NUMBER < 0x030000 */
    set_nonblock(rsocket);

    /* force the client to send its certificate to the server */
    if (tls == SKM_TLS_SERVER) {
        gnutls_certificate_server_set_request(conn->session,
                                              GNUTLS_CERT_REQUIRE);
    }

#if GNUTLS_VERSION_NUMBER >= 0x030406
    gnutls_session_set_verify_cert(conn->session, NULL, 0);
#endif

    DEBUG_PRINT1("Attempting TLS handshake");
    while ((rv = gnutls_handshake(conn->session)) < 0
           && gnutls_error_is_fatal(rv) == 0)
    {
        DEBUG_PRINT2("Re-attempting TLS handshake on non-fatal error %s",
                     gnutls_strerror(rv));
    }
    if (rv < 0) {
        if (rv == GNUTLS_E_PUSH_ERROR) {
            NOTICEMSG("Remote side disconnected during TLS handshake."
                      " Certificate may have been rejected.");
        } else if (rv == GNUTLS_E_CERTIFICATE_ERROR) {
            NOTICEMSG("TLS handshake failed while verifying the certificate");
        }
#if GNUTLS_VERSION_NUMBER >= 0x030406
        else if (rv == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
            int type;
            unsigned int status;
            gnutls_datum_t out;

            /* check certificate verification status */
            type = gnutls_certificate_type_get(conn->session);
            status = gnutls_session_get_verify_cert_status(conn->session);
            if (gnutls_certificate_verification_status_print(
                    status, (gnutls_certificate_type_t)type, &out, 0) == 0)
            {
                NOTICEMSG("Failed to verify peer's certificate: %s", out.data);
                gnutls_free(out.data);
            } else {
                NOTICEMSG("Failed to verify peer's certificate"
                          " during TLS handshake");
            }
        }
#endif  /* GNUTLS_VERSION_NUMBER >= 0x030406 */
        else {
            NOTICEMSG(("TLS handshake failed"
                       " (peer may have rejected the certificate): %s"),
                      gnutls_strerror(rv));
        }

        gnutls_deinit(conn->session);
        RETURN(-1);
    }
    DEBUG_PRINT1("TLS handshake succeeded");

    conn->use_tls = 1;

    RETURN(0);
}
#endif /* SK_ENABLE_GNUTLS */


static int
create_connection(
    sk_msg_queue_t         *q,
    int                     rsocket,
    int                     wsocket,
    struct sockaddr        *addr,
    socklen_t               addrlen,
    sk_msg_conn_queue_t   **rconn,
    skm_tls_type_t          tls)
{
    sk_msg_conn_queue_t *conn;
    sk_queue_and_conn_t *qac;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(rconn);
    ASSERT_QUEUE_LOCK(q);

    DEBUG_PRINT3("create_connection() = %d, %d", rsocket, wsocket);

    /* Allocate space for the connection */
    conn = (sk_msg_conn_queue_t *)calloc(1, sizeof(*conn));
    MEM_ASSERT(conn != NULL);

#if SK_ENABLE_GNUTLS
    if (tls != SKM_TLS_NONE) {
        rv = setup_tls(q, conn, rsocket, wsocket, tls);
        if (rv != 0) {
            free(conn);
            RETURN(-1);
        }
    }
#endif /* SK_ENABLE_GNUTLS */

    /* Set the read and write sockets */
    conn->rsocket = rsocket;
    conn->wsocket = wsocket;

    /* And the address */
    conn->addr = addr;
    conn->addrlen = addrlen;

    conn->transport = (tls == SKM_TLS_NONE) ? CONN_TCP : CONN_TLS;

    /* Set up the channel queue and refcount */
    conn->channelmap = int_dict_create(sizeof(sk_msg_channel_queue_t *));
    MEM_ASSERT(conn->channelmap != NULL);
    conn->refcount = 0;

    /* Set the connections initial state */
    conn->state = SKM_CREATED;

    /* Set up the write queue */
    conn->queue = skDequeCreate();
    XASSERT(conn->queue != NULL);

    /* Initialize the writer thread start state */
    pthread_cond_init(&conn->writer_cond, NULL);
    conn->writer_state = SKM_THREAD_BEFORE;

    /* Initialize the reader thread start state */
    pthread_cond_init(&conn->reader_cond, NULL);
    conn->reader_state = SKM_THREAD_BEFORE;

    /* Set up and start the writer thread */
    qac = (sk_queue_and_conn_t *)malloc(sizeof(*qac));
    MEM_ASSERT(qac != NULL);
    qac->q = q;
    qac->conn = conn;
    THREAD_START("skmsg_writer", rv, q, &conn->writer, writer_thread, qac);
    XASSERT(rv == 0);

    /* Start the reader thread, */
    qac = (sk_queue_and_conn_t *)malloc(sizeof(*qac));
    MEM_ASSERT(qac != NULL);
    qac->q = q;
    qac->conn = conn;
    THREAD_START("skmsg_reader", rv, q, &conn->reader, reader_thread, qac);
    XASSERT(rv == 0);

    *rconn = conn;
    RETURN(0);
}

static void
start_connection(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn)
{
    DEBUG_ENTER_FUNC;
    SK_UNUSED_PARAM(q);

    assert(q);
    assert(conn);
    ASSERT_QUEUE_LOCK(q);

    assert(conn->reader_state == SKM_THREAD_BEFORE);
    assert(conn->writer_state == SKM_THREAD_BEFORE);
    conn->reader_state = SKM_THREAD_RUNNING;
    conn->writer_state = SKM_THREAD_RUNNING;
    MUTEX_BROADCAST(&conn->reader_cond);
    MUTEX_BROADCAST(&conn->writer_cond);

    RETURN_VOID;
}

static void
unblock_connection(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn)
{
    static sk_msg_t unblocker = {{SKMSG_CHANNEL_CONTROL,
                                  SKMSG_WRITER_UNBLOCKER, 0},
                                 NULL, NULL, 1, {{NULL, 0}}};
    skDQErr_t err;

    DEBUG_ENTER_FUNC;
    SK_UNUSED_PARAM(q);

    assert(q);
    assert(conn);
    ASSERT_QUEUE_LOCK(q);

    /* Add a special messaage to the writers queue to guarantee it
       will unblock */
    DEBUG_PRINT1("Sending SKMSG_WRITER_UNBLOCKER message");
    err = skDequePushBack(conn->queue, &unblocker);
    XASSERT(err == SKDQ_SUCCESS);

    RETURN_VOID;
}


/* Stops and destroys a connection.  A return value of 0 means the
 * connection object still exists; another thread is destroying that
 * connection right now.  A return value of 1 means the connection has
 * been destroyed.  */
static int
destroy_connection(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn)
{
    sk_msg_channel_queue_t *chan;
    void *cont;
    sk_msg_t *msg;
    skDQErr_t err;
    pthread_t self;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(conn);
    ASSERT_QUEUE_LOCK(q);

    DEBUG_PRINT3("destroy_connection() = %d, %d",
                 conn->rsocket, conn->wsocket);

    /* Check to see if this connection is already being shut down */
    if (conn->state == SKM_CLOSED) {
        RETURN(0);
    }

    /* Okay, start closing */
    conn->state = SKM_CLOSED;
    conn->writer_state = SKM_THREAD_SHUTTING_DOWN;
    conn->reader_state = SKM_THREAD_SHUTTING_DOWN;
    unblock_connection(q, conn);

    /* Empty the queue */
    while ((err = skDequePopBackNB(conn->queue, (void**)&msg))
           == SKDQ_SUCCESS)
    {
        skMsgDestroy(msg);
    }
    assert(err == SKDQ_EMPTY);

    /* Shut down the queue */
    ASSERT_RESULT(skDequeUnblock(conn->queue), skDQErr_t, SKDQ_SUCCESS);

    /* Mark all channels using this connection as closed. */
    if (conn->first_channel) {
        assert(conn->first_channel->state == SKM_CREATED);
        conn->first_channel->state = SKM_CLOSED;
        destroy_channel(q, conn->first_channel);
        conn->first_channel = NULL;
    }
    cont = int_dict_get_first(conn->channelmap, NULL, &chan);
    while (cont != NULL) {
        intkey_t channel = chan->channel;
        if ((chan->state == SKM_CONNECTING ||
             chan->state == SKM_CONNECTED))
        {
            set_channel_closed(q, chan, 1);
        }

        cont = int_dict_get_next(conn->channelmap, &channel, &chan);
    }
    assert(conn->refcount == 0);

    /* End the threads */
    self = pthread_self();
    if (!pthread_equal(self, conn->writer)) {
        /* Wait for the writer thread to end */
        THREAD_WAIT_END(q, conn->writer_state);
        pthread_join(conn->writer, NULL);
    }
    if (!pthread_equal(self, conn->reader)) {
        /* Wait for the reader  */
        THREAD_WAIT_END(q, conn->reader_state);
        pthread_join(conn->reader, NULL);
    }
    if (pthread_equal(self, conn->reader)
        || pthread_equal(self, conn->writer))
    {
        DEBUG_PRINT1("Detaching self");
        pthread_detach(self);
    }

    /* Destroy the channelmap */
    int_dict_destroy(conn->channelmap);

#if SK_ENABLE_GNUTLS
    /* End the connection */
    if (conn->use_tls) {
        int rv;
        do {
            rv = gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
            DEBUG_PRINT2("gnutls_bye() -> %d", rv);
        } while (rv == GNUTLS_E_AGAIN || rv == GNUTLS_E_INTERRUPTED);
    }
#endif /* SK_ENABLE_GNUTLS */

    /* Close the socket(s) */
    close(conn->rsocket);
    if (conn->rsocket != conn->wsocket) {
        close(conn->wsocket);
    }

    /* Destroy the queue */
    ASSERT_RESULT(skDequeDestroy(conn->queue), skDQErr_t, SKDQ_SUCCESS);

#if SK_ENABLE_GNUTLS
    /* Destroy the session */
    if (conn->use_tls) {
        gnutls_deinit(conn->session);
    }
#endif /* SK_ENABLE_GNUTLS */

    /* Destroy the condition variables */
    ASSERT_RESULT(pthread_cond_destroy(&conn->writer_cond), int, 0);
    ASSERT_RESULT(pthread_cond_destroy(&conn->reader_cond), int, 0);

    /* Destroy the address */
    if (conn->addr != NULL) {
        free(conn->addr);
    }

    /* Remove any incomplete buffers */
    if (conn->msg_read_buf.msg) {
        skMsgDestroy(conn->msg_read_buf.msg);
    }

    /* Finally, free the connection object */
    free(conn);

    RETURN(1);
}


static int
accept_connection(
    sk_msg_queue_t     *q,
    int                 listen_sock)
{
    int fd;
    sk_msg_conn_queue_t *conn;
    int rv;
    sk_sockaddr_t addr;
    struct sockaddr *addr_copy;
    socklen_t addrlen = sizeof(addr);
    char addr_buf[128];

    DEBUG_ENTER_FUNC;

    assert(q);
    ASSERT_QUEUE_LOCK(q);
    assert(q->root->listener_state == SKM_THREAD_RUNNING);

    while ((fd = accept(listen_sock, &addr.sa, &addrlen)) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            DEBUG_PRINT1("Properly handling EAGAIN/EWOULDBLOCK");
            RETURN(1);
        }
        if (errno == EINTR) {
            DEBUGMSG("accept() [%s]", strerror(errno));
            continue;
        }
        if (errno == EBADF) {
            DEBUGMSG("accept() [%s]", strerror(errno));
            RETURN(-1);
        }
        CRITMSG("Unexpected accept() error: %s", strerror(errno));
        XASSERT(0);
        skAbort();
    }
    skSockaddrString(addr_buf, sizeof(addr_buf), &addr);
    DEBUGMSG("Accepted connection from %s", addr_buf);

    /* Create the queue and both references */
    addr_copy = (struct sockaddr *)malloc(addrlen);
    if (addr_copy != NULL) {
        memcpy(addr_copy, &addr, addrlen);
    }
    rv = create_connection(q, fd, fd, addr_copy, addrlen, &conn,
                           q->root->bind_tls ? SKM_TLS_SERVER : SKM_TLS_NONE);
    if (rv != 0) {
        NOTICEMSG("Unable to initialize connection with %s", addr_buf);
        close(fd);
        free(addr_copy);
        RETURN(-1);
    }

    conn->first_channel = create_channel(q);

    start_connection(q, conn);

    RETURN(0);
}

static int
handle_system_control_message(
    sk_msg_queue_t         *q,
    sk_msg_conn_queue_t    *conn,
    sk_msg_t               *msg)
{
    int rv;
    int retval = 0;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(msg);
    ASSERT_QUEUE_LOCK(q);

    switch (msg->hdr.type) {
      case SKMSG_CTL_CHANNEL_ANNOUNCE:
        /* Handle the announcement of a connection */
        {
            skm_channel_t rchannel;
            skm_channel_t lchannel;
            sk_msg_channel_queue_t *chan;
            sk_channel_pair_t pair;
            sk_new_channel_info_t info;

            DEBUG_PRINT1("Handling SKMSG_CTL_CHANNEL_ANNOUNCE");
            assert(msg->hdr.size == sizeof(rchannel));
            assert(msg->segments == 2);

            /* Decode the remote channel */
            rchannel = SKMSG_CTL_MSG_GET_CHANNEL(msg);

            /* Create a local channel */
            if (conn->first_channel) {
                chan = conn->first_channel;
                conn->first_channel = NULL;
            } else {
                chan = create_channel(q);
            }
            lchannel = chan->channel;

            /* Attach the channel to the connection */
            ASSERT_RESULT(set_channel_connecting(q, chan, conn), int, 0);

            /* Set the remote channel */
            ASSERT_RESULT(set_channel_connected(q, chan, rchannel), int, 0);

            /* Respond to the announcement with the channel pair */
            pair.rchannel = htons(rchannel);
            pair.lchannel = htons(lchannel);
            DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_REPLY (Ext-control)");
            rv = send_message(q, lchannel,
                              SKMSG_CTL_CHANNEL_REPLY,
                              &pair, sizeof(pair), SKM_SEND_CONTROL,
                              0, NULL);
            if (rv != 0) {
                DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_REPLY failed");
                retval = -11;
                break;
            }

            /* Announce the new channel internally */
            info.channel = pair.lchannel;
            if (conn->addr != NULL) {
                memcpy(&info.addr, conn->addr, conn->addrlen);
                info.known = 1;
            } else {
                info.known = 0;
            }
            DEBUG_PRINT1("Sending SKMSG_CTL_NEW_CONNECTION (Internal)");
            rv = send_message(q, SKMSG_CHANNEL_CONTROL,
                              SKMSG_CTL_NEW_CONNECTION,
                              &info, sizeof(info),
                              SKM_SEND_INTERNAL, 0, NULL);
            XASSERT(rv == 0);
        }
        break;

      case SKMSG_CTL_CHANNEL_REPLY:
        /* Handle the reply to a channel announcement */
        {
            sk_channel_pair_t *pair;
            sk_msg_channel_queue_t *chan;
            skm_channel_t rchannel;
            skm_channel_t lchannel;

            DEBUG_PRINT1("Handling SKMSG_CTL_CHANNEL_REPLY");
            assert(sizeof(*pair) == msg->hdr.size);
            assert(2 == msg->segments);

            /* Decode the channels: Reversed directionality is on
               purpose. */
            pair = (sk_channel_pair_t *)msg->segment[1].iov_base;
            rchannel = ntohs(pair->lchannel);
            lchannel = ntohs(pair->rchannel);

            /* Get the channel object */
            chan = find_channel(q, lchannel);
            XASSERT(chan != NULL);

            /* Set the remote channel */
            ASSERT_RESULT(set_channel_connected(q, chan, rchannel), int, 0);

            chan->conn->state = SKM_CONNECTED;

            /* Complete the connection */
            assert(chan->state != SKM_CONNECTING);
            assert(chan->is_pending);
            MUTEX_BROADCAST(&chan->pending);
        }
        break;

      case SKMSG_CTL_CHANNEL_KILL:
        /* Handle the death of a remote channel */
        {
            skm_channel_t channel;
            sk_msg_channel_queue_t *chan;

            DEBUG_PRINT1("Handling SKMSG_CTL_CHANNEL_KILL");

            assert(msg->hdr.size == sizeof(channel));
            assert(msg->segments == 2);

            /* Decode the channel. */
            channel = SKMSG_CTL_MSG_GET_CHANNEL(msg);

            /* Get the channel object. */
            chan = find_channel(q, channel);
            XASSERT(chan != NULL);

            /* Close the channel. */
            retval = set_channel_closed(q, chan, 0);
        }
        break;

      case SKMSG_CTL_CHANNEL_KEEPALIVE:
        DEBUG_PRINT1("Handling SKMSG_CTL_CHANNEL_KEEPALIVE");
        assert(msg->hdr.size == 0);
        /* Do nothing on KEEPALIVE*/
        break;

      default:
        skAbortBadCase(msg->hdr.type);
    }

    skMsgDestroy(msg);

    RETURN(retval);
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "skmsg_listener" thread, started from
 *    skMsgQueueBind()
 */
static void *
listener_thread(
    void               *vq)
{
    sk_msg_queue_t *q = (sk_msg_queue_t *)vq;
    int count;
    nfds_t len, valid;
    struct pollfd *pfd;

    DEBUG_ENTER_FUNC;

    DEBUG_PRINT1("Started listener_thread");

    assert(q);

    QUEUE_LOCK(q);

    pfd = q->root->pfd;
    len = q->root->pfd_len;
    valid = len;
    q->root->listener_state = SKM_THREAD_RUNNING;
    MUTEX_BROADCAST(&q->root->listener_cond);
    QUEUE_UNLOCK(q);

    while (valid && q->root->listener_state == SKM_THREAD_RUNNING) {
        unsigned i;
        int rv;

        /* Call poll */
        count = poll(pfd, len, SKMSG_IO_POLL_TIMEOUT);
        if (count == -1) {
            if (errno == EINTR || errno == EBADF) {
                DEBUG_PRINT2("Ignoring expected poll() error: %s",
                             strerror(errno));
                continue;
            }
            CRITMSG("Unexpected poll() error: %s", strerror(errno));
            skAbort();
        }

        /* Check the file descriptor results */
        for (i = 0; i < len; i++) {
            if (pfd[i].fd < 0) {
                continue;
            }
            if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                DEBUG_PRINT3("Poll returned %d, but revents was %d",
                             count, pfd[i].revents);
                pfd[i].fd = -1;
                valid--;
            } else if (pfd[i].revents & POLLIN) {
                DEBUG_PRINT1("Accepting connection: trying");
                QUEUE_LOCK(q);
                if (q->root->listener_state != SKM_THREAD_RUNNING) {
                    QUEUE_UNLOCK(q);
                    DEBUG_PRINT1("Accepting connection: thread is ending");
                    break;
                }
                rv = accept_connection(q, pfd[i].fd);
                QUEUE_UNLOCK(q);
                if (rv == 0) {
                    DEBUG_PRINT1("Accepting connection: succeeded");
                } else {
                    DEBUG_PRINT1("Accepting connection: failed");
                }
            }
        }
    }

    QUEUE_LOCK(q);
    q->root->listener_state = SKM_THREAD_ENDED;
    THREAD_END(q);
    QUEUE_UNLOCK(q);

    DEBUG_PRINT1("STOPPED listener_thread");

    RETURN(NULL);
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "skmsg_reader" thread, started from
 *    create_connection().  Argument is a temporary structure that
 *    contains pointers to the queue and the connection.
 */
static void *
reader_thread(
    void               *vconn)
{
    sk_queue_and_conn_t *both = (sk_queue_and_conn_t *)vconn;
    sk_msg_conn_queue_t *conn = both->conn;
    sk_msg_queue_t *q         = both->q;
    sk_msg_channel_queue_t *chan;
    int destroyed = 0;
    struct pollfd pfd;
    sk_sockaddr_t addr;
    char addr_buf[128] = "<unknown>";

    DEBUG_ENTER_FUNC;

    DEBUG_PRINT1("STARTED reader_thread");

    assert(conn);
    assert(q);

    free(both);
    both = NULL;

    /* Wait for a signal to start */
    QUEUE_LOCK(q);
    while (conn->reader_state == SKM_THREAD_BEFORE) {
        QUEUE_WAIT(&conn->reader_cond, q);
    }
    QUEUE_UNLOCK(q);

    /* Get the peer's address for error reporting */
    if (conn->addr != NULL) {
        memcpy(&addr.sa, conn->addr, conn->addrlen);
        skSockaddrString(addr_buf, sizeof(addr_buf), &addr);
    }

    /* Add the current time to the connection */
    conn->last_recv = time(NULL);

    /* Set up the poll descriptor */
    pfd.fd = conn->rsocket;
    pfd.events = POLLIN;

    while (!destroyed && conn->state != SKM_CLOSED
           && conn->reader_state == SKM_THREAD_RUNNING)
    {
        int           rv;
        sk_msg_t     *message = NULL;

#if SK_ENABLE_GNUTLS
        /* If the transport is TLS and there are still pending bytes
         * in the session, don't bother polling; we have data. */
        if (conn->transport != CONN_TLS
            || !gnutls_record_check_pending(conn->session))
#endif  /* SK_ENABLE_GNUTLS */
        {
            /* Poll for new data on the socket */
            rv = poll(&pfd, 1, SKMSG_IO_POLL_TIMEOUT);
            if (rv == -1) {
                if (errno == EINTR || errno == EBADF) {
                    DEBUG_PRINT2("Ignoring expected poll(POLLIN) error: %s",
                                 strerror(errno));
                    continue;
                }
                CRITMSG("Unexpected poll(POLLIN) error for %s: %s",
                        addr_buf, strerror(rv));
                skAbort();
            }
            if (rv == 0) {
                if (CONNECTION_STAGNANT(conn, time(NULL))) {
                    /* It's been too long since we have heard something.
                     * Assume the connection died. */
                    INFOMSG(("Destroying connection to %s due to"
                             " %.0f seconds of inactivity"),
                            addr_buf, difftime(time(NULL), conn->last_recv));
                    QUEUE_LOCK(q);
                    destroyed = destroy_connection(q, conn);
                    QUEUE_UNLOCK(q);
                    break;
                }
#if SENDRCV_DEBUG & DEBUG_SKMSG_POLL_TIMEOUT
                WRAP_ERRNO(SKTHREAD_DEBUG_PRINT3(
                               "Timeout on poll(%d, POLLIN) for %s",
                               pfd.fd, addr_buf));
#endif  /* DEBUG_SKMSG_POLL_TIMEOUT */
                continue;
            }
            if (pfd.revents & POLLNVAL) {
                /* This is handled the same as EBADF from poll().  The
                 * standard states that we should get POLLNVAL for a
                 * bad file descriptor.  Under Linux, we might get a
                 * EBADF errno from the poll instead. */
                DEBUG_PRINT1("poll(POLLIN) returned POLLNVAL");
                continue;
            }
            if (pfd.revents & (POLLHUP | POLLERR)) {
                /* Handle a disconnect or device error  */
                INFOMSG("Closing connection to %s due to a disconnect (%s)",
                        addr_buf, SK_POLL_EVENT_STR(pfd.revents));
                QUEUE_LOCK(q);
                destroyed = destroy_connection(q, conn);
                QUEUE_UNLOCK(q);
                break;
            }
        }
#if SK_ENABLE_GNUTLS && ((SENDRCV_DEBUG) & DEBUG_SKMSG_OTHER)
        else {
            DEBUG_PRINT2("Skipping poll(); %" SK_PRIuZ " bytes are pending",
                         gnutls_record_check_pending(conn->session));
        }
#endif  /* DEBUG_SKMSG_OTHER */

        /* Update time for last received data; used by CONNECTION_STAGNANT */
        conn->last_recv = time(NULL);

        /* Read a message */
        DEBUG_PRINT1("Calling recv");
#if SK_ENABLE_GNUTLS
        if (CONN_TLS == conn->transport) {
            rv = tls_recv(conn, &message);
        } else
#endif  /* SK_ENABLE_GNUTLS */
        {
            rv = tcp_recv(conn, &message);
        }
        if (rv == SKMERR_PARTIAL || rv == SKMERR_EMPTY) {
            assert(NULL == message);
            /* the recv() was successful, but only part of the message
             * was available to read, or nothing was read at all */
            continue;
        }
        if (rv != 0) {
            /* Treat the connection as closed */
            INFOMSG("Closing connection to %s due to failed read: %s",
                    addr_buf, skmerr_strerror(conn, rv));
            QUEUE_LOCK(q);
            destroyed = destroy_connection(q, conn);
            QUEUE_UNLOCK(q);
            break;
        }

        assert(message);

        /* Handle control messages */
        if (message->hdr.channel == SKMSG_CHANNEL_CONTROL &&
            message->hdr.type >= SKMSG_MINIMUM_SYSTEM_CTL_CHANNEL)
        {
            QUEUE_LOCK(q);
            rv = handle_system_control_message(q, conn, message);
            QUEUE_UNLOCK(q);
            if (rv == 1) {
                destroyed = 1;
            }
            continue;
        }

        /* Handle ordinary messages */
        chan = find_channel(q, message->hdr.channel);
        if (chan == NULL) {
            skMsgDestroy(message);
        } else {
            /* Put the message on the queue */
            DEBUG_PRINT3("Enqueue: chan=%#x type=%#x",
                         message->hdr.channel, message->hdr.type);
            DEBUG_PRINT2("From reader: %p", (void *)message);
            rv = mqQueueAdd(chan->queue, message);
            if (rv != 0) {
                XASSERT(conn->state == SKM_CLOSED ||
                        conn->reader_state != SKM_THREAD_RUNNING);
                skMsgDestroy(message);
            }
        }
    }

    QUEUE_LOCK(q);
    if (!destroyed) {
        conn->reader_state = SKM_THREAD_ENDED;
    }
    THREAD_END(q);
    QUEUE_UNLOCK(q);

    DEBUG_PRINT1("STOPPED reader_thread");

    RETURN(NULL);
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "skmsg_writer" thread, started from
 *    create_connection().  Argument is a temporary structure that
 *    contains pointers to the queue and the connection.
 */
static void *
writer_thread(
    void               *vconn)
{
    sk_queue_and_conn_t *both      = (sk_queue_and_conn_t *)vconn;
    sk_msg_conn_queue_t *conn      = both->conn;
    sk_msg_queue_t      *q         = both->q;
    int                  have_msg  = 0;
    int                  destroyed = 0;
    sk_msg_write_buf_t   write_buf;
    struct pollfd pfd;
    sk_sockaddr_t addr;
    char addr_buf[128] = "<unknown>";

    DEBUG_ENTER_FUNC;

    DEBUG_PRINT1("STARTED writer_thread");

    assert(conn);
    assert(q);

    free(both);

    memset(&write_buf, 0, sizeof(write_buf));

    /* Wait for a signal to start */
    QUEUE_LOCK(q);
    while (conn->writer_state == SKM_THREAD_BEFORE) {
        QUEUE_WAIT(&conn->writer_cond, q);
    }
    QUEUE_UNLOCK(q);

    /* Get the peer's address for error reporting */
    if (conn->addr != NULL) {
        memcpy(&addr.sa, conn->addr, conn->addrlen);
        skSockaddrString(addr_buf, sizeof(addr_buf), &addr);
    }

    /* Set up the poll descriptor */
    pfd.fd = conn->wsocket;
    pfd.events = POLLOUT;

    while (conn->writer_state == SKM_THREAD_RUNNING) {
        int           rv;
        skDQErr_t     err;
        int           block = (conn->state != SKM_CLOSED);

        /* If not currently sending a message, get a new message to
         * send from the queue  */
        if (!have_msg) {
            if (!block) {
                /* If the connection is closed, don't block in the deque */
                err = skDequePopBackNB(conn->queue, (void**)&write_buf.msg);
            } else if (conn->keepalive == 0) {
                err = skDequePopBack(conn->queue, (void**)&write_buf.msg);
            } else {
                err = skDequePopBackTimed(conn->queue, (void**)&write_buf.msg,
                                          conn->keepalive);
                if (err == SKDQ_TIMEDOUT) {
                    /* Create a keepalive message */
                    write_buf.msg = (sk_msg_t*)calloc(1, sizeof(sk_msg_t));
                    MEM_ASSERT(write_buf.msg);
                    write_buf.msg->segments = 1;
                    write_buf.msg->segment[0].iov_base = &write_buf.msg->hdr;
                    write_buf.msg->segment[0].iov_len
                        = sizeof(write_buf.msg->hdr);
                    write_buf.msg->hdr.channel = SKMSG_CHANNEL_CONTROL;
                    write_buf.msg->hdr.type = SKMSG_CTL_CHANNEL_KEEPALIVE;
                    /* Pretend it came from the queue */
                    err = SKDQ_SUCCESS;
                    DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_KEEPALIVE");
                }
            }
            if (err != SKDQ_SUCCESS) {
                assert(err == SKDQ_UNBLOCKED || err == SKDQ_DESTROYED
                       || err == SKDQ_EMPTY);
                break;
            }
            if (write_buf.msg->hdr.channel == SKMSG_CHANNEL_CONTROL
                && write_buf.msg->hdr.type == SKMSG_WRITER_UNBLOCKER)
            {
                /* Do not destroy message, as this is a special static
                 * message. */
                write_buf.msg = NULL;
                DEBUG_PRINT1("Handling SKMSG_WRITER_UNBLOCKER message");
                continue;
            }
            have_msg = 1;
            write_buf.msg_size
                = sizeof(write_buf.msg->hdr) + write_buf.msg->hdr.size;
            write_buf.cur_seg = 0;
            write_buf.seg_offset = 0;

            /* Convert data to network byte order */
            write_buf.msg->hdr.channel = htons(write_buf.msg->hdr.channel);
            write_buf.msg->hdr.type    = htons(write_buf.msg->hdr.type);
            write_buf.msg->hdr.size    = htons(write_buf.msg->hdr.size);
        }

        /* Wait for socket to be available for writing */
        rv = poll(&pfd, 1, SKMSG_IO_POLL_TIMEOUT);
        if (rv == -1) {
            if (errno == EINTR || errno == EBADF) {
                DEBUG_PRINT2("Ignoring expected poll(POLLOUT) error: %s",
                             strerror(errno));
                continue;
            }
            CRITMSG("Unexpected poll(POLLOUT) error for %s: %s",
                    addr_buf, strerror(errno));
            skAbort();
        }
        if (rv == 0) {
#if SENDRCV_DEBUG & DEBUG_SKMSG_POLL_TIMEOUT
            WRAP_ERRNO(SKTHREAD_DEBUG_PRINT3(
                           "Timeout on poll(%d, POLLOUT) for %s",
                           pfd.fd, addr_buf));
#endif  /* DEBUG_SKMSG_POLL_TIMEOUT */
            continue;
        }
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            /* Handle a disconnect or device error  */
            INFOMSG("Closing connection to %s due to a disconnect (%s)",
                    addr_buf, SK_POLL_EVENT_STR(pfd.revents));
            QUEUE_LOCK(q);
            destroyed = destroy_connection(q, conn);
            QUEUE_UNLOCK(q);
            break;
        }

#if SK_ENABLE_GNUTLS
        if (CONN_TLS == conn->transport) {
            rv = tls_send(conn, &write_buf);
        } else
#endif  /* SK_ENABLE_GNUTLS */
        {
            rv = tcp_send(conn, &write_buf);
        }
        if (rv == SKMERR_PARTIAL) {
            /* partial write */
            continue;
        }
        have_msg = 0;
        skMsgDestroy(write_buf.msg);
        write_buf.msg = NULL;
        if (rv != 0) {
            /* Treat the connection as closed */
            INFOMSG("Closing connection to %s due to failed write: %s",
                    addr_buf, skmerr_strerror(conn, rv));
            QUEUE_LOCK(q);
            destroyed = destroy_connection(q, conn);
            QUEUE_UNLOCK(q);
            break;
        }
    }

    if (write_buf.msg) {
        skMsgDestroy(write_buf.msg);
    }

    QUEUE_LOCK(q);
    if (!destroyed) {
        conn->writer_state = SKM_THREAD_ENDED;
    }
    THREAD_END(q);
    QUEUE_UNLOCK(q);

    DEBUG_PRINT1("STOPPED writer_thread");

    RETURN(NULL);
}


int
skMsgQueueCreate(
    sk_msg_queue_t    **queue)
{
    sk_msg_queue_t *q;
    int retval = 0;
    int fd[2];
    int rv;
    sk_msg_conn_queue_t *conn;
    sk_msg_channel_queue_t *chan;

    DEBUG_ENTER_FUNC;

    q = (sk_msg_queue_t*)calloc(1, sizeof(sk_msg_queue_t));
    if (q == NULL) {
        RETURN(SKMERR_MEMORY);
    }

    q->root = (sk_msg_root_t*)calloc(1, sizeof(sk_msg_root_t));
    if (q->root == NULL) {
        free(q);
        RETURN(SKMERR_MEMORY);
    }

    THREAD_INFO_INIT(q);

    q->root->channel = int_dict_create(sizeof(sk_msg_channel_queue_t *));
    if (q->root->channel == NULL) {
        retval = SKMERR_MEMORY;
        goto error;
    }
    q->root->groups = int_dict_create(sizeof(sk_msg_queue_t *));
    if (q->root->groups == NULL) {
        retval = SKMERR_MEMORY;
        goto error;
    }
    q->channel = int_dict_create(sizeof(sk_msg_channel_queue_t *));
    if (q->channel == NULL) {
        retval = SKMERR_MEMORY;
        goto error;
    }

    rv = pthread_mutex_init(QUEUE_MUTEX(q), NULL);
    if (rv != 0) {
        retval = SKMERR_MUTEX;
        goto error;
    }

    rv = pthread_cond_init(&q->shutdowncond, NULL);
    if (rv != 0) {
        retval = SKMERR_MUTEX;
        goto error;
    }

    q->group = mqCreateFair(sk_destroy_report_message);
    if (q->group == NULL) {
        goto error;
    }

    rv = pipe(fd);
    if (rv == -1) {
        retval = SKMERR_PIPE;
        goto error;
    }

#if SK_ENABLE_GNUTLS
    rv = skMsgQueueInitializeGnuTLS(q);
    if (rv != 0) {
        retval = SKMERR_GNUTLS;
        goto error;
    }
#endif  /* SK_ENABLE_GNUTLS */

    /* Initialize the listener thread start state */
    pthread_cond_init(&q->root->listener_cond, NULL);
    q->root->listener_state = SKM_THREAD_BEFORE;

    /* Lock the mutex to satisfy preconditions for mucking with
       connections and channels. */
    QUEUE_LOCK(q);

    /* Create an internal connection for the control channel. */
    rv = create_connection(q, fd[READ], fd[WRITE], NULL, 0, &conn,
                           SKM_TLS_NONE);
    conn->keepalive = SKMSG_CONTROL_KEEPALIVE_TIMEOUT;
    unblock_connection(q, conn);
    XASSERT(rv == 0);

    /* Create a channel for the control channel. */
    q->root->next_channel = SKMSG_CHANNEL_CONTROL;
    chan = create_channel(q);

    /* Start the connection */
    start_connection(q, conn);

    /* Attach the internal connection to the control channel. */
    ASSERT_RESULT(set_channel_connecting(q, chan, conn), int, 0);

    /* And let's completely connect it. */
    ASSERT_RESULT(set_channel_connected(q, chan, SKMSG_CHANNEL_CONTROL),
                  int, 0);
    conn->state = SKM_CONNECTED;

    /* Unlock the mutex */
    QUEUE_UNLOCK(q);

    *queue = q;
    RETURN(0);

  error:
    skMsgQueueDestroy(q);
    RETURN(retval);
}

static void
sk_msg_queue_shutdown(
    sk_msg_queue_t     *q)
{
    sk_msg_channel_queue_t *chan;
    void *cont;

    DEBUG_ENTER_FUNC;

    assert(q);
    ASSERT_QUEUE_LOCK(q);

    if (q->shuttingdown) {
        RETURN_VOID;
    }

    q->shuttingdown = 1;

    /* Shut down a queue by shutting down all its channels. */
    cont = int_dict_get_first(q->channel, NULL, &chan);
    while (cont != NULL) {
        intkey_t key = chan->channel;
        if (chan->state == SKM_CONNECTED || chan->state == SKM_CONNECTING) {
            set_channel_closed(q, chan, 0);
        }
        cont = int_dict_get_next(q->channel, &key, &chan);
    }

    /* And then shutting down the multiqueue */
    mqShutdown(q->group);

    q->shuttingdown = 0;

    MUTEX_BROADCAST(&q->shutdowncond);

    RETURN_VOID;
}


void
skMsgQueueShutdown(
    sk_msg_queue_t     *q)
{
    DEBUG_ENTER_FUNC;

    assert(q);

    QUEUE_LOCK(q);

    sk_msg_queue_shutdown(q);

    QUEUE_UNLOCK(q);
    RETURN_VOID;
}


void
skMsgQueueShutdownAll(
    sk_msg_queue_t     *q)
{
    sk_msg_channel_queue_t *chan;
    void *cont;

    DEBUG_ENTER_FUNC;

    if (!q) {
        RETURN_VOID;
    }
    QUEUE_LOCK(q);

    if (q->root->shuttingdown) {
        QUEUE_UNLOCK(q);
        RETURN_VOID;
    }

    q->root->shuttingdown = 1;
    q->root->shutdownqueue = q;

    q->root->listener_state = SKM_THREAD_SHUTTING_DOWN;

    /* Shut down all channels */
    cont = int_dict_get_first(q->root->channel, NULL, &chan);
    while (cont != NULL) {
        intkey_t key = chan->channel;
        sk_msg_queue_shutdown(chan->group);
        cont = int_dict_get_next(q->root->channel, &key, &chan);
    }

    if (q->root->pfd) {
        nfds_t i;

        for (i = 0; i < q->root->pfd_len; i++) {
            if (q->root->pfd[i].fd >= 0) {
                close(q->root->pfd[i].fd);
                q->root->pfd[i].fd = -1;
            }
        }
    }

    THREAD_WAIT_ALL_END(q);

    if (q->root->pfd) {
        pthread_join(q->root->listener, NULL);
        free(q->root->pfd);
        q->root->pfd = NULL;
    }

    q->root->shuttingdown = 0;

    MUTEX_BROADCAST(&q->shutdowncond);

    QUEUE_UNLOCK(q);

    RETURN_VOID;
}


static void
skMsgQueueDestroyAll(
    sk_msg_queue_t     *q)
{
    DEBUG_ENTER_FUNC;

    assert(q);
    ASSERT_QUEUE_LOCK(q);

    /* Verify that all channels have been destroyed */
    assert(int_dict_get_first(q->root->channel, NULL, NULL) == NULL);

    int_dict_destroy(q->root->channel);
    int_dict_destroy(q->root->groups);

    QUEUE_UNLOCK(q);

    THREAD_INFO_DESTROY(q);

#if SK_ENABLE_GNUTLS
    if (q->root->cred_set) {
        gnutls_certificate_free_credentials(q->root->cred);
    }
#endif  /* SK_ENABLE_GNUTLS */

    ASSERT_RESULT(pthread_cond_destroy(&q->root->listener_cond), int, 0);
    ASSERT_RESULT(pthread_mutex_destroy(QUEUE_MUTEX(q)), int, 0);

    free(q->root);
    free(q);

    RETURN_VOID;
}


void
skMsgQueueDestroy(
    sk_msg_queue_t     *q)
{
    sk_msg_root_t *root;
    sk_msg_channel_queue_t *chan;
    void *cont;

    DEBUG_ENTER_FUNC;

    assert(q);

    QUEUE_LOCK(q);

    root = q->root;

    while (q->shuttingdown
           || (root->shuttingdown && root->shutdownqueue == q))
    {
        QUEUE_WAIT(&q->shutdowncond, q);
    }

    /* Destroy the channels */
    cont = int_dict_get_first(q->channel, NULL, &chan);
    while (cont != NULL) {
        intkey_t channel = chan->channel;
        destroy_channel(q, chan);
        cont = int_dict_get_next(q->channel, &channel, &chan);
    }

    mqShutdown(q->group);
    mqDestroy(q->group);

    int_dict_destroy(q->channel);

    if (int_dict_get_first(q->root->groups, NULL, NULL) == NULL) {
        skMsgQueueDestroyAll(q);
        RETURN_VOID;
    }

    free(q);

    MUTEX_UNLOCK(&root->mutex);

    RETURN_VOID;
}

int
skMsgQueueBind(
    sk_msg_queue_t             *q,
    const sk_sockaddr_array_t  *listen_addrs)
{
    static int on = 1;
    uint32_t i, n;
    struct pollfd *pfd;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(listen_addrs);
    assert(skSockaddrArrayGetSize(listen_addrs) > 0);

    pfd = (struct pollfd*)calloc(skSockaddrArrayGetSize(listen_addrs),
                                 sizeof(struct pollfd));
    MEM_ASSERT(pfd);

    n = 0;
    DEBUGMSG(("Attempting to bind %" PRIu32 " addresses for %s"),
             skSockaddrArrayGetSize(listen_addrs),
             skSockaddrArrayGetHostPortPair(listen_addrs));
    for (i = 0; i < skSockaddrArrayGetSize(listen_addrs); i++) {
        char addr_string[PATH_MAX];
        int sock;
        sk_sockaddr_t *addr = skSockaddrArrayGet(listen_addrs, i);

        skSockaddrString(addr_string, sizeof(addr_string), addr);

        /* Bind a socket to the address*/
        sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);
        if (sock == -1) {
            DEBUGMSG("Skipping %s: Unable to create stream socket: %s",
                     addr_string, strerror(errno));
            pfd[i].fd = -1;
            continue;
        }
        rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                        &on, sizeof(on));
        XASSERT(rv != -1);
        rv = bind(sock, &addr->sa, skSockaddrGetLen(addr));
        if (rv == 0) {
            DEBUGMSG("Succeeded binding to %s", addr_string);
            rv = listen(sock, LISTENQ);
            XASSERT(rv != -1);
            set_nonblock(sock);
            pfd[i].events = POLLIN;
            n++;
        } else {
            DEBUGMSG("Skipping %s: Unable to bind: %s",
                     addr_string, strerror(errno));
            close(sock);
            sock = -1;
        }
        pfd[i].fd = sock;
    }
    if (n == 0) {
        ERRMSG("Failed to bind any addresses for %s",
               skSockaddrArrayGetHostPortPair(listen_addrs));
        free(pfd);
        RETURN(-1);
    }

    DEBUGMSG(("Bound %" PRIu32 "/%" PRIu32 " addresses for %s"),
             (uint32_t)n, skSockaddrArrayGetSize(listen_addrs),
             skSockaddrArrayGetHostPortPair(listen_addrs));

    QUEUE_LOCK(q);

    if (q->root->listener_state != SKM_THREAD_BEFORE) {
        QUEUE_UNLOCK(q);
        for (i = 0; i < skSockaddrArrayGetSize(listen_addrs); i++) {
            if (pfd[i].fd >= 0) {
                close(pfd[i].fd);
            }
        }
        free(pfd);
        RETURN(-1);
    }

    /* Set the listen sock for the queue. */
    assert(q->root->pfd == NULL);
    q->root->pfd = pfd;
    q->root->pfd_len = skSockaddrArrayGetSize(listen_addrs);
    q->root->bind_tls = (connection_type == CONN_TLS);

    THREAD_START("skmsg_listener", rv, q, &q->root->listener,
                 listener_thread, q);
    XASSERT(rv == 0);

    while (q->root->listener_state == SKM_THREAD_BEFORE) {
        QUEUE_WAIT(&q->root->listener_cond, q);
    }
    assert(q->root->listener_state == SKM_THREAD_RUNNING);

    QUEUE_UNLOCK(q);

    RETURN(0);
}


int
skMsgQueueConnect(
    sk_msg_queue_t     *q,
    struct sockaddr    *addr,
    socklen_t           addrlen,
    skm_channel_t      *channel)
{
    int rv;
    int sock;
    sk_msg_conn_queue_t *conn;
    sk_msg_channel_queue_t *chan;
    int retval;
    skm_channel_t lchannel;
    struct sockaddr *copy;

    DEBUG_ENTER_FUNC;

    assert(q);
    sock = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sock == -1) {
        RETURN(-1);
    }

    /* Connect to the remote side */
    rv = connect(sock, addr, addrlen);
    if (rv == -1) {
        DEBUGMSG("Failed to connect: %s", strerror(errno));
        close(sock);
        RETURN(-1);
    }

    /* Create a channel and connection, and bind them */
    QUEUE_LOCK(q);
    if (q->shuttingdown) {
        close(sock);
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }
    copy = (struct sockaddr *)malloc(addrlen);
    if (copy != NULL) {
        memcpy(copy, addr, addrlen);
    }
    rv = create_connection(q, sock, sock, copy, addrlen, &conn,
                           ((connection_type == CONN_TLS)
                            ? SKM_TLS_CLIENT : SKM_TLS_NONE));
    if (rv == -1) {
        close(sock);
        free(copy);
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }

    chan = create_channel(q);
    start_connection(q, conn);
    rv = set_channel_connecting(q, chan, conn);
    XASSERT(rv == 0);

    /* Announce the channel id to the remote queue */
    lchannel = htons(chan->channel);
    DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_ANNOUNCE (Ext-control)");
    rv = send_message(q, chan->channel,
                      SKMSG_CTL_CHANNEL_ANNOUNCE,
                      &lchannel, sizeof(lchannel), SKM_SEND_CONTROL, 0, NULL);
    if (rv != 0) {
        DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_ANNOUNCE failed");
        destroy_connection(q, conn);
        close(sock);
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }

    /* Wait for a reply */
    chan->is_pending = 1;
    while (chan->is_pending && chan->state == SKM_CONNECTING) {
        QUEUE_WAIT(&chan->pending, q);
    }
    chan->is_pending = 0;

    if (chan->state == SKM_CLOSED) {
        destroy_channel(q, chan);
        retval = -1;
    } else {
        retval = 0;
        *channel = chan->channel;
    }

    QUEUE_UNLOCK(q);

    RETURN(retval);
}

int
skMsgChannelNew(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_channel_t      *new_channel)
{
    sk_msg_channel_queue_t *chan;
    sk_msg_channel_queue_t *newchan;
    skm_channel_t lchannel;
    int retval;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(new_channel);

    QUEUE_LOCK(q);

    if (q->shuttingdown) {
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }

    chan = find_channel(q, channel);
    XASSERT(chan != NULL);
    XASSERT(chan->state == SKM_CONNECTED);
    assert(chan->conn != NULL);

    /* Create a channel and connection, and bind it to the connection */
    newchan = create_channel(q);
    ASSERT_RESULT(set_channel_connecting(q, newchan, chan->conn), int, 0);

    lchannel = htons(newchan->channel);

    /* Announce the channel id to the remote queue */
    DEBUG_PRINT1("Sending SKMSG_CTL_CHANNEL_ANNOUNCE (Ext-control))");
    rv = send_message(q, newchan->channel,
                      SKMSG_CTL_CHANNEL_ANNOUNCE,
                      &lchannel, sizeof(lchannel), SKM_SEND_CONTROL, 0, NULL);
    if (rv != 0) {
        destroy_channel(q, newchan);
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }

    /* Wait for a response */
    newchan->is_pending = 1;
    while (newchan->is_pending && newchan->state == SKM_CONNECTING) {
        QUEUE_WAIT(&newchan->pending, q);
    }
    newchan->is_pending = 0;

    if (newchan->state == SKM_CLOSED) {
        retval = -1;
        destroy_channel(q, newchan);
    } else {
        retval = 0;
        *new_channel = newchan->channel;
    }

    QUEUE_UNLOCK(q);

    RETURN(retval);
}


int
skMsgChannelSplit(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    sk_msg_queue_t    **new_queue)
{
    sk_msg_queue_t *new_q;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);

    new_q = (sk_msg_queue_t *)calloc(1, sizeof(*new_q));
    if (new_q == NULL) {
        return -1;
    }

    rv = pthread_cond_init(&new_q->shutdowncond, NULL);
    if (rv != 0) {
        free(new_q);
        return -1;
    }

    new_q->channel = int_dict_create(sizeof(sk_msg_channel_queue_t *));
    if (new_q->channel == NULL) {
        free(new_q);
        return -1;
    }

    new_q->group = mqCreateFair(sk_destroy_report_message);
    if (new_q->group == NULL) {
        int_dict_destroy(new_q->channel);
        free(new_q);
        return -1;
    }

    new_q->root = q->root;

    rv = skMsgChannelMove(channel, new_q);
    if (rv != 0) {
        skMsgQueueDestroy(new_q);
    } else {
        *new_queue = new_q;
    }

    return rv;
}


int
skMsgChannelMove(
    skm_channel_t       channel,
    sk_msg_queue_t     *q)
{
    sk_msg_channel_queue_t *chan;
    int retval = 0;

    DEBUG_ENTER_FUNC;

    assert(q);

    QUEUE_LOCK(q);

    chan = find_channel(q, channel);
    if (chan == NULL) {
        retval = -1;
        goto end;
    }

    ASSERT_RESULT(mqQueueMove(q->group, chan->queue), int, 0);
    ASSERT_RESULT(int_dict_del(chan->group->channel, channel), int, 0);
    ASSERT_RESULT(int_dict_set(q->channel, channel, &chan), int, 0);
    ASSERT_RESULT(int_dict_set(q->root->groups, channel, &q), int, 0);

    chan->group = q;

  end:
    QUEUE_UNLOCK(q);

    RETURN(retval);
}


int
skMsgChannelKill(
    sk_msg_queue_t     *q,
    skm_channel_t       channel)
{
    sk_msg_channel_queue_t *chan;

    DEBUG_ENTER_FUNC;

    assert(q);

    QUEUE_LOCK(q);

    if (!q->shuttingdown) {
        chan = find_channel(q, channel);
        XASSERT(chan != NULL);

        destroy_channel(q, chan);
    }

    QUEUE_UNLOCK(q);

    RETURN(0);
}


static int
send_message(
    sk_msg_queue_t     *q,
    skm_channel_t       lchannel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    sk_send_type_t      send_type,
    int                 no_copy,
    void              (*free_fn)(void *))
{
    sk_msg_channel_queue_t *chan;
    sk_msg_t *msg;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(message || length == 0);
    assert((NULL == free_fn) ? (0 == no_copy) : (1 == no_copy));
    ASSERT_QUEUE_LOCK(q);

    if (int_dict_get(q->root->channel, lchannel, &chan) == NULL) {
        if (no_copy) {
            free_fn(message);
        }
        RETURN(-1);
    }

    if (chan->state == SKM_CLOSED && send_type != SKM_SEND_INTERNAL) {
        if (no_copy) {
            free_fn(message);
        }
        RETURN(0);
    }

    msg = (sk_msg_t*)malloc(sizeof(sk_msg_t)
                            + (length ? sizeof(struct iovec) : 0));
    MEM_ASSERT(msg);

    msg->free_fn = msg_simple_free;
    msg->simple_free = NULL;

    msg->segment[0].iov_base = &msg->hdr;
    msg->segment[0].iov_len = sizeof(msg->hdr);

    if (!length) {
        msg->segments = 1;
    } else {
        msg->segments = 2;
        msg->segment[1].iov_len = length;
        if (no_copy) {
            msg->simple_free = free_fn;
            msg->segment[1].iov_base = message;
        } else {
            msg->segment[1].iov_base = malloc(length);
            if (msg->segment[1].iov_base == NULL) {
                free(msg);
                RETURN(-1);
            }
            memcpy(msg->segment[1].iov_base, message, length);
        }
    }

    msg->hdr.type = type;
    msg->hdr.size = length;

    rv = send_message_internal(chan, msg, send_type);
    if (rv != 0) {
        skMsgDestroy(msg);
        RETURN(-1);
    }

    RETURN(0);
}


static int
send_message_internal(
    sk_msg_channel_queue_t *chan,
    sk_msg_t               *msg,
    sk_send_type_t          send_type)
{
    skDQErr_t err;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(chan);
    assert(msg);

    switch (send_type) {
      case SKM_SEND_INTERNAL:
        msg->hdr.channel = chan->channel;
        DEBUG_PRINT3("Enqueue: chan=%#x type=%#x",
                     msg->hdr.channel, msg->hdr.type);
        rv = mqQueueAdd(chan->queue, msg);
        if (rv != 0) {
            RETURN(-1);
        }
        break;
      case SKM_SEND_REMOTE:
        msg->hdr.channel = chan->rchannel;
        err = skDequePushFront(chan->conn->queue, msg);
        if (err != SKDQ_SUCCESS) {
            RETURN(-1);
        }
        break;
      case SKM_SEND_CONTROL:
        msg->hdr.channel = SKMSG_CHANNEL_CONTROL;
        err = skDequePushFront(chan->conn->queue, msg);
        if (err != SKDQ_SUCCESS) {
            RETURN(-1);
        }
        break;
      default:
        skAbortBadCase(send_type);
    }

    RETURN(0);
}


int
skMsgQueueSendMessage(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_type_t          type,
    const void         *message,
    skm_len_t           length)
{
    int rv;

    DEBUG_ENTER_FUNC;

    QUEUE_LOCK(q);
    rv = send_message(q, channel, type, (void *)message,
                      length, SKM_SEND_REMOTE, 0, NULL);
    QUEUE_UNLOCK(q);
    RETURN(rv);
}


int
skMsgQueueInjectMessage(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_type_t          type,
    const void         *message,
    skm_len_t           length)
{
    int rv;

    DEBUG_ENTER_FUNC;

    QUEUE_LOCK(q);
    rv = send_message(q, channel, type, (void *)message,
                      length, SKM_SEND_INTERNAL, 0, NULL);
    QUEUE_UNLOCK(q);
    RETURN(rv);
}

int
skMsgQueueSendMessageNoCopy(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    void              (*free_fn)(void *))
{
    int rv;

    DEBUG_ENTER_FUNC;

    QUEUE_LOCK(q);
    rv = send_message(q, channel, type, message, length, SKM_SEND_REMOTE,
                      1, free_fn);
    QUEUE_UNLOCK(q);
    RETURN(rv);
}

int
skMsgQueueScatterSendMessageNoCopy(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_type_t          type,
    uint16_t            num_segments,
    struct iovec       *segments,
    void              (*free_fn)(uint16_t, struct iovec *))
{
    sk_msg_channel_queue_t *chan;
    sk_msg_t               *msg;
    size_t                  size;
    uint16_t                i;
    int                     rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert((num_segments && segments) || (!num_segments && !segments));

    QUEUE_LOCK(q);

    if (int_dict_get(q->root->channel, channel, &chan) == NULL) {
        free_fn(num_segments, segments);
        rv = -1;
        goto end;
    }

    if (chan->state == SKM_CLOSED) {
        free_fn(num_segments, segments);
        rv = 0;
        goto end;
    }

    msg = (sk_msg_t*)malloc(sizeof(sk_msg_t)
                            + sizeof(struct iovec) * num_segments);
    MEM_ASSERT(msg);

    msg->free_fn = free_fn;
    msg->simple_free = NULL;

    msg->segment[0].iov_base = &msg->hdr;
    msg->segment[0].iov_len = sizeof(msg->hdr);
    msg->segments = 1;

    msg->hdr.type = type;
    size = 0;

    /* add all segments to msg before checking the size; this ensures
     * they all get freed if the overall message size is too large */
    for (i = 0; i < num_segments; i++) {
        msg->segment[i + 1] = segments[i];
        size += segments[i].iov_len;
        ++msg->segments;
    }
    if (size > UINT16_MAX) {
        memset(&msg->hdr, 0, sizeof(msg->hdr));
        skMsgDestroy(msg);
        rv = -1;
        goto end;
    }

    msg->hdr.size = size;

    rv = send_message_internal(chan, msg, SKM_SEND_REMOTE);
    if (rv != 0) {
        skMsgDestroy(msg);
    }

  end:
    QUEUE_UNLOCK(q);

    RETURN(rv);
}


int
skMsgQueueInjectMessageNoCopy(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    skm_type_t          type,
    void               *message,
    skm_len_t           length,
    void              (*free_fn)(void *))
{
    int rv;

    DEBUG_ENTER_FUNC;

    QUEUE_LOCK(q);
    rv = send_message(q, channel, type, message, length, SKM_SEND_INTERNAL,
                      1, free_fn);
    QUEUE_UNLOCK(q);
    RETURN(rv);
}


int
skMsgQueueGetMessage(
    sk_msg_queue_t     *q,
    sk_msg_t          **message)
{
    sk_msg_t *msg;
    sk_msg_channel_queue_t *chan;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(message);

    do {
        rv = mqGet(q->group, (void **)&msg);
        if (rv != 0) {
            RETURN(-1);
        }
        DEBUG_PRINT2("From GetMessage: %p", (void *)msg);
        DEBUG_PRINT4("Dequeue: chan=%#x type=%#x size=%d",
                     msg->hdr.channel, msg->hdr.type, msg->hdr.size);

        chan = find_channel(q, msg->hdr.channel);
    } while (chan == NULL);

    *message = msg;

    RETURN(0);
}


int
skMsgQueueGetMessageFromChannel(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    sk_msg_t          **message)
{
    sk_msg_t *msg;
    sk_msg_channel_queue_t *chan;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(message);

    chan = find_channel(q, channel);

    if (chan == NULL) {
        RETURN(-1);
    }

    rv = mqQueueGet(chan->queue, (void **)&msg);
    if (rv != 0) {
        RETURN(-1);
    }
    DEBUG_PRINT4("Dequeue: chan=%#x type=%#x size=%d",
                 msg->hdr.channel, msg->hdr.type, msg->hdr.size);

    assert(msg->hdr.channel == channel);

    chan = find_channel(q, msg->hdr.channel);

    if (chan == NULL) {
        RETURN(-1);
    }

    *message = msg;

    RETURN(0);
}

int
skMsgGetRemoteChannelID(
    sk_msg_queue_t     *q,
    skm_channel_t       lchannel,
    skm_channel_t      *rchannel)
{
    sk_msg_channel_queue_t *chan;
    int                     retval;

    DEBUG_ENTER_FUNC;

    assert(q);

    chan = find_channel(q, lchannel);
    if (chan == NULL) {
        retval = -1;
    } else {
        *rchannel = chan->rchannel;
        retval = 0;
    }

    return retval;
}


int
skMsgSetKeepalive(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    uint16_t            keepalive)
{
    sk_msg_channel_queue_t *chan;
    int                     retval;

    DEBUG_ENTER_FUNC;

    assert(q);

    QUEUE_LOCK(q);

    chan = find_channel(q, channel);
    if (chan == NULL || chan->state != SKM_CONNECTED) {
        retval = -1;
    } else {
        chan->conn->keepalive = keepalive;
        unblock_connection(q, chan->conn);
        retval = 0;
    }
    QUEUE_UNLOCK(q);

    return retval;
}


int
skMsgGetConnectionInformation(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    char               *buffer,
    size_t              buffer_size)
{
    sk_msg_channel_queue_t *chan;
    sk_msg_conn_queue_t    *conn;
    int                     rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(buffer);

    QUEUE_LOCK(q);
    chan = find_channel(q, channel);
    if (chan == NULL) {
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }
    conn = chan->conn;
    if (conn == NULL) {
        QUEUE_UNLOCK(q);
        RETURN(-1);
    }

#if SK_ENABLE_GNUTLS
    if (conn->use_tls) {
        const char *protocol;
        const char *encryption;
        const char *key_exchange;
        const char *mac;

        protocol = gnutls_protocol_get_name(
            gnutls_protocol_get_version(conn->session));
        encryption = gnutls_cipher_get_name(gnutls_cipher_get(conn->session));
        key_exchange = gnutls_kx_get_name(gnutls_kx_get(conn->session));
        mac = gnutls_mac_get_name(gnutls_mac_get(conn->session));
        /* compression = gnutls_compression_get_name(
         *   gnutls_compression_get(conn->session)); */
        QUEUE_UNLOCK(q);

        rv = snprintf(buffer, buffer_size, "TCP, %s, %s, %s, %s",
                      protocol, encryption, key_exchange, mac);
        RETURN(rv);
    }
#endif  /* SK_ENABLE_GNUTLS */

    QUEUE_UNLOCK(q);
    rv = snprintf(buffer, buffer_size, "TCP");
    RETURN(rv);
}


int
skMsgGetLocalPort(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    uint16_t           *port)
{
    sk_msg_channel_queue_t *chan;
    sk_msg_conn_queue_t    *conn;
    sk_sockaddr_t           addr;
    socklen_t               addrlen;
    int rv;

    DEBUG_ENTER_FUNC;

    assert(q);
    assert(port);

    rv = -1;

    QUEUE_LOCK(q);
    chan = find_channel(q, channel);
    if (chan == NULL) {
        goto END;
    }
    conn = chan->conn;
    if (conn == NULL) {
        goto END;
    }

    addrlen = sizeof(addr);
    if (-1 == getsockname(conn->rsocket, &addr.sa, &addrlen)) {
        goto END;
    }

    *port = skSockaddrGetPort(&addr);
    rv = 0;

  END:
    QUEUE_UNLOCK(q);
    RETURN(rv);
}


void
skMsgDestroy(
    sk_msg_t           *msg)
{
    DEBUG_ENTER_FUNC;

    assert(msg);

    if (msg->segments == 2 && msg->simple_free) {
        msg->simple_free(msg->segment[1].iov_base);
    } else if (msg->segments > 1 && msg->free_fn) {
        msg->free_fn(msg->segments - 1, &msg->segment[1]);
    }
    /* We use a static message to unblock the writer queue.  It should
     * not be freed. */
    if (msg->hdr.channel != SKMSG_CHANNEL_CONTROL ||
        msg->hdr.type != SKMSG_WRITER_UNBLOCKER)
    {
        free(msg);
    }

    RETURN_VOID;
}


skm_channel_t
skMsgChannel(
    const sk_msg_t     *msg)
{
    DEBUG_ENTER_FUNC;

    assert(msg);
    RETURN(msg->hdr.channel);
}


skm_type_t
skMsgType(
    const sk_msg_t     *msg)
{
    DEBUG_ENTER_FUNC;

    assert(msg);
    RETURN(msg->hdr.type);
}


skm_len_t
skMsgLength(
    const sk_msg_t     *msg)
{
    DEBUG_ENTER_FUNC;

    assert(msg);
    RETURN(msg->hdr.size);
}


const void *
skMsgMessage(
    const sk_msg_t     *msg)
{
    DEBUG_ENTER_FUNC;

    assert(msg);
    if (msg->segments == 0) {
        RETURN(NULL);
    } else {
        RETURN(msg->segment[1].iov_base);
    }
}


#if !SK_ENABLE_GNUTLS
/* no-op function used when gnutls is not available */

void
skMsgGnuTLSTeardown(
    void)
{
}

int
skMsgTlsOptionsRegister(
    const char         *passwd_env_name)
{
    SK_UNUSED_PARAM(passwd_env_name);
    return 0;
}

void
skMsgTlsOptionsUsage(
    FILE               *fh)
{
    SK_UNUSED_PARAM(fh);
}

int
skMsgTlsOptionsVerify(
    unsigned int       *tls_available)
{
    if (tls_available) {
        *tls_available = 0;
    }
    return 0;
}

#endif /* !SK_ENABLE_GNUTLS */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
