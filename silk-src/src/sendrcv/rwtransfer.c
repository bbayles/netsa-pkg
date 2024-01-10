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
**  rwtransfer.c
**
**    This file contains functions that are common to rwsender and
**    rwreceiver, such as options processing and establishing the
**    connection.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwtransfer.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/sklog.h>
#include <silk/skdaemon.h>
#include "rwtransfer.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* Illegal ident characters */
#define ILLEGAL_IDENT_CHARS " \t:/\\.,"

/* Define lowest protocol version which we handle */
#define LOW_VERSION  1

/* Version protocol we emit */
#define EMIT_VERISION 2

/* Environment variable used to turn off keepalive.  Used for
 * debugging. */
#define RWTRANSFER_TURN_OFF_KEEPALIVE "RWTRANSFER_TURN_OFF_KEEPALIVE"

/* Maximum expected size of connection information string*/
#define RWTRANSFER_CONNECTION_TYPE_SIZE_MAX 50

typedef struct connection_msg_data_st {
    const char *name;
    int32_t     size;
} connection_msg_data_t;


/* EXPORTED VARIABLE DEFINITIONS */

int main_retval = EXIT_SUCCESS;


/* LOCAL VARIABLE DEFINITIONS */

/* Mode (client/server) */
static enum {CLIENT, SERVER, NOT_SET} mode;

#define OPTION_NOT_SEEN -1

/* Initialize these to OPTION_NOT_SEEN. Set to the opt_index in the
 * client and server option handlers to know what types of options
 * were given. */
static int client_sentinel;
static int server_sentinel;

/* Daemon identity */
static char *identity;

/* Whether GnuTLS CA/key/certificate files were given */
static unsigned int tls_available;

/* Message queue */
static sk_msg_queue_t *control;

/* Temporary transfer_t item */
static transfer_t *global_temp_item;

/* Control message thread */
static pthread_t control_thread;
static int       control_thread_valid;

/* Address upon which to listen for incoming connections */
static sk_sockaddr_array_t *listen_address = NULL;
static const char *listen_address_arg = NULL;

/* Locations which can be addressed as return values */
static void *exit_standard   = &exit_standard;
static void *exit_disconnect = &exit_disconnect;
static void *exit_failure    = &exit_failure;

/* Main thread */
static pthread_t main_thread;

/* Detached thread entry/exit control (see comment in serverMain()) */
static uint16_t detached_thread_count = 0;
static pthread_mutex_t detached_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  detached_thread_cond  = PTHREAD_COND_INITIALIZER;

typedef int (*connection_fn_t)(
    sk_msg_queue_t *,
    struct sockaddr *,
    socklen_t,
    skm_channel_t *);

typedef struct conn_info_st {
    sk_msg_queue_t *queue;
    skm_channel_t   channel;
    transfer_t     *trnsfr;
    unsigned        tls;
} conn_info_t;

typedef enum {
    /* Global options */
    OPT_MODE, OPT_IDENT
} appOptionsEnum;

static struct option appOptions[] = {
    {"mode",            REQUIRED_ARG, 0, OPT_MODE},
    {"identifier",      REQUIRED_ARG, 0, OPT_IDENT},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Run as a client or as a server. Choices: client, server"),
    ("Specify the name to use when establishing connections"),
    (char *)NULL
};

typedef enum {
    /* Client options */
    OPT_SERVER_ADDR
} appClientOptionsEnum;

static struct option appClientOptions[] = {
    {"server-address", REQUIRED_ARG, 0, OPT_SERVER_ADDR},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appClientHelp[] = {
    ("Connect to the server having this identifier, name,\n"
     "\tand port, specified as IDENT:HOST:PORT. Wrap an IPv6 address in\n"
     "\tsquare brackets. Repeat to connect to multiple servers"),
    (char *)NULL
};

typedef enum {
    /* Server options */
    OPT_SERVER_PORT, OPT_CLIENT_IDENT
} appServerOptionsEnum;

static struct option appServerOptions[] = {
    {"server-port",  REQUIRED_ARG, 0, OPT_SERVER_PORT},
    {"client-ident", REQUIRED_ARG, 0, OPT_CLIENT_IDENT},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appServerHelp[] = {
    ("Listen for incoming client connections on this port.\n"
     "\tListen on all addresses unless a host is provided before the port,\n"
     "\tspecified as HOST:PORT. Wrap an IPv6 address in square brackets"),
    ("Allow a client having this identifier to connect to\n"
     "\tthis server. Repeat to allow connections from multiple clients"),
    (char *)NULL
};


/*
 *  Connection message textual representation and lengths.
 *
 *  Length of -1 indicates a variable length message (use of
 *  sendString() implies variable length).
 */
static connection_msg_data_t
conn_msg_data[CONN_NUMBER_OF_CONNECTION_MESSAGES] = {
    {"CONN_SENDER_VERSION",    sizeof(uint32_t)},
    {"CONN_RECEIVER_VERSION",  sizeof(uint32_t)},
    {"CONN_IDENT",            -1},
    {"CONN_READY",             0},
    {"CONN_DISCONNECT_RETRY", -1},
    {"CONN_DISCONNECT",       -1},
    {"CONN_NEW_FILE",         -1},
    {"CONN_NEW_FILE_READY",    0},
    {"CONN_FILE_BLOCK",       -1},
    {"CONN_FILE_COMPLETE",     0},
    {"CONN_DUPLICATE_FILE",   -1},
    {"CONN_REJECT_FILE",      -1}
};


/* LOCAL FUNCTION PROTOTYPES */

static void *clientMain(void *); /* Thread entry point */
static void *serverMain(void *); /* Thread entry point */
static int
appOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);
static int
appClientOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);
static int
appServerOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);
static void
parseServerAddress(
    const char         *const_addr);
static void
addClientIdent(
    const char         *ident);


/* FUNCTION DEFINITIONS */

/*
 *  checkIdent(ident, switch_name);
 *
 *    Check to see if an ident is legal.  If illegal, print an error
 *    message to the error stream, end exit.
 */
int
checkIdent(
    const char         *ident,
    const char         *switch_name)
{
    const char *invalid;
    const char *c;

    if (ident == NULL || ident[0] == '\0') {
        skAppPrintErr(
            "Invalid %s: Identifier must contain at least one character",
            switch_name);
        exit(EXIT_FAILURE);
    }
    invalid = strpbrk(ident, ILLEGAL_IDENT_CHARS);
    if (invalid != NULL) {
        skAppPrintErr(
            "Invalid %s: Identifier '%s' contains the illegal character '%c'",
            switch_name, ident, *invalid);
        exit(EXIT_FAILURE);
    }
    for (c = ident; *c; c++) {
        if (!isprint((int)*c)) {
            skAppPrintErr(("Invalid %s: Identifier '%s' contains"
                           " the nonprintable character %#x"),
                          switch_name, ident, (int)*c);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}


/*
 * appModeUsage();
 *
 *    Print usage information for the mode named 'mode_str', using the
 *    given 'options' and 'help'.
 */
static void
appModeUsage(
    FILE               *fh,
    const char         *mode_str,
    struct option       options[],
    const char         *help[])
{
    unsigned int i;

    fprintf(fh, "\n%s switches:\n", mode_str);
    for (i = 0; options[i].name; ++i) {
        if (help[i]) {
            fprintf(fh, "--%s %s. %s\n", options[i].name,
                    SK_OPTION_HAS_ARG(options[i]), help[i]);
        }
    }
}


void
transferUsageLong(
    FILE               *fh,
    const char         *usage,
    struct option       options[],
    const char         *help[])
{
    unsigned int i;
    unsigned int j;

    fprintf(fh, "%s %s", skAppName(), usage);

    fprintf(fh, "\nCommon switches:\n");
    skOptionsDefaultUsage(fh);

    /* print common options defined in this file, but do not print
     * encryption switches yet */
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]), appHelp[i]);
    }
    /* print the application-specific switches */
    for (j = 0; options[j].name; ++j) {
        fprintf(fh, "--%s %s. %s\n", options[j].name,
                SK_OPTION_HAS_ARG(options[j]), help[j]);
    }
    /* print switches for client and server mode */
    appModeUsage(fh, "Client", appClientOptions, appClientHelp);
    appModeUsage(fh, "Server", appServerOptions, appServerHelp);

    /* now print the encryption switches */
    skMsgTlsOptionsUsage(fh);

    fprintf(fh, "\nLogging and daemon switches:\n");
    skdaemonOptionsUsage(fh);
}


int
transferSetup(
    void)
{
    /* verify that the sizes of options and help match */
    assert((sizeof(appHelp)/sizeof(char*)) ==
           (sizeof(appOptions)/sizeof(struct option)));
    assert((sizeof(appClientHelp)/sizeof(char*)) ==
           (sizeof(appClientOptions)/sizeof(struct option)));
    assert((sizeof(appServerHelp)/sizeof(char*)) ==
           (sizeof(appServerOptions)/sizeof(struct option)));

    mode                  = NOT_SET;
    client_sentinel       = OPTION_NOT_SEEN;
    server_sentinel       = OPTION_NOT_SEEN;
    identity              = NULL;
    global_temp_item      = NULL;
    control_thread_valid  = 0;

    /* register the options and handler */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to transfer application options");
        return -1;
    }

    /* register the client options and handler */
    if (skOptionsRegister(appClientOptions, &appClientOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register client options");
        return -1;
    }

    /* register the server options and handler */
    if (skOptionsRegister(appServerOptions, &appServerOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register server options");
        return -1;
    }

    if (skMsgTlsOptionsRegister(password_env)) {
        skAppPrintErr("Unable to register TLS-related options");
        return -1;
    }

    return 0;
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    This function is passed to skOptionsRegister(); it will be called
 *    by skOptionsParse() for each user-specified switch that the
 *    application has registered; it should handle the switch as
 *    required---typically by setting global variables---and return 1
 *    if the switch processing failed or 0 if it succeeded.  Returning
 *    a non-zero from from the handler causes skOptionsParse() to return
 *    a negative value.
 *
 *    The clientData in 'cData' is typically ignored; 'opt_index' is
 *    the index number that was specified as the last value for each
 *    struct option in appOptions[]; 'opt_arg' is the user's argument
 *    to the switch for options that have a REQUIRED_ARG or an
 *    OPTIONAL_ARG.
 */
static int
appOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    SK_UNUSED_PARAM(cData);

    switch ((appOptionsEnum)opt_index) {
      case OPT_MODE:
        if (0 == strcmp(opt_arg, "server")) {
            mode = SERVER;
        } else if (0 == strcmp(opt_arg, "client")) {
            mode = CLIENT;
        } else {
            skAppPrintErr("Invalid --%s '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_IDENT:
        checkIdent(opt_arg, appOptions[opt_index].name);
        identity = opt_arg;
        break;
    }

    return 0;  /* OK */
}


int
transferVerifyOptions(
    void)
{
    RBLIST *list;
    transfer_t *item;
    int error_count = 0;

    /* Check mode options */
    if (mode == NOT_SET) {
        skAppPrintErr(("Client or server mode must be chosen "
                       "via the --%s switch"),
                      appOptions[OPT_MODE].name);
        ++error_count;
    }
    if ((mode == CLIENT && (server_sentinel != OPTION_NOT_SEEN)) ||
        (mode == SERVER && (client_sentinel != OPTION_NOT_SEEN)))
    {
        int badopt = (mode == CLIENT) ? server_sentinel : client_sentinel;
        struct option *opts =
            (mode == CLIENT) ? appServerOptions : appClientOptions;
        const char *mode_string = (mode == CLIENT) ? "client" : "server";
        skAppPrintErr("The --%s switch cannot be used in %s mode",
                      opts[badopt].name, mode_string);
        return -1;
    }

    if (identity == NULL) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_IDENT].name);
        ++error_count;
    }

    if (rbmin(transfers) == NULL && mode != NOT_SET) {
        skAppPrintErr("Must supply at least one --%s switch",
                      (mode == CLIENT)
                      ? appClientOptions[OPT_SERVER_ADDR].name
                      : appServerOptions[OPT_CLIENT_IDENT].name);
        ++error_count;
    }

    if (skMsgTlsOptionsVerify(&tls_available)) {
        ++error_count;
    }

    switch (mode) {
      case SERVER:
        if (listen_address == NULL) {
            skAppPrintErr("Must supply a port using --%s in server mode",
                          appServerOptions[OPT_SERVER_PORT].name);
            ++error_count;
        }
        break;

      case CLIENT:
        list = rbopenlist(transfers);
        if (list == NULL) {
            skAppPrintErr("Memory allocation failure verifying options");
            return -1;
        }
        while ((item = (transfer_t *)rbreadlist(list)) != NULL) {
            if (item->address_exists == 0) {
                skAppPrintErr("Ident %s has no address associated with it",
                              item->ident);
                return -1;
            }
        }
        rbcloselist(list);
        break;

      case NOT_SET:
        break;
    }

    if (error_count) {
        return -1;
    }

    main_thread = pthread_self();

    return 0;
}


void
transferShutdown(
    void)
{
    RBLIST *iter;
    transfer_t *trnsfr;
    int rv;

    assert(shuttingdown);

    skMsgQueueShutdownAll(control);

    iter = rbopenlist(transfers);
    CHECK_ALLOC(iter);
    while ((trnsfr = (transfer_t *)rbreadlist(iter)) != NULL) {
        rv = transferUnblock(trnsfr);
        if (rv != 0) {
            CRITMSG("Unexpected failure to unblock transfer");
            _exit(EXIT_FAILURE);
        }
    }
    rbcloselist(iter);
}


void
transferTeardown(
    void)
{
    /* Wait for transfer threads to end.  In server mode, all these
     * threads are detached, and as such may not be joinable.  */
    if (mode != SERVER) {
        RBLIST *iter;
        transfer_t *trnsfr;

        iter = rbopenlist(transfers);
        CHECK_ALLOC(iter);
        while ((trnsfr = (transfer_t *)rbreadlist(iter)) != NULL) {
            if (trnsfr->thread_exists) {
                DEBUGMSG("Waiting for thread %s to end...", trnsfr->ident);
                pthread_join(trnsfr->thread, NULL);
                DEBUGMSG("Thread %s has ended.", trnsfr->ident);
            }
        }
        rbcloselist(iter);
    }

    /* Wait for control thread to end */
    if (control_thread_valid) {
        DEBUGMSG("Waiting for control thread to end...");
        pthread_join(control_thread, NULL);
        DEBUGMSG("Control thread has ended.");
    }

    /* Wait for detached threads to end */
    DEBUGMSG("Waiting for detached threads to end...");
    pthread_mutex_lock(&detached_thread_mutex);
    while (detached_thread_count) {
        pthread_cond_wait(&detached_thread_cond, &detached_thread_mutex);
    }
    pthread_mutex_unlock(&detached_thread_mutex);
    DEBUGMSG("Detached threads have ended.");

    /* Destroy stuff */
    if (control) {
        skMsgQueueDestroy(control);
    }
    if (listen_address) {
        skSockaddrArrayDestroy(listen_address);
        listen_address = NULL;
    }
    if (global_temp_item != NULL) {
        free(global_temp_item);
    }

    skMsgGnuTLSTeardown();
}


static int
appClientOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    SK_UNUSED_PARAM(cData);

    client_sentinel = opt_index;

    switch ((appClientOptionsEnum)opt_index) {
      case OPT_SERVER_ADDR:
        parseServerAddress(opt_arg);
        break;
    }

    return 0;  /* OK */
}


static int
appServerOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    int rv;

    SK_UNUSED_PARAM(cData);

    server_sentinel = opt_index;

    switch ((appServerOptionsEnum)opt_index) {
      case OPT_CLIENT_IDENT:
        addClientIdent(opt_arg);
        break;

      case OPT_SERVER_PORT:
        rv = skStringParseHostPortPair(&listen_address,opt_arg, PORT_REQUIRED);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[opt_index].name, opt_arg,
                          skStringParseStrerror(rv));
            return 1;
        }
        listen_address_arg = opt_arg;
        break;
    }

    return 0;  /* OK */
}



/* String compare for receiver rbtree */
static int
transferCompare(
    const void         *va,
    const void         *vb,
    const void         *cbdata)
{
    const transfer_t *a = (const transfer_t *)va;
    const transfer_t *b = (const transfer_t *)vb;
    SK_UNUSED_PARAM(cbdata);
    return strcmp(a->ident, b->ident);
}


struct rbtree *
transferIdentTreeCreate(
    void)
{
    return rbinit(transferCompare, NULL);
}


/* Create temporary transfer_t objects */
transfer_t *
initTemp(
    void)
{
    /* Allocate and/or clear the temporary item */
    if (global_temp_item == NULL) {
        global_temp_item = (transfer_t *)calloc(1, sizeof(*global_temp_item));
    } else {
        memset(global_temp_item, 0, sizeof(*global_temp_item));
    }
    return global_temp_item;
}

/* If a program wishes to keep a temporary transfer object, it should
   call this. */
void
clearTemp(
    void)
{
    global_temp_item = NULL;
}


/* Parse a <ident>:<address>:<port> specification */
static void
parseServerAddress(
    const char         *const_addr)
{
#define FMT_PARSE_FAILURE                               \
    ("Server address parse failure parsing '%s'\n"      \
     "\tCorrect form is <ident>:<address>:<port>")
#define FMT_MEM_FAILURE                                         \
    "Memory allocation failure when parsing server address %s"

    char *addr = strdup(const_addr);
    char *colon, *next;
    transfer_t *old;
    const void *test;
    int rv;
    transfer_t *temp_item;

    temp_item = initTemp();

    if (addr == NULL || temp_item == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, const_addr);
        exit(EXIT_FAILURE);
    }

    /* First, extract the ident */
    colon = strchr(addr, ':');
    if (colon == NULL) {
        free(addr);
        skAppPrintErr(FMT_PARSE_FAILURE, const_addr);
        exit(EXIT_FAILURE);
    }
    *colon = '\0';
    checkIdent(addr, appClientOptions[OPT_SERVER_ADDR].name);
    temp_item->ident = addr;


    /* See if it has already been used */
    old = (transfer_t *)rbfind(temp_item, transfers);
    if (old != NULL) {
        if (!old->address_exists) {
            memcpy(temp_item, old, sizeof(*temp_item));
            test = rbdelete(old, transfers);
            assert(test == old);
            temp_item->ident = addr;
            free(old->ident);
            free(old);
        } else {
            free(addr);
            skAppPrintErr("Duplicate ident in server address %s", const_addr);
            exit(EXIT_FAILURE);
        }
    }

    /* Next, extract the address */
    next = colon + 1;
    rv = skStringParseHostPortPair(&temp_item->addr, next,
                                   HOST_REQUIRED | PORT_REQUIRED);
    if (rv < 0) {
        skAppPrintErr("Could not parse address: %s",
                      skStringParseStrerror(rv));
        exit(EXIT_FAILURE);
    }

    /* Add to our server list */
    temp_item->ident = strdup(temp_item->ident);
    free(addr);
    if (temp_item->ident == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, const_addr);
        exit(EXIT_FAILURE);
    }
    test = rbsearch(temp_item, transfers);
    if (test == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, const_addr);
        exit(EXIT_FAILURE);
    }
    temp_item->address_exists = 1;

    assert(test == temp_item);
    clearTemp();

#undef FMT_PARSE_FAILURE
#undef FMT_MEM_FAILURE
}


/* Add a bare ident to the transfer list */
static void
addClientIdent(
    const char         *ident)
{
#define FMT_MEM_FAILURE "Memory allocation failure when parsing ident %s"
    const void *test;
    transfer_t *temp_item;

    checkIdent(ident, appServerOptions[OPT_CLIENT_IDENT].name);
    temp_item = initTemp();
    if (temp_item == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, ident);
        exit(EXIT_FAILURE);
    }
    temp_item->ident = (char *)ident;
    test = rbsearch(temp_item, transfers);
    if (test == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, ident);
        exit(EXIT_FAILURE);
    }
    if (test != temp_item) {
        skAppPrintErr("Duplicate ident %s", ident);
        exit(EXIT_FAILURE);
    }
    temp_item->ident = strdup(ident);
    if (temp_item->ident == NULL) {
        skAppPrintErr(FMT_MEM_FAILURE, ident);
        exit(EXIT_FAILURE);
    }
    clearTemp();
#undef FMT_MEM_FAILURE
}


static void
getConnectionInformation(
    sk_msg_queue_t     *queue,
    skm_channel_t       channel,
    char               *buffer,
    size_t              buffer_size)
{
    int rv;

    rv = skMsgGetConnectionInformation(queue, channel, buffer, buffer_size);
    if (rv == -1) {
        strncpy(buffer, "<unknown>", buffer_size);
    }
    buffer[buffer_size - 1] = '\0';
}


int
handleDisconnect(
    sk_msg_t           *msg,
    const char         *type)
{
    skm_type_t msgtyp = skMsgType(msg);

    if (msgtyp == CONN_DISCONNECT || msgtyp == CONN_DISCONNECT_RETRY) {
        int length = MAX_ERROR_MESSAGE;

        if (skMsgLength(msg) < length) {
            length = skMsgLength(msg);
        }

        INFOMSG("Connection %s disconnected: %.*s",
                type, length, (char *)skMsgMessage(msg));

        return (msgtyp == CONN_DISCONNECT) ? -1 : 1;
    }

    return 0;
}


/*
 *    This function is used by servers and clients.  The function
 *    verifies the connection (version, ident), and then calls the
 *    transferFiles() function defined in rwsender.c or rwreceiver.c.
 *
 *    For a server, this is a THREAD ENTRY POINT.  Entry point for the
 *    "connection" thread, started from serverMain().  This thread is
 *    detached.
 *
 *    For a client, this function is called by startClientConnection()
 *    once the client has connected to a server.
 */
static void *
handleConnection(
    void               *vinfo)
{
    conn_info_t *info = (conn_info_t *)vinfo;
    transfer_t target;
    transfer_t *trnsfr = NULL;
    transfer_t *found = NULL;
    uint32_t version;
    skm_channel_t channel;
    sk_msg_queue_t *q;
    enum conn_state {Version, Ident, Ready, Running, Disconnect} state;
    int proto_err;
    int fatal_err = 0;
    const char *ident = "<unassigned>";
    void *retval = exit_failure;
    char connection_type[RWTRANSFER_CONNECTION_TYPE_SIZE_MAX];
    int transferred_file = 0;

    DEBUG_PRINT1("connection thread started");

    q = info->queue;
    channel = info->channel;
    trnsfr = info->trnsfr;
    free(info);

    /* start by sending my version and waiting for remote's version */
    state = Version;
    version = htonl(EMIT_VERISION);
    proto_err = skMsgQueueSendMessage(q, channel, local_version_check,
                                      &version, sizeof(version));

    while (!shuttingdown && !proto_err && !fatal_err && state != Running) {
        int rv;
        sk_msg_t *msg;

        rv = skMsgQueueGetMessage(q, &msg);
        if (rv == -1) {
            ASSERT_ABORT(shuttingdown);
            continue;
        }
        DEBUG_PRINT3("handleConnection() state=%d, got msg type=%d",
                     (int)state, (int)skMsgType(msg));

        rv = handleDisconnect(msg, ident);
        if (rv) {
            proto_err = 1;
            retval = transferred_file ? exit_disconnect : exit_failure;
            state = Disconnect;
        }

        switch (state) {
          case Version:
            /* expecting remote's version. if not valid, close the
             * channel.  if valid, send my ident and wait for remote's
             * ident */
            if ((proto_err = checkMsg(msg, q, remote_version_check))) {
                DEBUG_PRINT2("checkMsg(%s) FAILED",
                             conn_msg_data[remote_version_check].name);
                retval = exit_failure;
                break;
            }
            DEBUG_PRINT2("Received %s",
                         conn_msg_data[remote_version_check].name);
            version = MSG_UINT32(msg);
            if (version < LOW_VERSION) {
                sendString(q, skMsgChannel(msg), EXTERNAL,
                           CONN_DISCONNECT, LOG_WARNING,
                           ("Unsupported version %" PRIu32), version);
                proto_err = 1;
                retval = exit_failure;
                break;
            }
            if (!getenv(RWTRANSFER_TURN_OFF_KEEPALIVE)) {
                rv = skMsgSetKeepalive(q, channel, KEEPALIVE_TIMEOUT);
                assert(rv == 0);
            }
            state = Ident;
            proto_err = skMsgQueueSendMessage(q, channel, CONN_IDENT,
                                              identity, strlen(identity) + 1);
            if (proto_err != 0) {
                retval = exit_failure;
            }
            break;

          case Ident:
            /* expecting remote's ident.  if not valid, close the
             * channel.  if valid, send CONN_READY and wait for remote
             * to say it is ready */
            if ((proto_err = checkMsg(msg, q, CONN_IDENT))) {
                DEBUG_PRINT1("checkMsg(CONN_IDENT) FAILED");
                retval = exit_failure;
                break;
            }
            DEBUG_PRINT1("Received CONN_IDENT");
            target.ident = MSG_CHARP(msg);
            found = (transfer_t *)rbfind(&target, transfers);
            if (found == NULL
                || (trnsfr != NULL && trnsfr != found)
                || (trnsfr == NULL && found->thread_exists))
            {
                const char *reason;
                if (found == NULL) {
                    reason = "Unknown ident";
                } else if (trnsfr != NULL && trnsfr != found) {
                    reason = "Unexpected ident";
                } else {
                    reason = "Duplicate ident";
                }
                sendString(q, skMsgChannel(msg), EXTERNAL,
                           CONN_DISCONNECT, LOG_WARNING,
                           "%s %s", reason, target.ident);
                proto_err = 1;
                retval = exit_failure;
                break;
            }
            ident = found->ident;
            found->thread = pthread_self();
            found->thread_exists = 1;
            found->channel = channel;
            found->channel_exists = 1;
            found->remote_version = version;

            getConnectionInformation(q, channel, connection_type,
                                     sizeof(connection_type));
            INFOMSG("Connected to remote %s (%s, Protocol v%" PRIu32 ")",
                    ident, connection_type, version);
            state = Ready;
            proto_err = skMsgQueueSendMessage(q, channel, CONN_READY, NULL, 0);
            if (proto_err != 0) {
                DEBUG_PRINT1("skMsgQueueSendMessage(CONN_READY) failed");
                retval = exit_failure;
            }
            break;

          case Ready:
            /* expecting remote to say it is ready. if ready, call
             * transferFiles() */
            if ((proto_err = checkMsg(msg, q, CONN_READY))) {
                DEBUG_PRINT1("checkMsg(CONN_READY) FAILED");
                retval = exit_failure;
                break;
            }
            DEBUGMSG("Remote %s is ready for messages", ident);
            state = Running;
            rv = transferFiles(q, channel, found);
            switch (rv) {
              case -1:
                fatal_err = 1;
                break;
              case 1:
                transferred_file = 1;
                break;
              default:
                break;
            }
            break;

          case Disconnect:
            DEBUG_PRINT1("Disconnecting");
            break;

          case Running:
            ASSERT_ABORT(0);
        }

        /* Free message */
        skMsgDestroy(msg);
    }

    if (found) {
        found->channel_exists = 0;
        found->disconnect = 0;
    }

    skMsgQueueDestroy(q);

    /* If running in server mode, this was a detached thread. */
    if (trnsfr == NULL) {
        if (found) {
            found->thread_exists = 0;
        }
        pthread_mutex_lock(&detached_thread_mutex);
        detached_thread_count--;
        pthread_cond_signal(&detached_thread_cond);
        pthread_mutex_unlock(&detached_thread_mutex);
    }

    DEBUG_PRINT2("connection thread ended (status = %s)",
                 ((fatal_err)
                  ? "exit_failure [from transferFiles()]"
                  : ((exit_standard == retval)
                     ? "exit_standard"
                     : ((exit_disconnect == retval)
                        ? "exit_disconnect"
                        : ((exit_failure == retval)
                           ? "exit_failure"
                           : "UNKNOWN")))));

    if (fatal_err) {
        threadExit(EXIT_FAILURE, exit_failure);
    }

    return retval;
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "server_main" thread, started from
 *    startTransferDaemon().
 */
static void *
serverMain(
    void       *dummy)
{
    int rv;
    const char *connection_type = (tls_available ? "TCP, TLS" : "TCP");

    SK_UNUSED_PARAM(dummy);

    control_thread_valid = 1;

    DEBUG_PRINT1("server_main() thread started");

    assert(listen_address);

    rv = skMsgQueueBind(control, listen_address);
    if (rv < 0) {
        CRITMSG("Failed to bind to %s for listening", listen_address_arg);
        threadExit(EXIT_FAILURE, NULL);
    }

    INFOMSG("Bound to %s for listening (%s)",
            listen_address_arg, connection_type);

    while (!shuttingdown) {
        sk_msg_t *msg;
        skm_channel_t channel;
        pthread_t thread;
        conn_info_t *info;
        transfer_t *item;
        RBLIST *list;
        sk_new_channel_info_t *addr_info;
        char buf[PATH_MAX];
        char conn_type[RWTRANSFER_CONNECTION_TYPE_SIZE_MAX];

        rv = skMsgQueueGetMessageFromChannel(control, SKMSG_CHANNEL_CONTROL,
                                             &msg);
        if (rv == -1) {
            ASSERT_ABORT(shuttingdown);
            continue;
        }

        switch (skMsgType(msg)) {

          case SKMSG_CTL_NEW_CONNECTION:
            DEBUG_PRINT1("Received SKMSG_CTL_NEW_CONNECTION");
            channel = SKMSG_CTL_MSG_GET_CHANNEL(msg);
            addr_info = (sk_new_channel_info_t *)skMsgMessage(msg);
            getConnectionInformation(control, channel, conn_type,
                                     sizeof(conn_type));
            if (addr_info->known) {
                skSockaddrString(buf, sizeof(buf), &addr_info->addr);
            }
            INFOMSG("Received connection from %s (%s)",
                    (addr_info->known ? buf : "unknown address"), conn_type);
            info = (conn_info_t *)calloc(1, sizeof(*info));
            if (info == NULL) {
                CRITMSG("Memory allocation failure");
                threadExit(EXIT_FAILURE, NULL);
            }
            info->tls = tls_available;
            info->trnsfr = NULL;
            rv = skMsgChannelSplit(control, channel, &info->queue);
            if (rv != 0) {
                if (shuttingdown) {
                    break;
                }
                CRITMSG("Failed to split channel");
                threadExit(EXIT_FAILURE, NULL);
            }
            info->channel = channel;

            /* In server mode we don't have one thread per ident.
             * Instead we have one thread per entity that is
             * connecting to us.  Since there is no transfer object to
             * attach the thread to, we create a detached thread
             * instead, and use the detached_thread_mutex and
             * detached_thread_count to know when the threads have
             * ended. */
            pthread_mutex_lock(&detached_thread_mutex);
            rv = skthread_create_detached("connection", &thread,
                                          handleConnection, info);
            if (rv != 0) {
                pthread_mutex_unlock(&detached_thread_mutex);
                CRITMSG("Failed to create connection thread: %s",
                        strerror(rv));
                threadExit(EXIT_FAILURE, NULL);
            }
            detached_thread_count++;
            pthread_mutex_unlock(&detached_thread_mutex);
            break;

          case SKMSG_CTL_CHANNEL_DIED:
            DEBUG_PRINT1("Received SKMSG_CTL_CHANNEL_DIED");
            channel = SKMSG_CTL_MSG_GET_CHANNEL(msg);
            list = rbopenlist(transfers);
            CHECK_ALLOC(list);
            while ((item = (transfer_t *)rbreadlist(list)) != NULL) {
                if (item->channel_exists && channel == item->channel) {
                    INFOMSG("Channel to %s died", item->ident);
                    item->disconnect = 1;
                    rv = transferUnblock(item);
                    if (rv != 0) {
                        threadExit(EXIT_FAILURE, NULL);
                    }
                    break;
                }
            }
            rbcloselist(list);

            if (!shuttingdown) {
                sendString(control, channel, INTERNAL, CONN_DISCONNECT_RETRY,
                           LOG_INFO, "Remote side of channel died");
            }
            break;

          default:
            WARNINGMSG("Received unknown control message %d", skMsgType(msg));
        }

        skMsgDestroy(msg);
    }

    DEBUG_PRINT1("server_main() thread ended");

    return NULL;
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "connection" thread, started from
 *    clientMain().
 */
static void *
startClientConnection(
    void               *vitem)
{
    transfer_t *item = (transfer_t *)vitem;
    void *exit_status = exit_standard;
    int waitsecs = 0;
    const char *connection_type = (tls_available ? "TCP, TLS" : "TCP");
    socklen_t addrlen;
    char buf[SKIPADDR_STRLEN];

    item->thread_exists = 1;

    DEBUG_PRINT1("client_connection() thread started");

    while (!shuttingdown) {
        size_t i;
        int rv;
        skm_channel_t channel;

        if (waitsecs != 0) {
            int waitcount = waitsecs;

            DEBUG_PRINT2("Failure in connection, "
                         "waiting %d seconds", waitcount);
            while (waitcount-- && !shuttingdown) {
                sleep(1);
            }
            if (shuttingdown) {
                break;
            }
        }

        INFOMSG("Attempting to connect to %s (%s)...",
                item->ident, connection_type);

        for (rv = -1, i = 0;
             rv != 0 && i < skSockaddrArrayGetSize(item->addr); i++)
        {
            sk_sockaddr_t *addr = skSockaddrArrayGet(item->addr, i);
            switch (addr->sa.sa_family) {
              case AF_INET:
                addrlen = sizeof(addr->v4);
                break;
              case AF_INET6:
                addrlen = sizeof(addr->v6);
                break;
              default:
                continue;
            }
            skSockaddrString(buf, sizeof(buf), addr);
            DEBUGMSG("Address for %s is %s", item->ident, buf);
            rv = skMsgQueueConnect(control, &addr->sa, addrlen, &channel);
        }

        if (rv != 0) {
            INFOMSG("Attempt to connect to %s failed (%s)",
                    item->ident, connection_type);
            if (waitsecs < 60) {
                waitsecs += 5;
            }
        } else {
            conn_info_t *info;
            char conn_type[RWTRANSFER_CONNECTION_TYPE_SIZE_MAX];
            uint16_t port = 0;

            getConnectionInformation(control, channel,
                                     conn_type, sizeof(conn_type));
            skMsgGetLocalPort(control, channel, &port);
            DEBUGMSG("Connected (expecting ident %s) (local port %u, %s)",
                     item->ident, port, conn_type);
            info = (conn_info_t *)calloc(1, sizeof(*info));
            if (info == NULL) {
                CRITMSG("Memory allocation failure");
                threadExit(EXIT_FAILURE, exit_failure);
            }
            info->tls = tls_available;
            info->trnsfr = item;
            rv = skMsgChannelSplit(control, channel, &info->queue);
            if (rv != 0) {
                if (shuttingdown) {
                    break;
                }
                CRITMSG("Failed to split channel");
                threadExit(EXIT_FAILURE, exit_failure);
            }

            info->channel = channel;
            exit_status = handleConnection(info);
            if (exit_status != exit_failure) {
                waitsecs = 0;
            } else if (waitsecs < 60) {
                waitsecs += 5;
            }
        }
    }

    DEBUG_PRINT1("client_connection() thread ended");

    return exit_status;
}


/*
 *    THREAD ENTRY POINT
 *
 *    Entry point for the "client_main" thread, started from
 *    startTransferDaemon()
 */
static void *
clientMain(
    void               *dummy)
{
    RBLIST *list;
    transfer_t *item;
    int rv;

    SK_UNUSED_PARAM(dummy);

    control_thread_valid = 1;

    DEBUG_PRINT1("client_main() thread started");

    list = rbopenlist(transfers);
    if (list == NULL) {
        skAppPrintErr("Memory allocation failure stating client thread");
        threadExit(EXIT_FAILURE, NULL);
    }

    /* Start client threads */
    while ((item = (transfer_t *)rbreadlist(list)) != NULL) {
        rv = skthread_create("connection", &item->thread,
                             startClientConnection, item);
        if (rv != 0) {
            CRITMSG("Failed to create connection thread: %s", strerror(rv));
            threadExit(EXIT_FAILURE, NULL);
        }
    }
    rbcloselist(list);

    /* Start control loop */
    while (!shuttingdown) {
        sk_msg_t *msg;
        skm_channel_t channel;

        rv = skMsgQueueGetMessageFromChannel(control, SKMSG_CHANNEL_CONTROL,
                                             &msg);
        if (rv == -1) {
            assert(shuttingdown);
            continue;
        }

        switch (skMsgType(msg)) {

          case SKMSG_CTL_NEW_CONNECTION:
            /* This can't happen, as we aren't bound */
            ASSERT_ABORT(0);
            break;

          case SKMSG_CTL_CHANNEL_DIED:
            DEBUG_PRINT1("Received SKMSG_CTL_CHANNEL_DIED");
            channel = SKMSG_CTL_MSG_GET_CHANNEL(msg);
            list = rbopenlist(transfers);
            CHECK_ALLOC(list);
            while ((item = (transfer_t *)rbreadlist(list)) != NULL) {
                if (item->channel_exists && channel == item->channel) {
                    INFOMSG("Channel to %s died", item->ident);
                    item->disconnect = 1;
                    rv = transferUnblock(item);
                    if (rv != 0) {
                        threadExit(EXIT_FAILURE, NULL);
                    }
                    break;
                }
            }
            rbcloselist(list);

            sendString(control, channel, INTERNAL, CONN_DISCONNECT_RETRY,
                       LOG_INFO, "Remote side of channel died");
            break;

          default:
            WARNINGMSG("Received unknown control message %d", skMsgType(msg));
        }

        skMsgDestroy(msg);
    }

    DEBUG_PRINT1("client_main() thread ended");
    return NULL;
}


int
startTransferDaemon(
    void)
{
    int rv;

    /* Initialize the message queue */
    rv = skMsgQueueCreate(&control);
    if (rv != 0) {
        skAppPrintErr("Failed to initialize message queue");
        exit(EXIT_FAILURE);
    }

    switch (mode) {
      case CLIENT:
        rv = skthread_create("client_main", &control_thread,
                             clientMain, NULL);
        if (rv != 0) {
            CRITMSG("Failed to create primary client thread: %s",strerror(rv));
            return -1;
        }
        break;
      case SERVER:
        rv = skthread_create("server_main", &control_thread,
                             serverMain, NULL);
        if (rv != 0) {
            CRITMSG("Failed to create primary server thread: %s",strerror(rv));
            return -1;
        }
        break;
      default:
        ASSERT_ABORT(0);
    }

    return 0;
}


int
checkMsg(
    sk_msg_t           *msg,
    sk_msg_queue_t     *q,
    connection_msg_t    type)
{
    skm_type_t t;
    skm_len_t  len;

    assert(msg);
    assert(q);
    assert(type < CONN_NUMBER_OF_CONNECTION_MESSAGES);

    t = skMsgType(msg);

    if (t != type) {
        sendString(q, skMsgChannel(msg), EXTERNAL,
                   CONN_DISCONNECT, LOG_WARNING,
                   "Protocol error: expected %s, got %s (0x%04x)",
                   conn_msg_data[type].name,
                   ((t >= CONN_NUMBER_OF_CONNECTION_MESSAGES)
                    ? "<unknown>"
                    : conn_msg_data[t].name),
                   t);
        return 1;
    }

    if (conn_msg_data[type].size == -1) {
        return 0;
    }

    len = skMsgLength(msg);
    if (len != conn_msg_data[type].size) {
        sendString(q, skMsgChannel(msg), EXTERNAL,
                   CONN_DISCONNECT, LOG_WARNING,
                   "Protocol error: type %s, expected len %" PRId32 ", got %d",
                   conn_msg_data[type].name,
                   conn_msg_data[type].size, len);
        return 1;
    }

    return 0;
}


#undef sendString
int
sendString(
    sk_msg_queue_t     *q,
    skm_channel_t       channel,
    int                 internal,
    skm_type_t          type,
    int                 loglevel,
    const char         *fmt,
    ...)
{
    int rv;
    va_list args;
    char msg[MAX_ERROR_MESSAGE];
    int len;

    va_start(args, fmt);
    len = vsnprintf(msg, sizeof(msg), fmt, args);
    if (len >= (int)sizeof(msg)) {
        len = sizeof(msg) - 1;
        msg[len] = '\0';
    }

    if (internal) {
        rv = skMsgQueueInjectMessage(q, channel, type, msg, len + 1);
    } else {
        rv = skMsgQueueSendMessage(q, channel, type, msg, len + 1);
    }

    if (!internal) {
        sklog(loglevel, "Sending \"%s\"", msg);
    }
    return rv;
}


void
threadExit(
    int                 status,
    void               *retval)
{
    DEBUG_PRINT1("threadExit called");
    main_retval = status;
    pthread_kill(main_thread, SIGQUIT);
    pthread_exit(retval);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
