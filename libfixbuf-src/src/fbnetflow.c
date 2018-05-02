/**
 *@internal
 *
 * @file fbnetflow.c
 *
 * This implements a Netflow convertor for translating into IPFIX
 * within the fixbuf structure
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2008-2018 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Chris Inacio <inacio@cert.org>, Emily Sarneso <ecoff@cert.org>
 * ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of the libfixbuf system and related source code is subject to the terms
 * of the following licenses:
 *
 * Copyright 2018 Carnegie Mellon University. All Rights Reserved.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 * ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 * BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 * LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 * EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 * MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 * ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 * COPYRIGHT INFRINGEMENT.
 *
 * Released under a GNU-Lesser GPL 3.0-style license, please see
 * License.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for
 * public release and unlimited distribution.  Please see Copyright
 * notice for non-US Government use and distribution.
 *
 * Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 * Trademark Office by Carnegie Mellon University.
 *
 * @OPENSOURCE_HEADER_END@
 * ------------------------------------------------------------------------
 *
 * @Author:  $Author$
 * @Date:    $Date$
 * @Version: $Revision$
 *
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#include "fbcollector.h"

#include <pthread.h>


#ifndef FB_NETFLOW_DEBUG
#   define FB_NETFLOW_DEBUG 0
#endif

#define NF_MAX_SEQ_DIFF 100
#define NF_OUT_OF_ORDER 10
#define NF_REBOOT_SECS  60 * 1000 /* 1 min in milliseconds */


#if HAVE_ALIGNED_ACCESS_REQUIRED

#define fb_ntohll(x) (x)
#define fb_htonll(x) fb_ntohll(x)

/**
 * this set of macros for reading and writing U16's and U32's
 * uses memcpy's to avoid tripping over alignment issues on
 * platforms that cannot do unaligned access (e.g. SPARC, Alpha,
 * etc).  The next section, after the else, does not use memcpy's
 * and operates just fine on architectures that don't crash
 * from an unaligned access (x86, PowerPC, etc.)
 */

/**
 * READU16INC
 *
 * read U16 and increment
 *
 * read a U16 value from ptr, it assumes the pointer
 * is properly aligned and pointing at the correct
 * place; and then increment ptr appropriately
 * according to its size to adjust for reading a
 * U16; increments it 2-bytes
 *
 * does network to host translation
 */
#define READU16INC(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        memcpy(&ru16_t16val, ru16_t16ptr, sizeof(uint16_t)); \
        assignee = g_ntohs(ru16_t16val); \
        ptr += sizeof(*ru16_t16ptr) / sizeof(*ptr); \
    }

#define READU16(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        memcpy(&ru16_t16val, ru16_t16ptr, sizeof(uint16_t)); \
        assignee = g_ntohs(ru16_t16val); \
    }

#define WRITEU16(ptr,value) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = g_htons(value); \
        memcpy(ru16_t16ptr, &ru16_t16val, sizeof(uint16_t)); \
    }


/**
 * READU32INC
 *
 * read U32 and increment ptr
 *
 * read a U32 from the ptr given in ptr, it assumes
 * it is aligned and positioned correctly, then
 * increment the ptr appropriately based on its
 * size and having read a U32 to increment it
 * 4-bytes ahead
 *
 * does network to host translation
 */
#define READU32INC(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0;                        \
        memcpy(&ru32_t32val, ru32_t32ptr, sizeof(uint32_t));    \
        assignee = g_ntohl(ru32_t32val);                        \
        ptr += sizeof(*ru32_t32ptr) / sizeof(*ptr);             \
    }


#define READU32(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0; \
        memcpy(&ru32_t32val, ru32_t32ptr, sizeof(uint32_t)); \
        assignee = g_ntohl(ru32_t32val); \
    }

#define WRITEU32(ptr,value) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = g_htonl(value); \
        memcpy(ru32_t32ptr, &ru32_t32val, sizeof(uint32_t)); \
    }

#else


#define fb_ntohll(x) \
    ((((uint64_t)g_ntohl((uint32_t)((x) & 0xffffffff))) << 32)  \
     | g_ntohl((uint32_t)(((x) >> 32) & 0xffffffff)))
#define fb_htonll(x) fb_ntohll(x)


/**
 * READU16INC
 *
 * read U16 and increment
 *
 * read a U16 value from ptr, it assumes the pointer
 * is properly aligned and pointing at the correct
 * place; and then increment ptr appropriately
 * according to its size to adjust for reading a
 * U16; increments it 2-bytes
 *
 * does network to host translation
 */
#define READU16INC(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        ru16_t16val = g_ntohs(*ru16_t16ptr); \
        assignee = ru16_t16val; \
        ptr += sizeof(*ru16_t16ptr) / sizeof(*ptr); \
    }

#define READU16(ptr,assignee) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        uint16_t ru16_t16val = 0; \
        ru16_t16val = g_ntohs(*ru16_t16ptr); \
        assignee = ru16_t16val; \
    }

#define WRITEU16(ptr,value) { \
        uint16_t *ru16_t16ptr = (uint16_t *)(ptr);      \
        *ru16_t16ptr = g_htons(value); \
    }


/**
 * READU32INC
 *
 * read U32 and increment ptr
 *
 * read a U32 from the ptr given in ptr, it assumes
 * it is aligned and positioned correctly, then
 * increment the ptr appropriately based on its
 * size and having read a U32 to increment it
 * 4-bytes ahead
 *
 * does network to host translation
 */
#define READU32INC(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
    uint32_t ru32_t32val = 0; \
    ru32_t32val = g_ntohl(*ru32_t32ptr); \
    assignee = ru32_t32val; \
    ptr += sizeof(*ru32_t32ptr) / sizeof(*ptr); \
    }


#define READU32(ptr,assignee) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        uint32_t ru32_t32val = 0; \
        ru32_t32val = g_ntohl(*ru32_t32ptr); \
        assignee = ru32_t32val; \
    }

#define WRITEU32(ptr,value) { \
        uint32_t *ru32_t32ptr = (uint32_t *)(ptr);      \
        *ru32_t32ptr = g_htonl(value); \
    }

#endif


/** mini hash table for Netflow V9 */
typedef struct fbCollectorNetflowV9TemplateHash_st {
    /** id of the stored template, should be zeroed if not in use */
    uint16_t                    templateId;
    /** length of the template in question, zero is reserved for an
        unused field */
    uint16_t                    templateLength;
    /** boolean flag set if template ID represents an options template */
    gboolean                    optionsTemplate;
    /** boolean flag set if we added sysuptime field to template */
    gboolean                    addSysUpTime;
} fbCollectorNetflowV9TemplateHash_t;

typedef struct fbCollectorNetflowV9Session_st {
    /** template hash */
    GHashTable                 *templateHash;
    /** potential missed packets */
    uint32_t                    netflowMissed;
    /** current netflow seq num */
    uint32_t                    netflowSeqNum;
    /** current ipfix seq num */
    uint32_t                    ipfixSeqNum;
} fbCollectorNetflowV9Session_t;

/** defines the extra state needed to convert from NetflowV9 to IPFIX */
struct fbCollectorNetflowV9State_st {
    uint64_t                      sysUpTime;
    uint32_t                      observation_id;
    fbSession_t                   *sessionptr;
    fbCollectorNetflowV9Session_t *session;
    /* need to keep templates per domain */
    GHashTable                    *domainHash;
    pthread_mutex_t               ts_lock;
};

/**
 * templateHashDestroyHelper
 *
 * helps destroy the template hash by translating between the
 * GLib GDestroyNotify function type definition and using the
 * GLib slice free function
 *
 * @param datum pointer to the structure to be destroyed
 *
 */
static void         templateHashDestroyHelper (
    gpointer datum)
{
    g_slice_free(fbCollectorNetflowV9TemplateHash_t, datum);
}

static void         domainHashDestroyHelper(
    gpointer datum)
{
    if (((fbCollectorNetflowV9Session_t *)datum)->templateHash) {
        g_hash_table_destroy(((fbCollectorNetflowV9Session_t *)datum)->templateHash);
    }
    g_slice_free(fbCollectorNetflowV9Session_t, datum);
}

static guint        fooHash (
    gconstpointer   key)
{
    return (guint)((uintptr_t)key);
}

static gboolean     fooEqual (
    gconstpointer   alpha,
    gconstpointer   beta)
{
    uintptr_t   alphaInt = (uintptr_t)alpha;
    uintptr_t   betaInt = (uintptr_t)beta;

    if (alphaInt == betaInt) {
        return TRUE;
    }

    return FALSE;
}



/*#################################################
 *
 * netflow v9 functions for the collector, used
 * to optionally read
 *
 *#################################################*/

/**
 * fbCollectorDecodeV9MsgVL
 *
 * parses the header of a V9 message and determines
 * how much needs to be read in order to complete
 * the message, (at least in theory)
 *
 * @param collector a pointer to the collector state
 *        structure
 * @param hdr a pointer to the beginning of the buffer
 *        to parse as a message (get converted back
 *        into a uint8_t* and used as such)
 * @param b_len length of the buffer passed in for the
 *        hdr
 * @param m_len length of the message header that still
 *        needs to be read (always set to zero, since
 *        this reads the entire message)
 * @param err a pointer to glib error structure, used
 *        if an error occurs during processing the
 *        stream
 *
 *
 * @return number of octets to read to complete
 *         the message
 */
static gboolean     fbCollectorDecodeV9MsgVL(
     fbCollector_t               *collector,
     fbCollectorMsgVL_t          *hdr,
     size_t                      b_len,
     uint16_t                    *m_len,
     GError                      **err)
{
    uint16_t        recordCount;
    uint8_t         *dataBuf;
    uint8_t         *bufOffset;
    uint64_t        unix_secs;
    uint64_t        sysuptime;
    int             rc;
    unsigned int    loop;
    uint16_t        setLength;
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;
    struct setHeader_st {
        uint16_t    setId;
        uint16_t    setLength;
    } *setHeaderPtr;


    if (0x0009 != g_ntohs(hdr->n_version)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "Illegal NetflowV9 Message version 0x%04x; "
                    "input is probably not a NetflowV9 Message stream.",
                    g_ntohs(hdr->n_version));
        *m_len = 0;
        return FALSE;
    }

    /* so this is hopefully a netflow message;  I should now be able to
       read the entire message, it can't be larger than 1 packet, (the
       question becomes, what's a packet size) */

    recordCount = htons(hdr->n_len);
    dataBuf = (uint8_t *)hdr;
    bufOffset = dataBuf + sizeof(hdr);

    /* read the rest of the v9 header, ugly trick ahead:
    gonna read in the uptime, and then throw away the read
    and finish reading the rest of the header, dumping the
    uptime, because we don't really want it */
    if ((unsigned int)((bufOffset-dataBuf) + 16) < b_len) {
        g_set_error(err,FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "Error buffer too small to read NetflowV9 message header");
        *m_len = 0;
        return FALSE;
    }
    if (TRUE == collector->bufferedStream) {
        rc = fread(bufOffset, 1, 4, collector->stream.fp);
    } else {
        rc = read(collector->stream.fd, bufOffset, 4);
    }

    READU32(bufOffset, sysuptime);

    if (4 != rc) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "Could not complete read of the Netflow header");
        *m_len = 0;
        return FALSE;
    }

    if (TRUE == collector->bufferedStream) {
        rc = fread(bufOffset, 1, 12, collector->stream.fp);
    } else {
        rc = read(collector->stream.fd, bufOffset, 12);
    }

    if (12 != rc) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "Could not complete read of the Netflow header");
        *m_len = 0;
        return FALSE;
    }

    READU32(bufOffset, unix_secs);

    bufOffset += 12;

    /* now calculate time to put in element 160 */
    /* convert unix_secs to milliseconds then subtract sysuptime
       sysuptime = (milliseconds since reboot) */

    transState->sysUpTime = (unix_secs * 1000) - sysuptime;
    transState->sysUpTime = fb_htonll(transState->sysUpTime);

    /* so we don't really care about what is in the different sets,
       at this point, we just want to scan through recordCount
       number of them and read the length from each, and sum it,
       then we get to rewind the file offset so that we can go
       record-by-record back out to the application */

    for (loop = 0; loop < recordCount; loop++) {

        if ((unsigned int)((bufOffset-dataBuf) + 4) < b_len) {
            g_set_error(err,FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Error buffer to small to read NetflowV9 message");
            *m_len = 0;
            return FALSE;
        }

        if (TRUE == collector->bufferedStream) {
            rc = fread(bufOffset, 1, 4, collector->stream.fp);
        } else {
            rc = read(collector->stream.fd, bufOffset, 4);
        }

        if (4 != rc) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Error reading set header in NetflowV9 message"
                        "  expected read of 4 received %d", rc);
            *m_len = 0;
            return FALSE;
        }

        setHeaderPtr = (struct setHeader_st *)bufOffset;
        bufOffset += 4;
        setLength = g_ntohs(setHeaderPtr->setLength);

        if ((unsigned int)((bufOffset-dataBuf) + setLength) < b_len) {
            g_set_error(err,FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Error buffer to small to read NetflowV9 message");
            *m_len = 0;
            return FALSE;
        }

        if (TRUE == collector->bufferedStream) {
            rc = fread(bufOffset, 1, setLength, collector->stream.fp);
        } else {
            rc = read(collector->stream.fd, bufOffset, setLength);
        }

        if (setLength != rc) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Error reading NetflowV9 set payload");
            *m_len = 0;
            return FALSE;
        }
        bufOffset += setLength;
    }


    *m_len = 0;
    return TRUE;
}

/**
 * fbCollectorMessageHeaderV9
 *
 * this converts a NetFlow V9 header into something every so slightly
 * closer to an IPFIX header; it dumps the up time with a big memcpy
 *
 * @param collector pointer to the collector state structure
 * @param buffer pointer to the message buffer
 * @param b_len length of the buffer passed in
 * @param m_len pointer to the length of the resultant buffer
 * @param err pointer to a GLib error structure
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean    fbCollectorMessageHeaderV9 (
    fbCollector_t               *collector,
    uint8_t                     *buffer,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err)
{
    uint16_t                    tempRead16;
    uint64_t                    unix_secs;
    uint64_t                    sysuptime;
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;


    if (b_len < 20) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "Invalid NetFlow V9 Header. Buffer Length too short. "
                    "Length: %u", (unsigned int)b_len);
        return FALSE;
    }

    /* first make sure the message seems like a NetFlow V9 message */
    tempRead16 = g_ntohs(*((uint16_t *)buffer));

    if (0x0009 != tempRead16) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "invalid version number for NetFlow V9, expecting 0x0009,"
                    " received %#06x", tempRead16);
        return FALSE;
    }

    READU32((buffer + 4), sysuptime);
    READU32((buffer + 8), unix_secs);
    READU32((buffer + 16), collector->obdomain);
    collector->time = time(NULL);

    /* convert to milliseconds - subtract sysuptime to get time of reboot */
    transState->sysUpTime = (unix_secs * 1000) - sysuptime;
    transState->sysUpTime = fb_htonll(transState->sysUpTime);

    /* memcpy is no good here because src & dst overlap */
    memmove((buffer + 4), (buffer + 8), (b_len - 8));

    /* return that we shortened the buffer */
    *m_len = b_len - 4;

    return TRUE;
}



/**
 * netflowDataTemplateParse
 *
 * this parses a NetFlow V9 template and stores the results
 * into the template hash for this session.  It only stores
 * the template ID and the length of the resulting record.
 * it will error out on malformed templates and data records
 * which are not common between IPFIX and NetFlow V9
 *
 * @param collector pointer to the collector state record
 * @param dataBuf pointer to the buffer holding the template def
 *                points <b>after</b> the set ID and set length
 * @param recordLength pointer to the set header length field
 * @param msgBuf  pointer to the start of the netflow PDU
 * @param msgLen  pointer to the length of the whole msg
 * @param err GError pointer to store the error if one occurs
 *
 * @return Number of Templates Parsed
 *
 */
static int netflowDataTemplateParse (
    fbCollector_t   *collector,
    uint8_t         *dataBuf,
    uint16_t        *recordLength,
    uint8_t         *msgBuf,
    size_t          *msgLen,
    GError          **err)
{
    uint16_t        templateId = 0;
    uint16_t        fieldCount = 0;
    uint8_t         *bufPtr = dataBuf;
    uint16_t        targetRecSize = 0;
    uint16_t        recLength = g_ntohs(*recordLength);
    uint16_t        lengthParsed = 4; /* to account for set header */
    uint8_t         *fieldCountPtr;
    uintptr_t       bigTemplateId;
    unsigned int    loop;
    uint16_t        temp;
    int             tmplcount = 0;
#ifdef FB_MAP_POST_TO_REVERSE
    uint8_t         addReversePenFix = 0;
#endif
    gboolean        addSysUpTime = FALSE;
    gpointer        hashResult = NULL;
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;
    struct fbCollectorNetflowV9TemplateHash_st *newTemplate = NULL;
    fbCollectorNetflowV9Session_t *currentSession = transState->session;

    if ((recLength < 8) || 0 != (recLength % 4)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "NetFlow template record is either too short or not a "
                    "multiple of 4 octets, (recLength = %u)", recLength);
        return 0;
    }

    while ( lengthParsed < recLength ) {

        /* read the template ID */
        READU16INC(bufPtr, templateId);

        fieldCountPtr = bufPtr;
        /* read the number of data records in the template */
        READU16INC(bufPtr, fieldCount);

        /* lets keep a count of how far we've read into the rec */
        lengthParsed += 4;

        /* subtract 8 from the record length to account for the set
           header,(type & length 16-bits each)-but this can contain
           more than 1! */

        if (fieldCount > ((recLength - lengthParsed) / 4)) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "NetFlow V9 Field Count is greater than remaining "
                        "record length");
            return 0;
        }

        /* iterate through each type entry in the template
           record, make sure the IE model number is within
           what we can handle and then record the length to
           build up the length of each template number */

        for (loop = 0; loop < fieldCount; loop++) {

            READU16(bufPtr, temp);
            if ( 0 == temp ) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                            "NetFlow V9 template data record model type is not"
                            " common with IPFIX IE model: Unknown element:%d",
                            temp);
                return 0;
            } else if ( temp > 346 ) {
                /* convert Netflowv9 Arbitrary Element to IPFIX Generic */
                /* except for 40005 & 33002 (event ids that are in infomodel)*/
                if ( temp == 40005 ) {
                    WRITEU16(bufPtr, FB_CISCO_ASA_EVENT_ID);
                } else if ( temp == 33002 ) {
                    WRITEU16(bufPtr, FB_CISCO_ASA_EVENT_XTRA);
                } else if ( temp == 40001 ) {
                    /* postNATSourceIPv4Address */
                    WRITEU16(bufPtr, 225);
                } else if ( temp == 40002 ) {
                    /* postNATDestinationIPv4Address */
                    WRITEU16(bufPtr, 226);
                } else if ( temp == 40003 ) {
                    /* postNAPTSourceTransportPort */
                    WRITEU16(bufPtr, 227);
                } else if ( temp == 40004 ) {
                    /* postNAPTDestinationTransportPort */
                    WRITEU16(bufPtr, 228);
                } else {
                    WRITEU16(bufPtr, FB_CISCO_GENERIC);
                }
            }

#ifdef FB_MAP_POST_TO_REVERSE
            /*
             * The code inside the #ifdef FB_MAP_POST_TO_REVERSE
             * blocks in this function maps post*DeltaCount values to
             * reverse*DeltaCount values.  The code was written when
             * NetFlow v9 support was initially added to fixbuf.
             */

            /*
              because the IPFIX standard info model is broken, RFC 5102, we
              have to convert certain info model elements from their NetFlow
              v9 values into appropriate IPFIX numbers.
              (Cisco will be none too pleased)
            */

            /* convert V9 out bytes field into IPFIX reverseOctetDeltaCount */
            if (23 == temp) {
                WRITEU16(bufPtr, (IPFIX_ENTERPRISE_BIT | 1));
                addReversePenFix = 1;
            }
            /* convert V9 out pkts field into IPFIX reversePacketDeltaCount */
            if (24 == temp) {
                WRITEU16(bufPtr, (IPFIX_ENTERPRISE_BIT | 2));
                addReversePenFix = 1;
            }
#endif  /* FB_MAP_POST_TO_REVERSE */

            if ((21 == temp) || (22 == temp)) {
                /* need at add element 160 for sysuptime */
                addSysUpTime = TRUE;
            }

            bufPtr += sizeof(uint16_t);
            lengthParsed += sizeof(uint16_t);

            /* record how long each element is */
            READU16INC(bufPtr, temp);

            targetRecSize += temp;
            lengthParsed += sizeof(uint16_t);

#ifdef FB_MAP_POST_TO_REVERSE
            /* if we're supposed to add the reverse PEN for a NetFlow V9 ->
               IPFIX info model change, do it now */
            if (0 != addReversePenFix) {
                addReversePenFix = 0;
                if (FB_MSGLEN_MAX <= (*msgLen + sizeof(uint32_t))) {
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                               "NetFlow V9 unable to convert information model"
                                " elements, no space");
                    return 0;
                }
                /* make space for the extra 32-bit PEN */
                memmove((bufPtr + sizeof(uint32_t)), bufPtr,
                        (*msgLen - (bufPtr - msgBuf)));

                /* write the reverse PEN into the template */
                WRITEU32(bufPtr, IPFIX_REVERSE_PEN);
                bufPtr += sizeof(uint32_t);
                lengthParsed += sizeof(uint32_t);

                /* update the length of this set in the set header */
                WRITEU16(recordLength,
                         (g_ntohs(*recordLength) + sizeof(uint32_t)));

                /* update the length that this record is; we error check this
                   value later */

                recLength += sizeof(uint32_t);

                /* also increase the msglen, to note the change */
                *msgLen += sizeof(uint32_t);
            }
#endif  /* FB_MAP_POST_TO_REVERSE */
        }

        /* add the SysUpTime field (IPFIX element 160) to the template */
        if (addSysUpTime) {
            if (FB_MSGLEN_MAX <= (*msgLen + sizeof(uint32_t))) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                            "NetFlow V9 unable to convert information model "
                            "time elements, no space");
                return 0;
            }
            memmove((bufPtr + sizeof(uint32_t)), bufPtr,
                    (*msgLen - (bufPtr - msgBuf)));
            /* add (IPFIX info element 160) */
            WRITEU16(bufPtr, 160);
            bufPtr += sizeof(uint16_t);
            /* length is 8 */
            WRITEU16(bufPtr, 8);
            bufPtr += sizeof(uint16_t);
            lengthParsed += sizeof(uint32_t);
            /* modify the length of this message */
            WRITEU16(recordLength,(g_ntohs(*recordLength) + sizeof(uint32_t)));
            recLength += sizeof(uint32_t);
            *msgLen += sizeof(uint32_t);
            /* change fieldcount to add this field */
            WRITEU16(fieldCountPtr, fieldCount + 1);
        }

        newTemplate = g_slice_new(fbCollectorNetflowV9TemplateHash_t);
        if (NULL == newTemplate) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "could not allocate NetFlow v9 template storage "
                        "record");
            return 0;
        }

        newTemplate->templateId = templateId;
        newTemplate->templateLength = targetRecSize;
        newTemplate->optionsTemplate = FALSE;
        if (addSysUpTime) {
            newTemplate->addSysUpTime = TRUE;
        } else {
            newTemplate->addSysUpTime = FALSE;
        }
        addSysUpTime = FALSE;

        /* put the template into the hash, check/replace the template
           that is there if this template number already exists */
        if (currentSession->templateHash == NULL) {
            currentSession->templateHash =
                g_hash_table_new_full(fooHash, fooEqual,
                                      NULL, templateHashDestroyHelper);

            if (NULL == currentSession->templateHash) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                            "failure to allocate hash table for NetFlow "
                            "session");
                return FALSE;
            }
        }

        bigTemplateId = (uintptr_t)templateId;
        hashResult = g_hash_table_lookup(currentSession->templateHash,
                                         (gconstpointer)bigTemplateId);
        if (NULL != hashResult) {
            g_hash_table_replace(currentSession->templateHash,
                                 (gpointer)bigTemplateId, newTemplate);
        } else {
            g_hash_table_insert(currentSession->templateHash,
                                (gpointer)bigTemplateId, newTemplate);
        }

        tmplcount++;

#if FB_NETFLOW_DEBUG == 1
        fprintf(stderr, "template inserted into hash: templateId %d,"
                " templateSize: %d, Domain: %04x, SysUpTime %d, "
                "fieldCount: %d \n",
                templateId, targetRecSize, transState->observation_id,
                newTemplate->addSysUpTime, fieldCount);
#endif
        targetRecSize = 0; /* running tmpl size needs reset */

    }

    /* return the amount of templates we added so we can keep a track
       of the total number of records parsed */
    return tmplcount;
}


/**
 * netflowOptionsTemplateParse
 *
 * this parses a NetFlow V9 options template and stores the results
 * into the template hash for this session.  It only stores
 * the template ID and the length of the resulting record.
 * it will error out on malformed templates
 *
 * @param collector pointer to the collector state record
 * @param dataBuf pointer to the buffer holding the template def
 *                points <b>after</b> the set ID and set length
 * @param recordLength a pointer to the length of the flowSet
 * @param err GError pointer to store the error if one occurs
 *
 * @return number of templates parsed
 *
 */
static int netflowOptionsTemplateParse (
    fbCollector_t   *collector,
    uint8_t         *dataBuf,
    uint16_t        *recordLength,
    GError          **err)
{
    uint16_t        templateId = 0;
    uint8_t         *recOffset = dataBuf;
    uint8_t         *optScopeLenPtr;
    uint8_t         *optLenPtr;
    uint16_t        lengthParsed = 4; /* for set header */
    uint16_t        optScopeLen, optLen, type, fieldLen;
    uint16_t        templateLength = 0;
    uintptr_t       bigTemplateId;
    uint16_t        recLength = g_ntohs(*recordLength);
    unsigned int    loop;
    unsigned int    fieldCount;
    gpointer        hashResult = NULL;
    int             tmplcount = 0;
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;
    struct fbCollectorNetflowV9TemplateHash_st *newTemplate = NULL;
    fbCollectorNetflowV9Session_t *currentSession = transState->session;

    while (lengthParsed < recLength) {

        fieldCount = 0;

        if ((recLength - lengthParsed) < 6) {
            /* not enough for an options header - probably extra padding */
            return tmplcount;
        }

        /* read the template ID */
        READU16INC(recOffset,templateId);
        lengthParsed += sizeof(uint16_t);


        /* keep a placeholder for the options Scope Length because we need
           to change it to number of Scope Elements for IPFIX */
        optScopeLenPtr = recOffset;

        /* read the length of option scope bytes */
        READU16INC(recOffset,optScopeLen);
        lengthParsed += sizeof(uint16_t);

        /* keep a placeholder for the options Length because we need to change
           it to number of elements */
        optLenPtr = recOffset;

        /* read the length of the option bytes */
        READU16INC(recOffset,optLen);
        lengthParsed += sizeof(uint16_t);

        if (!optLen && !optScopeLen) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Options Template has No Length. "
                        "(optScopeLen %u, optLen %u).", optScopeLen,
                        optLen);
            return 0;
        }

#if FB_NETFLOW_DEBUG == 1
        fprintf(stderr, "Options Tmpl ID:%d;  ScopeLen %d;  Len %d\n",
                templateId, optScopeLen, optLen); /* debug */
#endif

        /* check the option scope length + option length to check to make sure
           that this record is sane - just make sure there is enough room*/
        if (recLength < (optScopeLen + optLen + lengthParsed)) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                      "Record Length is too short for options fields "
                      "(recLength %u optScopeLen %u optLen %u len parsed %d)",
                       recLength, optScopeLen, optLen, lengthParsed);
            return 0;
        }

        /* Get past Option Scope Elements */

        for (loop = 0; loop < optScopeLen; loop += 4) {
            /* replace option scope type with messageScope info element*/
            WRITEU16(recOffset,263);
            recOffset+=sizeof(uint16_t);

            READU16INC(recOffset,fieldLen);
            fieldCount++;
            lengthParsed += 4;
            templateLength += fieldLen;
        }

        /* IPFIX requires a scope count
           (otherwise - why is it an options tmpl?) */
        /* Cisco doesn't require a scope count - so make sure we have 1 */
        if (!fieldCount) {
            WRITEU16(optLenPtr,1);
        } else {
            /* In the IPFIX Options Template,
               Scope Field Count is actually the 3rd item
               in the Options header */
            WRITEU16(optLenPtr,fieldCount);
        }

        /* Get past Options Elements */
        for (loop = 0; loop < optLen; loop += 4) {

            READU16INC(recOffset,type);
            READU16INC(recOffset,fieldLen);
            lengthParsed += 4;
            fieldCount++;
            templateLength += fieldLen;
        }

        /* In IPFIX, Field Count is the total number of fields (including
           Scope Fields. */

        WRITEU16(optScopeLenPtr,fieldCount);

        newTemplate = g_slice_new(fbCollectorNetflowV9TemplateHash_t);
        if (NULL == newTemplate) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                      "could not allocate NetFlow v9 template storage record");
            return FALSE;
        }

        newTemplate->templateId = templateId;
        newTemplate->templateLength = templateLength;
        newTemplate->optionsTemplate = TRUE;
        newTemplate->addSysUpTime = FALSE;
        /* if there is no TemplateHash this is the first template we
           are receiving in the current domain. Create a Hash for the domain.*/
        if (currentSession->templateHash == NULL) {

            currentSession->templateHash =
                g_hash_table_new_full(fooHash, fooEqual,
                                      NULL, templateHashDestroyHelper);

            if (NULL == currentSession->templateHash) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                            "failure to allocate hash table for NetFlow "
                            "session");
                return FALSE;
            }
        }

        /* put the template into the hash, check/replace the template
           that is there if this template number already exists */

        bigTemplateId = (uintptr_t)templateId;
        hashResult = g_hash_table_lookup(currentSession->templateHash,
                                         (gconstpointer)bigTemplateId);
        if (NULL != hashResult) {
            g_hash_table_replace(currentSession->templateHash,
                                 (gpointer)bigTemplateId, newTemplate);
        } else {
            g_hash_table_insert(currentSession->templateHash,
                                (gpointer)bigTemplateId, newTemplate);
        }

#if FB_NETFLOW_DEBUG == 1
    fprintf(stderr, "Options template inserted into hash: templateId %d,"
                " templateSize: %d, Domain: %04x, SysUpTime %d, "
            "fieldCount: %u \n",
            templateId, templateLength, transState->observation_id,
            newTemplate->addSysUpTime, fieldCount);
#endif

        templateLength = 0; /* reset to 0 after each tmpl */

        tmplcount++;
    }

    /* return the number of templates added to keep track of record count */
    return tmplcount;
}


/**
 * fbCollectorPostProcV9
 *
 * converts a buffer that was read as a netflow V9
 * into a buffer that "conforms" to IPFIX for the
 * rest of fixbuf to process it
 *
 * @param collector pointer to the collector state structure
 * @param dataBuf pointer to the netflow PDU
 * @param bufLen  the size from UDP of the message
 * @param err     glib error set when FALSE is returned with an
 *                informative message
 *
 * @return TRUE on success FALSE on error
 */
static gboolean     fbCollectorPostProcV9(
    fbCollector_t   *collector,
    uint8_t         *dataBuf,
    size_t          *bufLen,
    GError          **err)
{
    uint16_t          recordCount;
    uint16_t          recordCounter = 0;
    int               i;
    uint8_t           *msgOsetPtr = dataBuf;
    uint16_t          padding = 0;
    uint16_t          *lengthCountPtr = NULL;
    uint16_t          *recLengthPtr = NULL;
    uint32_t          netflowSeqNum;
    uint32_t          ipfixRecordCount = 0;
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;
    uint32_t          timeStamp;
    uint32_t          obsDomain;
    uint16_t          version;
    uint32_t          *seqNumPtr;
    uint8_t           tmpls_parsed;
    uint16_t          setId;
    uint16_t          recordLength;
    fbCollectorNetflowV9Session_t *currentSession = NULL;
#if FB_NETFLOW_DEBUG == 1
    uint16_t          flowSet = 0;
    uint16_t          dLoop; /* debug */
    /* debug */
    {
        uint8_t  *d_tPtr8 = (uint8_t *)dataBuf;
        uint16_t *d_tPtr = (uint16_t *)dataBuf;
        uint16_t d_setid = g_ntohs(*d_tPtr);
        d_tPtr++;
        uint16_t d_setLen = g_ntohs(*d_tPtr);
        fprintf(stderr, "\nversion: %d count: %d\n",
                d_setid, d_setLen );
        for (dLoop=0; dLoop < *bufLen; dLoop++) {
            fprintf(stderr, "0x%02x ", (d_tPtr8)[dLoop]);
            if (0 == (dLoop+1)%4 && 0 != dLoop) fprintf(stderr, "\n");
        }
    }

#endif  /* FB_NETFLOW_DEBUG */

    /* the buffer header has been partially converted into
       IPFIX, mostly meaning that the extra uptime has been
       dropped; now the count has to be converted into length,
       and all the different records need to be updated
       appropriately */

    READU16(msgOsetPtr, version);
    WRITEU16(msgOsetPtr, 0x0a);
    msgOsetPtr += sizeof(uint16_t);

    lengthCountPtr = (uint16_t *)msgOsetPtr;
    READU16INC(msgOsetPtr, recordCount);
    READU32INC(msgOsetPtr, timeStamp);

    seqNumPtr = (uint32_t *)msgOsetPtr;
    READU32INC(msgOsetPtr, netflowSeqNum);

#if FB_NETFLOW_DEBUG
    fprintf(stderr, "Sequence number %u\n", netflowSeqNum);
#endif

    /* read the observation domain */
    READU32INC(msgOsetPtr, obsDomain);

    pthread_mutex_lock(&transState->ts_lock);

    transState->observation_id = obsDomain;

    if (transState->sessionptr != collector->udp_head->session) {
        /* lookup template Hash Table per Domain */
        transState->session =
            g_hash_table_lookup(transState->domainHash,
                                collector->udp_head->session);
        if (transState->session == NULL) {
            transState->session = g_slice_new0(fbCollectorNetflowV9Session_t);
            g_hash_table_insert(transState->domainHash,
                                (gpointer)collector->udp_head->session,
                                transState->session);
        }
        transState->sessionptr = collector->udp_head->session;
    }

    currentSession = transState->session;

    /* seq num logic */
    if (currentSession->netflowSeqNum != netflowSeqNum) {
        int seq_diff = netflowSeqNum - currentSession->netflowSeqNum;
#ifndef FB_SUPPRESS_LOGS
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
              "NetFlow V9 sequence number mismatch for domain 0x%04x, "
              "expecting 0x%04x received 0x%04x", obsDomain,
              currentSession->netflowSeqNum, netflowSeqNum);
#endif
        if (currentSession->netflowSeqNum) {
            if (seq_diff > 0) {
                if (seq_diff > NF_MAX_SEQ_DIFF) {
                    /* check for reboot */
                    if (transState->sysUpTime > NF_REBOOT_SECS) {
                        /* probably not a reboot so account for missed */
                        currentSession->netflowMissed += seq_diff;
                    } /* else - reboot? don't add to missed count */
                } else {
                    currentSession->netflowMissed += seq_diff;
                }
                currentSession->netflowSeqNum = netflowSeqNum;
            } else {
                /* out of order or reboot? */
                if ((currentSession->netflowSeqNum - netflowSeqNum) >
                    NF_OUT_OF_ORDER)
                {
                    /* this may be a reboot - it's pretty out of seq. */
                    currentSession->netflowSeqNum = netflowSeqNum;
                } else {
                    /* this is in accepted range for out of sequence */
                    /* account for not missing. don't reset sequence number */
                    /* But subtract one so when we add one below, it evens out */
                    if (currentSession->netflowMissed) {
                        currentSession->netflowMissed -= 1;
                    }
                    currentSession->netflowSeqNum -= 1;
                }
            }
        } else {
            /* this is the first one we received in this session */
            currentSession->netflowSeqNum = netflowSeqNum;
        }
    }

    /* iterate through the flowsets */
    /* a flowset can contain more than 1 record */
    /* recordLength is the TOTAL Length of the flowset - not each record */

    while ( msgOsetPtr < (dataBuf + *bufLen) ) {

        /* read the set ID, and adjust the reserved ones from
           Netflow to IPFIX */
        READU16INC(msgOsetPtr, setId);
        recLengthPtr = (uint16_t*)msgOsetPtr;
        READU16INC(msgOsetPtr, recordLength);

#if FB_NETFLOW_DEBUG == 1
        fprintf(stderr, "FlowSet %u;  SetId %u;  Length %u\n",
                ++flowSet, setId, recordLength); /* debug */
#endif

        if (recordLength < 4) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Invalid Netflow %s Record Length (%u < 4)",
                        ((1 == setId) ? "Options" : "Data"), recordLength);
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }
        /* Check to make sure we won't overrun buffer - Add 4 for set header */
        if (recordLength > ((dataBuf + *bufLen + 4) - msgOsetPtr)) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "Malformed NetFlow Record: %s Length (%d) is "
                        "larger than remaining buffer length (%ld)",
                        (1 == setId) ? "Options" : "Record",
                        recordLength, ((dataBuf + *bufLen + 4) - msgOsetPtr));
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;
        }

        if (0 == setId) {
            /* TEMPLATE RECORD */
            /* Template SET ID = 0 in netflow, 2 in IPFIX */
            WRITEU16(msgOsetPtr-2*sizeof(uint16_t), 2);

            tmpls_parsed = netflowDataTemplateParse(collector, msgOsetPtr,
                                                    recLengthPtr,
                                                    dataBuf, bufLen, err);
            if (!tmpls_parsed) {
                pthread_mutex_unlock(&transState->ts_lock);
                return FALSE;
            }

            recordCounter += tmpls_parsed;

            /* adjust the message pointer to skip over the payload of
               the template record, read the size from the record
               because it may have been updated in the template parse
               call (take into account that the pointer is 4-bytes
               into the record already (type & length)) */
            msgOsetPtr += (g_ntohs(*recLengthPtr) - (2 * sizeof(uint16_t)));

        } else if (1 == setId) {
            /* OPTIONS TEMPLATE */
            /* Template SET ID = 3 for IPFIX */
            WRITEU16(msgOsetPtr-2*sizeof(uint16_t),3);

            tmpls_parsed = netflowOptionsTemplateParse(collector, msgOsetPtr,
                                                       recLengthPtr, err);
            if (!tmpls_parsed) {
                /* Needs to contain at least 1 */
                pthread_mutex_unlock(&transState->ts_lock);
                return FALSE;
            }

            recordCounter += tmpls_parsed;

            /* adjust the message pointer to skip over the payload of
               the template record (take into account that the pointer is
               4-bytes into the record already (type & length)) */
            msgOsetPtr += recordLength - (2 * sizeof(uint16_t));

        } else if (setId < 256) {
            /* data records must be 256 or higher */
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                        "NetFlow record type (%u) is not supported", setId);
            pthread_mutex_unlock(&transState->ts_lock);
            return FALSE;

        } else {
            /* DATA */
            struct fbCollectorNetflowV9TemplateHash_st *derTemplate = NULL;
            uint16_t numberRecordsInSet = 0;
            uintptr_t bigSetId = (uintptr_t) setId;

            if (NULL == currentSession->templateHash) {
                /* return if this is the last FlowSet in the packet */
                if ((dataBuf + *bufLen) <= (msgOsetPtr - 4 + recordLength)) {
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                                "No Templates Present for this session."
                                " %u Flows Lost.", recordCount-recordCounter);
                    currentSession->netflowSeqNum++;
                    pthread_mutex_unlock(&transState->ts_lock);
                    return FALSE;
                }
                /* else, remove these bytes from the packet */
#if FB_NETFLOW_DEBUG == 1
                fprintf(stderr, "remove data set with no template\n");
#endif

                g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                      "No Templates Present for this session.");

                msgOsetPtr -= 4;
                memmove(msgOsetPtr, (msgOsetPtr + recordLength),
                        *bufLen - ((msgOsetPtr + recordLength) - dataBuf));
                *bufLen -= recordLength;

            } else if ((derTemplate =
                        g_hash_table_lookup(currentSession->templateHash,
                                            (gconstpointer)bigSetId)) == NULL)
            {
                if ((dataBuf + *bufLen) <= (msgOsetPtr - 4 + recordLength)) {
                    /* return if this is the last FlowSet in the packet */
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                                "No Template 0x%02x Present for this Session."
                                " %u Flows Lost.", setId,
                                (recordCount-recordCounter));
                    currentSession->netflowSeqNum++;
                    pthread_mutex_unlock(&transState->ts_lock);
                    return FALSE;
                }
                /* else, remove these bytes from the packet */
#if FB_NETFLOW_DEBUG == 1
                fprintf(stderr, "remove data set with no template\n");
#endif

                g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                      "No Template 0x%02x Present for Session", setId);

                msgOsetPtr -= 4;
                memmove((msgOsetPtr), (msgOsetPtr + recordLength),
                        *bufLen - ((msgOsetPtr + recordLength) - dataBuf));
                *bufLen -= recordLength;

            } else {

                numberRecordsInSet = (recordLength - 4) /
                                     derTemplate->templateLength;
                /* 4 for set id and length */
                padding = ((recordLength - 4) % derTemplate->templateLength);

#if FB_NETFLOW_DEBUG == 1
                fprintf(stderr,
                        "number of data records in set %02x is %d (0x%x)\n",
                        setId, numberRecordsInSet, numberRecordsInSet);
#endif
                if (numberRecordsInSet == 0) {
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                                "NetFlow Data Record with 0 Records");
                    pthread_mutex_unlock(&transState->ts_lock);
                    return FALSE;
                }

                recordCounter += numberRecordsInSet;
                ipfixRecordCount += numberRecordsInSet;

                /* now check if need to add sysuptime to the record */
                if (derTemplate->addSysUpTime) {
                    for (i = 0; i < numberRecordsInSet; i++) {
                        msgOsetPtr += derTemplate->templateLength;
                        if (FB_MSGLEN_MAX <= (*bufLen + sizeof(uint64_t))) {
                            g_set_error(err, FB_ERROR_DOMAIN,
                                        FB_ERROR_NETFLOWV9,
                                        "NetFlow V9 unable to convert "
                                        "information model "
                                        "time elements, no space");
                            pthread_mutex_unlock(&transState->ts_lock);
                            return FALSE;
                        }

                        memmove((msgOsetPtr + sizeof(uint64_t)), msgOsetPtr,
                                (*bufLen - (msgOsetPtr - dataBuf)));
                        /* add sysUpTime to flow record */
                        memcpy(msgOsetPtr, &(transState->sysUpTime),
                               sizeof(uint64_t));
                        msgOsetPtr += sizeof(uint64_t);
                        *bufLen += sizeof(uint64_t);
                    }
                    msgOsetPtr += padding;
                    *recLengthPtr = g_htons(recordLength +
                                            (numberRecordsInSet *
                                             sizeof(uint64_t)));
                } else {
                    /* subtract 4 since we already incremented msgOsetPtr 4
                       for id & length */
                    msgOsetPtr += recordLength - 4;
                }
            }
        }
    }

    /* fixup the length value (from record count)*/
    *lengthCountPtr = g_htons(msgOsetPtr - dataBuf);

    if ((msgOsetPtr - dataBuf) < (long)*bufLen) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "NetFlow Record Length Mismatch: (buffer has "
                    "%u, processed %u)", (unsigned int)(*bufLen),
                    ntohs(*lengthCountPtr));
        currentSession->netflowSeqNum++;
        pthread_mutex_unlock(&transState->ts_lock);
        return FALSE;
    }

    /* fixup the sequence number */
    *seqNumPtr = g_htonl(currentSession->ipfixSeqNum);

    /* increment the ipfix record count with the number of relevent
       records we observed*/
    currentSession->ipfixSeqNum += ipfixRecordCount;

    /* increment the sequence number for the netflow side */
    currentSession->netflowSeqNum++;

    if (recordCount != recordCounter) {
#ifndef FB_SUPPRESS_LOGS
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
              "NetFlow V9 Record Count Discrepancy. "
              "Reported: %d. Found: %d.",
              recordCount, recordCounter);
#endif
    }

#if FB_NETFLOW_DEBUG == 1
    /* debug */
    {
        uint8_t  *d_tPtr8 = (uint8_t *)dataBuf;
        uint16_t *d_tPtr = (uint16_t *)dataBuf;
        uint16_t d_setid = g_ntohs(*d_tPtr);
        d_tPtr++;
        uint16_t d_setLen = g_ntohs(*d_tPtr);
        fprintf(stderr, "\nversion: %d count: %d\n",
                d_setid, d_setLen );
        for (dLoop=0; dLoop < *bufLen; dLoop++) {
            fprintf(stderr, "0x%02x ", (d_tPtr8)[dLoop]);
            if (0 == (dLoop+1)%4 && 0 != dLoop) fprintf(stderr, "\n");
        }
    }
#endif

    pthread_mutex_unlock(&transState->ts_lock);

    return TRUE;
}





/**
 * fbCollectorTransCloseV9
 *
 * frees the state included as part of the collector when the
 * Netflow V9 translator is enabled
 *
 * @param collector, pointer to the collector state structure
 *
 */
static void         fbCollectorTransCloseV9(
    fbCollector_t   *collector)
{
    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;

    /* this should destroy each entry in the template */
    g_hash_table_destroy(transState->domainHash);
    transState->domainHash = NULL;

    pthread_mutex_destroy(&transState->ts_lock);

    if (NULL != collector->translatorState) {
        g_free(collector->translatorState);
    }

    collector->translatorState = NULL;
    return;
}

/**
 * fbCollectorTimeoutNetflowSession
 *
 * this timeouts sessions when we haven't seen messages for > 30 mins.
 *
 * @param collector pointer to collector state.
 * @param session pointer to session to timeout.
 *
 */
static void fbCollectorTimeOutSessionV9(
    fbCollector_t *collector,
    fbSession_t   *session)
{

    struct fbCollectorNetflowV9State_st     *transState =
        (struct fbCollectorNetflowV9State_st *)collector->translatorState;
    fbCollectorNetflowV9Session_t           *nfsession = NULL;

    if (transState == NULL) {
        return;
    }

    pthread_mutex_lock(&transState->ts_lock);

    nfsession = g_hash_table_lookup(transState->domainHash, session);
    if (nfsession == NULL) {
        /* don't need to free! */
        pthread_mutex_unlock(&transState->ts_lock);
        return;
    }

    /* remove this session, free the state */
    g_hash_table_remove(transState->domainHash, session);

    if (session == transState->sessionptr) {
        transState->sessionptr = NULL;
        transState->session = NULL;
    }

    pthread_mutex_unlock(&transState->ts_lock);

}



/**
 *fbCollectorSetNetflowV9Translator
 *
 * this sets the collector input translator
 * to convert NetFlowV9 into IPFIX for the
 * given collector
 *
 * @param collector pointer to the collector state
 *        to perform Netflow V9 conversion on
 * @param err GError structure that holds the error
 *        message if an error occurs
 *
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetNetflowV9Translator(
    fbCollector_t               *collector,
    GError                      **err)
{
    GHashTable *hashTable = NULL;
    struct fbCollectorNetflowV9State_st *nflowState =
        g_malloc(sizeof(struct fbCollectorNetflowV9State_st));

    if (NULL == nflowState) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TRANSMISC,
                    "failure to allocate Netflow V9 translator state");
        return FALSE;
    }


    hashTable = g_hash_table_new_full(g_direct_hash,
                                      g_direct_equal, NULL,
                                      domainHashDestroyHelper);

    if (NULL == hashTable) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NETFLOWV9,
                    "failure to allocate sequence no. hash table for "
                    "Netflow Session");
        return FALSE;
    }

#if FB_NETFLOW_DEBUG == 1
    fprintf(stderr, "Hash table address is %p for collector %p\n",
        hashTable, collector); /* debug */
#endif

    nflowState->domainHash = hashTable;
    nflowState->observation_id = 0;
    nflowState->sessionptr = NULL;
    pthread_mutex_init(&nflowState->ts_lock, NULL);

    return fbCollectorSetTranslator(collector, fbCollectorPostProcV9,
        fbCollectorDecodeV9MsgVL, fbCollectorMessageHeaderV9,
        fbCollectorTransCloseV9, fbCollectorTimeOutSessionV9, nflowState, err);

}


/**
 * fbCollectorGetNetflowMissed
 *
 * This returns the number of potential missed export packets
 * If peer is set, we search for a match and return the number of missed
 * packets for that ip/obdomain pair.  If peer is not set then we just
 * return the most recent UDP connection stats.  If peer is set and we don't
 * have a match, we just return 0.
 * we can't return the number of missed flow records since Netflow v9
 * increases sequence numbers by the number of export packets it has sent,
 * NOT the number of flow records (like IPFIX and netflow v5 does).
 *
 * @param collector
 * @param peer address of exporter to lookup
 * @param peerlen sizeof(peer)
 * @param obdomain observation domain of peer exporter
 * @return number of missed packets
 *
 */

uint32_t fbCollectorGetNetflowMissed(
    fbCollector_t         *collector,
    struct sockaddr       *peer,
    size_t                 peerlen,
    uint32_t               obdomain)
{
    struct fbCollectorNetflowV9State_st     *ts = NULL;
    fbUDPConnSpec_t                         *udp = NULL;
    fbSession_t                             *session = NULL;
    fbCollectorNetflowV9Session_t           *ts_session = NULL;
    uint32_t                                missed = 0;

    if (!collector) {
        return 0;
    }

    if (peer) {
        udp = collector->udp_head;
        while (udp) {
            /* loop through and find the match */
            if (udp->obdomain == obdomain) {
                if (!memcmp(&(udp->peer), peer, (peerlen > udp->peerlen) ?
                            udp->peerlen : peerlen))
                {
                    /* we have a match - set session */
                    session = udp->session;
                    break;
                }
            }
            udp = udp->next;
        }
    } else {
        /* set to most recent */
        session = collector->udp_head->session;
    }

    if (!session) {
        return 0;
    }

    ts = (struct fbCollectorNetflowV9State_st *)collector->translatorState;

    if (ts == NULL) {
        g_warning("NFv9 Translator not set on collector.");
        return 0;
    }

    pthread_mutex_lock(&ts->ts_lock);

    if (ts->sessionptr != session) {
        /* lookup template Hash Table per Domain */
        ts_session = g_hash_table_lookup(ts->domainHash, session);
    } else {
        ts_session = ts->session;
    }

    if (ts_session) {
        missed = ts_session->netflowMissed;
    }

    pthread_mutex_unlock(&ts->ts_lock);

    return missed;
}
