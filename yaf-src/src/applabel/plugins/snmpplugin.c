/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  snmpplugin.c
 *
 *  This recognizes SNMP packets
 *
 *  See RFC 1157 for SNMPv1
 *  See RFCs 1901, 1905, 1906 for SNMPv2c
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Ecoff
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

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <payloadScanner.h>


#define SNMP_PORT_NUMBER  161

YC_SCANNER_PROTOTYPE(snmpplugin_LTX_ycSnmpScanScan);

/* snmp data types */
#define SNMP_INT 0x02
#define SNMP_OCT 0x04
#define SNMP_NULL 0x05
#define SNMP_OBID 0x06

/* complex data types */
#define SNMP_SEQ 0x30
#define SNMP_GETREQ 0xa0
#define SNMP_GETRES 0xa2
#define SNMP_SETREQ 0xa3


/* Local Prototypes */

static uint8_t
snmpGetType(
    uint8_t   identifier);

/**
 * snmpplugin_LTX_ycSnmpScanScan
 *
 * the scanner for recognizing SNMP packets
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return SNMP_PORT_NUMBER for SNMP packets,
 *         otherwise 0
 */
uint16_t
snmpplugin_LTX_ycSnmpScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t offset = 0;
    uint8_t  pdu_type = 0;
    uint8_t  pdu_length = 0;
    uint8_t  version = 0;
    uint8_t  msg_len = 0;

    if (payloadSize < 5) {
        return 0;
    }

    if (!(pdu_type = snmpGetType(payload[0]))) {
        return 0;
    }

    offset++;
    /* Get length */
    pdu_length = *(payload + offset);

    if (pdu_length == 0) {
        return 0;
    }

    offset++;
    /* SNMP version type */
    if (*(payload + offset) != SNMP_INT) {
        return 0;
    }

    offset++;
    /* Should be length of 1 */
    if (*(payload + offset) != 1) {
        return 0;
    }

    offset++;
    /* Now at version number */
    version = *(payload + offset);
    if (version == 0 || version == 1) {
        /* v1 or v2c*/
        offset++;

        if (offset > payloadSize) {
            return 0;
        }
        if (*(payload + offset) != SNMP_OCT) {
            /* no community string */
            return 0;
        }
        offset++;

        if (offset > payloadSize) {
            return 0;
        }
        /* length of community string  & go past community string */
        offset += *(payload + offset) + 1;
        if (offset > payloadSize) {
            return 0;
        }

        if (!(pdu_type = snmpGetType(*(payload + offset)))) {
            return 0;
        }

        if ((pdu_type != SNMP_GETREQ) && (pdu_type != SNMP_GETRES) &&
            (pdu_type != SNMP_SETREQ))
        {
            return 0;
        }

        offset++;
        if (offset > payloadSize) {
            return 0;
        }
        pdu_length = *(payload + offset);

        if (pdu_length == 0) {
            return 0;
        }
        offset++;
        if (offset > payloadSize) {
            return 0;
        }

        /* check request ID */
        if (*(payload + offset) != SNMP_INT) {
            return 0;
        }

        offset++;
        if (offset > payloadSize) {
            return 0;
        }

        /* actual request id is here  - go past it*/
        if (*(payload + offset) == 4) {
            offset += 5;
        } else if (*(payload + offset) == 2) {
            offset += 3;
        } else if (*(payload + offset) == 1) {
            offset += 2;
        } else {
            return 0;
        }

        if (((size_t)offset + 8) > payloadSize) {
            return 0;
        }

        /* now go to Error field */
        if (*(payload + offset) != SNMP_INT) {
            return 0;
        }
        offset++;
        if (*(payload + offset) != 1) {
            return 0;
        }
        offset++;
        /* Check Error Status code */
        if (*(payload + offset) > 0x05) {
            return 0;
        }

        offset++;
        /* Check Error Index */
        if (*(payload + offset) != SNMP_INT) {
            return 0;
        }

        offset++;
        if (*(payload + offset) != 1) {
            return 0;
        }

        offset += 2;
        /* Error Index is here */

        /* Next should be varbind list of type Sequence */
        if (*(payload + offset) != SNMP_SEQ) {
            return 0;
        }
        offset++;

        /* Length of varbind list is next */
        if (*(payload + offset) == 0) {
            return 0;
        }

        /* close enough */

        return SNMP_PORT_NUMBER;
    } else if (version == 3) {
        /* version 3 fun - not there yet */
        uint8_t msg_flags = 0;

        if ((size_t)offset + 5 > payloadSize) {
            return 0;
        }

        offset++;
        /* check for msg_max_size sequence PDU */
        if (*(payload + offset) != SNMP_SEQ) {
            return 0;
        }

        offset += 2;
        /* should be an integer next */
        if (*(payload + offset) != SNMP_INT) {
            return 0;
        }

        offset++;
        /* should be of length 4 */
        msg_len = *(payload + offset);
        if (msg_len == 0) {
            return 0;
        }

        offset++;
        /* msg id is here */
        offset += msg_len;
        if (offset > payloadSize) {
            return 0;
        }

        if ((size_t)offset + 4 > payloadSize) {
            return 0;
        }
        if (*(payload + offset) != SNMP_INT) {
            return 0;
        }

        offset++;

        /* Msg Len can be more than 2 */
        msg_len = *(payload + offset);
        if (msg_len == 0) {
            return 0;
        }
        offset += 1 + msg_len;

        if ((size_t)offset + 3 > payloadSize) {
            return 0;
        }
        /* 1 for type - 1 for length */
        if (*(offset + payload) != SNMP_OCT) {
            return 0;
        }

        offset++;

        msg_len = *(offset + payload);
        if (msg_len == 0) {
            return 0;
        }

        offset++;
        if (msg_len == 1) {
            msg_flags = *(payload + offset);
            offset++;

            if (msg_flags > 7) {
                return 0;
            }
        } else {
            offset += msg_len;
        }

        if ((size_t)offset + 3 > payloadSize) {
            return 0;
        }

        /* message security model */
        if (*(offset + payload) == SNMP_INT) {
            offset++;

            msg_len = *(payload + offset);

            offset += msg_len + 1;
        } else {
            return 0;
        }

        if ((size_t)offset + 3 > payloadSize) {
            return 0;
        }

        if (*(payload + offset) != SNMP_OCT) {
            return 0;
        }
        offset++;

        pdu_length = *(payload + offset);
        if (pdu_length == 0) {
            return 0;
        }

        return SNMP_PORT_NUMBER;
    } else {
        return 0;
    }
}


static uint8_t
snmpGetType(
    uint8_t   identifier)
{
    switch (identifier) {
      case SNMP_INT:
        return SNMP_INT;
      case SNMP_OCT:
        return SNMP_OCT;
      case SNMP_NULL:
        return SNMP_NULL;
      case SNMP_OBID:
        return SNMP_OBID;
      case SNMP_SEQ:
        return SNMP_SEQ;
      case SNMP_GETREQ:
        return SNMP_GETREQ;
      case SNMP_GETRES:
        return SNMP_GETRES;
      case SNMP_SETREQ:
        return SNMP_GETREQ;
      default:
        return 0;
    }
}
