/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mysqlplugin.c
 *
 *  this is a protocol classifier for the MySQL protocol (MySQL)
 *
 *  MySQL
 *
 *  http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol
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
#include <arpa/inet.h>
#include <payloadScanner.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define MYSQL_PORT_NUMBER 3306

YC_SCANNER_PROTOTYPE(mysqlplugin_LTX_ycMYSQLScanScan);


/**
 * mysqlplugin_LTX_ycMYSQLScanScan
 *
 * returns MYSQL_PORT_NUMBER if the passed in payload matches
 * a MySQL Server Greeting packet
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * return 0 if no match
 */
uint16_t
mysqlplugin_LTX_ycMYSQLScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint32_t offset = 0;
    uint32_t fillerOffset = 0;
    int      i = 0;
    uint8_t  packetNumber;
    uint32_t packetLength;
    uint8_t  temp;

    if (0 == payloadSize) {
        return 0;
    }

    packetLength = ((*(uint32_t *)payload)) & 0x00FFFFFF;

    offset += 3;
    if (packetLength < 49 || offset > payloadSize ||
        packetLength > payloadSize)
    {
        return 0;
    }

    packetNumber = *(payload + offset);

    offset++;

    if (packetNumber != 0 && packetNumber != 1) {
        return 0;
    }

    if (offset > payloadSize) {
        return 0;
    }

    if (packetNumber == 0) {
        /* Server Greeting */
        /*protoVersion = *(payload + offset);*/
        offset++;

        /* Version would be here - str until null*/

        /* Beginning of 0x00 fillers */
        fillerOffset = packetLength - 26 + 4;

        if (fillerOffset + 13 > payloadSize) {
            return 0;
        }

        for (i = 0; i < 13; i++) {
            temp = *(payload + fillerOffset + i);
            if (temp != 0) {
                return 0;
            }
        }
    } else {
        /* Client Authentication */
        /* Client Capabilities && Extended Capabilities*/
        offset += 4;

        /* Max Packet Size + 1 for Charset*/
        offset += 5;

        if ((size_t)offset + 23 > payloadSize) {
            return 0;
        }

        for (i = 0; i < 23; i++) {
            temp = *(payload + offset);
            if (temp != 0) {
                return 0;
            }
            offset++;
        }

#if YAF_ENABLE_HOOKS
        /* Here's the Username */
        i = 0;
        while ((offset < packetLength) &&
               ((size_t)offset + i < payloadSize))
        {
            if (*(payload + offset + i)) {
                i++;
            } else {
                break;
            }
        }

        yfHookScanPayload(flow, payload, i, NULL, offset, 223,
                          MYSQL_PORT_NUMBER);

        /* Rest of pkt is password. Add 4 for pkt len & pkt num*/
        offset = packetLength + 4;

        if (packetLength > payloadSize) {
            return MYSQL_PORT_NUMBER;
        }

        /* Check for more packets */
        while (offset < payloadSize) {
            packetLength =
                (*(uint32_t *)(payload + offset)) & 0x00FFFFFF;

            if (packetLength > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            offset += 4; /* add one for packet number */

            if (offset > payloadSize || packetLength == 0) {
                return MYSQL_PORT_NUMBER;
            }

            packetNumber = *(payload + offset);

            offset++;

            /* The text of the command follows */
            i = (packetLength - 1);

            if ((size_t)offset + i > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            yfHookScanPayload(flow, payload, i, NULL, offset,
                              packetNumber,
                              MYSQL_PORT_NUMBER);

            offset += i;
        }

#endif /* if YAF_ENABLE_HOOKS */
    }

    return MYSQL_PORT_NUMBER;
}
