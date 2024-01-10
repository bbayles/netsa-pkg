/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  piplugin.c
 *
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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


#define PIOFFSET 256

YC_SCANNER_PROTOTYPE(piplugin_LTX_ycPIScanScan);

/**
 * piplugin_LTX_ycPIScanScan
 *
 * the scanner for recognizing Poison Ivy.
 * Analysis: http://badishi.com/initial-analysis-of-poison-ivy/
 *
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
 * @return 1 for PI Packets
 *         otherwise 0
 */
uint16_t
piplugin_LTX_ycPIScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    unsigned int loop = 0;
    int          size = 0;
    uint32_t     length;

    if (flow->val.payload == NULL || flow->rval.payload == NULL) {
        return 0;
    }

    if (flow->key.proto != YF_PROTO_TCP) {
        return 0;
    }

    /* if first non zero payload boundary is not PIOFFSET, return */
    while (loop < flow->val.pkt && loop < YAF_MAX_PKT_BOUNDARY) {
        if (flow->val.paybounds[loop] == 0) {
            loop++;
            continue;
        } else {
            if (flow->val.paybounds[loop] != PIOFFSET) {
                if (flow->val.paybounds[loop] == 255) {
                    /* check for TCP keep alive */
                    if ((loop + 1) < flow->val.pkt) {
                        if (flow->val.paybounds[loop + 1] == 255) {
                            size = 1;
                            break;
                        }
                    }
                }
                return 0;
            } else {
                size = 1;
                break;
            }
        }
    }

    if (!size) {
        return 0;
    }

    loop = 0;
    /* find first non zero payload boundary and see if it is PIOFFSET */
    while (loop < flow->rval.pkt && loop < YAF_MAX_PKT_BOUNDARY) {
        if (flow->rval.paybounds[loop] == 0) {
            loop++;
            continue;
        } else {
            if (flow->rval.paybounds[loop] != PIOFFSET) {
                if (flow->rval.paybounds[loop] == 255) {
                    /* check for TCP keep alive */
                    if ((loop + 1) < flow->rval.pkt) {
                        if (flow->rval.paybounds[loop + 1] == 255) {
                            break;
                        }
                    }
                }
                return 0;
            } else {
                break;
            }
        }
    }

    /* After the challenge/response, the server sends 4 bytes
     * that signify the length of the next encrypted data which
     * may be sent over the next few packets - make sure
     * it's at least feasible. */
    if (flow->rval.paylen > 260) {
        length = *(uint32_t *)(flow->rval.payload + 256);
        if (flow->rval.oct >= (length + 256)) {
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}
