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
#ifndef _V5PDU_H
#define _V5PDU_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_V5PDU_H, "$SiLK: v5pdu.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");


/*
**  v5pdu.h
**
**  Structures defining Version 5 PDU NetFlow Records
**
*/

/*
** v5Header is 24 bytes, v5Record is 48 bytes.  Using the Ethernet MTU
** of 1500, we get get: ((1500 - 24)/48) => 30 v5Records per MTU, and
** the overall length of the PDU will be: (24 + (30*48)) => 1464 bytes
*/
#define V5PDU_LEN 1464
#define V5PDU_MAX_RECS 30

#define V5PDU_MAX_RECS_STR  "30"


typedef struct v5Header_st {
  uint16_t version;
  uint16_t count;
  uint32_t SysUptime;
  uint32_t unix_secs;
  uint32_t unix_nsecs;
  uint32_t flow_sequence;
  uint8_t  engine_type;
  uint8_t  engine_id;
  uint16_t sampling_interval;
} v5Header;

typedef struct v5Record_st {
  uint32_t  srcaddr;   /*  0- 3 */
  uint32_t  dstaddr;   /*  4- 7 */
  uint32_t  nexthop;   /*  8-11 */
  uint16_t  input;     /* 12-13 */
  uint16_t  output;    /* 14-15 */
  uint32_t  dPkts;     /* 16-19 */
  uint32_t  dOctets;   /* 20-23 */
  uint32_t  First;     /* 24-27 */
  uint32_t  Last;      /* 28-31 */
  uint16_t  srcport;   /* 32-33 */
  uint16_t  dstport;   /* 34-35 */
  uint8_t   pad1;      /* 36    */
  uint8_t   tcp_flags; /* 37    */
  uint8_t   prot;      /* 38    */
  uint8_t   tos;       /* 39    */
  uint16_t  src_as;    /* 40-41 */
  uint16_t  dst_as;    /* 42-43 */
  uint8_t   src_mask;  /* 44    */
  uint8_t   dst_mask;  /* 45    */
  uint16_t  pad2;      /* 46-47 */
} v5Record;

typedef struct v5PDU_st {
  v5Header hdr;
  v5Record data[V5PDU_MAX_RECS];
} v5PDU;

#ifdef __cplusplus
}
#endif
#endif /* _V5PDU_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
