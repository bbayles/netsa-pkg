/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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
**  rwrec.c
**
**    Functions to get/set values on the rwRec structure.
**
**    Usually these are not used, since we prefer to use macros to get
**    and set values on rwRec; however some functionality is complex
**    enough to require a function, particular those dealing with IPv6
**    addresses.
**
**    In addition, these functions are used when RWREC_OPAQUE is 1.
**
*/

#define RWREC_DEFINE_BODY 1
#include <silk/silk.h>

RCSIDENT("$SiLK: rwrec.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/utils.h>


/* FUNCTION DEFINITIONS */


#if SK_ENABLE_IPV6
/*
 *    Helper function to compare an IP on an rwRec with an skipaddr_t.
 */
static int
recCompareIPAddr(
    const rwRec        *r,
    const skIPUnion_t  *ip,
    const skipaddr_t   *cmp_addr)
{
    skIPUnion_t tmp;

    if (_recIsIPv6(r)) {
        if (cmp_addr->ip_is_v6) {
            /* both are IPv6 */
            return memcmp(ip->ipu_ipv6, cmp_addr->ip_ip.ipu_ipv6, 16);
        }
        /* must convert cmp_addr to V6 */
        skIPUnion4to6(&(cmp_addr->ip_ip), &tmp);
        return memcmp(ip->ipu_ipv6, tmp.ipu_ipv6, 16);
    }
    if (cmp_addr->ip_is_v6) {
        /* must convert record IP to V6 */
        skIPUnion4to6(ip, &tmp);
        return memcmp(tmp.ipu_ipv6, cmp_addr->ip_ip.ipu_ipv6, 16);
    }
    /* both addresses are IPv4 */
    if (ip->ipu_ipv4 < cmp_addr->ip_ip.ipu_ipv4) {
        return -1;
    }
    if (ip->ipu_ipv4 > cmp_addr->ip_ip.ipu_ipv4) {
        return 1;
    }
    return 0;
}


/*
 *    Helper function to mask an IP on an rwRec with an skipaddr_t.
 */
static void
recApplyMaskIPAddr(
    rwRec              *r,
    skIPUnion_t        *ip,
    const skipaddr_t   *mask_addr)
{
    skIPUnion_t tmp;

    if (_recIsIPv6(r)) {
        if (mask_addr->ip_is_v6) {
            /* both are IPv6 */
            skIPUnionApplyMaskV6(ip, mask_addr->ip_ip.ipu_ipv6);
            return;
        }
        /* must convert mask_addr to V6 */
        skIPUnion4to6(&(mask_addr->ip_ip), &tmp);
        skIPUnionApplyMaskV6(ip, tmp.ipu_ipv6);
        return;
    }
    if (mask_addr->ip_is_v6) {
        /* Record is IPv4 and 'mask_addr' is IPv6. if bytes 10 and 11
         * of 'mask_addr' are 0xFFFF, then an IPv4 address will
         * result; otherwise, we must convert the record to IPv6 and
         * we'll get something strange */
        if (memcmp(&mask_addr->ip_ip.ipu_ipv6[10], &sk_ipv6_v4inv6[10], 2)
            == 0)
        {
            uint32_t mask_v4;
            memcpy(&mask_v4, &mask_addr->ip_ip.ipu_ipv6[12], 4);
            skIPUnionApplyMaskV4(ip, ntohl(mask_v4));
            return;
        }
        _recConvertToIPv6(r);
        skIPUnionApplyMaskV6(ip, mask_addr->ip_ip.ipu_ipv6);
        return;
    }
    /* both addresses are IPv4 */
    skIPUnionApplyMaskV4(ip, mask_addr->ip_ip.ipu_ipv4);
}
#endif  /* SK_ENABLE_IPV6 */


uint8_t
rwrec_GetIcmpType(
    const rwRec        *r)
{
    return _recGetIcmpType(r);
}


void
rwrec_SetIcmpType(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetIcmpType(r, in_v);
}


void
rwrec_MemGetIcmpType(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetIcmpType(r, (uint8_t*)out_vp);
}


uint8_t
rwrec_GetIcmpCode(
    const rwRec        *r)
{
    return _recGetIcmpCode(r);
}


void
rwrec_SetIcmpCode(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetIcmpCode(r, in_v);
}


void
rwrec_MemGetIcmpCode(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetIcmpCode(r, (uint8_t*)out_vp);
}


uint16_t
rwrec_GetIcmpTypeAndCode(
    const rwRec        *r)
{
    return _recGetIcmpTypeAndCode(r);
}


void
rwrec_SetIcmpTypeAndCode(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetIcmpTypeAndCode(r, in_v);
}


void
rwrec_MemGetIcmpTypeAndCode(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetIcmpTypeAndCode(r, out_vp);
}


void
rwrec_MemSetIcmpTypeAndCode(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetIcmpTypeAndCode(r, in_vp);
}


int
rwrec_MemCmpIcmpTypeAndCode(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpIcmpTypeAndCode(r, vp);
}


uint32_t
rwrec_GetSIPv4(
    const rwRec        *r)
{
    return _recGetSIPv4(r);
}


void
rwrec_SetSIPv4(
    rwRec              *r,
    uint32_t            in_v)
{
    _recSetSIPv4(r, in_v);
}


void
rwrec_MemGetSIPv4(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetSIPv4(r, out_vp);
}


void
rwrec_MemSetSIPv4(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetSIPv4(r, in_vp);
}


int
rwrec_MemCmpSIPv4(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpSIPv4(r, vp);
}


uint32_t
rwrec_GetMaskSIPv4(
    const rwRec        *r,
    uint32_t            mask)
{
    return _recGetMaskSIPv4(r, mask);
}


void
rwrec_ApplyMaskSIPv4(
    rwRec              *r,
    uint32_t            mask)
{
    _recApplyMaskSIPv4(r, mask);
}


uint32_t
rwrec_GetDIPv4(
    const rwRec        *r)
{
    return _recGetDIPv4(r);
}


void
rwrec_SetDIPv4(
    rwRec              *r,
    uint32_t            in_v)
{
    _recSetDIPv4(r, in_v);
}


void
rwrec_MemGetDIPv4(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetDIPv4(r, out_vp);
}


void
rwrec_MemSetDIPv4(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetDIPv4(r, in_vp);
}


int
rwrec_MemCmpDIPv4(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpDIPv4(r, vp);
}


uint32_t
rwrec_GetMaskDIPv4(
    const rwRec        *r,
    uint32_t            mask)
{
    return _recGetMaskDIPv4(r, mask);
}


void
rwrec_ApplyMaskDIPv4(
    rwRec              *r,
    uint32_t            mask)
{
    _recApplyMaskDIPv4(r, mask);
}


uint16_t
rwrec_GetSPort(
    const rwRec        *r)
{
    return _recGetSPort(r);
}


void
rwrec_SetSPort(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetSPort(r, in_v);
}


void
rwrec_MemGetSPort(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetSPort(r, out_vp);
}


void
rwrec_MemSetSPort(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetSPort(r, in_vp);
}


int
rwrec_MemCmpSPort(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpSPort(r, vp);
}


uint16_t
rwrec_GetDPort(
    const rwRec        *r)
{
    return _recGetDPort(r);
}


void
rwrec_SetDPort(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetDPort(r, in_v);
}


void
rwrec_MemGetDPort(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetDPort(r, out_vp);
}


void
rwrec_MemSetDPort(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetDPort(r, in_vp);
}


int
rwrec_MemCmpDPort(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpDPort(r, vp);
}


uint8_t
rwrec_GetProto(
    const rwRec        *r)
{
    return _recGetProto(r);
}


void
rwrec_SetProto(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetProto(r, in_v);
}


void
rwrec_MemGetProto(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetProto(r, out_vp);
}


void
rwrec_MemSetProto(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetProto(r, in_vp);
}


int
rwrec_MemCmpProto(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpProto(r, vp);
}


uint32_t
rwrec_GetPkts(
    const rwRec        *r)
{
    return _recGetPkts(r);
}


void
rwrec_SetPkts(
    rwRec              *r,
    uint32_t            in_v)
{
    _recSetPkts(r, in_v);
}


void
rwrec_MemGetPkts(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetPkts(r, out_vp);
}


void
rwrec_MemSetPkts(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetPkts(r, in_vp);
}


int
rwrec_MemCmpPkts(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpPkts(r, vp);
}


uint32_t
rwrec_GetBytes(
    const rwRec        *r)
{
    return _recGetBytes(r);
}


void
rwrec_SetBytes(
    rwRec              *r,
    uint32_t            in_v)
{
    _recSetBytes(r, in_v);
}


void
rwrec_MemGetBytes(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetBytes(r, out_vp);
}


void
rwrec_MemSetBytes(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetBytes(r, in_vp);
}


int
rwrec_MemCmpBytes(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpBytes(r, vp);
}


uint8_t
rwrec_GetFlags(
    const rwRec        *r)
{
    return _recGetFlags(r);
}


void
rwrec_SetFlags(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetFlags(r, in_v);
}


void
rwrec_MemGetFlags(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetFlags(r, out_vp);
}


void
rwrec_MemSetFlags(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetFlags(r, in_vp);
}


int
rwrec_MemCmpFlags(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpFlags(r, vp);
}


sktime_t
rwrec_GetStartTime(
    const rwRec        *r)
{
    return _recGetStartTime(r);
}


void
rwrec_SetStartTime(
    rwRec              *r,
    sktime_t            in_v)
{
    _recSetStartTime(r, in_v);
}


void
rwrec_MemGetStartTime(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetStartTime(r, out_vp);
}


void
rwrec_MemSetStartTime(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetStartTime(r, in_vp);
}


int
rwrec_MemCmpStartTime(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpStartTime(r, vp);
}


uint32_t
rwrec_GetStartSeconds(
    const rwRec        *r)
{
    return _recGetStartSeconds(r);
}


void
rwrec_MemGetStartSeconds(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetStartSeconds(r, out_vp);
}


uint32_t
rwrec_GetElapsed(
    const rwRec        *r)
{
    return _recGetElapsed(r);
}


void
rwrec_SetElapsed(
    rwRec              *r,
    sktime_t            in_v)
{
    _recSetElapsed(r, in_v);
}


void
rwrec_MemGetElapsed(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetElapsed(r, out_vp);
}


void
rwrec_MemSetElapsed(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetElapsed(r, in_vp);
}


int
rwrec_MemCmpElapsed(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpElapsed(r, vp);
}


uint32_t
rwrec_GetElapsedSeconds(
    const rwRec        *r)
{
    return _recGetElapsedSeconds(r);
}


void
rwrec_MemGetElapsedSeconds(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetElapsedSeconds(r, out_vp);
}


sktime_t
rwrec_GetEndTime(
    const rwRec        *r)
{
    return _recGetEndTime(r);
}


void
rwrec_MemGetEndTime(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetEndTime(r, out_vp);
}


uint32_t
rwrec_GetEndSeconds(
    const rwRec        *r)
{
    return _recGetEndSeconds(r);
}


void
rwrec_MemGetEndSeconds(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetEndSeconds(r, out_vp);
}


sk_sensor_id_t
rwrec_GetSensor(
    const rwRec        *r)
{
    return _recGetSensor(r);
}


void
rwrec_SetSensor(
    rwRec              *r,
    sk_sensor_id_t      in_v)
{
    _recSetSensor(r, in_v);
}


void
rwrec_MemGetSensor(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetSensor(r, out_vp);
}


void
rwrec_MemSetSensor(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetSensor(r, in_vp);
}


int
rwrec_MemCmpSensor(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpSensor(r, vp);
}


uint32_t
rwrec_GetNhIPv4(
    const rwRec        *r)
{
    return _recGetNhIPv4(r);
}


void
rwrec_SetNhIPv4(
    rwRec              *r,
    uint32_t            in_v)
{
    _recSetNhIPv4(r, in_v);
}


void
rwrec_MemGetNhIPv4(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetNhIPv4(r, out_vp);
}


void
rwrec_MemSetNhIPv4(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetNhIPv4(r, in_vp);
}


int
rwrec_MemCmpNhIPv4(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpNhIPv4(r, vp);
}


uint32_t
rwrec_GetMaskNhIPv4(
    const rwRec        *r,
    uint32_t            mask)
{
    return _recGetMaskNhIPv4(r, mask);
}


void
rwrec_ApplyMaskNhIPv4(
    rwRec              *r,
    uint32_t            mask)
{
    _recApplyMaskNhIPv4(r, mask);
}


uint16_t
rwrec_GetInput(
    const rwRec        *r)
{
    return _recGetInput(r);
}


void
rwrec_SetInput(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetInput(r, in_v);
}


void
rwrec_MemGetInput(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetInput(r, out_vp);
}


void
rwrec_MemSetInput(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetInput(r, in_vp);
}


int
rwrec_MemCmpInput(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpInput(r, vp);
}


uint16_t
rwrec_GetOutput(
    const rwRec        *r)
{
    return _recGetOutput(r);
}


void
rwrec_SetOutput(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetOutput(r, in_v);
}


void
rwrec_MemGetOutput(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetOutput(r, out_vp);
}


void
rwrec_MemSetOutput(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetOutput(r, in_vp);
}


int
rwrec_MemCmpOutput(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpOutput(r, vp);
}


uint8_t
rwrec_GetInitFlags(
    const rwRec        *r)
{
    return _recGetInitFlags(r);
}


void
rwrec_SetInitFlags(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetInitFlags(r, in_v);
}


void
rwrec_MemGetInitFlags(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetInitFlags(r, out_vp);
}


void
rwrec_MemSetInitFlags(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetInitFlags(r, in_vp);
}


int
rwrec_MemCmpInitFlags(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpInitFlags(r, vp);
}


uint8_t
rwrec_GetRestFlags(
    const rwRec        *r)
{
    return _recGetRestFlags(r);
}


void
rwrec_SetRestFlags(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetRestFlags(r, in_v);
}


void
rwrec_MemGetRestFlags(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetRestFlags(r, out_vp);
}


void
rwrec_MemSetRestFlags(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetRestFlags(r, in_vp);
}


int
rwrec_MemCmpRestFlags(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpRestFlags(r, vp);
}


uint8_t
rwrec_GetTcpState(
    const rwRec        *r)
{
    return _recGetTcpState(r);
}


void
rwrec_SetTcpState(
    rwRec              *r,
    uint8_t             in_v)
{
    _recSetTcpState(r, in_v);
}


void
rwrec_MemGetTcpState(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetTcpState(r, out_vp);
}


void
rwrec_MemSetTcpState(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetTcpState(r, in_vp);
}


int
rwrec_MemCmpTcpState(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpTcpState(r, vp);
}


sk_flowtype_id_t
rwrec_GetFlowType(
    const rwRec        *r)
{
    return _recGetFlowType(r);
}


void
rwrec_SetFlowType(
    rwRec              *r,
    sk_flowtype_id_t    in_v)
{
    _recSetFlowType(r, in_v);
}


void
rwrec_MemGetFlowType(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetFlowType(r, out_vp);
}


void
rwrec_MemSetFlowType(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetFlowType(r, in_vp);
}


int
rwrec_MemCmpFlowType(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpFlowType(r, vp);
}


uint16_t
rwrec_GetApplication(
    const rwRec        *r)
{
    return _recGetApplication(r);
}


void
rwrec_SetApplication(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetApplication(r, in_v);
}


void
rwrec_MemGetApplication(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetApplication(r, out_vp);
}


void
rwrec_MemSetApplication(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetApplication(r, in_vp);
}


int
rwrec_MemCmpApplication(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpApplication(r, vp);
}


uint16_t
rwrec_GetMemo(
    const rwRec        *r)
{
    return _recGetMemo(r);
}


void
rwrec_SetMemo(
    rwRec              *r,
    uint16_t            in_v)
{
    _recSetMemo(r, in_v);
}


void
rwrec_MemGetMemo(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetMemo(r, out_vp);
}


void
rwrec_MemSetMemo(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetMemo(r, in_vp);
}


int
rwrec_MemCmpMemo(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpMemo(r, vp);
}


void
rwrec_MemGetSIP(
    const rwRec        *r,
    skipaddr_t         *out_vp)
{
    _recMemGetSIP(r, out_vp);
}


void
rwrec_MemSetSIP(
    rwRec              *r,
    const skipaddr_t   *in_vp)
{
    _recMemSetSIP(r, in_vp);
}


int
rwrec_MemCmpSIP(
    const rwRec        *r,
    const skipaddr_t   *cmp_addr)
{
#if !SK_ENABLE_IPV6
    return _recMemCmpSIP(r, cmp_addr);
#else
    return recCompareIPAddr(r, &(r->sIP), cmp_addr);
#endif
}


void
rwrec_ApplyMaskSIP(
    rwRec              *r,
    const skipaddr_t   *mask_addr)
{
#if !SK_ENABLE_IPV6
    _recApplyMaskSIP(r, mask_addr);
#else
    recApplyMaskIPAddr(r, &(r->sIP), mask_addr);
#endif
}


void
rwrec_MemGetDIP(
    const rwRec        *r,
    skipaddr_t         *out_vp)
{
    _recMemGetDIP(r, out_vp);
}


void
rwrec_MemSetDIP(
    rwRec              *r,
    const skipaddr_t   *in_vp)
{
    _recMemSetDIP(r, in_vp);
}


int
rwrec_MemCmpDIP(
    const rwRec        *r,
    const skipaddr_t   *cmp_addr)
{
#if !SK_ENABLE_IPV6
    return _recMemCmpDIP(r, cmp_addr);
#else
    return recCompareIPAddr(r, &(r->dIP), cmp_addr);
#endif
}


void
rwrec_ApplyMaskDIP(
    rwRec              *r,
    const skipaddr_t   *mask_addr)
{
#if !SK_ENABLE_IPV6
    _recApplyMaskDIP(r, mask_addr);
#else
    recApplyMaskIPAddr(r, &(r->dIP), mask_addr);
#endif
}


void
rwrec_MemGetNhIP(
    const rwRec        *r,
    skipaddr_t         *out_vp)
{
    _recMemGetNhIP(r, out_vp);
}


void
rwrec_MemSetNhIP(
    rwRec              *r,
    const skipaddr_t   *in_vp)
{
    _recMemSetNhIP(r, in_vp);
}


int
rwrec_MemCmpNhIP(
    const rwRec        *r,
    const skipaddr_t   *cmp_addr)
{
#if !SK_ENABLE_IPV6
    return _recMemCmpNhIP(r, cmp_addr);
#else
    return recCompareIPAddr(r, &(r->nhIP), cmp_addr);
#endif
}


void
rwrec_ApplyMaskNhIP(
    rwRec              *r,
    const skipaddr_t   *mask_addr)
{
#if !SK_ENABLE_IPV6
    _recApplyMaskNhIP(r, mask_addr);
#else
    recApplyMaskIPAddr(r, &(r->nhIP), mask_addr);
#endif
}


#if SK_ENABLE_IPV6

int
rwrec_IsIPv6(
    const rwRec        *r)
{
    return _recIsIPv6(r);
}


void
rwrec_ConvertToIPv6(
    rwRec              *r)
{
    _recConvertToIPv6(r);
}


int
rwrec_ConvertToIPv4(
    rwRec              *r)
{
    uint32_t ipv4;

    if (!SK_IPV6_IS_V4INV6(r->sIP.ipu_ipv6)
        || !SK_IPV6_IS_V4INV6(r->dIP.ipu_ipv6)
        || (!SK_IPV6_IS_V4INV6(r->nhIP.ipu_ipv6)
            && !SK_IPV6_IS_ZERO(r->nhIP.ipu_ipv6)))
    {
        return -1;
    }

    memcpy(&ipv4, &(r->sIP.ipu_ipv6[12]), 4);
    r->sIP.ipu_ipv4 = ntohl(ipv4);

    memcpy(&ipv4, &(r->dIP.ipu_ipv6[12]), 4);
    r->dIP.ipu_ipv4 = ntohl(ipv4);

    memcpy(&ipv4, &(r->nhIP.ipu_ipv6[12]), 4);
    r->nhIP.ipu_ipv4 = ntohl(ipv4);

    _recSetIPv4(r);

    return 0;
}


void
rwrec_SetIPv4(
    rwRec              *r)
{
    _recSetIPv4(r);
}


void
rwrec_SetIPv6(
    rwRec              *r)
{
    _recSetIPv6(r);
}


void
rwrec_MemGetSIPv6(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetSIPv6(r, out_vp);
}


void
rwrec_MemSetSIPv6(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetSIPv6(r, in_vp);
}


int
rwrec_MemCmpSIPv6(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpSIPv6(r, vp);
}


void
rwrec_ApplyMaskSIPv6(
    rwRec              *r,
    const void         *mask_vp)
{
    _recApplyMaskSIPv6(r, mask_vp);
}


void
rwrec_MemGetDIPv6(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetDIPv6(r, out_vp);
}


void
rwrec_MemSetDIPv6(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetDIPv6(r, in_vp);
}


int
rwrec_MemCmpDIPv6(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpDIPv6(r, vp);
}


void
rwrec_ApplyMaskDIPv6(
    rwRec              *r,
    const void         *mask_vp)
{
    _recApplyMaskDIPv6(r, mask_vp);
}


void
rwrec_MemGetNhIPv6(
    const rwRec        *r,
    void               *out_vp)
{
    _recMemGetNhIPv6(r, out_vp);
}


void
rwrec_MemSetNhIPv6(
    rwRec              *r,
    const void         *in_vp)
{
    _recMemSetNhIPv6(r, in_vp);
}


int
rwrec_MemCmpNhIPv6(
    const rwRec        *r,
    const void         *vp)
{
    return _recMemCmpNhIPv6(r, vp);
}


void
rwrec_ApplyMaskNhIPv6(
    rwRec              *r,
    const void         *mask_vp)
{
    _recApplyMaskNhIPv6(r, mask_vp);
}


#endif /* SK_ENABLE_IPV6 */



/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
