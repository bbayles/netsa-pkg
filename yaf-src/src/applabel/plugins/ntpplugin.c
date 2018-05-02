#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

/**
 *  ** ------------------------------------------------------------------------
 ** Copyright (C) 2017 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Matt Coates <mfcoates@cert.org>
 ** ------------------------------------------------------------------------
 **
 */
/**
 * ntpplugin_LTX_ycNTP
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 1 if this is an NTP packet
 */
uint16_t ntpplugin_LTX_ycNTP (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
    /* supress compiler warnings about unused arguments */
    (void) argc;
    (void) argv;

    if (flow->key.proto == YF_PROTO_TCP) /*  must be UDP */
        return 0;

    /* g_debug("NTP: payload size: 0x%x",payloadSize); */
    if (payload == NULL || payloadSize < 48) /* minimum NTP size = 48 bytes */
        return 0;
   
    uint8_t ntp_version = (payload[0] & (uint8_t)0x38) >> 3;
    /* g_debug("NTP version %d",ntp_version); */
    if (ntp_version == 0 || ntp_version > 4) /* NTP is at version 4 */
    	return 0;

    /* unsigned short ntp_mode = flow->val.payload[0] & 0x07;  // nevermind: 0-6 are valid, and 7 is reserved */
    
    if (payloadSize == 48) /* standard size w/o key/MAC and extension fields for all versions */
        return 1;
    
    if (ntp_version >= 3 && payloadSize == 68) /*  20 bytes for key and MAC (optional) */
        return 1;
    
    if (ntp_version == 2 && payloadSize == 60) /* 12 bytes for Authenticator (optional) */
        return 1;
    
    int consumed = 48;
    uint16_t extension_field_len;

    if (ntp_version == 4)
    {
        while (consumed < (payloadSize-20))
        {
            /*  we have extension fields */
            extension_field_len = ((uint16_t)payload[consumed+2])>>8 | payload[consumed+3]; /* byte order flipping, ugly */
            /* g_debug("Extension field length: 0x%x starting at 0x%x",extension_field_len,consumed); */
            if (extension_field_len < 16 || extension_field_len % 4 != 0 || ((extension_field_len + consumed) > (payloadSize-20)))
            {
                /* g_debug("Invalid extension field length."); */
                return 0;
            }
            consumed += extension_field_len;
        }
        
        /*  we saw extension fields, which mandate the key id and MAC */
        /*  ensure there is enough bytes remaining in the packet to hold them. */
        if (payloadSize-consumed == 20)
        {
            return 1;
        }
        else
            ;/* g_debug("Not enough space for key and MAC (0x%x bytes), invalid NTP.",payloadSize-consumed); */
    }
    return 0;
}
