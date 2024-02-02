/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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
#if 0
/*
 *    This file is dead.
 *
 *    The algorithms in this file have been incorporated into
 *    skipset.c.
 */

/*
 * iptree.c
 *
 * This is a data structure for providing marked sets of ip addresses
 * in a tree format.
 *
 * This revision of the iptree module now moves it off into a cleaner
 * separate space and has replaced the read and write statements with
 * atomic operations.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: iptree.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/iptree.h>
#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* DEFINES AND TYPEDEFS */

/* Version to write into the file's header */
#define IPSET_FILE_VERSION  2

/*
 *    An IPTree contains this number of skIPNode_t's, where each node
 *    represents a /16 and contains a bitmap of 64k bits to say
 *    whether an IP is present in the IPTree.
 */
#define SKIP_BBLOCK_COUNT   65536

/*
 *    Each skIPNode_t in an IPTree represents a bitmap.  To implement
 *    the bitmap, there is an array containing this number of
 *    uint32_t's.  (2^16 / 32).
 */
#define SKIP_BBLOCK_SIZE    2048

/*
 *    Check for bit 'lower16' in 'node'.  The value in 'lower16' must
 *    be the 16 least significant bits of an address; 'node' is the
 *    skIPNode_t for the 16 most significant bits of the address.
 */
#define iptreeNodeHasMark(node, lower16)                                \
    ((node)->addressBlock[(lower16) >> 5] & (1 << ((lower16) & 0x1F)))

/* skIPNode_t */
struct skIPNode_st {
    uint32_t    addressBlock[SKIP_BBLOCK_SIZE];
};
typedef struct skIPNode_st skIPNode_t;

/* skIPTree_t */
struct skIPTree_st {
    skIPNode_t *nodes[SKIP_BBLOCK_COUNT];
};
/* typedef struct skIPTree_st skIPTree_t;  // skipset.h */


/**
 *    An iterator structure for looping over the elements in an IPset.
 */
struct skIPTreeIterator_st {
    const skIPTree_t   *tree;
    uint32_t            top_16;
    uint16_t            mid_11;
    uint16_t            bot_5;
};
/* typedef struct skIPTreeIterator_st skIPTreeIterator_t; */

/**
 *    The skIPTreeCIDRBlockIterator_t iterates over CIDR blocks and
 *    fills an skIPTreeCIDRBlock_t.
 */
struct skIPTreeCIDRBlockIterator_st {
    /**  the underlying iterator over the IPs */
    skIPTreeIterator_t  tree_iter;
    /**  the number of /27s yet to be returned */
    uint32_t            count;
    /**  the maximum number of trailing 0s; used to set the CIDR mask.
     *  'count' is always <= (1 << (trail_zero - 5)) */
    uint32_t            trail_zero;
    /**  the starting address for the next cidr block */
    uint32_t            base_ip;
};
/* typedef struct skIPTreeCIDRBlockIterator_st skIPTreeCIDRBlockIterator_t; */


/* LOCAL VARIABLES */

/*
 *    The skIPNode_t contains an array of uint32_t's, where each
 *    uint32_t is treated as a bitmap for a /27.
 *
 *    This array contains the bits that correspond a CIDR prefix for
 *    one of these uint32_t values.  Prefix must be between 27 and 32
 *    inclusive.  The key to this array is (prefix - 27).
 */
static const uint32_t prefix_as_bits[] = {
    0xFFFFFFFF, 0xFFFF, 0xFF, 0xF, 0x3, 0x1
};


/* FUNCTION DEFINITIONS */

/*
 *    If the IPTree 'ipset' has a node for 'msb_16' where 'msb_16' are
 *    the 16 most significant bits of an IPaddress, return that node.
 *    Otherwise, attempt to allocate the node, position the node in
 *    the tree, and return the newly allocated node.
 */
static inline skIPNode_t *
iptreeNodeGet(
    skIPTree_t         *ipset,
    uint32_t            msb_16)
{
    if (NULL == ipset->nodes[msb_16]) {
        ipset->nodes[msb_16] = (skIPNode_t*)calloc(1, sizeof(skIPNode_t));
    }
    return ipset->nodes[msb_16];
}


/* Add addr to ipset */
int
skIPTreeAddAddress(
    skIPTree_t         *ipset,
    uint32_t            addr)
{
    assert(ipset);
    if (!iptreeNodeGet(ipset, addr>>16)) {
        return SKIP_ERR_ALLOC;
    }
    ipset->nodes[addr>>16]->addressBlock[(addr & 0xFFFF) >> 5]
        |= (1 << (addr & 0x1F));

    return SKIP_OK;
}


/* Add the addresses in an IPWildcard to ipset */
int
skIPTreeAddIPWildcard(
    skIPTree_t             *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    skIPNode_t *node;
    skipaddr_t ipaddr;
    uint32_t ipv4;
    uint32_t ipv4_end;
    uint32_t prefix;

    /* Iterate over the IPs from the wildcard */
    skIPWildcardIteratorBindV4(&iter, ipwild);
    while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
           == SK_ITERATOR_OK)
    {
        assert(prefix <= 32);
        ipv4 = skipaddrGetV4(&ipaddr);
        if (prefix >= 27) {
            node = iptreeNodeGet(ipset, ipv4 >> 16);
            if (!node) {
                return SKIP_ERR_ALLOC;
            }
            node->addressBlock[(ipv4 & 0xFFFF) >> 5]
                |= (prefix_as_bits[prefix - 27] << ((ipv4) & 0x1F));

        } else if (prefix <= 16) {
            ipv4_end = ((UINT32_MAX >> prefix) | ipv4) >> 16;
            ipv4 >>= 16;
            do {
                node = iptreeNodeGet(ipset, ipv4);
                if (!node) {
                    return SKIP_ERR_ALLOC;
                }
                memset(node->addressBlock, 0xFF, sizeof(skIPNode_t));
            } while (ipv4++ < ipv4_end);

        } else {
            /* 16 < prefix < 27 */
            node = iptreeNodeGet(ipset, ipv4 >> 16);
            if (!node) {
                return SKIP_ERR_ALLOC;
            }
            memset(&node->addressBlock[(ipv4 & 0xFFFF) >> 5],
                   0xFF, (sizeof(skIPNode_t) >> (prefix - 16)));
        }
    }

    return SKIP_OK;
}


/* Return 1 if the address is present in the ipset */
int
skIPTreeCheckAddress(
    const skIPTree_t   *ipset,
    uint32_t            addr)
{
    assert(ipset);
    return (ipset->nodes[addr >> 16]
            && iptreeNodeHasMark(ipset->nodes[addr >> 16], (addr & 0xFFFF)));
}


/* Return 1 if the two IPsets have any IPs in common */
int
skIPTreeCheckIntersectIPTree(
    const skIPTree_t   *ipset1,
    const skIPTree_t   *ipset2)
{
    int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        /* check for intersection at the /16 level */
        if ((ipset1->nodes[i] == NULL) || (ipset2->nodes[i] == NULL)) {
            continue;
        }

        /* Need to intersect the bits in the /16 */
        for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
            if (ipset1->nodes[i]->addressBlock[j]
                & ipset2->nodes[i]->addressBlock[j])
            {
                return 1;
            }
        }
    }

    /* no intersesction */
    return 0;
}


/* Return 1 if the IPset and IPWildcard have any IPs in common */
int
skIPTreeCheckIntersectIPWildcard(
    const skIPTree_t       *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    const skIPNode_t *node;
    skipaddr_t ipaddr;
    uint32_t ipv4;
    uint32_t ipv4_end;
    uint32_t prefix;
    skIPNode_t empty_node;

    memset(&empty_node, 0, sizeof(empty_node));

    /* Iterate over the IPs from the wildcard */
    skIPWildcardIteratorBindV4(&iter, ipwild);
    while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
           == SK_ITERATOR_OK)
    {
        assert(prefix <= 32);
        ipv4 = skipaddrGetV4(&ipaddr);

        if (prefix >= 27) {
            node = ipset->nodes[ipv4 >> 16];
            if (node
                && (node->addressBlock[(ipv4 & 0xFFFF)>>5]
                    & (prefix_as_bits[prefix - 27] << ((ipv4) & 0x1F))))
            {
                return 1;
            }

        } else if (prefix <= 16) {
            ipv4_end = ((UINT32_MAX >> prefix) | ipv4) >> 16;
            ipv4 >>= 16;
            do {
                node = ipset->nodes[ipv4];
                if (node && memcmp(&empty_node, node, sizeof(empty_node))) {
                    return 1;
                }
            } while (ipv4++ < ipv4_end);

        } else {
            /* 16 < prefix < 27 */
            node = ipset->nodes[ipv4 >> 16];
            if (node
                && memcmp(&node->addressBlock[(ipv4 & 0xFFFF)>>5],
                          &empty_node,
                          sizeof(uint32_t)*(SKIP_BBLOCK_SIZE >> (prefix-16))))
            {
                return 1;
            }
        }
    }

    /* no intersesction */
    return 0;
}


/* Return 1 if the IPset in 'ipset_path' intersects with 'ipset'.
 * Return 0 for no intersect or on error.  */
int
skIPTreeCheckIntersectIPTreeFile(
    const skIPTree_t   *ipset,
    const char         *ipset_path,
    skIPTreeErrors_t   *err_code)
{
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    int swap_flag;
    uint32_t tBuffer[9];
    ssize_t b;
    int i;
    int rv;
    int intersect = 0;
    skIPTreeErrors_t err = SKIP_OK;
    skIPNode_t *n;

    if (ipset_path == NULL || ipset == NULL) {
         err = SKIP_ERR_BADINPUT;
         goto END;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, ipset_path))
        || (rv = skStreamOpen(stream)))
    {
        err = SKIP_ERR_OPEN;
        goto END;
    }

    rv = skStreamReadSilkHeader(stream, &hdr);
    if (rv) {
        err = SKIP_ERR_FILEIO;
        goto END;
    }

    rv = skStreamCheckSilkHeader(stream, FT_IPSET, 0, IPSET_FILE_VERSION,NULL);
    if (rv) {
        if (SKSTREAM_ERR_UNSUPPORT_VERSION == rv) {
            err = SKIP_ERR_FILEVERSION;
        } else {
            err = SKIP_ERR_FILETYPE;
        }
        goto END;
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    /*
     * IPs are stored on disk in blocks of nine 32-bit words which
     * represent a /24.  The first uint32_t is the base IP of the /24
     * (a.b.c.0); the remaining eight uint32_t's have a bit for each
     * address in the /24.
     */
    while ((b = skStreamRead(stream, tBuffer, sizeof(tBuffer)))
           == sizeof(tBuffer))
    {
        if (swap_flag) {
            for (i = 0; i < 9; ++i) {
                tBuffer[i] = BSWAP32(tBuffer[i]);
            }
        }

        n = ipset->nodes[tBuffer[0] >> 16];
        if (NULL == n) {
            /* ignore this block */
            continue;
        }

        for (i = 0; i < 8; ++i) {
            if (n->addressBlock[i] & tBuffer[i+1]) {
                intersect = 1;
                goto END;
            }
        }
    }
    if (b == -1) {
        /* read error */
        err = SKIP_ERR_FILEIO;
        goto END;
    }

  END:
    skStreamDestroy(&stream);
    if (err_code) {
        *err_code = err;
    }
    return intersect;
}


/* Return a count of the number of IPs in tree. */
uint64_t
skIPTreeCountIPs(
    const skIPTree_t   *ipset)
{
    int      i, j;
    uint64_t count = 0;
    uint32_t bits;

    for (i = 0; i < SKIP_BBLOCK_COUNT; i++) {
        if (ipset->nodes[i] != NULL) {
            /* Break the abstraction to speed up the counting */
            for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                if (ipset->nodes[i]->addressBlock[j]) {
                    BITS_IN_WORD32(&bits, ipset->nodes[i]->addressBlock[j]);
                    count += bits;
                }
            }
        }
    }

    return count;
}


/* Allocate an IPset and set contents to empty */
int
skIPTreeCreate(
    skIPTree_t        **ipset)
{
    if (ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    *ipset = (skIPTree_t*)calloc(1, sizeof(skIPTree_t));
    if (*ipset == NULL) {
        return SKIP_ERR_ALLOC;
    }
    return SKIP_OK;
}


/* Frees space associated with *ipset. */
void
skIPTreeDelete(
    skIPTree_t        **ipset)
{
    int i;

    if (ipset == NULL || *ipset == NULL) {
        return;
    }

    for (i = 0; i < SKIP_BBLOCK_COUNT; i++) {
        if ((*ipset)->nodes[i] != NULL) {
            free((*ipset)->nodes[i]);
            (*ipset)->nodes[i] = NULL;
        }
    }
    free(*ipset);
    *ipset = NULL;
}


/* Turn off bits of 'result_ipset' that are off in 'ipset'. */
void
skIPTreeIntersect(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (result_ipset->nodes[i] != NULL) {
            if (ipset->nodes[i] == NULL) {
                /* This /16 is off in 'ipset', turn off in 'result_ipset' */
                free(result_ipset->nodes[i]);
                result_ipset->nodes[i] = NULL;
            } else  {
                int nonzero = 0;
                /* Need to intersect the bits in the /16 */
                for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                    result_ipset->nodes[i]->addressBlock[j] &=
                        ipset->nodes[i]->addressBlock[j];
                    nonzero = nonzero ||
                              result_ipset->nodes[i]->addressBlock[j];
                }
                if (!nonzero) {
                    free(result_ipset->nodes[i]);
                    result_ipset->nodes[i] = NULL;
                }
            }
        }
        /* ELSE this /16 is off in the 'result_ipset'.  Leave it alone. */
    }
}


/* Mask the IPs in ipset so only one is set per every (32-mask) bits */
void
skIPTreeMask(
    skIPTree_t         *ipset,
    uint32_t            mask)
{
    int step;
    int i, j, k;

    if (mask == 0 || mask >= 32) {
        return;
    }

    if (mask <= 16) {
        step = 1 << (16 - mask);
        for (i = 0; i < SKIP_BBLOCK_COUNT; i += step) {
            for (k = (i + step - 1); k >= i; --k) {
                if (ipset->nodes[k] != NULL) {
                    break;
                }
            }
            if (k < i) {
                continue;
            }
            if (ipset->nodes[i] == NULL) {
                ipset->nodes[i] = ipset->nodes[k];
                ipset->nodes[k] = NULL;
            }
            memset(ipset->nodes[i], 0, sizeof(skIPNode_t));
            ipset->nodes[i]->addressBlock[0] = 1;
            for (k = (i + step - 1); k > i; --k) {
                if (ipset->nodes[k]) {
                    free(ipset->nodes[k]);
                    ipset->nodes[k] = NULL;
                }
            }
        }
        return;
    }

    if (mask <= 27) {
        step = 1 << (27 - mask);
        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (ipset->nodes[i] == NULL) {
                continue;
            }
            for (j = 0; j < SKIP_BBLOCK_SIZE; j += step) {
                for (k = (j + step - 1); k >= j; --k) {
                    if (ipset->nodes[i]->addressBlock[k]) {
                        break;
                    }
                }
                if (k < j) {
                    continue;
                }
                ipset->nodes[i]->addressBlock[j] = 1;
                for (k = (j + step - 1); k > j; --k) {
                    ipset->nodes[i]->addressBlock[k] = 0;
                }
            }
        }
        return;
    }

    /* operate on each integer */
    step = 1 << (32 - mask);
    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (ipset->nodes[i] == NULL) {
            continue;
        }
        for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
            for (k = 0; k < 32; k += step) {
                if (GET_MASKED_BITS(ipset->nodes[i]->addressBlock[j],
                                    k, step))
                {
                    SET_MASKED_BITS(ipset->nodes[i]->addressBlock[j],
                                    1, k, step);
                }
            }
        }
    }
}


/* Read IPset from filename---a wrapper around skIPTreeRead(). */
int
skIPTreeLoad(
    skIPTree_t        **ipset,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int rv;

    if (filename == NULL || ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIP_ERR_OPEN;
        goto END;
    }

    rv = skIPTreeRead(ipset, stream);
    if (rv) { goto END; }

  END:
    skStreamDestroy(&stream);
    return rv;
}


/* Print a textual prepresentation of the IP Tree. */
void
skIPTreePrint(
    const skIPTree_t   *ipset,
    skstream_t         *stream,
    skipaddr_flags_t    ip_format,
    int                 as_cidr)
{
    char buf[SKIPADDR_STRLEN+1];
    skipaddr_t ipaddr;

    if (as_cidr) {
        skIPTreeCIDRBlockIterator_t cidr_iter;
        skIPTreeCIDRBlock_t cidr;

        skIPTreeCIDRBlockIteratorBind(&cidr_iter, ipset);
        while (skIPTreeCIDRBlockIteratorNext(&cidr, &cidr_iter)
               == SK_ITERATOR_OK)
        {
            skipaddrSetV4(&ipaddr, &cidr.addr);
            skipaddrString(buf, &ipaddr, ip_format);
            if (cidr.mask == 32) {
                skStreamPrint(stream, "%s\n", buf);
            } else {
                skStreamPrint(stream, ("%s/%" PRIu32 "\n"), buf, cidr.mask);
            }
        }
    } else {
        skIPTreeIterator_t iter;
        uint32_t addr;

        /* memset to eliminate gcc warning */
        memset(&iter, 0, sizeof(skIPTreeIterator_t));

        skIPTreeIteratorBind(&iter, ipset);
        while (skIPTreeIteratorNext(&addr, &iter) == SK_ITERATOR_OK) {
            skipaddrSetV4(&ipaddr, &addr);
            skipaddrString(buf, &ipaddr, ip_format);
            skStreamPrint(stream, "%s\n", buf);
        }
    }
}


/* Allocate 'ipset' and read it from the data stream 'stream'. */
int
skIPTreeRead(
    skIPTree_t        **ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    int swap_flag;
    uint32_t tBuffer[9];
    uint32_t blockStart;
    uint32_t rootAddr;
    ssize_t b;
    int i;
    int rv;

    if (stream == NULL || ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    if ((*ipset) != NULL) {
        return SKIP_ERR_NONEMPTY;
    }

    rv = skStreamReadSilkHeader(stream, &hdr);
    if (rv) {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIP_ERR_FILEIO;
        goto END;
    }

    /*
     * There has only been one IPset file format, but it may have
     * version 0, 1, or 2.  Files of v2 support compression on write;
     * for compatibility with SiLK-0.10.0 through 0.10.4, compression
     * on read is supported regardless of version.
     *
     * When first released, the version of the IPset was never
     * initialized.  To work with those files, the version check was
     * never implemented.
     */
    rv = skStreamCheckSilkHeader(stream, FT_IPSET, 0, IPSET_FILE_VERSION,NULL);
    if (rv) {
        if (SKSTREAM_ERR_UNSUPPORT_VERSION == rv) {
            rv = SKIP_ERR_FILEVERSION;
        } else {
            rv = SKIP_ERR_FILETYPE;
        }
        goto END;
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    rv = skIPTreeCreate(ipset);
    if (rv != SKIP_OK) {
        goto END;
    }

    /*
     * IPs are stored on disk in blocks of nine 32-bit words which
     * represent a /24.  The first uint32_t is the base IP of the /24
     * (a.b.c.0); the remaining eight uint32_t's have a bit for each
     * address in the /24.
     */
    while ((b = skStreamRead(stream, tBuffer, sizeof(tBuffer)))
           == sizeof(tBuffer))
    {
        if (swap_flag) {
            for (i = 0; i < 9; ++i) {
                tBuffer[i] = BSWAP32(tBuffer[i]);
            }
        }

        /* Put the first two octets into rootAddr, and allocate the
         * space for the /16 if we need to */
        rootAddr = (tBuffer[0] >> 16);
        if (!iptreeNodeGet(*ipset, rootAddr)) {
            rv = SKIP_ERR_ALLOC;
            goto END;
        }

        /* Locate where this /24 occurs inside the larger /16, then
         * copy it into place.  Following is equivalent to
         * (((tBuffer[0] >> 8) & 0xFF) * 8); */
        blockStart = ((tBuffer[0] & 0x0000FF00) >> 5);
        memcpy(((*ipset)->nodes[rootAddr]->addressBlock + blockStart),
               tBuffer + 1, 8 * sizeof(uint32_t));
    }
    if (b == -1) {
        /* read error */
        rv = SKIP_ERR_FILEIO;
        goto END;
    }

    rv = SKIP_OK;

  END:
    if (rv != SKIP_OK) {
        /* Do cleanup (Delete tree) and return */
        if ((*ipset) != NULL) {
            skIPTreeDelete(ipset);
        }
    }
    return rv;
}


/* Remove all addresses from an IPset */
int
skIPTreeRemoveAll(
    skIPTree_t         *ipset)
{
    int i;

    if (ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }
    /* delete all the nodes */
    for (i = 0; i < SKIP_BBLOCK_COUNT; i++) {
        if (ipset->nodes[i] != NULL) {
            free(ipset->nodes[i]);
        }
    }

    memset(ipset, 0, sizeof(skIPTree_t));
    return SKIP_OK;
}


/* Write 'ipset' to 'filename'--a wrapper around skIPTreeWrite(). */
int
skIPTreeSave(
    const skIPTree_t   *ipset,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int rv;

    if (filename == NULL || ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIP_ERR_OPEN;
        goto END;
    }

    rv = skIPTreeWrite(ipset, stream);

  END:
    skStreamDestroy(&stream);
    return rv;
}


/* Convert 'error_code' to a string. */
const char *
skIPTreeStrError(
    int                 error_code)
{
    static char buf[128];

    switch ((skIPTreeErrors_t)error_code) {
      case SKIP_OK:
        return "Success";
      case SKIP_ERR_ALLOC:
        return "Unable to allocate memory";
      case SKIP_ERR_BADINPUT:
        return "Empty input value";
      case SKIP_ERR_FILEIO:
        return "Error in read/write";
      case SKIP_ERR_FILETYPE:
        return "Input is not an IPset";
      case SKIP_ERR_NONEMPTY:
        return "Input IPset is not empty";
      case SKIP_ERR_OPEN:
        return "Error opening file";
      case SKIP_ERR_IPV6:
        return "IPsets do not support IPv6 addresses";
      case SKIP_ERR_FILEVERSION:
        return "This application does not support the new IPset file format";
    }

    snprintf(buf, sizeof(buf), "Unrecognized IPTree error code %d",error_code);
    buf[sizeof(buf)-1] = '\0';
    return buf;
}


/* Subtract 'ipset' from 'result_ipset' */
void
skIPTreeSubtract(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if ((result_ipset->nodes[i] != NULL) && (ipset->nodes[i] != NULL)) {
            int nonzero = 0;
            /* Need to intersect with the complement in the /16 */
            for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                result_ipset->nodes[i]->addressBlock[j] &=
                    ~(ipset->nodes[i]->addressBlock[j]);
                nonzero = nonzero || result_ipset->nodes[i]->addressBlock[j];
            }
            if (!nonzero) {
                free(result_ipset->nodes[i]);
                result_ipset->nodes[i] = NULL;
            }
        }
        /* ELSE This /16 is off in at least one ipset.  Leave it alone. */
    }
}


/* Merge 'ipset' into 'result_ipset' */
int
skIPTreeUnion(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (NULL != ipset->nodes[i]) {
            if (NULL != result_ipset->nodes[i]) {
                /* need to merge */
                for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                    result_ipset->nodes[i]->addressBlock[j] |=
                        ipset->nodes[i]->addressBlock[j];
                }
            } else {
                /* copy block from ipset to result_ipset */
                result_ipset->nodes[i]
                    = (skIPNode_t*)malloc(sizeof(skIPNode_t));
                if (result_ipset->nodes[i] == NULL) {
                    return SKIP_ERR_ALLOC;
                }
                memcpy(result_ipset->nodes[i], ipset->nodes[i],
                       sizeof(skIPNode_t));
            }
        }
    }

    return SKIP_OK;
}


/* Write 'ipset' to 'stream'. */
int
skIPTreeWrite(
    const skIPTree_t   *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    uint32_t i;
    uint32_t j;
    uint32_t jOffset;
    uint32_t class_c;
    skIPNode_t *workNode;
    int rv;

    if (stream == NULL || ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    hdr = skStreamGetSilkHeader(stream);
    skHeaderSetFileFormat(hdr, FT_IPSET);
    skHeaderSetRecordVersion(hdr, IPSET_FILE_VERSION);
    /* skHeaderSetRecordLength(hdr, 9 * sizeof(uint32_t)); */
    skHeaderSetRecordLength(hdr, 1);

    /*
     * Prep and write the IPTree's header information.
     */
    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIP_ERR_FILETYPE;
        goto END;
    }

    /*
     * IPs are stored on disk in blocks of nine 32-bit words which
     * represent a /24.  The first uint32_t is the base IP of the /24
     * (a.b.c.0); the remaining eight uint32_t's have a bit for each
     * address in the /24.
     */
    for (i = 0; i < SKIP_BBLOCK_COUNT; i++) {
        /* workNode represents a /16 */
        workNode = ipset->nodes[i];
        if (workNode == NULL) {
            continue;
        }

        /*
         * There is data in this /16, now walk over the addressBlocks,
         * which are /27s, and for any which have IP bits set, write
         * the entire /24 to disk.
         */
        j = 0;
        while (j < SKIP_BBLOCK_SIZE) {
            if (workNode->addressBlock[j] == 0) {
                /* nothing in this /27 */
                j = j + 1;
                continue;
            }

            /* there is data in this /27; get the /24 that it is part
             * of, and write that base address. */
            class_c = ((i << 16) | (j << 5)) & 0xFFFFFF00;
            if (skStreamWrite(stream, &class_c, sizeof(uint32_t)) == -1) {
                rv = SKIP_ERR_FILEIO;
                goto END;
            }

            /* compute the first /27 that has data for the /24, then
             * write the complete /24: 8 uint32_t's */
            jOffset = (j & (0xff << 3));
            if (skStreamWrite(stream, (workNode->addressBlock+jOffset),
                              8 * sizeof(uint32_t))
                == -1)
            {
                rv = SKIP_ERR_FILEIO;
                goto END;
            }
            /* move the start of the next /24 */
            j = ((j & (0xff << 3)) + 8);
        }
    }

    rv = skStreamFlush(stream);
    if (rv) {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIP_ERR_FILEIO;
        goto END;
    }

    rv = SKIP_OK;

  END:
    return rv;
}



/* ITERATOR CODE */


/* Bind iterator to ipset */
int
skIPTreeIteratorBind(
    skIPTreeIterator_t *iter,
    const skIPTree_t   *ipset)
{
    if (iter == NULL || ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    iter->tree = ipset;
    skIPTreeIteratorReset(iter);

    return SKIP_OK;
}


/* Create iterator */
int
skIPTreeIteratorCreate(
    skIPTreeIterator_t    **out_iter,
    const skIPTree_t       *ipset)
{
    assert(out_iter);

    *out_iter = (skIPTreeIterator_t*)malloc(sizeof(skIPTreeIterator_t));
    if (*out_iter == NULL) {
        return SKIP_ERR_ALLOC;
    }

    if (skIPTreeIteratorBind(*out_iter, ipset)) {
        skIPTreeIteratorDestroy(out_iter);
        return SKIP_ERR_BADINPUT;
    }

    return SKIP_OK;
}


/* Destroy iterator */
void
skIPTreeIteratorDestroy(
    skIPTreeIterator_t    **out_iter)
{
    if (*out_iter) {
        (*out_iter)->tree = NULL;
        free(*out_iter);
        *out_iter = NULL;
    }
}


#define FIND_NEXT_ITER_TOP(iter)                                        \
    for ( ; (iter)->top_16 < SKIP_BBLOCK_COUNT; ++(iter)->top_16) {     \
        if ((iter)->tree->nodes[(iter)->top_16] != NULL) {              \
            /* found a /16 with data */                                 \
            break;                                                      \
        }                                                               \
    }


/* Get next entry in tree */
skIteratorStatus_t
skIPTreeIteratorNext(
    uint32_t           *out_addr,
    skIPTreeIterator_t *iter)
{
    assert(out_addr);

    while (iter->top_16 < SKIP_BBLOCK_COUNT) {
        for ( ; iter->mid_11 < SKIP_BBLOCK_SIZE ; ++iter->mid_11) {
            if ((iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11])
                == 0)
            {
                continue;
            }

            for ( ; iter->bot_5 < 32; ++iter->bot_5) {
                if (iptreeNodeHasMark((iter->tree->nodes[iter->top_16]),
                                      ((iter->mid_11 << 5) + iter->bot_5)))
                {
                    /* Generate the IP address */
                    *out_addr = (((iter->top_16) << 16)
                                 | (iter->mid_11 << 5)
                                 | iter->bot_5);
                    /* Prepare to search from next IP address */
                    ++iter->bot_5;
                    return SK_ITERATOR_OK;
                }
            }

            /* reset bottom counter */
            iter->bot_5 = 0;
        }

        /* reset middle counter; move top counter to next valid block */
        iter->mid_11 = 0;
        ++iter->top_16;
        FIND_NEXT_ITER_TOP(iter);
    }

    return SK_ITERATOR_NO_MORE_ENTRIES;
}


/* Reset iterator */
void
skIPTreeIteratorReset(
    skIPTreeIterator_t *iter)
{
    /* Set everything to zero, then find the first IP non-NULL node */
    iter->top_16 = iter->mid_11 = iter->bot_5 = 0;

    FIND_NEXT_ITER_TOP(iter);
}


/* Bind a CIDR iterator to an IPset */
int
skIPTreeCIDRBlockIteratorBind(
    skIPTreeCIDRBlockIterator_t    *block_iter,
    const skIPTree_t               *ipset)
{
    /* memset to eliminate gcc warning */
    memset(block_iter, 0, sizeof(skIPTreeCIDRBlockIterator_t));

    if (skIPTreeIteratorBind(&block_iter->tree_iter, ipset)) {
        return SKIP_ERR_BADINPUT;
    }
    skIPTreeCIDRBlockIteratorReset(block_iter);
    return SKIP_OK;
}


/* Create CIDR iterator */
int
skIPTreeCIDRBlockIteratorCreate(
    skIPTreeCIDRBlockIterator_t   **out_block_iter,
    const skIPTree_t               *ipset)
{
    assert(out_block_iter);

    *out_block_iter = ((skIPTreeCIDRBlockIterator_t*)
                       malloc(sizeof(skIPTreeCIDRBlockIterator_t)));
    if (*out_block_iter == NULL) {
        return SKIP_ERR_ALLOC;
    }

    if (skIPTreeCIDRBlockIteratorBind(*out_block_iter, ipset)) {
        skIPTreeCIDRBlockIteratorDestroy(out_block_iter);
        return SKIP_ERR_BADINPUT;
    }

    return SKIP_OK;
}


/* Destroy CIDR iterator */
void
skIPTreeCIDRBlockIteratorDestroy(
    skIPTreeCIDRBlockIterator_t   **out_block_iter)
{
    if (*out_block_iter) {
        free(*out_block_iter);
        *out_block_iter = NULL;
    }
}


skIteratorStatus_t
skIPTreeCIDRBlockIteratorNext(
    skIPTreeCIDRBlock_t            *out_cidr,
    skIPTreeCIDRBlockIterator_t    *block_iter)
{
    skIPTreeIterator_t *iter = &(block_iter->tree_iter);
    uint32_t max_slash27;
    uint32_t slash27;
    uint32_t bmap;

    assert(out_cidr);

    /* if we have already found a CIDR block, return it */
    if (block_iter->count) {
        goto END;
    }

    /* check stopping condition */
    if (iter->top_16 >= SKIP_BBLOCK_COUNT) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    /* iterator should always be on a valid value */
    bmap = iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11];
    assert(bmap > 0);

    if (bmap < UINT32_MAX) {
        /* This /27 is only partially filled */

        /* find position of least significant high bit in 'bmap',
         * ignoring bits we have already checked */
        bmap >>= iter->bot_5;
        if (!(bmap & 0x1)) {
            if ((bmap & 0xFFFF) == 0) {
                bmap >>= 16;
                iter->bot_5 += 16;
            }
            if ((bmap & 0xFF) == 0) {
                bmap >>= 8;
                iter->bot_5 += 8;
            }
            if ((bmap & 0xF) == 0) {
                bmap >>= 4;
                iter->bot_5 += 4;
            }
            if ((bmap & 0x3) == 0) {
                bmap >>= 2;
                iter->bot_5 += 2;
            }
            if ((bmap & 0x1) == 0) {
                bmap >>= 1;
                iter->bot_5 += 1;
            }
        }

        out_cidr->addr = ((iter->top_16 << 16)
                          | (iter->mid_11 << 5)
                          | (iter->bot_5));

        /* find number of consecutive high bits in 'bmap' that map
         * into a CIDR block */
        switch (iter->bot_5) {
          case 0: case 16:
            if ((bmap & 0xFFFF) == 0xFFFF) {
                out_cidr->mask = 28;
                iter->bot_5 += 16;
                bmap >>= 16;
                break;
            }
            /* FALLTHROUGH */
          case 8: case 24:
            if ((bmap & 0xFF) == 0xFF) {
                out_cidr->mask = 29;
                iter->bot_5 += 8;
                bmap >>= 8;
                break;
            }
            /* FALLTHROUGH */
          case 4: case 12: case 20: case 28:
            if ((bmap & 0xF) == 0xF) {
                out_cidr->mask = 30;
                iter->bot_5 += 4;
                bmap >>= 4;
                break;
            }
            /* FALLTHROUGH */
          case  2: case  6: case 10: case 14:
          case 18: case 22: case 26: case 30:
            if ((bmap & 0x3) == 0x3) {
                out_cidr->mask = 31;
                iter->bot_5 += 2;
                bmap >>= 2;
                break;
            }
            /* FALLTHROUGH */
          default:
            out_cidr->mask = 32;
            ++iter->bot_5;
            bmap >>= 1;
            break;
        }

        /* increment the iterator if there are no more bits in this
         * bitmap */
        if (0 == bmap || 32 == iter->bot_5) {
            iter->bot_5 = 0;
            ++iter->mid_11;
            /* fall into code below to find next bitmap with data */
        }
    } else if (iter->mid_11 & 0x1) {
        /* this /27 is full and the base IP is odd.  Return the /27 */
        out_cidr->addr = (iter->top_16 << 16) | (iter->mid_11 << 5);
        out_cidr->mask = 27;
        ++iter->mid_11;
        /* fall into code below to find next bitmap with data */

    } else {
        /* this /27 is full; attempt to join it with additional /27s
         * to make a larger CIDR block */

        /* compute the maximum number of /27s that can be joined with
         * this one by counting the number of trailing zeros on the
         * IP---we know the least significant 5 bits are 0 */
        block_iter->base_ip = (iter->top_16 << 16) | (iter->mid_11 << 5);
        slash27 = (block_iter->base_ip >> 5);
        if (0 == slash27) {
            block_iter->trail_zero = 32;
        } else {
            block_iter->trail_zero = 6;
            if ((slash27 & 0xFFFF) == 0) {
                slash27 >>= 16;
                block_iter->trail_zero += 16;
            }
            if ((slash27 & 0xFF) == 0) {
                slash27 >>= 8;
                block_iter->trail_zero += 8;
            }
            if ((slash27 & 0xF) == 0) {
                slash27 >>= 4;
                block_iter->trail_zero += 4;
            }
            if ((slash27 & 0x3) == 0) {
                slash27 >>= 2;
                block_iter->trail_zero += 2;
            }
            block_iter->trail_zero -= (slash27 & 1);
        }

        max_slash27 = (1 << (block_iter->trail_zero - 5));
        block_iter->count = 1;

        ++iter->mid_11;
        assert(iter->mid_11 < SKIP_BBLOCK_SIZE);

        for (;;) {
            if (iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11]
                == 0)
            {
                /* return whatever CIDR block we built; but first we
                 * need to find the next /27-bitmap with data */
                ++iter->mid_11;
                break;
            }
            if (iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11]
                != UINT32_MAX)
            {
                /* return whatever CIDR block we built; we know the
                 * current /27-bitmap has data but it is not full */
                goto END;
            }
            ++block_iter->count;
            if (block_iter->count == max_slash27) {
                /* the CIDR block is at its maximum size; find the
                 * next /27-bitmap that has data */
                ++iter->mid_11;
                break;
            }
            /* keep growing the current CIDR block */
            ++iter->mid_11;
            if (iter->mid_11 == SKIP_BBLOCK_SIZE) {
                iter->mid_11 = 0;
                ++iter->top_16;
                assert(iter->top_16 < SKIP_BBLOCK_COUNT);
                if (NULL == iter->tree->nodes[iter->top_16]) {
                    /* return whatever CIDR we have built; drop into
                     * code below to find the next bitmap with data */
                    FIND_NEXT_ITER_TOP(iter);
                    break;
                }
            }
        }
    }

    /* find the next /27-bitmap with data */
    while (iter->top_16 < SKIP_BBLOCK_COUNT) {
        for ( ; iter->mid_11 < SKIP_BBLOCK_SIZE; ++iter->mid_11) {
            if (iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11]
                != 0)
            {
                goto END;
            }
        }
        /* end of this /16; find the next one with data */
        iter->mid_11 = 0;
        ++iter->top_16;
        FIND_NEXT_ITER_TOP(iter);
    }

  END:
    /* return CIDR block if we have one */
    if (block_iter->count) {
        assert(block_iter->trail_zero >= 5);
        while (block_iter->count < (1u << (block_iter->trail_zero - 5))) {
            --block_iter->trail_zero;
        }
        out_cidr->addr = block_iter->base_ip;
        out_cidr->mask = (32 - block_iter->trail_zero);
        block_iter->count -= (1 << (block_iter->trail_zero - 5));
        block_iter->base_ip |= (0x20u << (block_iter->trail_zero - 5));
        --block_iter->trail_zero;
    }

    return SK_ITERATOR_OK;
}


void
skIPTreeCIDRBlockIteratorReset(
    skIPTreeCIDRBlockIterator_t    *block_iter)
{
    skIPTreeIterator_t *iter;

    assert(block_iter);

    block_iter->count = block_iter->trail_zero = block_iter->base_ip = 0;

    iter = &(block_iter->tree_iter);
    iter->bot_5 = 0;

    /* find first /27 that has data */
    FIND_NEXT_ITER_TOP(iter);
    while (iter->top_16 < SKIP_BBLOCK_COUNT) {
        for (iter->mid_11 = 0; iter->mid_11 < SKIP_BBLOCK_SIZE; ++iter->mid_11)
        {
            if (iter->tree->nodes[iter->top_16]->addressBlock[iter->mid_11]) {
                return;
            }
        }
        ++iter->top_16;
        FIND_NEXT_ITER_TOP(iter);
    }
}

#endif  /* 0 */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
