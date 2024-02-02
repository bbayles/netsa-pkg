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

/*
 *  iptree.h
 *
 *    THIS FILE AND ALL FUNCTIONS/MACROS/STUCTURES IT DECLARES/DEFINES
 *    ARE DEPRECATED AS OF SiLK 3.10.0.  USE skipset.h INSTEAD.
 *
 *
 *    Michael Collins
 *    May 6th, 2003
 *
 *    This is a tree structure for ip addresses containing a bitmap of
 *    ip addresses.
 *
 */
#ifndef _IPTREE_H
#define _IPTREE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_IPTREE_H, "$SiLK: iptree.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>
#include <silk/skipset.h>

/**
 *  @file
 *
 *    An skIPTree is the form of the IPset used in SiLK versions prior
 *    to SiLK-3.0.
 *
 *    This file is part of libsilk.
 */

/**
 *    Return values for skIPTree* functions.
 */
typedef enum skIPTreeErrors_en {
    /**  Success */
    SKIP_OK = 0,
    /**  Unable to allocate memory */
    SKIP_ERR_ALLOC,
    /**  Empty input value */
    SKIP_ERR_BADINPUT,
    /**  Error in read/write */
    SKIP_ERR_FILEIO,
    /**  Input is not an IPset */
    SKIP_ERR_FILETYPE,
    /**  Input IPset is not empty */
    SKIP_ERR_NONEMPTY,
    /**  Error opening file */
    SKIP_ERR_OPEN,
    /**  IPsets do not support IPv6 addresses */
    SKIP_ERR_IPV6,
    /**  This application does not support the new IPset file format */
    SKIP_ERR_FILEVERSION
} skIPTreeErrors_t;


typedef skipset_iterator_t skIPTreeIterator_t;

typedef skipset_iterator_t skIPTreeCIDRBlockIterator_t;

struct skIPTreeCIDRBlock_st {
    uint32_t addr;
    uint32_t mask;
};
typedef struct skIPTreeCIDRBlock_st skIPTreeCIDRBlock_t;


/* FUNCTION PROTOTYPES */

/**
 *    Add the IP Address 'addr' to the binary IPSet 'ipset'.  Returns
 *    SKIP_OK for success, or SKIP_ERR_ALLOC if there is not enough
 *    memory to allocate space for the new IP address.
 */
int
skIPTreeAddAddress(
    skIPTree_t         *ipset,
    uint32_t            addr);


/**
 *    Add all the addresses in the IPWildcard 'ipwild' to the IPset
 *    'ipset'.
 *
 *    When 'ipwild' contains IPv6 addresses, map each address within
 *    the ::ffff:0:0/96 netblock to an IPv4 address and add it to
 *    'ipset'.  This behavior is new as of SiLK 3.9.0.  In prior
 *    releases of SiLK, the entire contents of the wildcard was
 *    ignored and SKIP_ERR_IPV6 was returned when 'ipwild' contained
 *    any IPv6 addresses.
 *
 *    Returns SKIP_OK for success or SKIP_ERR_ALLOC if there is a
 *    memory allocation error.
 */
int
skIPTreeAddIPWildcard(
    skIPTree_t             *ipset,
    const skIPWildcard_t   *ipwild);


/**
 *    Return 1 if the IPv4 address 'ipv4' is in the IPset 'ipset';
 *    otherwise, return 0.
 */
int
skIPTreeCheckAddress(
    const skIPTree_t   *ipset,
    uint32_t            ipv4);


/**
 *    Return 1 if the IPsets 'ipset1' and 'ipset2' have any IPs in
 *    common; otherwise, return 0.
 */
int
skIPTreeCheckIntersectIPTree(
    const skIPTree_t   *ipset1,
    const skIPTree_t   *ipset2);


/**
 *    Return 1 if the IPset 'ipset' and IPWildcard 'ipwild' have any
 *    IPs in common; otherwise, return 0.
 *
 *    When 'ipwild' contains IPv6 addresses, map each address within
 *    the ::ffff:0:0/96 netblock to an IPv4 address and determine if
 *    it appears in 'ipset'.  This behavior is new as of SiLK 3.9.0.
 *    In prior relases of SiLK, the entire contents of the wildcard
 *    was ignored and 0 was returned when 'ipwild' contained any IPv6
 *    addresses.
 */
int
skIPTreeCheckIntersectIPWildcard(
    const skIPTree_t       *ipset,
    const skIPWildcard_t   *ipwild);


/**
 *    Like skIPTreeCheckIntersectIPTree(), except compares the in-core
 *    IPset 'ipset' with the IPset contained in the file 'ipset_path'.
 *    Returns 1 if the IPsets have an IPs in common; returns 0 if they
 *    do not or to signify an error, in which case the error code will
 *    be put into the memory referenced 'err_code', if that value is
 *    non-NULL.
 */
int
skIPTreeCheckIntersectIPTreeFile(
    const skIPTree_t   *ipset,
    const char         *ipset_path,
    skIPTreeErrors_t   *err_code);


/**
 *    Returns a count of the number of IP addresses marked in the
 *    'ipset'.
 */
uint64_t
skIPTreeCountIPs(
    const skIPTree_t   *ipset);


/**
 *    Allocation and creation function; initializes a new ipset at the
 *    space specified by '*ipset' and sets the contents to empty.
 *
 *    Returns SKIP_OK if everything went well, else SKIP_ERR_ALLOC
 *    on a malloc failure, or SKIP_ERR_BADINPUT if ipset was NULL.
 *
 *    skIPTreeDelete() is the corresponding free function.
 */
int
skIPTreeCreate(
    skIPTree_t        **ipset);


/**
 *    Frees the space associated with *ipset and sets *ipset to
 *    NULL.  Does nothing if 'ipset' or '*ipset' is NULL.
 */
void
skIPTreeDelete(
    skIPTree_t        **ipset);


/**
 *    Perform an intersection of 'result_ipset' and 'ipset', with the
 *    result in the 'result_ipset'; i.e., turn off all addresses in
 *    'result_ipset' that are off in 'ipset'.
 */
void
skIPTreeIntersect(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset);


/**
 *    Create(allocate) a new IPset at the location pointed at by
 *    'ipset' and fill it with the data that the function reads from
 *    the file 'filename'.
 *
 *    This function is similar to skIPTreeRead(), except that this
 *    function will create the skstream_t from the specified filename.
 *
 *    In addition to the possible return values listed for
 *    skIPTreeRead(), this function may return:
 *      SKIP_ERR_OPEN - error in opening the file
 */
int
skIPTreeLoad(
    skIPTree_t        **ipset,
    const char         *filename);


/**
 *    Modify in place the specified 'ipset' so it contains at most 1
 *    IP address for every block of bitmask length 'mask', a value
 *    from 1 to 32.  If the 'ipset' has any IP active within each
 *    block, all IPs in that block are turned off except for the IP at
 *    the start of the block.
 *
 *    Specify mask==16 with an IPset containing these IPs:
 *        10.0.0.23
 *        10.0.1.0/24
 *        10.7.1.0/24
 *        20.20.0.243
 *    produces an IPset with these three IPs:
 *        10.0.0.0
 *        10.7.0.0
 *        20.20.0.0
 */
void
skIPTreeMask(
    skIPTree_t         *ipset,
    uint32_t            mask);


/**
 *    Print, to the stream 'stream', a textual representation of the
 *    IPset given by 'ipset'.  The parameter 'ip_format' decribes how
 *    to print the ipset (see utils.h).  If 'as_cidr' is non-zero, the
 *    output will be in CIDR notation.
 */
void
skIPTreePrint(
    const skIPTree_t   *ipset,
    skstream_t         *stream,
    skipaddr_flags_t    ip_format,
    int                 as_cidr);


/**
 *    Allocate a new IPset at the location pointed at by 'ipset' and
 *    fill it with the data that the function reads from the stream
 *    'stream'.  'stream' should be bound to a file and open.
 *
 *    Returns one of the following:
 *      SKIP_OK on success
 *      SKIP_ERR_BADINPUT - one of the input values is NULL
 *      SKIP_ERR_ALLOC  - failure to allocate memory.
 *      SKIP_ERR_NONEMPTY - the '*ipset' is not empty
 *      SKIP_ERR_FILETYPE - the file is not of the correct type
 *      SKIP_ERR_FILEIO   - error during a read call
 *
 *    On failure, 'ipset' is set back to null and deleted.
 */
int
skIPTreeRead(
    skIPTree_t        **ipset,
    skstream_t         *stream);


/**
 *    Remove all IPs from an IPset.
 */
int
skIPTreeRemoveAll(
    skIPTree_t         *ipset);


/**
 *    Write the IPset at 'ipset' to the disk file 'filename'; the
 *    disk format is specified in iptree.api.
 *
 *    This function is similar to skIPTreeWrite(), except this
 *    function writes directly to a file using the default compression
 *    method.
 *
 *    In addition to the possible return values listed for
 *    skIPTreeWrite(), this function may return:
 *      SKIP_ERR_OPEN - error in opening the file
 */
int
skIPTreeSave(
    const skIPTree_t   *ipset,
    const char         *filename);


/**
 *    Return a text string describing 'err_code'.
 */
const char *
skIPTreeStrError(
    int                 err_code);


/**
 *    Subtract 'ipset' from 'result_ipset' with the result in the
 *    'result_ipset'; i.e., if an address is off in 'ipset', do not
 *    modify the value in 'result_ipset', otherwise, turn off that
 *    address in 'result_ipset'.
 */
void
skIPTreeSubtract(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset);


/**
 *    Perform the union of 'result_ipset' and 'ipset', with the result
 *    in 'result_ipset'; i.e., merge 'ipset' into 'result_ipset'.
 *    Returns 0 on success, or 1 on memory allocation error.
 */
int
skIPTreeUnion(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset);


/**
 *   Write the IPset at 'ipset' the output stream 'stream'.  'stream'
 *   should be bound to a file and open.  The caller may set the
 *   compression method of the stream before calling this function.
 *   If not set, the default compression method is used.
 *
 *   Returns one of the following values:
 *        SKIP_OK          on success.
 *        SKIP_ERR_OPEN    if the file already exists.
 *        SKIP_ERR_FILEIO  if there's an error writing the data to disk.
 *        SKIP_ERR_ALLOC   on a memory allocatin problem for the ipset.
 */
int
skIPTreeWrite(
    const skIPTree_t   *ipset,
    skstream_t         *stream);



/*
 *   Iteration over the members of an IPset
 */


/**
 *    Bind the IPset iterator 'iter' to iterate over all the entries
 *    in the IPSet 'ipset'.  Return 0 on success, non-zero otherwise.
 */
int
skIPTreeIteratorBind(
    skIPTreeIterator_t *iter,
    const skIPTree_t   *ipset);


/**
 *    Create a new iterator at the address pointed to by 'out_iter'
 *    and bind it to iterate over all the entries in the IPSet
 *    'ipset'.  Return 0 on success, non-zero otherwise.
 */
int
skIPTreeIteratorCreate(
    skIPTreeIterator_t    **out_iter,
    const skIPTree_t       *ipset);


/**
 *    Destroy the iterator pointed to by 'out_iter'.  Does nothing if
 *    'out_iter' or the location it points to is NULL.
 */
void
skIPTreeIteratorDestroy(
    skIPTreeIterator_t    **out_iter);


/**
 *    If there are more entries in the IPSet, put the
 *    next IP Address into the location referenced by 'out_addr' and
 *    return SK_ITERATOR_OK.  Otherwise, to not  modify 'out_addr'
 *    and return SK_ITERATOR_NO_MORE_ENTRIES.
 */
skIteratorStatus_t
skIPTreeIteratorNext(
    uint32_t           *out_addr,
    skIPTreeIterator_t *iter);


/**
 *    Reset the iterator 'iter' to begin looping through the entries
 *    in the IPSet again.
 */
void
skIPTreeIteratorReset(
    skIPTreeIterator_t *iter);



/*
 *   Iteration over the CIDR Blocks of an IPset
 */


/**
 *    Bind the IPset CIDR Block iterator 'iter' to iterate over all
 *    the CIDR blocks in the IPSet 'ipset'.  Return 0 on success,
 *    non-zero otherwise.
 */
int
skIPTreeCIDRBlockIteratorBind(
    skIPTreeCIDRBlockIterator_t    *iter,
    const skIPTree_t               *ipset);


/**
 *    Create a new CIDR Block iterator at the address pointed to by
 *    'out_iter' and bind it to iterate over all the CIDR Blocks in
 *    the IPSet 'ipset'.  Return 0 on success, non-zero otherwise.
 */
int
skIPTreeCIDRBlockIteratorCreate(
    skIPTreeCIDRBlockIterator_t   **out_iter,
    const skIPTree_t               *ipset);


/**
 *    Destroy the iterator pointed to by 'out_iter'.  Does nothing if
 *    'out_iter' or the location it points to is NULL.
 */
#if 1
#define skIPTreeCIDRBlockIteratorDestroy skIPTreeIteratorDestroy
#else
void
skIPTreeCIDRBlockIteratorDestroy(
    skIPTreeCIDRBlockIterator_t   **out_iter);
#endif


/**
 *    If there are more CIDR Blocks in the IPSet, fill
 *    next CIDR Block pointer 'out_cidr' with that CIDR Block and
 *    return SK_ITERATOR_OK.  Otherwise, do not modify 'out_cidr'
 *    and return SK_ITERATOR_NO_MORE_ENTRIES.
 */
skIteratorStatus_t
skIPTreeCIDRBlockIteratorNext(
    skIPTreeCIDRBlock_t            *out_cidr,
    skIPTreeCIDRBlockIterator_t    *iter);


/**
 *    Reset the iterator 'iter' to begin looping through the entries
 *    in the IPSet again.
 */
#if 1
#define skIPTreeCIDRBlockIteratorReset skIPTreeIteratorReset
#else
void
skIPTreeCIDRBlockIteratorReset(
    skIPTreeCIDRBlockIterator_t    *iter);
#endif


#ifdef __cplusplus
}
#endif
#endif /* _IPTREE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
