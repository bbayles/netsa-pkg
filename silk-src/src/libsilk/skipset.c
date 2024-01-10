/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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
**  skipset.c
**
**    skipset.c provides a data structure for maintaining IP
**    addresses.  The implementation uses a Radix Tree (aka Patricia
**    Trie) to keep IP addresses and their prefixes.  The
**    implementation can support IPv4 or IPv6 addresses, though each
**    instance of an IPset can only hold one type of IP address.
**
**    skipset.c is a replacement for the skIPTree_t data structure
**    defined in iptree.c.
**
**    Mark Thomas
**    Febrary 2011
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skipset.c c3cb530920e1 2023-04-26 14:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include "skheader_priv.h"


/*
 *  IMPLEMENTATION
 *
 *    The IPset code for to represent an IPv6 IPset in memory is
 *    implemented as a type of Radix Tree (aka Patricia Tree), where
 *    internal members of the tree are "nodes" and the terminal
 *    members are "leaves".  Within an IPset instance, all nodes are
 *    allocated in one array, and all leaves are allocated in another
 *    array.  The Radix Tree is not binary; each node points to
 *    IPSET_NUM_CHILDREN other nodes or leaves, and NUM_BITS is the
 *    number of bits of an IP address that must be examined to
 *    determine which branch to follow from a node.
 *
 *    There is both an IPv4 and IPv6 version of the Radix Tree.  The
 *    IPv4 Radix tree was used until SiLK 3.6.0; at that point the
 *    in-core IPv4 tree reverted the IPTree format.  Using the IPv4
 *    Radix tree internally may be requested via an envvar.
 *
 *    The IPv4 node structure is given here and described below:
 *
 *    struct ipset_node_v4_st {
 *        uint32_t        child[IPSET_NUM_CHILDREN];
 *
 *        SET_BMAP_DECLARE(child_is_leaf, IPSET_NUM_CHILDREN);
 *
 *        SET_BMAP_DECLARE(child_repeated, IPSET_NUM_CHILDREN);
 *
 *        uint8_t         prefix;
 *
 *        // reserved/unsed bytes
 *        uint8_t         reserved3;
 *        uint8_t         reserved2;
 *        uint8_t         reserved1;
 *
 *        uint32_t        ip;
 *    };
 *
 *    Each node has an 'ip' member to hold a complete IP address; a
 *    'prefix' value in the node says how many of the bits in that IP
 *    address are valid.  The IP/prefix on a node provides the lower
 *    and upper bounds for the CIDR blocks of the children of the
 *    node.  The prefix of a node will always be an even multiple of
 *    the NUM_BITS value of the IPset.
 *
 *    IPv4 addresses are stored as uint32_t's in native byte order.
 *    IPv6 addresses are stored as an ipset_ipv6_t, which contains 2
 *    uint64_t's in native byte order.  The 'ip' value appears at the
 *    bottom of the node, so that the layout of IPv4 nodes and IPv6
 *    nodes (ipset_node_v6_st) are identical except for the IP.
 *
 *    Instead of nodes having pointers to other nodes or leaves, nodes
 *    contain the 'child[]' array of integer values that are indexes
 *    into either the array of nodes or the array of leaves.  Since a
 *    given index may refer to either the node array or the leaf
 *    array, nodes also contain the 'child_is_leaf' bitmap that says
 *    which array the index references.
 *
 *    If a node points to a leaf where the leaf's prefix is
 *    numerically less than (node->prefix + NUM_BITS), then more than
 *    one child[] entry will point to the same leaf index.  When this
 *    occurs, the lowest entry in the child[] array that points to
 *    this leaf is considered the "real" entry, and the other indexes
 *    to this leaf in child[] will also have their bit set within the
 *    'child_repeated' bitmap on the node.
 *
 *    Assume an IPset where NUM_BITS is set to 4, so that each node
 *    points to 16 children.  Also assume a node that contains
 *    2.0.0.0/8.  If the child[] array points to any nodes, the prefix
 *    on those nodes must not be larger than a /12 (that is, the value
 *    of the prefix must be 12 or numerically greater).  Suppose the
 *    IPset contains the value 2.32.0.0/11.  child[2] and child[3]
 *    will both contain the index of the leaf; bits 2 and 3 of the
 *    'child_is_leaf' bitmap will be set, and bit 3 of the
 *    'child_repeated' bitmap will be set.
 *
 *    When a node is removed from the IPset such that it is no longer
 *    needed, the node is added to a 'free_list' of nodes, which is
 *    maintained by the IPset.  The list is implemented as a stack,
 *    where child[0] of each node contains the index of the previous
 *    node in the stack.  The index zero is reserved to mean the
 *    free_list is empty.
 *
 *    The structure of the leaf for IPv4 is given here:
 *
 *    struct ipset_leaf_v4_st {
 *        uint8_t         prefix;
 *
 *        // reserved/unsed bytes
 *        uint8_t         reserved3;
 *        uint8_t         reserved2;
 *        uint8_t         reserved1;
 *
 *        uint32_t        ip;
 *    };
 *
 *    The leaf contains only the IP and the prefix.
 *
 *    The IPset also maintains a 'free_list' of leaves that is
 *    maintained as a stack.  For leaves, the 'ip' member is used as
 *    the index to the previous leaf in the stack.
 *
 *    If an IPset is marked as 'clean', the array of leaves contains
 *    the leaves in sorted order.  This allows for fast iteration over
 *    the leaves of the IPset and allows streaming of the IPset.
 *    Additional properties of a 'clean' IPset are (a)Contiguous
 *    leaves have been combined to contain the largest possible CIDR
 *    block, (b)The leaves array contains no holes (that is, the
 *    'free_list' of leaves is empty), and (c)The nodes array contains
 *    no holes.
 *
 *    An IPset can be made clean by calling skIPSetClean(); some
 *    operations on the IPset require that the set be clean before it
 *    can be operated on.
 *
 *    The root of the tree can be any node or leaf.  The index of the
 *    root is specified in the skipset_t structure.  The skipset_t
 *    structure also contains a flag denoting whether the index is a
 *    node or a leaf.
 *
 *    The on-disk storage may match the in-core storage.  This would
 *    allow us to mmap() the data section of the file when reading a
 *    set---as long as the set is in native byte order and the data
 *    section is not compressed.
 *
 *
 *    The IPset structure is currently optimized to hold large CIDR
 *    blocks.  When a large number of widely spaced individual IPs are
 *    given, the size of the IPset will explode, since each IP is
 *    represented by an ipset_leaf_vX_t structure that is twice as
 *    large as the individual IP address.  We need to allow some way
 *    for the leaves of the IPset to hold multiple IPs.  For example,
 *    if the leaves held a bitmap of which IPs were set.
 *
 *
 */


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Set to non-zero to print a message to stderr whenever the
 *    radix-tree buffer is (re-)allocated.
 */
/* #define TRACE_ALLOC 1 */
#ifndef TRACE_ALLOC
#define TRACE_ALLOC 0
#endif

/*
 *    The numeric id of the initial format of an IPset file.  This
 *    format is only capable of holding IPv4 addresses.
 *
 *    IPs are stored on disk in blocks of nine 32-bit words which
 *    represent a /24.  The first uint32_t (position [0]) is the base
 *    IP of the /24 (a.b.c.0); the remaining eight uint32_t's are a
 *    256-bit bitmap that represents the IPs in that /24.  Each
 *    uint32_t is a /27.  A high bit indicates the address is present.
 *    The least significant bit in position [1] is a.b.c.0, and the
 *    most significant bit in position [8] is a.b.c.255.
 *
 *    The /24s in the file appear in sorted order.  All values are
 *    written to the file in native byte order.
 *
 *    No header entry is associated with this format.
 *
 *    Note: Very early IPset files did not properly set the version,
 *    and pre-SiLK 1.0 files that have a version number of 0 or 1 are
 *    identical to version 2.
 */
#define IPSET_REC_VERSION_CLASSC            2

/*
 *    The numeric id of the IPset file format introduced in SiLK-3.0.
 *    Files in this format may store either IPv4 or IPv6 addresses (a
 *    header entry specifies which).
 *
 *    This version contains a dump of the radix-tree data structure
 *    that is used in-memory.  The reasoning behind this was that the
 *    data could be mmap()ed directly from disk without having to read
 *    the file into memory.  For this to work, the file's data must
 *    not be compressed, the byte-order of the file must match the
 *    machine's byte-order, and the stream must be seekable (not
 *    standard input).
 *
 *    The radix data structure maintains the (interior) nodes separate
 *    from the leaves.  In the output stream, all nodes are written
 *    first, then the leaves.  The leaves are sorted by IP before
 *    being written, and the first leaf in the output stream does not
 *    contain data.  An individual leaf is 8 octets for IPv4 and 24
 *    octets for IPv6.  For IPv4, a leaf contains the CIDR prefix in
 *    the first octet, three empty octets, and the 32-bit IPv4 address
 *    in native byte order.  For IPv6, a leaf contains the CIDR prefix
 *    in the first octet, seven(!) empty octets, followed by two
 *    unsigned 64-bit numbers is native byte order.  The first 64-bit
 *    number contains the upper 8 octets of the IPv6 address, and the
 *    second number contains the lower 8 octets.
 *
 *    The file has a header entry that may be used to determine
 *    whether the file contains IPv4 or IPv6 addresses.  The contents
 *    of the header are the number of children per node, the number of
 *    leaves, the size of a leaf, the number of (interior) nodes, the
 *    size of a node, and the location of the root node.  The leaf
 *    size is 8 for IPv4 and 24 for IPv6.
 *
 *    All IPv4 IPsets were written in this format between SiLK 3.0.0
 *    and SiLK 3.5.1.  SiLK 3.6.0 reverted to using
 *    IPSET_REC_VERSION_CLASSC files for IPv4 IPsets.
 */
#define IPSET_REC_VERSION_RADIX             3

/*
 *    The numeric id of the IPset file format introduced in SiLK-3.7.
 *    The file may contain either IPv4 or IPv6 addresses (a header
 *    entry specifies which).
 *
 *    This format is not the default in order that previous releases
 *    of the SiLK 3.x series may read IPsets created by the default
 *    configuration of this release.
 *
 *    IP addresses are stored as "blocks".  Each block starts with an
 *    IP address and a single unsigned octet value.  If the single
 *    octet is less than or equal to 0x80, that is the end of the
 *    block.  The IP address is the base address of a netblock and the
 *    single octet is the CIDR mask for the netblock.
 *
 *    If the octet is strictly greater than 0x80, the address is the
 *    base address for a bitmap.  The value of 0x81 means the bitmap
 *    has 256 bits containing a /24 in IPv4 or a /120 in IPv6.  These
 *    bitmaps are similar to those in IPSET_REC_VERSION_CLASSC.
 *
 *    The IPs in the file appear in sorted order.  IPv4 addresses and
 *    values in the bitmap are written in native byte order.  IPv6
 *    addresses are stored as an array of 16 uint8_t's in network byte
 *    order.
 *
 *    The file has a header entry that may be used to determine
 *    whether the file contains IPv4 or IPv6 addresses.  The header
 *    entry is identical with that used by IPSET_REC_VERSION_RADIX.
 *    All fields are 0 except for the leaf length field.  The leaf
 *    length is 4 for files containing IPv4 addresses and 16 for files
 *    containing IPv6.
 */
#define IPSET_REC_VERSION_CIDRBMAP          4

/*
 *    The numeric id of the IPset file format introduced in SiLK-3.14.
 *    The file may contain only IPv6 addresses.
 *
 *    This format is not the default in order that previous releases
 *    of the SiLK 3.x series may read IPsets created by the default
 *    configuration of this release.
 *
 *    IP addresses are split into two 64 bit values, and they may be
 *    viewed as being on a two level tree, where the upper 64 bits
 *    appear on one level and the lower 64 bits on the other.  Each 64
 *    bit value is followed by a single byte.  When the IP represents
 *    a /64 or larger (more IPs), the block is represented by a single
 *    64 bit value and the prefix; all other IPs are represented by
 *    two 64 bit values.  For IPs in the same /64, the upper 64 bit
 *    value appears once followed by 0x82.  Next are the lower 64 bits
 *    of all the IPs in that /64.  Each lower IP is followed either by
 *    a value between 0 and 0x80 indicating the prefix of the netblock
 *    or the value 0x81 indicating that a 256-bit bitmap follows for
 *    the IPs in that /120, similar to IPSET_REC_VERSION_CIDRBMAP and
 *    IPSET_REC_VERSION_CLASSC.
 *
 *    The IPs appear in sorted order.  All values are written in
 *    native byte order.
 *
 *    Although the file format contains only IPv6 addresses, there is
 *    a header entry that confirms this.  The header entry is
 *    identical to that used by IPSET_REC_VERSION_RADIX.  All fields
 *    are 0 except for the leaf length field.  The expected leaf
 *    length is 16.
 */
#define IPSET_REC_VERSION_SLASH64           5

/*
 *    Ideas for the IPset file formats of the future:
 *
 *    Separate IPv4 addresses from IPv6 to save 12 bytes per IPv4
 *    address.
 *
 *    Instead of intermixing single IPs, bitmaps, and CIDR blocks in
 *    one list (with an extra byte per address to specify what type
 *    type of thing it is), separate the three types of things into
 *    three separate lists.
 *
 *    Disadvantage of both of these changes is that the addresses in
 *    the file are no longer sorted.
 */

/*
 *    This record version tells the writer to
 *    IPSET_REC_VERSION_DEFAULT_IPV4 for IPv4 IPsets and
 *    IPSET_REC_VERSION_DEFAULT_IPV6 for IPv6 IPsets.
 */
#define IPSET_REC_VERSION_DEFAULT           0

/*
 *    When writing a IPset that contains IPv4 addresses, this is the
 *    default version file format to use.
 */
#if     !defined(SK_IPSET_DEFAULT_VERSION)
#define IPSET_REC_VERSION_DEFAULT_IPV4      IPSET_REC_VERSION_CLASSC
#elif   SK_IPSET_DEFAULT_VERSION == 5
#define IPSET_REC_VERSION_DEFAULT_IPV4      IPSET_REC_VERSION_CIDRBMAP
#elif   SK_IPSET_DEFAULT_VERSION == 4
#define IPSET_REC_VERSION_DEFAULT_IPV4      IPSET_REC_VERSION_CIDRBMAP
#else
#define IPSET_REC_VERSION_DEFAULT_IPV4      IPSET_REC_VERSION_CLASSC
#endif

/*
 *    When writing a IPset that contains IPv6 addresses, this is the
 *    default version file format to use.
 */
#if     !defined(SK_IPSET_DEFAULT_VERSION)
#define IPSET_REC_VERSION_DEFAULT_IPV6      IPSET_REC_VERSION_RADIX
#elif   SK_IPSET_DEFAULT_VERSION == 5
#define IPSET_REC_VERSION_DEFAULT_IPV6      IPSET_REC_VERSION_SLASH64
#elif   SK_IPSET_DEFAULT_VERSION == 4
#define IPSET_REC_VERSION_DEFAULT_IPV6      IPSET_REC_VERSION_CIDRBMAP
#else
#define IPSET_REC_VERSION_DEFAULT_IPV6      IPSET_REC_VERSION_RADIX
#endif

/*
 *    Minimum file version available
 */
#define IPSET_REC_VERSION_MIN               IPSET_REC_VERSION_DEFAULT

/*
 *    Maximum file version available
 */
#define IPSET_REC_VERSION_MAX               IPSET_REC_VERSION_SLASH64

/*
 *    Name of an environment variable that, when set, is used in place
 *    of IPSET_REC_VERSION_DEFAULT.  This is advertised.
 */
#define IPSET_REC_VERSION_ENVAR             "SILK_IPSET_RECORD_VERSION"

/*
 *    Name of an environment variable used to determine how
 *    IPv4-IPsets are represented internally.  Legal values are
 *    "iptree" for the SiLK-2 IPTree structure and "radix" for the
 *    Radix-Tree structure.  Not intended for end users.  Used by
 *    IPSET_USE_IPTREE and ipset_use_iptree.
 */
#define IPSET_ENVAR_INCORE_FORMAT           "SKIPSET_INCORE_FORMAT"

/*
 *    Name of an environment variable used to force the Radix-tree to
 *    print, to standard error, its structure when it is destoryed.
 *    Not intended for end users.
 */
#define IPSET_ENVAR_DESTROY_PRINT           "SKIPSET_DESTROY_PRINT"


/*
 *    Whether to use the IPTree or Radix-Tree data structure for
 *    in-memory IPv4-IPsets.  Uses the environment variable specified
 *    by the IPSET_ENVAR_INCORE_FORMAT macro.
 */
#define IPSET_USE_IPTREE                                                \
    (ipset_use_iptree >= 0 ? ipset_use_iptree : ipsetCheckFormatEnvar())

/*
 *    Default value for IPSET_USE_IPTREE if the envar is not set.  See
 *    the 'ipset_use_iptree' variable below.
 */
#define IPSET_USE_IPTREE_DEFAULT           1

/* Number of nodes/leaves to create initially in the radix tree */
#define  IPSET_INITIAL_ENTRY_COUNT       2048

/* After the radix tree array contains this number of nodes/leaves,
 * grow by adding this many more nodes/leaves to the current size. */
#define  IPSET_GROW_LINEARLY         0x100000

/* Number of bits if IP to examine when branching at a node */
#define  NUM_BITS  4

/* Number of children in each interior node */
#define  IPSET_NUM_CHILDREN         (1 << NUM_BITS)

/* Number of uint32_t's required to hold a bitmap of
 * IPSET_NUM_CHILDREN bits */
#define  BITMAP_SIZE_NUM_CHILDREN               \
    ((IPSET_NUM_CHILDREN + 31) >> 5)

/* Number of bytes in an IPv6 address */
#define  IPSET_LEN_V6  16

/* Number of bytes in an IPv4 address */
#define  IPSET_LEN_V4   4

/* The library uses recursion in few places, and instead maintains a
 * stack of nodes; this constant is the required depth of the
 * stack.  */
#define  IPSET_MAX_DEPTH_V4                                             \
    (IPSET_NUM_CHILDREN * (1 + ((IPSET_LEN_V4 * CHAR_BIT) / NUM_BITS)))
#define  IPSET_MAX_DEPTH_V6                                             \
    (IPSET_NUM_CHILDREN * (1 + ((IPSET_LEN_V6 * CHAR_BIT) / NUM_BITS)))
#if SK_ENABLE_IPV6
#  define IPSET_MAX_DEPTH  IPSET_MAX_DEPTH_V6
#else
#  define IPSET_MAX_DEPTH  IPSET_MAX_DEPTH_V4
#endif  /* SK_ENABLE_IPV6 */

/* Index of first leaf when iterating over the leaves in a clean IPset */
#define IPSET_LINK_LIST_ANCHOR         1
#define IPSET_ITER_FIRST_LEAF          1

/* Magic parent_idx value to denote that ipsetFindVx() returned the
 * root of the tree */
#define IPSET_NO_PARENT                UINT32_MAX

/* Return the root index for an IPset */
#define IPSET_ROOT_INDEX(iri_set)      ((iri_set)->s.v3->root_idx)

/* Return a non-zero value if the root index references a leaf */
#define IPSET_ROOT_IS_LEAF(iril_set)   ((iril_set)->s.v3->root_is_leaf)

/* Set the root index of the IPset */
#define IPSET_ROOT_INDEX_SET(iris_set, iris_index, iris_is_leaf)        \
    {                                                                   \
        ((iris_set)->s.v3->root_idx) = (iris_index);                    \
        ((iris_set)->s.v3->root_is_leaf) = (iris_is_leaf);              \
    }

/* Is the IPset empty? */
#define IPSET_ISEMPTY(iie_ipset)                \
    (0 == (iie_ipset)->s.v3->nodes.entry_count)

/* Helper macro to get the node at 'ge_index' */
#define GET_ENTRY(ge_buf, ge_index)                     \
    (&((ge_buf).buf[(ge_buf).entry_size * (ge_index)]))

/* Get the node at position 'np_index' and cast to correct type */
#define NODE_PTR(np_set, np_index)                              \
    ((ipset_node_t*)GET_ENTRY((np_set)->s.v3->nodes, np_index))

#define NODE_PTR_V4(np_set, np_index)                                   \
    (&(((ipset_node_v4_t*)((np_set)->s.v3->nodes.buf))[(np_index)]))

#define NODE_PTR_V6(np_set, np_index)                                   \
    (&(((ipset_node_v6_t*)((np_set)->s.v3->nodes.buf))[(np_index)]))

/* Get the member of the node structure to use when handling nodes on
 * the free list */
#define NODEPTR_FREE_LIST(npmfl_node)           \
    ((npmfl_node)->v4.child[0])
#define NODEIDX_FREE_LIST(nimfl_set, nimfl_nodeidx)             \
    NODEPTR_FREE_LIST(NODE_PTR((nimfl_set), (nimfl_nodeidx)))

/* "Free" the node at position 'nf_index' by pusing onto free list */
#define NODEIDX_FREE(nf_set, nf_index)                  \
    {                                                   \
        NODEIDX_FREE_LIST((nf_set), (nf_index))         \
            = (nf_set)->s.v3->nodes.free_list;          \
        (nf_set)->s.v3->nodes.free_list = (nf_index);   \
    }

/* Get the leaf at position 'np_index' and cast to correct type */
#define LEAF_PTR(np_set, np_index)                                      \
    ((ipset_leaf_t*)GET_ENTRY((np_set)->s.v3->leaves, np_index))

#define LEAF_PTR_V4(np_set, np_index)                                   \
    (&(((ipset_leaf_v4_t*)((np_set)->s.v3->leaves.buf))[(np_index)]))

#define LEAF_PTR_V6(np_set, np_index)                                   \
    (&(((ipset_leaf_v6_t*)((np_set)->s.v3->leaves.buf))[(np_index)]))

/* Get the member of the leaf structure to use for handling leaves on
 * the free list */
#define LEAFPTR_FREE_LIST(lpmfl_leaf)           \
    ((lpmfl_leaf)->v4.ip)
#define LEAFIDX_FREE_LIST(limfl_set, limfl_leafidx)             \
    LEAFPTR_FREE_LIST(LEAF_PTR((limfl_set), (limfl_leafidx)))

/* "Free" the leaf at position 'lf_index' by pushing onto free list */
#define LEAFIDX_FREE(lf_set, lf_index)                  \
    {                                                   \
        LEAFIDX_FREE_LIST((lf_set), (lf_index))         \
            = (lf_set)->s.v3->leaves.free_list;         \
        (lf_set)->s.v3->leaves.free_list = (lf_index);  \
    }


/* Return a non-zero value if the child at index position 'ncil_pos'
 * on the node 'ncil_node' is a leaf.  'ncil_node' must be an
 * ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_IS_LEAF(ncil_node, ncil_pos)              \
    SET_BMAP_GET((ncil_node)->child_is_leaf, (ncil_pos))

/* Similar to NODEPTR_CHILD_IS_LEAF(), but specifies whether the child
 * at 'ncir_pos' is a repeat of the child to its left---which may also
 * be a repeat of the child to its left, etc. */
#define NODEPTR_CHILD_IS_REPEAT(ncir_node, ncir_pos)            \
    SET_BMAP_GET((ncir_node)->child_repeated, (ncir_pos))

/* Specify that the child at index position 'ncsl_pos' on the node
 * 'ncsl_node' is a leaf not a node.  'ncsl_node' must an
 * ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_SET_LEAF(ncsl_node, ncsl_pos)             \
    SET_BMAP_SET((ncsl_node)->child_is_leaf, (ncsl_pos))

/* Specify that the child at index position 'nccl_pos' on the node
 * 'nccl_node' is NOT a leaf.  'nccl_node' must an
 * ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_CLEAR_LEAF(nccl_node, nccl_pos)           \
    SET_BMAP_CLEAR((nccl_node)->child_is_leaf, (nccl_pos))

/* Specify that the children between index position 'ncsl_pos1' and
 * 'ncsl_pos2' on the node 'ncsl_node' are leaves.  'ncsl_node' must
 * an ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_SET_LEAF2(ncsl_node, ncsl_pos1, ncsl_pos2)        \
    SET_BMAP_RANGE_SET((ncsl_node)->child_is_leaf, (ncsl_pos1), (ncsl_pos2))

/* Specify that the children between index position 'nccl_pos1' and
 * 'nccl_pos2' on the node 'nccl_node' are NOT leaves.  'nccl_node'
 * must an ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_CLEAR_LEAF2(nccl_node, nccl_pos1, nccl_pos2)      \
    SET_BMAP_RANGE_CLEAR((nccl_node)->child_is_leaf, (nccl_pos1), (nccl_pos2))

/* Specify that the child at index position 'ncsr_pos' on the node
 * 'ncsr_node' is a repeat of the child to its left.  'ncsr_node' must
 * an ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_SET_REPEAT(ncsr_node, ncsr_pos)           \
    SET_BMAP_SET((ncsr_node)->child_repeated, (ncsr_pos))

/* Specify the the children between index position 'ncsr_pos1' and
 * 'ncsr_pos2' on the node 'ncsr_node' are leaves.  'ncsr_node' must
 * an ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_SET_REPEAT2(ncsr_node, ncsr_pos1, ncsr_pos2)      \
    SET_BMAP_RANGE_SET((ncsr_node)->child_repeated, (ncsr_pos1), (ncsr_pos2))

/* Specify that the child at index position 'nccr_pos' on the node
 * 'nccr_node' is NOT a repeat.  'nccr_node' must an
 * ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_CLEAR_REPEAT(nccr_node, nccr_pos)         \
    SET_BMAP_CLEAR((nccr_node)->child_repeated, (nccr_pos))

/* Specify that the children between index position 'nccr_pos1' and
 * 'nccr_pos2' on the node 'nccr_node' are NOT repeats.  'nccr_node'
 * must an ipset_node_v{4,6}_t, not a generic ipset_node_t. */
#define NODEPTR_CHILD_CLEAR_REPEAT2(nccr_node, nccr_pos1, nccr_pos2)    \
    SET_BMAP_RANGE_CLEAR((nccr_node)->child_repeated, (nccr_pos1), (nccr_pos2))



/* Ensure that an IPset is in-core.  If required, it calls the
 * function to change an mmap()ed IPset to an in-core IPset */
#define IPSET_COPY_ON_WRITE(cow_ipset)                          \
    if (!(cow_ipset)->s.v3->mapped_file) { /* no-op */ } else { \
        int cow_rv = ipsetCopyOnWrite(cow_ipset);               \
        if (cow_rv) {                                           \
            return cow_rv;                                      \
        }                                                       \
    }

/* If the leaf buffer was reallocated, check to see if any leaves can
 * be reclaimed by combining adjacent CIDR blocks */
#define IPSET_MAYBE_COMBINE(mc_ipset)                           \
    if (!(mc_ipset)->s.v3->realloc_leaves) { /*no-op*/ } else { \
        ipsetCombineAdjacentCIDR(mc_ipset);                     \
        (mc_ipset)->s.v3->realloc_leaves = 0;                   \
    }


/* Macros for checking and manipulating the bitmaps on the
 * ipset_node_vX_t structures. */
#define SET_BMAP_DECLARE(sbd_map, sbd_size)     \
    BITMAP_DECLARE(sbd_map, sbd_size)

#define SET_BMAP_SET(sbs_map, sbs_pos)          \
    BITMAP_SETBIT(sbs_map, sbs_pos)

#define SET_BMAP_GET(sbg_map, sbg_pos)          \
    BITMAP_GETBIT(sbg_map, sbg_pos)

#define SET_BMAP_CLEAR(sbc_map, sbc_pos)        \
    BITMAP_CLEARBIT(sbc_map, sbc_pos)

#define SET_BMAP_CLEAR_ALL(sbca_map)            \
    BITMAP_INIT(sbca_map)

#if BITMAP_SIZE_NUM_CHILDREN == 1

#define SET_BMAP_RANGE_SET(sbrs_map, sbrs_beg, sbrs_end)                \
    SET_MASKED_BITS((sbrs_map)[_BMAP_INDEX(sbrs_beg)], UINT32_MAX,      \
                    (sbrs_beg) & 0x1F, 1+(sbrs_end)-(sbrs_beg))

#define SET_BMAP_RANGE_CLEAR(sbrs_map, sbrs_beg, sbrs_end)      \
    SET_MASKED_BITS((sbrs_map)[_BMAP_INDEX(sbrs_beg)], 0,       \
                    (sbrs_beg) & 0x1F, 1+(sbrs_end)-(sbrs_beg))

#else  /* #if BITMAP_SIZE_NUM_CHILDREN == 1 */

#define SET_BMAP_RANGE_SET(sbrs_map, sbrs_beg, sbrs_end)                \
    do {                                                                \
        uint32_t sbrs_i = _BMAP_INDEX(sbrs_beg);                        \
        uint32_t sbrs_j = _BMAP_INDEX(sbrs_end);                        \
        if (sbrs_i == sbrs_j) {                                         \
            /* single word */                                           \
            SET_MASKED_BITS((sbrs_map)[sbrs_i], UINT32_MAX,             \
                            (sbrs_beg) & 0x1F, 1+(sbrs_end)-(sbrs_beg)); \
        } else {                                                        \
            SET_MASKED_BITS((sbrs_map)[sbrs_i], UINT32_MAX,             \
                            (sbrs_beg) & 0x1F, 32-((sbrs_beg) & 0x1F)); \
            ++sbrs_i;                                                   \
            memset(&(sbrs_map)[sbrs_i], 0xFF,                           \
                   (sbrs_j - sbrs_i) * sizeof(uint32_t));               \
            SET_MASKED_BITS((sbrs_map)[sbrs_j], UINT32_MAX,             \
                            0, 1 + ((sbrs_end) & 0x1F));                \
        }                                                               \
    } while(0)

#define SET_BMAP_RANGE_CLEAR(sbrs_map, sbrs_beg, sbrs_end)              \
    do {                                                                \
        uint32_t sbrs_i = _BMAP_INDEX(sbrs_beg);                        \
        uint32_t sbrs_j = _BMAP_INDEX(sbrs_end);                        \
        if (sbrs_i == sbrs_j) {                                         \
            /* single word */                                           \
            SET_MASKED_BITS((sbrs_map)[sbrs_i], 0,                      \
                            (sbrs_beg) & 0x1F, 1+(sbrs_end)-(sbrs_beg)); \
        } else {                                                        \
            SET_MASKED_BITS((sbrs_map)[sbrs_i], 0,                      \
                            (sbrs_beg) & 0x1F, 32-((sbrs_beg) & 0x1F)); \
            ++sbrs_i;                                                   \
            memset(&(sbrs_map)[sbrs_i], 0,                              \
                   (sbrs_j - sbrs_i) * sizeof(uint32_t));               \
            SET_MASKED_BITS((sbrs_map)[sbrs_j], 0,                      \
                            0, 1 + ((sbrs_end) & 0x1F));                \
        }                                                               \
    } while(0)

#endif  /* #else of BITMAP_SIZE_NUM_CHILDREN == 1 */


/* Given an IPv4 address of a child and the prefix of the node holding
 * that child, return the index of child[] where the address
 * belongs */
#define WHICH_CHILD_V4(wc_ip, wc_prefix)                                \
    (((wc_ip) >> (32 - NUM_BITS - ((wc_prefix) & ~(NUM_BITS - 1))))     \
     & ((1u << NUM_BITS) - 1))

#if   NUM_BITS == 3
#elif NUM_BITS == 5
#elif NUM_BITS == 7
#else
#define WHICH_CHILD_V6(wc_ip, wc_prefix)                        \
    (((wc_prefix) >= 64)                                        \
     ? (((wc_ip)->ip[1]                                         \
         >> (128 - NUM_BITS - ((wc_prefix) & ~(NUM_BITS - 1)))) \
        & ((1u << NUM_BITS) - 1))                               \
     : (((wc_ip)->ip[0]                                         \
         >> (64 - NUM_BITS - ((wc_prefix) & ~(NUM_BITS - 1))))  \
        & ((1u << NUM_BITS) - 1)))
#endif


/* Convert from an IPv6 skipaddr_t 'aviv_addr' to ipset_ipv6_t
 * 'aviv_ip' */
#define IPSET_IPV6_FROM_ADDRV6(aviv_ip, aviv_addr6)     \
    {                                                   \
        skipaddrGetV6((aviv_addr6), (aviv_ip));         \
        (aviv_ip)->ip[0] = ntoh64((aviv_ip)->ip[0]);    \
        (aviv_ip)->ip[1] = ntoh64((aviv_ip)->ip[1]);    \
    }

/* Convert from an IPv4 skipaddr_t 'aviv_addr' to ipset_ipv6_t 'aviv_ip' */
#define IPSET_IPV6_FROM_ADDRV4(aviv_ip, aviv_addr4)     \
    {                                                   \
        skipaddrGetAsV6((aviv_addr4), (aviv_ip));       \
        (aviv_ip)->ip[0] = ntoh64((aviv_ip)->ip[0]);    \
        (aviv_ip)->ip[1] = ntoh64((aviv_ip)->ip[1]);    \
    }

/* Convert from ipset_ipv6_t 'aviv_ip' to an IPv6 skipaddr_t 'aviv_addr' */
#define IPSET_IPV6_TO_ADDR(aviv_ip, aviv_addr)          \
    {                                                   \
        ipset_ipv6_t aviv_tmp;                          \
        aviv_tmp.ip[0] = hton64((aviv_ip)->ip[0]);      \
        aviv_tmp.ip[1] = hton64((aviv_ip)->ip[1]);      \
        skipaddrSetV6((aviv_addr), &aviv_tmp);          \
    }

/* Convert from ipset_ipv6_t 'aviv_ip' to an IPv4 skipaddr_t 'aviv_addr' */
#define IPSET_IPV6_TO_ADDR_V4(aviv_ip, aviv_addr)                       \
    {                                                                   \
        uint32_t aviv_ipv4;                                             \
        assert(0 == (aviv_ip)->ip[0]);                                  \
        assert(UINT64_C(0x0000ffff00000000)                             \
               == (UINT64_C(0xffffffff00000000) & (aviv_ip)->ip[1]));   \
        aviv_ipv4 = (uint32_t)(UINT64_C(0x00000000ffffffff)             \
                               & (aviv_ip)->ip[1]);                     \
        skipaddrSetV4((aviv_addr), &aviv_ipv4);                         \
    }

/* Convert from ipset_ipv6_t 'aviv_ip' to an array[16] of uint8_t
 * 'aviv_array' */
#define IPSET_IPV6_TO_ARRAY(aviv_ip, aviv_array)                \
    {                                                           \
        ipset_ipv6_t aviv_tmp;                                  \
        aviv_tmp.ip[0] = hton64((aviv_ip)->ip[0]);              \
        aviv_tmp.ip[1] = hton64((aviv_ip)->ip[1]);              \
        memcpy((aviv_array), &aviv_tmp, IPSET_LEN_V6);          \
    }

/* Convert from an array[16] of uint8_t 'aviv_array' to an
 * ipset_ipv6_t 'aviv_ip' */
#define IPSET_IPV6_FROM_ARRAY(aviv_ip, aviv_array)              \
    {                                                           \
        ipset_ipv6_t aviv_tmp;                                  \
        memcpy(&aviv_tmp, (aviv_array), IPSET_LEN_V6);          \
        (aviv_ip)->ip[0] = hton64(aviv_tmp.ip[0]);              \
        (aviv_ip)->ip[1] = hton64(aviv_tmp.ip[1]);              \
    }

/* Copy an 'ipset_ipv6_t' */
#define IPSET_IPV6_COPY(ipc_dest, ipc_src)      \
    memcpy(ipc_dest, ipc_src, IPSET_LEN_V6)

/* Apply netblock mask 'ipac_prefix' to the ipset_ipv6_t 'ipac_ip' */
#define IPSET_IPV6_APPLY_CIDR(ipac_ip, ipac_prefix)                     \
    if ((ipac_prefix) > 64) {                                           \
        (ipac_ip)->ip[1] &= ~(UINT64_MAX >> ((ipac_prefix) - 64));      \
    } else {                                                            \
        (ipac_ip)->ip[1] = 0;                                           \
        if ((ipac_prefix) < 64) {                                       \
            (ipac_ip)->ip[0] &= ~(UINT64_MAX >> (ipac_prefix));         \
        }                                                               \
    }

/* Copy an 'ipset_ipv6_t' and apply the CIDR mask */
#define IPSET_IPV6_COPY_AND_MASK(ipcam_dest, ipcam_src, ipcam_prefix)   \
    if ((ipcam_prefix) > 64) {                                          \
        (ipcam_dest)->ip[0] = (ipcam_src)->ip[0];                       \
        (ipcam_dest)->ip[1] = ((ipcam_src)->ip[1]                       \
                               & ~(UINT64_MAX >> ((ipcam_prefix)-64))); \
    } else if ((ipcam_prefix) == 64) {                                  \
        (ipcam_dest)->ip[0] = (ipcam_src)->ip[0];                       \
        (ipcam_dest)->ip[1] = 0;                                        \
    } else {                                                            \
        (ipcam_dest)->ip[0] = ((ipcam_src)->ip[0]                       \
                               & ~(UINT64_MAX >> (ipcam_prefix)));      \
        (ipcam_dest)->ip[1] = 0;                                        \
    }

/* Return true if 'ipset_ipv6_t' is 0 */
#define IPSET_IPV6_IS_ZERO(ipiz)                        \
    ((0 == (ipiz)->ip[0]) && (0 == (ipiz)->ip[1]))

/* Set 'mb_result_ptr' to the number of leading 0 bits in
 * 'mb_expression', a 32 bit value */
#define COUNT_MATCHING_BITS32(mb_result_ptr, mb_expression)     \
    {                                                           \
        uint32_t t1, t2;                                        \
        t1 = (mb_expression);                                   \
        t2 = t1 >> 16;                                          \
        if (t2) {                                               \
            t1 = t2 >> 8;                                       \
            *(mb_result_ptr) = (t1                              \
                                ? bit_diff_offset[t1]           \
                                : (8 + bit_diff_offset[t2]));   \
        } else {                                                \
            t2 = t1 >> 8;                                       \
            *(mb_result_ptr) = (t2                              \
                                ? (16 + bit_diff_offset[t2])    \
                                : (24 + bit_diff_offset[t1]));  \
        }                                                       \
    }

/* Set 'mb_result_ptr' to the number of leading 0 bits in
 * 'mb_expression', a 64 bit value */
#define COUNT_MATCHING_BITS64(mb_result_ptr, mb_expression)             \
    {                                                                   \
        uint64_t t1, t2;                                                \
        t2 = (mb_expression);                                           \
        t1 = t2 >> 32;                                                  \
        if (t1) {                                                       \
            t2 = t1 >> 16;                                              \
            if (t2) {                                                   \
                t1 = t2 >> 8;                                           \
                *(mb_result_ptr) = (t1                                  \
                                    ? bit_diff_offset[t1]               \
                                    : (8 + bit_diff_offset[t2]));       \
            } else {                                                    \
                t2 = t1 >> 8;                                           \
                *(mb_result_ptr) = (t2                                  \
                                    ? (16 + bit_diff_offset[t2])        \
                                    : (24 + bit_diff_offset[t1]));      \
            }                                                           \
        } else {                                                        \
            t1 = t2 >> 16;                                              \
            if (t1) {                                                   \
                t2 = t1 >> 8;                                           \
                *(mb_result_ptr) = (t2                                  \
                                    ? (32 + bit_diff_offset[t2])        \
                                    : (40 + bit_diff_offset[t1]));      \
            } else {                                                    \
                t1 = t2 >> 8;                                           \
                *(mb_result_ptr) = (t1                                  \
                                    ? (48 + bit_diff_offset[t1])        \
                                    : (56 + bit_diff_offset[t2]));      \
            }                                                           \
        }                                                               \
    }


/* In IPSET_REC_VERSION_CIDRBMAP and IPSET_REC_VERSION_SLASH64 files,
 * mapping from the 'prefix' byte to size of the bitmap */
#define SET_CIDRBMAP_MAP256     0x81

/* In IPSET_REC_VERSION_SLASH64, value that indicates this 64bit value
 * starts a new /64. */
#define SET_SLASH64_IS_SLASH64  0x82


#if   !defined(NUM_BITS)
#  error "NUM_BITS must be defined"
#elif NUM_BITS <= 0
#  errror "NUM_BITS must be > 0"
#endif


/* Macros used by the SiLK-2 (IPTree) version of IPsets */

/*  The number of uint32_t values for each /24.  Value is computed by
 *  ((1 << 8) / (1 << 5)) ==> (1 << 3) ==> 8 */
#define IPTREE_WORDS_PER_SLASH24  8

/*
 *    NOTE: Must be called on the IPTree pointer, not the IPset.
 *
 *    NOTE: May cause the function that uses it to return.
 *
 *    If the IPTree 'iptree' has a node for 'high16' where 'high16'
 *    are the 16 most significant bits of an IPv4 address, do nothing.
 *    Otherwise, attempt to allocate the node and position the node in
 *    the tree.  If the allocation fail, this macro causes the
 *    function return SKIPSET_ERR_ALLOC to the caller.
 */
#define IPTREE_NODE_ALLOC(iptree, high16)                       \
    if ((iptree)->nodes[(high16)]) { /*no-op*/ } else {         \
        (iptree)->nodes[(high16)]                               \
            = (skIPNode_t*)calloc(1, sizeof(skIPNode_t));       \
        if (NULL == (iptree)->nodes[(high16)]) {                \
            return SKIPSET_ERR_ALLOC;                           \
        }                                                       \
    }

#ifdef   NDEBUG
#define  ASSERT_OK(func_call)  func_call
#else
#define  ASSERT_OK(func_call)                   \
    {                                           \
        int assert_ok = func_call;              \
        assert(0 == assert_ok);                 \
    }
#endif


/* define an ipv6 address type */
typedef struct ipset_ipv6_st {
    uint64_t ip[2];
} ipset_ipv6_t;

/* Forward declare the node types */
typedef struct ipset_node_v4_st ipset_node_v4_t;
typedef struct ipset_node_v6_st ipset_node_v6_t;
typedef union ipset_node_un ipset_node_t;

typedef struct ipset_leaf_v4_st ipset_leaf_v4_t;
typedef struct ipset_leaf_v6_st ipset_leaf_v6_t;
typedef union ipset_leaf_un ipset_leaf_t;

typedef struct ipset_buffer_st {
    uint8_t        *buf;
    /* the size of an entry in the array */
    size_t          entry_size;
    /* the number of nodes in the array of entries. bytes allocated is
     * given by (entry_capacity * entry_size). */
    uint32_t        entry_capacity;
    /* maximum index used in the array.  this is not the number of
     * valid entries since it also includes nodes on the free-list. */
    uint32_t        entry_count;
    /* location of first available element in free-list, or 0 if empty */
    uint32_t        free_list;
} ipset_buffer_t;


/* THE IPSET Structure as of SiLK 3 */
typedef struct skipset_v3_st {
    /* pointer to mmap()ed file */
    void                       *mapped_file;
    /* the size of the mmap()ed space */
    size_t                      mapped_size;
    /* structures to hold the nodes and leaves */
    ipset_buffer_t              nodes;
    ipset_buffer_t              leaves;
    /* location of the root of tree; may be a node or a leaf; which it
     * is is given by the root_is_leaf member below */
    uint32_t                    root_idx;
    /* whether root_idx is a leaf or a node */
    unsigned                    root_is_leaf :1;
    /* whether changes to tree caused the "leaves" buffer to be
     * reallocated */
    unsigned                    realloc_leaves :1;
} skipset_v3_t;

/* A COMMON IPSET Structure */
struct skipset_st {
    /* options used when writing an IPset */
    const skipset_options_t    *options;
    /* which pointer to use in this union depends on the setting of
     * the 'is_iptree' member */
    union body_un {
        skipset_v3_t   *v3;
        skIPTree_t     *v2;
    }                           s;
    /* whether the 's' member holds a SiLK-3 IPset (==0) or a SiLK-2
     * IPTree (==1).  See also 'is_ipv6'. */
    unsigned                    is_iptree :1;
    /* whether the SiLK-3 IPset holds IPv6 addresses.  When this is 1,
     * the 'is_iptree' member must be 0. */
    unsigned                    is_ipv6 :1;
    /* whether the tree has changed since last call to skIPSetClean() */
    unsigned                    is_dirty:1;
    /* whether an attempt to insert an IPv6 address into an IPv4 tree
     * should returnan error.  when this is 0, the tree will
     * automatically be converted to IPv6. */
    unsigned                    no_autoconvert :1;
};



/* IPSET NODE */

/* The nodes of a tree hold either IPv4 or IPv6 addresses.  The
 * structures are indentical except for the IP address, which allows
 * safe access to all non-IP elements. */

struct ipset_node_v4_st {
    /* index of the children, which may be nodes or leaves. for a node
     * on free_list, child[0] is the next of the next node on the
     * free_list */
    uint32_t        child[IPSET_NUM_CHILDREN];

    /* bitmap that specifies whether a child[] refers to another node
     * or to a leaf. */
    SET_BMAP_DECLARE(child_is_leaf, IPSET_NUM_CHILDREN);

    /* bitmap that specifies whether a child[] is a repeat of the
     * child to its left.  this is used when a leaf's prefix is larger
     * (holds more IPs) than node->prefix + NUM_BITS. */
    SET_BMAP_DECLARE(child_repeated, IPSET_NUM_CHILDREN);

    /* prefix is number of significant bits in the IP; on the nodes,
     * prefix is the number of bits to compare before deciding which
     * child[] to branch to. */
    uint8_t         prefix;

    /* reserved/unsed bytes */
    uint8_t         reserved3;
    uint8_t         reserved2;
    uint8_t         reserved1;

    /* IP address */
    uint32_t        ip;
};

struct ipset_node_v6_st {
    uint32_t        child[IPSET_NUM_CHILDREN];

    SET_BMAP_DECLARE(child_is_leaf, IPSET_NUM_CHILDREN);
    SET_BMAP_DECLARE(child_repeated, IPSET_NUM_CHILDREN);

    uint8_t         prefix;
    uint8_t         reserved3;
    uint8_t         reserved2;
    uint8_t         reserved1;

#if SK_ENABLE_IPV6
    uint32_t        pad_align;
    ipset_ipv6_t    ip;
#else
    uint32_t        ip;
#endif  /* SK_ENABLE_IPV6 */
};

/* A generic "node" pointer */
/* from above: typedef union ipset_node_un ipset_node_t; */
union ipset_node_un {
    ipset_node_v6_t v6;
    ipset_node_v4_t v4;
};


/*  IPSET LEAF  */

struct ipset_leaf_v4_st {
    /* prefix is number of significant bits in the IP. */
    uint8_t         prefix;
    /* reserved/unused bytes */
    uint8_t         reserved3;
    uint8_t         reserved2;
    uint8_t         reserved1;

    /* IP address */
    uint32_t        ip;
};

struct ipset_leaf_v6_st {
    uint8_t         prefix;
    uint8_t         reserved3;
    uint8_t         reserved2;
    uint8_t         reserved1;

#if SK_ENABLE_IPV6
    uint32_t        pad_align;
    ipset_ipv6_t    ip;
#else
    uint32_t        ip;
#endif
};

/* A generic "leaf" pointer */
/* from above: typedef union ipset_leaf_un ipset_leaf_t; */
union ipset_leaf_un {
    ipset_leaf_v6_t v6;
    ipset_leaf_v4_t v4;
};

/* Support structure for counting the IPs in an IPset, used by
 * skIPSetCount() and ipsetCountCallbackV*() */
typedef struct ipset_count_st {
    uint64_t    lower;
    uint64_t    upper;
    uint64_t    full;
} ipset_count_t;

/* Support structure for ipsetFind() */
typedef struct ipset_find_st {
    uint32_t    parent_idx;
    uint32_t    node_idx;
    uint32_t    parents_child;
    int         result;
    uint8_t     bitpos;
    uint8_t     node_is_leaf;
} ipset_find_t;

/* Support structure for intersecting two IPsets; used by
 * skIPSetIntersect() and ipsetIntersectCallback() */
typedef struct ipset_intersect_st {
    skipaddr_t          addr[2];
    sk_vector_t        *vec_add;
    skipset_iterator_t  iter;
} ipset_intersect_t;

/* Support structure for printing the IPs in an IPset, used by
 * skIPSetPrint() and ipsetPrintCallback() */
typedef struct ipset_print_st {
    const skipset_t    *ipset;
    skstream_t         *stream;
    skipaddr_flags_t    ip_format;
} ipset_print_t;

typedef int (ipset_walk_v4_fn_t)(
    uint32_t            ipv4,
    uint32_t            prefix,
    void               *cb_data);

typedef int (ipset_walk_v6_fn_t)(
    const ipset_ipv6_t *ipv6,
    uint32_t            prefix,
    void               *cb_data);


/* Support structure for walking over the IPset */
typedef struct ipset_walk_st {
    /* user function to invoke for each IP/CIDR block */
    skipset_walk_fn_t   callback;
    /* user-provided data to pass to the callback */
    void               *cb_data;
    /* how to handle IP addresses */
    sk_ipv6policy_t     v6policy;
    /* whether to return CIDR blocks (1) or individual IPs (0).  (This
     * may eventually become the maximum size block to return.) */
    uint8_t             cidr_blocks;
} ipset_walk_t;

/* Support strucuture for writing a SiLK-3 IPset in the SiLK-2 file
 * format; used by ipsetWriteClasscFromRadix() and
 * ipsetWriteClasscFromRadixCallback(). */
typedef struct ipset_write_silk2_st {
    /* the stream to write to */
    skstream_t *stream;
    /* the current /24 is in buffer[0]; remaining values are a bitmap
     * of addresses for that /24. */
    uint32_t    buffer[1+IPTREE_WORDS_PER_SLASH24];
    /* true when the buffer contains valid data */
    unsigned    buffer_is_dirty :1;
} ipset_write_silk2_t;


/*  SILK-2 IPTREE FORMAT */

/*
 *    Prior to SiLK 3.0.0, the in-memory structure used to represent
 *    IPsets was the skIPTree_t.  This structure is still used to
 *    represent IPsets that contain only IPv4 addresses.
 *
 *    The skIPTree_t consists of a 64k pointers, each of which is
 *    either NULL or a pointer to a node, the skIPNode_t.  A node
 *    contains 64k bits for marking the addresses in an IPset.  The
 *    bitmap is represented as an array of uint32_t, where each
 *    uint32_t maps to a /27.  Dividing 64k by 32 means there are 2k
 *    uint32_t's.
 */
typedef struct skIPNode_st skIPNode_t;

/*
 *    Number of skIPNode_t's in an skIPTree_t.
 */
#define SKIP_BBLOCK_COUNT   65536

/*
 *    Number of uint32_t's in an skIPNode_t.
 */
#define SKIP_BBLOCK_SIZE    2048

/* skIPTree_t */
struct skIPTree_st {
    skIPNode_t *nodes[SKIP_BBLOCK_COUNT];
};
/* typedef struct skIPTree_st skIPTree_t;  // skipset.h */

/* skIPNode_t */
struct skIPNode_st {
    uint32_t    addressBlock[SKIP_BBLOCK_SIZE];
};

/*
 *    Check for bit 'lower16' in 'node'.  The value in 'lower16' must
 *    be the 16 least significant bits of an address; 'node' is the
 *    skIPNode_t for the 16 most significant bits of the address.
 */
#define IPTREE_NODE_CHECK_BIT(m_node, m_lower16)                              \
    ((m_node)->addressBlock[(m_lower16) >> 5] & (1 << ((m_lower16) & 0x1F)))

/*
 *    Return TRUE if 'addr' is set on tree 'iptree'; FALSE otherwise
 */
#define IPTREE_CHECK_ADDRESS(m_iptree, m_addr)                  \
    ((m_iptree)->nodes[(m_addr) >> 16]                          \
     && IPTREE_NODE_CHECK_BIT((m_iptree)->nodes[(m_addr)>>16],  \
                              ((m_addr) & 0xFFFF)))


/*  HEADER ENTRY */

/*
 *    sk_hentry_ipset_t is an in-memory representation of a streams's
 *    header entry that describes the IPset data structure.  It is
 *    present in IPset version 3, version 4, and version 5 files.
 */
struct sk_hentry_ipset_st {
    sk_header_entry_spec_t  he_spec;
    uint32_t                child_node;
    uint32_t                leaf_count;
    uint32_t                leaf_size;
    uint32_t                node_count;
    uint32_t                node_size;
    uint32_t                root_idx;
};
typedef struct sk_hentry_ipset_st sk_hentry_ipset_t;


/*  IPSET OPTIONS  */

enum ipset_options_en {
    OPT_IPSET_INVOCATION_STRIP,
    /* record-version is handled separately; it must be last */
    OPT_IPSET_RECORD_VERSION
};
static const struct option ipset_options[] = {
    {"invocation-strip",    NO_ARG,       0, OPT_IPSET_INVOCATION_STRIP},
    {0, 0, 0, 0}            /* sentinel entry */
};
static const char *ipset_options_help[] = {
    "Strip invocation history from the IPset file. Def. no",
    (char*)NULL
};

static const char *ipset_options_record_version_default_name =
    "record-version";

static struct option ipset_options_record_version[] = {
    {NULL,                  REQUIRED_ARG, 0, OPT_IPSET_RECORD_VERSION},
    {0, 0, 0, 0}            /* sentinel entry */
};


/* LOCAL VARIABLE DEFINITIONS */

/*
 *    Whether to use the IPTree or Radix-Tree data structure for
 *    in-memory IPv4-IPsets.  Used by IPSET_USE_IPTREE.  This is -1 if
 *    the value has not been initialized; 0 for RADIX, and 1 for
 *    IPTREE.  See ipsetCheckFormatEnvar().
 */
static int ipset_use_iptree = -1;

/* for handling IPset files Version 2 and Version 4 */
static const uint32_t bmap256_zero[IPTREE_WORDS_PER_SLASH24] =
    {0, 0, 0, 0, 0, 0, 0, 0};
static const uint32_t bmap256_full[IPTREE_WORDS_PER_SLASH24] =
    {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
     UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};

/* this is used to find which bit of two uint8_t's differ. */
static const uint8_t bit_diff_offset[256] =
{
    /*   0- 15 */  8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
    /*  16- 31 */  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    /*  32- 47 */  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /*  48- 63 */  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /*  64- 79 */  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /*  80- 95 */  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /*  96-111 */  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 112-127 */  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 128-143 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 144-159 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 160-175 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 176-191 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 192-207 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 208-223 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 224-239 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    /* 240-255 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* LOCAL FUNCTION PROTOTYPES */

static int
ipsetCheckFormatEnvar(
    void);
static int
ipsetCreate(
    skipset_t         **ipset_out,
    int                 support_ipv6,
    int                 force_radix);
static void
ipsetDestroySubtree(
    skipset_t          *ipset,
    uint32_t            destroy_node_idx,
    int                 destroy_self);
static int
ipsetFindV4(
    const skipset_t    *ipset,
    const uint32_t      ipv4,
    const uint32_t      prefix,
    ipset_find_t       *find_state);
#if SK_ENABLE_IPV6
static int
ipsetFindV6(
    const skipset_t    *ipset,
    const ipset_ipv6_t *ipv6,
    const uint32_t      prefix,
    ipset_find_t       *find_state);
#endif
static sk_header_entry_t *
ipsetHentryCreate(
    uint32_t            child_node,
    uint32_t            leaf_count,
    uint32_t            leaf_size,
    uint32_t            node_count,
    uint32_t            node_size,
    uint32_t            root_idx);
static void
ipsetHentryFree(
    sk_header_entry_t  *hentry);
static int
ipsetNewEntries(
    skipset_t          *ipset,
    uint32_t            num_nodes,
    uint32_t            num_leaves,
    uint32_t           *node_indexes,
    uint32_t           *leaf_indexes);
static int
ipsetProcessStreamCallback(
    const ipset_ipv6_t *v6_start,
    const uint32_t     *v4_start,
    uint32_t            prefix,
    ipset_walk_t       *proc_stream_state);
static void
ipsetReadStrerrror(
    skstream_t         *stream,
    const char         *format,
    ...)
    SK_CHECK_PRINTF(2, 3);
static uint32_t
ipsetReplaceNodeWithLeaf(
    skipset_t          *ipset,
    ipset_node_t       *parent,
    uint32_t            which_child);
static int
ipsetVerify(
    const skipset_t    *ipset);


/* FUNCTION DEFINITIONS */

/*
 *  status = ipsetAllocEntries(ibuf, new_cap);
 *
 *    Grow or shink the entries list in 'ibuf' to hold 'new_cap'
 *    nodes.  If 'new_cap' is 0, the size of the current array is
 *    doubled unless the current array size is IPSET_GROW_LINEARLY or
 *    greater in which case an additional IPSET_GROW_LINEARLY elements
 *    are added.  If no memory is currently allocated, an array of
 *    IPSET_INITIAL_ENTRY_COUNT nodes is allocated.
 *
 *    Return 0 on success, or SKIPSET_ERR_ALLOC if memory cannot be
 *    allocated.
 */
static int
ipsetAllocEntries(
    ipset_buffer_t     *ibuf,
    size_t              new_cap)
{
    size_t old_cap;
    uint8_t *old_entries;

#if     !defined(TRACE_ALLOC) || !TRACE_ALLOC
#define ALLOC_TRACEMSG(old_size, new_size)
#else
#define ALLOC_TRACEMSG(old_size, new_size)                      \
    fprintf(stderr, ("%s:%d: growing memory capacity from"      \
                     " %" SK_PRIuZ " to %" SK_PRIuZ "\n"),      \
            __FILE__, __LINE__, (old_size), (new_size))
#endif

    assert(ibuf);

    /* the current capacity of the tree */
    old_cap = ibuf->entry_capacity;

    /* handle empty tree */
    if (0 == old_cap) {
        if (0 == new_cap) {
            new_cap = IPSET_INITIAL_ENTRY_COUNT;
        }
        /* allocate new memory */
        ALLOC_TRACEMSG((size_t)0, new_cap);
        ibuf->buf = (uint8_t*)calloc(new_cap, ibuf->entry_size);
        if (NULL == ibuf->buf) {
            return SKIPSET_ERR_ALLOC;
        }
        ibuf->entry_capacity = new_cap;
        return 0;
    }

    /* handle case where no new capacity is specified */
    if (new_cap) {
        ALLOC_TRACEMSG(old_cap, new_cap);
    } else {
        if (old_cap >= IPSET_GROW_LINEARLY) {
            new_cap = old_cap + IPSET_GROW_LINEARLY;
            ALLOC_TRACEMSG(old_cap, new_cap);
        } else if (old_cap < (IPSET_INITIAL_ENTRY_COUNT >> 1)) {
            new_cap = IPSET_INITIAL_ENTRY_COUNT;
            ALLOC_TRACEMSG(old_cap, new_cap);
        } else {
            new_cap = 2 * old_cap;
            ALLOC_TRACEMSG(old_cap, new_cap);
        }
    }

    if (new_cap > SIZE_MAX / ibuf->entry_size) {
        return SKIPSET_ERR_ALLOC;
    }

    /* realloc */
    old_entries = ibuf->buf;
    ibuf->buf = (uint8_t*)realloc(old_entries, (new_cap * ibuf->entry_size));
    /* handle failure */
    if (NULL == ibuf->buf) {
        ibuf->buf = old_entries;
        return SKIPSET_ERR_ALLOC;
    }

    /* bzero the new memory */
    if (old_cap < new_cap) {
        memset((ibuf->buf + (old_cap * ibuf->entry_size)),
               0, ((new_cap - old_cap) * ibuf->entry_size));
    }

    ibuf->entry_capacity = new_cap;
    return 0;
}


/*
 *  use_iptree = ipsetCheckFormatEnvar();
 *
 *    Check the value of the environment variable specified by the
 *    IPSET_ENVAR_INCORE_FORMAT macro and set the global
 *    'ipset_use_iptree' variable appropriately.  If the envar is not
 *    set, set 'ipset_use_iptree' to the default structure specified
 *    by IPSET_USE_IPTREE_DEFAULT.
 */
static int
ipsetCheckFormatEnvar(
    void)
{
    const char *envar;

    if (ipset_use_iptree >= 0) {
        return ipset_use_iptree;
    }
    envar = getenv(IPSET_ENVAR_INCORE_FORMAT);
    if (envar) {
        if (0 == strcasecmp("iptree", envar)) {
            ipset_use_iptree = 1;
            return ipset_use_iptree;
        }
        if (0 == strcasecmp("radix", envar)) {
            ipset_use_iptree = 0;
            return ipset_use_iptree;
        }
    }
    ipset_use_iptree = IPSET_USE_IPTREE_DEFAULT;
    return ipset_use_iptree;
}


/*
 *  status = ipsetCheckIPSetCallbackV4(ipaddr, prefix, ipset);
 *  status = ipsetCheckIPSetCallbackV6(ipaddr, prefix, ipset);
 *
 *    Callback functions used by skIPSetCheckIPSet().
 *
 *    Check whether the 'ipaddr'/'prefix' is in 'ipset'.  If it is
 *    not, return SKIPSET_OK so iteration continues.  Otherwise,
 *    return SKIPSET_ERR_SUBSET so iteration stops.
 */
static int
ipsetCheckIPSetCallbackV4(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_search_set)
{
    uint32_t ipv4;

    if (skipaddrGetAsV4(ipaddr, &ipv4)) {
        return SKIPSET_OK;
    }
    switch (ipsetFindV4((const skipset_t*)v_search_set, ipv4, prefix, NULL)) {
      case SKIPSET_OK:
      case SKIPSET_ERR_SUBSET:
        return SKIPSET_ERR_SUBSET;
      default:
        break;
    }
    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetCheckIPSetCallbackV6(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_search_set)
{
    ipset_ipv6_t ipv6;

    IPSET_IPV6_FROM_ADDRV6(&ipv6, ipaddr);

    switch (ipsetFindV6((const skipset_t*)v_search_set, &ipv6, prefix, NULL)) {
      case SKIPSET_OK:
      case SKIPSET_ERR_SUBSET:
        return SKIPSET_ERR_SUBSET;
      default:
        break;
    }
    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Helper function for skIPSetCheckIPSet() when both IPsets are
 *    implmented by a SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeCheckIntersectIPTree().
 */
static int
ipsetCheckIPSetIPTree(
    const skIPTree_t   *ipset1,
    const skIPTree_t   *ipset2)
{
    unsigned int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        /* check for intersection at the /16 level */
        if ((NULL == ipset1->nodes[i]) || (NULL == ipset2->nodes[i])) {
            /* do nothing */

        } else {
            /* Need to intersect the bits in the /16 */
            for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                if (ipset1->nodes[i]->addressBlock[j]
                    & ipset2->nodes[i]->addressBlock[j])
                {
                    return 1;
                }
            }
        }
    }

    /* no intersesction */
    return 0;
}


/*
 *    Helper function for skIPSetCheckIPWildcard() when the IPset is
 *    implmented by a SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeCheckIntersectIPWildcard().
 */
static int
ipsetCheckWildcardIPTree(
    const skIPTree_t       *ipset,
    const skIPWildcard_t   *ipwild)
{
    /* for a description of 'prefix_as_bits', see
     * ipsetInsertAddressIPTree() */
    const uint32_t prefix_as_bits[] = {
        0xFFFFFFFF, 0xFFFF, 0xFF, 0xF, 0x3, 0x1
    };
    skIPWildcardIterator_t iter;
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

        if (prefix <= 16) {
            ipv4_end = ((UINT32_MAX >> prefix) | ipv4) >> 16;
            ipv4 >>= 16;
            do {
                if (ipset->nodes[ipv4]) {
                    /* assumes any non-NULL IPTree node contains at
                     * least one high bit */
                    return 1;
                }
            } while (ipv4++ < ipv4_end);

        } else if (NULL == ipset->nodes[ipv4 >> 16]) {
            /* no intersection */

        } else if (prefix >= 27) {
            if (ipset->nodes[ipv4 >> 16]->addressBlock[(ipv4 & 0xFFFF)>>5]
                    & (prefix_as_bits[prefix - 27] << ((ipv4) & 0x1F)))
            {
                return 1;
            }

        } else {
            /* 16 < prefix < 27 */
            if (memcmp(&ipset->nodes[ipv4>>16]->addressBlock[(ipv4&0xFFFF)>>5],
                       &empty_node, (sizeof(skIPNode_t) >> (prefix - 16))))
            {
                return 1;
            }
        }
    }

    /* no intersesction */
    return 0;
}


/*
 *  ipsetCombineSubtreeV4(ipset, parent_idx, node_idx, which_child);
 *  ipsetCombineSubtreeV6(ipset, parent_idx, node_idx, which_child);
 *
 *    Helper function for ipsetCombineAdjacentCIDR().
 *
 *    Reduce the number of nodes used in the 'ipset' by combining
 *    nodes that form a contiguous block into a larger block and by
 *    removing nodes that contain a single leaf.
 *
 *    The algorithm uses a recursive, depth first traversal from
 *    'node_idx'.
 *
 *    The 'node_idx' passed into this function must not be a leaf
 *    node.
 */
static void
ipsetCombineSubtreeV4(
    skipset_t          *ipset,
    uint32_t            parent_idx,
    uint32_t            node_idx,
    uint32_t            which_child)
{
    ipset_node_v4_t *parent;
    ipset_node_v4_t *node;
    ipset_leaf_v4_t *leaf1;
    ipset_leaf_v4_t *leaf2;
    uint32_t first_child;
    uint32_t last_child;
    uint32_t child[IPSET_NUM_CHILDREN];
    uint32_t depth;
    uint32_t i;
    uint32_t j;

#ifndef NDEBUG
    assert(node_idx < ipset->s.v3->nodes.entry_count);
    if (parent_idx != IPSET_NO_PARENT) {
        node = NODE_PTR_V4(ipset, parent_idx);
        assert(which_child < IPSET_NUM_CHILDREN);
        assert(node->child[which_child] == node_idx);
        assert(!NODEPTR_CHILD_IS_LEAF(node, which_child));
    }
#endif  /* NDEBUG */

    /* note the position of the first and last child on the node so we
     * can later determine whether all children on this node point to
     * the same leaf. */
    first_child = IPSET_NUM_CHILDREN;
    last_child = IPSET_NUM_CHILDREN;

    /* the child[] array is a stack of child positions waiting to be
     * merged into a larger contiguous block if possible.  depth is
     * the index into the child[] array. */
    depth = 0;

    node = NODE_PTR_V4(ipset, node_idx);

    /* find child in highest position */
    for (i = IPSET_NUM_CHILDREN; i > 0; ) {
        --i;
        if (node->child[i]) {
            last_child = i;
            break;
        }
    }

    if (IPSET_NUM_CHILDREN == last_child) {
        /* node has no children!! */
        if (IPSET_NO_PARENT == parent_idx) {
            skIPSetRemoveAll(ipset);
        } else {
            assert(which_child < IPSET_NUM_CHILDREN);
            parent = NODE_PTR_V4(ipset, parent_idx);
            parent->child[which_child] = 0;
        }
        return;
    }

    do {
        if (0 == node->child[i]) {
            /* not contiguous */
            depth = 0;
            continue;
        }
        assert(NODEPTR_CHILD_IS_LEAF(node, i)
               ? (node->child[i] < ipset->s.v3->leaves.entry_count)
               : (node->child[i] < ipset->s.v3->nodes.entry_count));
        if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
            continue;
        }
        first_child = i;
        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
            ipsetCombineSubtreeV4(ipset, node_idx, node->child[i], i);
            if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                depth = 0;
                continue;
            }
        }
        if ((0 == depth) || (i & 0x1)) {
            child[depth++] = i;
            continue;
        }
        while (depth) {
            /* for two leaves to be joinable, they must have the same
             * prefix and the XOR of their values must be less than
             * the IP range covered by the proposed prefix, which is
             * one less than the current prefix. */
            leaf1 = LEAF_PTR_V4(ipset, node->child[i]);
            leaf2 = LEAF_PTR_V4(ipset, node->child[child[depth-1]]);
            assert(leaf1->prefix > 0);
            assert(leaf1->prefix <= 32);
            if (leaf1->prefix != leaf2->prefix
                || ((leaf1->ip ^ leaf2->ip) >= (1u << (33 - leaf1->prefix))))
            {
                /* cannot be joined */
                break;
            }

            /* combine these two leaves */
            --leaf1->prefix;
            leaf1->ip &= ~(UINT32_MAX >> leaf1->prefix);
            j = child[depth-1];
            LEAFIDX_FREE(ipset, node->child[j]);
            NODEPTR_CHILD_SET_REPEAT2(node, i+1, j);
            do {
                node->child[j] = node->child[i];
                ++j;
            } while (j < IPSET_NUM_CHILDREN
                     && NODEPTR_CHILD_IS_REPEAT(node, j));
            --depth;
        }
        child[depth++] = i;

    } while (i-- > 0);

    if (node->child[first_child] != node->child[last_child]
        || !NODEPTR_CHILD_IS_LEAF(node, first_child)
        || !NODEPTR_CHILD_IS_LEAF(node, last_child))
    {
        return;
    }

    /* replace the node with the leaf */
    if (IPSET_NO_PARENT == parent_idx) {
        IPSET_ROOT_INDEX_SET(ipset, node->child[first_child], 1);
    } else {
        assert(which_child < IPSET_NUM_CHILDREN);
        parent = NODE_PTR_V4(ipset, parent_idx);
        parent->child[which_child] = node->child[first_child];
        SET_BMAP_SET(parent->child_is_leaf, which_child);
    }
    NODEIDX_FREE(ipset, node_idx);
}

#if SK_ENABLE_IPV6
static void
ipsetCombineSubtreeV6(
    skipset_t          *ipset,
    uint32_t            parent_idx,
    uint32_t            node_idx,
    uint32_t            which_child)
{
    ipset_node_v6_t *parent;
    ipset_node_v6_t *node;
    ipset_leaf_v6_t *leaf1;
    ipset_leaf_v6_t *leaf2;
    uint32_t first_child;
    uint32_t last_child;
    uint32_t child[IPSET_NUM_CHILDREN];
    uint32_t depth;
    uint32_t i;
    uint32_t j;

#ifndef NDEBUG
    assert(node_idx < ipset->s.v3->nodes.entry_count);
    if (parent_idx != IPSET_NO_PARENT) {
        node = NODE_PTR_V6(ipset, parent_idx);
        assert(which_child < IPSET_NUM_CHILDREN);
        assert(node->child[which_child] == node_idx);
        assert(!NODEPTR_CHILD_IS_LEAF(node, which_child));
    }
#endif  /* NDEBUG */

    /* note the position of the first and last child on the node so we
     * can later determine whether all children on this node point to
     * the same leaf. */
    first_child = IPSET_NUM_CHILDREN;
    last_child = IPSET_NUM_CHILDREN;

    /* the child[] array is a stack of child positions waiting to be
     * merged into a larger contiguous block if possible.  depth is
     * the index into the child[] array. */
    depth = 0;

    node = NODE_PTR_V6(ipset, node_idx);

    /* find child in highest position */
    for (i = IPSET_NUM_CHILDREN; i > 0; ) {
        --i;
        if (node->child[i]) {
            last_child = i;
            break;
        }
    }

    if (IPSET_NUM_CHILDREN == last_child) {
        /* node has no children!! */
        if (IPSET_NO_PARENT == parent_idx) {
            skIPSetRemoveAll(ipset);
        } else {
            assert(which_child < IPSET_NUM_CHILDREN);
            parent = NODE_PTR_V6(ipset, parent_idx);
            parent->child[which_child] = 0;
        }
        return;
    }

    do {
        if (0 == node->child[i]) {
            depth = 0;
            continue;
        }
        assert(NODEPTR_CHILD_IS_LEAF(node, i)
               ? (node->child[i] < ipset->s.v3->leaves.entry_count)
               : (node->child[i] < ipset->s.v3->nodes.entry_count));
        if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
            continue;
        }
        first_child = i;
        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
            ipsetCombineSubtreeV6(ipset, node_idx, node->child[i], i);
            if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                depth = 0;
                continue;
            }
        }
        if ((0 == depth) || (i & 0x1)) {
            child[depth++] = i;
            continue;
        }
        while (depth) {
            /* for two leaves to be joinable, the must have the same
             * prefix and the XOR of their values must be less than 1
             * shifted by the proposed prefix subtracted from 32,
             * where the proposed prefix is one less than the current
             * prefix. */
            leaf1 = LEAF_PTR_V6(ipset, node->child[i]);
            leaf2 = LEAF_PTR_V6(ipset, node->child[child[depth-1]]);
            if (leaf1->prefix != leaf2->prefix) {
                break;
            }
            assert(leaf1->prefix > 0);
            assert(leaf1->prefix <= 128);
            if (leaf1->prefix <= 64) {
                /* this change affects the most significant 64 bits */
                if ((leaf1->ip.ip[0] ^ leaf2->ip.ip[0])
                    >= (UINT64_C(1) << (65 - leaf1->prefix)))
                {
                    /* cannot be joined */
                    break;
                }
                /* combine these two leaves */
                --leaf1->prefix;
                leaf1->ip.ip[0] &= ~(UINT64_MAX >> leaf1->prefix);
            } else if (leaf1->prefix == 65) {
                /* this change affects the least significant 64 bits */
                if (leaf1->ip.ip[0] != leaf2->ip.ip[0]) {
                    /* cannot be joined. */
                    break;
                }
                /* a prefix of 65 must succeed, since the ranges must
                 * be W:X:Y:Z:0::/65 and W:X:Y:Z:8000::/65 */
                --leaf1->prefix;
                leaf1->ip.ip[1] = 0;
            } else {
                /* this change affects the least significant 64 bits */
                if ((leaf1->ip.ip[0] != leaf2->ip.ip[0])
                    || ((leaf1->ip.ip[1] ^ leaf2->ip.ip[1])
                        >= (UINT64_C(1) << (129 - leaf1->prefix))))
                {
                    /* cannot be joined. */
                    break;
                }
                --leaf1->prefix;
                leaf1->ip.ip[1] &= ~(UINT64_MAX >> (leaf1->prefix - 64));
            }

            j = child[depth-1];
            LEAFIDX_FREE(ipset, node->child[j]);
            NODEPTR_CHILD_SET_REPEAT2(node, i+1, j);
            do {
                node->child[j] = node->child[i];
                ++j;
            } while (j < IPSET_NUM_CHILDREN
                     && NODEPTR_CHILD_IS_REPEAT(node, j));
            --depth;
        }
        child[depth++] = i;

    } while (i-- > 0);

    if (node->child[first_child] != node->child[last_child]
        || !NODEPTR_CHILD_IS_LEAF(node, first_child)
        || !NODEPTR_CHILD_IS_LEAF(node, last_child))
    {
        return;
    }

    /* replace the node with the leaf */
    if (IPSET_NO_PARENT == parent_idx) {
        IPSET_ROOT_INDEX_SET(ipset, node->child[first_child], 1);
    } else {
        assert(which_child < IPSET_NUM_CHILDREN);
        parent = NODE_PTR_V6(ipset, parent_idx);
        parent->child[which_child] = node->child[first_child];
        NODEPTR_CHILD_SET_LEAF(parent, which_child);
    }
    NODEIDX_FREE(ipset, node_idx);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  ipsetCombineAdjacentCIDR(ipset);
 *
 *    Visit the nodes in the tree looking for leaves that form a
 *    contiguous block of IPs.  When found, combine the leaves into a
 *    single leaf.  This will make reduce the size required by the
 *    tree.
 */
static void
ipsetCombineAdjacentCIDR(
    skipset_t          *ipset)
{
    if (!IPSET_ROOT_IS_LEAF(ipset)) {
#if SK_ENABLE_IPV6
        if (ipset->is_ipv6) {
            ipsetCombineSubtreeV6(ipset, IPSET_NO_PARENT,
                                  IPSET_ROOT_INDEX(ipset), IPSET_NUM_CHILDREN);
        } else
#endif  /* SK_ENABLE_IPV6 */
        {
            ipsetCombineSubtreeV4(ipset, IPSET_NO_PARENT,
                                  IPSET_ROOT_INDEX(ipset), IPSET_NUM_CHILDREN);
        }
    }
}


/*
 *  ipsetCompact(ipset);
 *
 *    Make the nodes and leaves arrays in the 'ipset' use contiguous
 *    blocks of memory.  Any holes in the arrays---represented by
 *    nodes/leaves in the free-list---will become occupied.  When this
 *    function returns, the memory will be contiguous and the free
 *    list will be empty.
 */
static void
ipsetCompact(
    skipset_t          *ipset)
{
    ipset_node_t *node;
    ipset_leaf_t *leaf;
    uint32_t nodes_in_use;
    uint32_t nodes_free_idx;
    uint32_t leaves_in_use;
    uint32_t leaves_free_idx;
    uint32_t to_visit[IPSET_MAX_DEPTH];
    uint32_t depth;
    int i;

    /* if the free lists are empty, the tree is compact */
    if (0 == ipset->s.v3->nodes.free_list
        && 0 == ipset->s.v3->leaves.free_list)
    {
        return;
    }

    /* handle a leaf at the root as a special case */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        /* values 1 and 2 due to node#0 and leaf#0 never used */
        nodes_in_use = 1;
        leaves_in_use = 2;
        if (IPSET_ROOT_INDEX(ipset) >= leaves_in_use) {
            leaves_free_idx = 1;
            /* copy the child to this location */
            memcpy(LEAF_PTR(ipset, leaves_free_idx),
                   LEAF_PTR(ipset, IPSET_ROOT_INDEX(ipset)),
                   ipset->s.v3->leaves.entry_size);
            /* update the root's pointer to the child */
            IPSET_ROOT_INDEX_SET(ipset, leaves_free_idx, 1);
        }
        goto CLEAR_MEMORY;
    }

    /* determine the number of nodes currently in use by subtracting
     * the nodes on the free list from the total number of nodes */
    nodes_in_use = ipset->s.v3->nodes.entry_count;
    for (nodes_free_idx = ipset->s.v3->nodes.free_list;
         0 != nodes_free_idx;
         nodes_free_idx = NODEPTR_FREE_LIST(node))
    {
        assert(nodes_free_idx < ipset->s.v3->nodes.entry_count);
        --nodes_in_use;
        node = NODE_PTR(ipset, nodes_free_idx);
    }
    if (ipset->s.v3->nodes.entry_count < nodes_in_use) {
        /* the only way for this to happen is for the nodes_in_use
         * value to underflow 0 */
        skAbort();
    }

    /* repeat the process for the leaves */
    leaves_in_use = ipset->s.v3->leaves.entry_count;
    for (leaves_free_idx = ipset->s.v3->leaves.free_list;
         0 != leaves_free_idx;
         leaves_free_idx = LEAFPTR_FREE_LIST(leaf))
    {
        assert(leaves_free_idx < ipset->s.v3->leaves.entry_count);
        --leaves_in_use;
        leaf = LEAF_PTR(ipset, leaves_free_idx);
    }
    if (ipset->s.v3->leaves.entry_count < leaves_in_use) {
        skAbort();
    }

    /* Since Node#0 and Leaf#0 are never used, nodes_in_use and
     * leaves_in_use can be 0 or they can be a value >= 2, but they
     * should never be 1. */
    /* However, I am leary of enabling these asserts.
     * assert(nodes_in_use != 1);
     * assert(leaves_in_use != 1);
     */

    /* handle the root */
    assert(0 == IPSET_ROOT_IS_LEAF(ipset));
    if (IPSET_ROOT_INDEX(ipset) >= nodes_in_use) {
        /* pop nodes from the free list until we find one smaller
         * than nodes_in_use. */
        do {
            nodes_free_idx = ipset->s.v3->nodes.free_list;
            ipset->s.v3->nodes.free_list
                = NODEIDX_FREE_LIST(ipset, nodes_free_idx);
        } while (nodes_free_idx >= nodes_in_use);
        assert(nodes_free_idx != 0);

        /* copy the child to the location we just popped
         * from the free_list */
        memcpy(NODE_PTR(ipset, nodes_free_idx),
               NODE_PTR(ipset, IPSET_ROOT_INDEX(ipset)),
               ipset->s.v3->nodes.entry_size);

        /* update the root's pointer to the child */
        IPSET_ROOT_INDEX_SET(ipset, nodes_free_idx, 0);
    }

    /* visit the nodes in the tree. */
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        node = NODE_PTR(ipset, to_visit[--depth]);

        /* if the indexes of the children of this node are larger than
         * 'nodes_in_use' or leaves_in_use', pop an entry from
         * the appropriate free-list and copy that child to the new
         * location.  handled just like the root. */
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if (node->v4.child[i]) {
                if (!NODEPTR_CHILD_IS_LEAF(&node->v4, i)) {
                    /* this is a node */
                    if (node->v4.child[i] >= nodes_in_use) {
                        do {
                            nodes_free_idx = ipset->s.v3->nodes.free_list;
                            ipset->s.v3->nodes.free_list
                                = NODEIDX_FREE_LIST(ipset, nodes_free_idx);
                        } while (nodes_free_idx >= nodes_in_use);
                        assert(nodes_free_idx != 0);
                        memcpy(NODE_PTR(ipset, nodes_free_idx),
                               NODE_PTR(ipset, node->v4.child[i]),
                               ipset->s.v3->nodes.entry_size);
                        node->v4.child[i] = nodes_free_idx;
                    }
                    /* we must visit this child */
                    assert(depth < IPSET_MAX_DEPTH - 1);
                    to_visit[depth++] = node->v4.child[i];

                } else {
                    /* this is a leaf: it is handled just slightly
                     * differently than a node */
                    if (node->v4.child[i] >= leaves_in_use) {
                        do {
                            leaves_free_idx = ipset->s.v3->leaves.free_list;
                            ipset->s.v3->leaves.free_list
                                = LEAFIDX_FREE_LIST(ipset, leaves_free_idx);
                        } while (leaves_free_idx >= leaves_in_use);
                        assert(leaves_free_idx != 0);
                        memcpy(LEAF_PTR(ipset, leaves_free_idx),
                               LEAF_PTR(ipset, node->v4.child[i]),
                               ipset->s.v3->leaves.entry_size);
                        node->v4.child[i] = leaves_free_idx;

                        /* handle repeated leaf */
                        while ((i < (IPSET_NUM_CHILDREN - 1))
                               && NODEPTR_CHILD_IS_REPEAT(&node->v4, i+1))
                        {
                            ++i;
                            node->v4.child[i] = leaves_free_idx;
                        }
                    }
                }
            }
        }
    }

  CLEAR_MEMORY:
    /* we have compacted the tree.  bzero the memory we just cleared,
     * set the entry_counts to the number of active entries, and reset
     * the free lists. */
    memset((ipset->s.v3->nodes.buf
            + (nodes_in_use * ipset->s.v3->nodes.entry_size)),
           0, ((ipset->s.v3->nodes.entry_count - nodes_in_use)
               * ipset->s.v3->nodes.entry_size));
    ipset->s.v3->nodes.entry_count = nodes_in_use;
    ipset->s.v3->nodes.free_list = 0;

    memset((ipset->s.v3->leaves.buf
            + (leaves_in_use * ipset->s.v3->leaves.entry_size)),
           0, ((ipset->s.v3->leaves.entry_count - leaves_in_use)
               * ipset->s.v3->leaves.entry_size));
    ipset->s.v3->leaves.entry_count = leaves_in_use;
    ipset->s.v3->leaves.free_list = 0;
}


#if SK_ENABLE_IPV6
/*
 *  status = ipsetConvertIPTreetoV6(ipset);
 *
 *    Convert the contents of a SiLK-2 based IPset (IPTree) to a
 *    SiLK-3 based IPv6 IPset.  The IPv4 addresses in the IPset will
 *    be mapped into the "::ffff:0.0.0.0/96" address space.  Return
 *    SKIPSET_OK on success, or SKIPSET_ERR_ALLOC if memory cannot be
 *    allocated to hold the IPv6 addresses.
 */
static int
ipsetConvertIPTreetoV6(
    skipset_t          *ipset)
{
    skIPTree_t *iptree;
    skipset_t *v6ipset;
    skipset_iterator_t iter;
    skipaddr_t ipaddr;
    uint32_t prefix;
    int rv;

    assert(ipset);
    assert(1 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);
    assert(0 == ipset->no_autoconvert);

    rv = ipsetCreate(&v6ipset, 1, 1);
    if (rv) {
        return rv;
    }

    skIPSetClean(ipset);

    ASSERT_OK(skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_FORCE));
    while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK) {
        rv = skIPSetInsertAddress(v6ipset, &ipaddr, prefix);
        if (rv) {
            skIPSetDestroy(&v6ipset);
            return rv;
        }
    }

    /* swap the IPsets */
    iptree = ipset->s.v2;
    ipset->s.v3 = v6ipset->s.v3;
    ipset->is_iptree = 0;
    ipset->is_ipv6 = 1;

    v6ipset->is_ipv6 = 0;
    v6ipset->is_iptree = 1;
    v6ipset->s.v2 = iptree;

    skIPSetDestroy(&v6ipset);

    skIPSetClean(ipset);

    return SKIPSET_OK;
}


/*
 *  status = ipsetConvertV4toV6(ipset);
 *
 *    Helper function for skIPSetConvert();
 *
 *    Convert the contents of a Radix-Tree based 'ipset' so it
 *    contains IPv6 addresses.
 *
 *    The IPv4 addresses in the IPset will be mapped into the
 *    "::ffff:0.0.0.0/96" address space.  Return SKIPSET_OK on
 *    success, or SKIPSET_ERR_ALLOC if memory cannot be allocated to
 *    hold the IPv6 addresses.
 */
static int
ipsetConvertV4toV6(
    skipset_t          *ipset)
{
    ipset_node_v6_t *node6;
    ipset_node_v4_t *node4;
    ipset_leaf_v6_t *leaf6;
    ipset_leaf_v4_t *leaf4;
    size_t num_entries;
    size_t ip_offset;
    uint32_t i;
    int rv;

    assert(ipset);
    assert(0 == ipset->is_iptree);
    assert(sizeof(ipset_node_v4_t) == ipset->s.v3->nodes.entry_size);

    if (IPSET_ISEMPTY(ipset)) {
        goto SET_ATTRIBUTES;
    }

    /* compute the number of bytes required to hold the nodes once
     * they are converted to IPv6, then divide by the IPv4 node size
     * to get the number of IPv4 nodes to request.  The -1/+1 handle a
     * partial node. */
    num_entries
        = (((ipset->s.v3->nodes.entry_count * sizeof(ipset_node_v6_t) - 1)
            / sizeof(ipset_node_v4_t)) + 1);
    if (num_entries > ipset->s.v3->nodes.entry_capacity) {
        rv = ipsetAllocEntries(&ipset->s.v3->nodes, num_entries);
        if (rv) {
            return rv;
        }
    }

    /* repeat for the leaves */
    num_entries
        = (((ipset->s.v3->leaves.entry_count * sizeof(ipset_leaf_v6_t) - 1)
            / sizeof(ipset_leaf_v4_t)) + 1);
    if (num_entries > ipset->s.v3->leaves.entry_capacity) {
        rv = ipsetAllocEntries(&ipset->s.v3->leaves, num_entries);
        if (rv) {
            return rv;
        }
    }

    /* modify the nodes */

    ip_offset = offsetof(ipset_node_v4_t, ip);
    assert(offsetof(ipset_node_v6_t, ip) >= ip_offset);

    /* break the NODE_PTR() abstraction here.  Count from
     * 'entry_count' down to 1, converting each node from a V4 node to
     * a V6 node. */
    node4 = &(((ipset_node_v4_t*)ipset->s.v3->nodes.buf)
              [ipset->s.v3->nodes.entry_count-1]);
    node6 = &(((ipset_node_v6_t*)ipset->s.v3->nodes.buf)
              [ipset->s.v3->nodes.entry_count-1]);

    for (i = ipset->s.v3->nodes.entry_count - 1; i > 0; --i, --node4, --node6){
        /* copy and convert the IP; must do the IP first, since its
         * location is overwritten by the memmove() call */
        node6->ip.ip[1] = UINT64_C(0xffff00000000) | node4->ip;
        node6->ip.ip[0] = 0;
        /* use memmove to copy the node except for the IP; must use
         * memmove() since the nodes overlap */
        memmove(node6, node4, ip_offset);
        node6->prefix += 96;
        /* node6->pad_align = 0 */
    }
    assert(0 == i);
    assert((void*)node4 == (void*)ipset->s.v3->nodes.buf);
    assert((void*)node6 == (void*)ipset->s.v3->nodes.buf);

    /* node-0 is unused; clear out the IP address */
    node6->ip.ip[0] = 0;
    node6->ip.ip[1] = 0;

    /* repeat for the leaves */

    ip_offset = offsetof(ipset_leaf_v4_t, ip);
    assert(offsetof(ipset_leaf_v6_t, ip) >= ip_offset);

    /* break the LEAF_PTR() abstraction here.  Count from
     * 'entry_count' down to 0, converting each leaf from a V4 leaf to
     * a V6 leaf. */
    leaf4 = &(((ipset_leaf_v4_t*)ipset->s.v3->leaves.buf)
              [ipset->s.v3->leaves.entry_count-1]);
    leaf6 = &(((ipset_leaf_v6_t*)ipset->s.v3->leaves.buf)
              [ipset->s.v3->leaves.entry_count-1]);

    for (i = ipset->s.v3->leaves.entry_count - 1; i > 0; --i, --leaf4, --leaf6)
    {
        /* use memcpy to copy the leaf; can use memcpy, since leaf6 is
         * twice the size of leaf4 */
        memcpy(leaf6, leaf4, ip_offset);
        leaf6->prefix += 96;
        /* copy and convert the IP */
        leaf6->ip.ip[1] = UINT64_C(0xffff00000000) | leaf4->ip;
        leaf6->ip.ip[0] = 0;
    }
    assert(0 == i);
    assert((void*)leaf4 == (void*)ipset->s.v3->leaves.buf);
    assert((void*)leaf6 == (void*)ipset->s.v3->leaves.buf);

    /* clear the IP address in leaf-0 */
    leaf6->ip.ip[0] = 0;
    leaf6->ip.ip[1] = 0;

  SET_ATTRIBUTES:
    /* set the IPset attributes for IPv6 */
    ipset->s.v3->nodes.entry_size = sizeof(ipset_node_v6_t);
    ipset->s.v3->leaves.entry_size = sizeof(ipset_leaf_v6_t);
    ipset->is_ipv6 = 1;
    ipset->is_dirty = 1;

    /* adjust the capacities.  this may result in a few wasted bytes
     * until the next realloc() */
    ipset->s.v3->nodes.entry_capacity
        = (ipset->s.v3->nodes.entry_capacity
           * sizeof(ipset_node_v4_t) / sizeof(ipset_node_v6_t));
    assert(ipset->s.v3->nodes.entry_capacity >= ipset->s.v3->nodes.entry_count);
    ipset->s.v3->leaves.entry_capacity
        = (ipset->s.v3->leaves.entry_capacity
           * sizeof(ipset_leaf_v4_t) / sizeof(ipset_leaf_v6_t));
    assert(ipset->s.v3->leaves.entry_capacity
           >= ipset->s.v3->leaves.entry_count);

    return SKIPSET_OK;
}


/*
 *  status = ipsetConvertV6toV4(ipset);
 *
 *    Helper function for skIPSetConvert();
 *
 *    Convert the contents of 'ipset' so it contains only IPv4
 *    addresses.  This function should not be called on IPsets that
 *    contain IPv6 addresses outside of "::ffff:0.0.0.0/96".
 */
static int
ipsetConvertV6toV4(
    skipset_t          *ipset)
{
    ipset_node_v6_t *node6;
    ipset_node_v4_t *node4;
    ipset_leaf_v6_t *leaf6;
    ipset_leaf_v4_t *leaf4;
    size_t ip_offset;
    uint32_t i;

    assert(ipset);
    assert(0 == ipset->is_iptree);
    assert(sizeof(ipset_node_v6_t) == ipset->s.v3->nodes.entry_size);
    assert(sizeof(ipset_leaf_v6_t) == ipset->s.v3->leaves.entry_size);
    assert(0 == skIPSetContainsV6(ipset));

    if (IPSET_ISEMPTY(ipset)) {
        goto SET_ATTRIBUTES;
    }

    ip_offset = offsetof(ipset_node_v4_t, ip);
    assert(offsetof(ipset_node_v6_t, ip) >= ip_offset);

    /* break the NODE_PTR() abstraction here.  Count from 0 to
     * 'entry_count', converting each node from a V6 node to a V4
     * node. */
    node4 = (ipset_node_v4_t*)ipset->s.v3->nodes.buf;
    node6 = (ipset_node_v6_t*)ipset->s.v3->nodes.buf;

    /* just need to set the IP to 0 for node 0 */
    node4->ip = 0;

    for (i = 1, ++node4, ++node6;
         i < ipset->s.v3->nodes.entry_count;
         ++i, ++node4, ++node6)
    {
        memmove(node4, node6, ip_offset);
        node4->ip = (uint32_t)(node6->ip.ip[1] & UINT32_MAX);
        node4->prefix -= 96;
    }


    /* Repeat the same process for the leaves */

    ip_offset = offsetof(ipset_leaf_v4_t, ip);
    assert(offsetof(ipset_leaf_v6_t, ip) >= ip_offset);

    leaf4 = (ipset_leaf_v4_t*)ipset->s.v3->leaves.buf;
    leaf6 = (ipset_leaf_v6_t*)ipset->s.v3->leaves.buf;

    leaf4->ip = 0;

    for (i = 1, ++leaf4, ++leaf6;
         i < ipset->s.v3->leaves.entry_count;
         ++i, ++leaf4, ++leaf6)
    {
        memcpy(leaf4, leaf6, ip_offset);
        leaf4->ip = (uint32_t)(leaf6->ip.ip[1] & UINT32_MAX);
        leaf4->prefix -= 96;
    }

  SET_ATTRIBUTES:
    /* set the IPset attributes for IPv4 */
    ipset->s.v3->nodes.entry_size = sizeof(ipset_node_v4_t);
    ipset->s.v3->leaves.entry_size = sizeof(ipset_leaf_v4_t);
    ipset->is_ipv6 = 0;
    ipset->is_dirty = 1;

    /* adjust the capacities.  this may result in a waste of a few
     * bytes */
    ipset->s.v3->nodes.entry_capacity
        = (ipset->s.v3->nodes.entry_capacity
           * sizeof(ipset_node_v6_t) / sizeof(ipset_node_v4_t));
    ipset->s.v3->leaves.entry_capacity
        = (ipset->s.v3->leaves.entry_capacity
           * sizeof(ipset_leaf_v6_t) / sizeof(ipset_leaf_v4_t));

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status  = ipsetCopyOnWrite(ipset);
 *
 *    Use the IPSET_COPY_ON_WRITE() macro to invoke this function,
 *    which only calls this function when necessary.
 *
 *    Change the IPset 'ipset' so that it uses in-core memory to hold
 *    its nodes instead of using mmap()ed data.  Return 0 on success,
 *    or SKIPSET_ERR_ALLOC if memory cannot be allocated.
 */
static int
ipsetCopyOnWrite(
    skipset_t          *ipset)
{
    uint8_t *node_buf;
    uint8_t *leaf_buf;
    int rv;

    assert(ipset->s.v3->mapped_file && ipset->s.v3->mapped_size);

    /* cache the current buffer values in case the allocation fails */
    node_buf = ipset->s.v3->nodes.buf;
    leaf_buf = ipset->s.v3->leaves.buf;

    /* clear the values so we can allocate the space */
    ipset->s.v3->nodes.buf = NULL;
    ipset->s.v3->nodes.entry_capacity = 0;
    ipset->s.v3->leaves.buf = NULL;
    ipset->s.v3->leaves.entry_capacity = 0;

    rv = ipsetAllocEntries(&ipset->s.v3->nodes, ipset->s.v3->nodes.entry_count);
    if (rv) {
        ipset->s.v3->nodes.buf = node_buf;
        ipset->s.v3->nodes.entry_capacity = ipset->s.v3->nodes.entry_count;
        ipset->s.v3->leaves.buf = leaf_buf;
        ipset->s.v3->leaves.entry_capacity = ipset->s.v3->leaves.entry_count;
        return rv;
    }
    rv = ipsetAllocEntries(&ipset->s.v3->leaves,
                           ipset->s.v3->leaves.entry_count);
    if (rv) {
        free(ipset->s.v3->nodes.buf);
        ipset->s.v3->nodes.buf = node_buf;
        ipset->s.v3->nodes.entry_capacity = ipset->s.v3->nodes.entry_count;
        ipset->s.v3->leaves.buf = leaf_buf;
        ipset->s.v3->leaves.entry_capacity = ipset->s.v3->leaves.entry_count;
        return rv;
    }

    /* copy the mmap()ed data into the newly allocated space */
    memcpy(ipset->s.v3->nodes.buf, node_buf,
           (ipset->s.v3->nodes.entry_count * ipset->s.v3->nodes.entry_size));
    memcpy(ipset->s.v3->leaves.buf, leaf_buf,
           (ipset->s.v3->leaves.entry_count * ipset->s.v3->leaves.entry_size));

    /* unmap the space */
    munmap(ipset->s.v3->mapped_file, ipset->s.v3->mapped_size);

    ipset->s.v3->mapped_file = NULL;
    ipset->s.v3->mapped_size = 0;

    return SKIPSET_OK;
}


/*
 *  status = ipsetCountCallbackV4(ipv4, prefix, &count_state)
 *  status = ipsetCountCallbackV6(ipv6, prefix, &count_state)
 *
 *    Helper function for skIPSetCount().
 *
 *    Compute (1 << 'prefix') to get the number of IPs in this block
 *    and update the count in 'count_state'.
 */
static int
ipsetCountCallbackV4(
    uint32_t     UNUSED(ipv4),
    uint32_t            prefix,
    void               *v_count_state)
{
    ipset_count_t *count_state = (ipset_count_t*)v_count_state;

    if (prefix > 32) {
        skAppPrintErr("Invalid prefix %u\n", prefix);
        skAbort();
    }
    count_state->lower += UINT64_C(1) << (32 - prefix);
    return 0;
}

#if SK_ENABLE_IPV6
static int
ipsetCountCallbackV6(
    const ipset_ipv6_t  UNUSED(*ipv6),
    uint32_t                    prefix,
    void                       *v_count_state)
{
    ipset_count_t *count_state = (ipset_count_t*)v_count_state;
    uint64_t tmp;

    if (prefix == 0) {
        ++count_state->full;
    } else if (prefix <= 64) {
        tmp = UINT64_C(1) << (64 - prefix);
        if ((UINT64_MAX - count_state->upper) >= tmp) {
            count_state->upper += tmp;
        } else {
            ++count_state->full;
            count_state->upper -= ((UINT64_MAX - tmp) + 1);
        }
    } else if (prefix <= 128) {
        tmp = UINT64_C(1) << (128 - prefix);
        if ((UINT64_MAX - count_state->lower) >= tmp) {
            count_state->lower += tmp;
        } else {
            ++count_state->upper;
            count_state->lower -= ((UINT64_MAX - tmp) + 1);
        }
    } else {
        skAppPrintErr("Invalid prefix %u\n", prefix);
        skAbort();
    }
    return 0;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Helper function for skIPSetCount() when the IPsets is implmented
 *    by a SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeCountIPs().
 */
static uint64_t
ipsetCountIPTree(
    const skIPTree_t   *iptree)
{
    unsigned int i, j;
    uint64_t count = 0;
    uint32_t bits;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (NULL != iptree->nodes[i]) {
            for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                if (iptree->nodes[i]->addressBlock[j]) {
                    BITS_IN_WORD32(&bits, iptree->nodes[i]->addressBlock[j]);
                    count += bits;
                }
            }
        }
    }

    return count;
}


/*
 *  occupied = ipsetCountOccupiedLeaves(ipset);
 *
 *    Return the number of occupied leaves in 'ipset'.
 */
static uint32_t
ipsetCountOccupiedLeaves(
    const skipset_t    *ipset)
{
    const ipset_leaf_t *leaf;
    uint32_t leaves_in_use;
    uint32_t leaves_free_idx;

    /* handle a leaf at the root as a special case */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        return 1;
    }

    /* determine the number of leaves currently in use by subtracting
     * the leaves on the free list from the total number of leaves */
    leaves_in_use = ipset->s.v3->leaves.entry_count;
    for (leaves_free_idx = ipset->s.v3->leaves.free_list;
         0 != leaves_free_idx;
         leaves_free_idx = LEAFPTR_FREE_LIST(leaf))
    {
        assert(leaves_free_idx < ipset->s.v3->leaves.entry_count);
        --leaves_in_use;
        leaf = LEAF_PTR(ipset, leaves_free_idx);
    }

    if (ipset->s.v3->leaves.entry_count < leaves_in_use) {
        skAbort();
    }

    return leaves_in_use;
}


/*
 *  status = ipsetCountStreamCallbackV4(ipaddr, prefix, count_state);
 *  status = ipsetCountStreamCallbackV6(ipaddr, prefix, count_state);
 *
 *    Helper functions for skIPSetProcessStreamCountIPs().
 *
 *    Compute (1 << 'prefix') to get the number of IPs in this block
 *    and update the count in 'count_state'.
 */
static int
ipsetCountStreamCallbackV4(
    skipaddr_t  UNUSED(*ipaddr),
    uint32_t            prefix,
    void               *v_count_state)
{
    return ipsetCountCallbackV4(0, prefix, v_count_state);
}

#if SK_ENABLE_IPV6
static int
ipsetCountStreamCallbackV6(
    skipaddr_t  UNUSED(*ipaddr),
    uint32_t            prefix,
    void               *v_count_state)
{
    return ipsetCountCallbackV6(NULL, prefix, v_count_state);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Convert the value in 'count_state' to a decimal number.
 *
 *    Helper function for skIPSetCountIPsString() and
 *    skIPSetProcessStreamCountIPs().
 */
static char *
ipsetCountToString(
    const ipset_count_t    *count_state,
    char                   *buf,
    size_t                  buflen)
{
    const uint64_t lim = UINT64_C(10000000000);
    const uint64_t map_ipv6_to_dec[][4] = {
        {          UINT64_C(1),                   0,  0, 0}, /* 1 <<  0 */
        { UINT64_C(4294967296),                   0,  0, 0}, /* 1 << 32 */
        { UINT64_C(3709551616), UINT64_C(1844674407), 0, 0}, /* 1 << 64 */
        { UINT64_C(3543950336), UINT64_C(1426433759), UINT64_C(792281625),
          0}, /* 1 << 96 */
    };
    /* the decimal value being calculated */
    uint64_t decimal[5] = {0, 0, 0, 0, 0};
    uint64_t tmp;
    uint64_t tmp2 = 0;
    ssize_t sz;
    int i, j;

    if (count_state->full) {
        sz = snprintf(buf, buflen, "340282366920938463463374607431768211456");
        goto END;
    }
    if (0 == count_state->upper) {
        sz = snprintf(buf, buflen, ("%" PRIu64), count_state->lower);
        goto END;
    }
    for (i = 0; i < 4; ++i) {
        switch (i) {
          case 0: tmp2 = (count_state->lower & UINT32_MAX);         break;
          case 1: tmp2 = ((count_state->lower >> 32) & UINT32_MAX); break;
          case 2: tmp2 = (count_state->upper & UINT32_MAX);         break;
          case 3: tmp2 = ((count_state->upper >> 32) & UINT32_MAX); break;
        }
        if (tmp2) {
            for (j = 0; j < 4 && map_ipv6_to_dec[i][j] > 0; ++j) {
                tmp = tmp2 * map_ipv6_to_dec[i][j];
                if (tmp < lim) {
                    decimal[j] += tmp;
                } else {
                    /* handle overflow */
                    decimal[j] += tmp % lim;
                    decimal[j+1] += tmp / lim;
                }
            }
        }
    }
    /* Final check for overflow and determine number of 'decimal'
     * elements that have a value */
    i = 0;
    for (j = 0; j < 4; ++j) {
        if (decimal[j] >= lim) {
            i = j;
            tmp = decimal[j];
            decimal[j] %= lim;
            decimal[j+1] += tmp / lim;
        } else if (decimal[j] > 0) {
            i = j;
        }
    }
    switch (i) {
      case 0:
        sz = snprintf(buf, buflen, "%" PRIu64, decimal[0]);
        break;
      case 1:
        sz = snprintf(buf, buflen, "%" PRIu64 "%010" PRIu64,
                      decimal[1], decimal[0]);
        break;
      case 2:
        sz = snprintf(buf, buflen, "%" PRIu64 "%010" PRIu64 "%010" PRIu64,
                      decimal[2], decimal[1], decimal[0]);
        break;
      case 3:
        sz = snprintf(buf, buflen,
                      "%" PRIu64 "%010" PRIu64 "%010" PRIu64 "%010" PRIu64,
                      decimal[3], decimal[2], decimal[1], decimal[0]);
        break;
      case 4:
        sz = snprintf(buf, buflen,
                      ("%" PRIu64 "%010" PRIu64 "%010" PRIu64
                       "%010" PRIu64 "%010" PRIu64),
                      decimal[4], decimal[3], decimal[2],
                      decimal[1], decimal[0]);
        break;
      default:
        skAbortBadCase(i);
    }

  END:
    if ((size_t)sz >= buflen) {
        return NULL;
    }
    return buf;
}


/*
 *    Return the number of trailing zeros in the bit representation of
 *    'v'.  NB return 31 when 'v' is 0.
 *
 *    From
 *    http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightBinSearch
 */
static uint32_t
ipsetCountTrailingZeros(
    uint32_t            v)
{
    uint32_t c;

    if (v & 0x1) {
        /* shortcut for odd 'v' */
        c = 0;
    } else {
        /* set c to one then subtract at the end */
        c = 1;
        if ((v & 0xFFFF) == 0) {
            v >>= 16;
            c += 16;
        }
        if ((v & 0xFF) == 0) {
            v >>= 8;
            c += 8;
        }
        if ((v & 0xF) == 0) {
            v >>= 4;
            c += 4;
        }
        if ((v & 0x3) == 0) {
            v >>= 2;
            c += 2;
        }
        c -= (v & 0x1);
    }
    return c;
}


/*
 *  status = ipsetCreate(ipset, support_ipv6, force_radix);
 *
 *    Helper function for skIPSetCreate() and used internally.
 *
 *    Allocates and initializes a new IPset at the space specified by
 *    '*ipset'.  The set is initially empty.  When 'support_ipv6' is
 *    non-zero, the IPset will be initialized to store IPv6 addresses;
 *    otherwise it will be initialized to hold IPv4 addresses.  When
 *    creating an IPv4 IPset, the IPTree format from SiLK-2 will be
 *    used unless the 'force_radix' parameter has a non-zero value.
 */
static int
ipsetCreate(
    skipset_t         **ipset_out,
    int                 support_ipv6,
    int                 force_radix)
{
    skipset_t *set;

    assert(ipset_out);

    set = (skipset_t*)calloc(1, sizeof(skipset_t));
    if (!set) {
        return SKIPSET_ERR_ALLOC;
    }

    if (support_ipv6) {
        set->s.v3 = (skipset_v3_t*)calloc(1, sizeof(skipset_v3_t));
        if (!set->s.v3) {
            free(set);
            return SKIPSET_ERR_ALLOC;
        }
        set->s.v3->nodes.entry_size = sizeof(ipset_node_v6_t);
        set->s.v3->leaves.entry_size = sizeof(ipset_leaf_v6_t);
        set->is_ipv6 = 1;
        set->is_iptree = 0;
    } else if (force_radix) {
        set->s.v3 = (skipset_v3_t*)calloc(1, sizeof(skipset_v3_t));
        if (!set->s.v3) {
            free(set);
            return SKIPSET_ERR_ALLOC;
        }
        set->s.v3->nodes.entry_size = sizeof(ipset_node_v4_t);
        set->s.v3->leaves.entry_size = sizeof(ipset_leaf_v4_t);
        set->is_ipv6 = 0;
        set->is_iptree = 0;
    } else {
        set->s.v2 = (skIPTree_t*)calloc(1, sizeof(skIPTree_t));
        if (!set->s.v2) {
            free(set);
            return SKIPSET_ERR_ALLOC;
        }
        set->is_ipv6 = 0;
        set->is_iptree = 1;
    }

    *ipset_out = set;
    return SKIPSET_OK;
}


/*
 *  status = ipsetDestroyIPTree(iptree);
 *
 *    Helper function for skIPSetDestroy().
 *
 *    Also a helper function for legacy skIPTreeDelete().
 *
 *    Destroy the skIPTree_t 'iptree'.
 */
static void
ipsetDestroyIPTree(
    skIPTree_t         *iptree)
{
    unsigned int i;

    if (iptree) {
        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (iptree->nodes[i]) {
                free(iptree->nodes[i]);
            }
        }
        free(iptree);
    }
}


/*
 *  ipsetDestroySubtree(ipset, node_idx, destroy_self);
 *
 *    Puts all the child nodes of 'node_idx' onto the free list.  If
 *    'destroy_self' is non-zero, the 'node_idx' node is also added to
 *    the free list.  If 'destroy_self' is zero, the child indexes on
 *    'node_idx' are set to 0.
 */
static void
ipsetDestroySubtree(
    skipset_t          *ipset,
    uint32_t            node_idx,
    int                 destroy_self)
{
    uint32_t to_visit[IPSET_MAX_DEPTH];
    uint32_t depth = 0;
    ipset_node_t *node;
    int i;

    if (destroy_self) {
        /* add this node to the list of nodes to destroy */
        to_visit[depth++] = node_idx;
    } else {
        /* destroy any leaves off of this node; add this node's child
         * nodes to the list of nodes to destroy */
        node = NODE_PTR(ipset, node_idx);
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if (node->v4.child[i]
                && !NODEPTR_CHILD_IS_REPEAT(&node->v4, i))
            {
                if (NODEPTR_CHILD_IS_LEAF(&node->v4, i)) {
                    LEAFIDX_FREE(ipset, node->v4.child[i]);
                } else {
                    to_visit[depth++] = node->v4.child[i];
                }
            }
        }
        /* clear the child array and bitmaps */
        memset(node->v4.child, 0, sizeof(node->v4.child));
        SET_BMAP_CLEAR_ALL(node->v4.child_is_leaf);
        SET_BMAP_CLEAR_ALL(node->v4.child_repeated);
    }

    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR(ipset, node_idx);
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if (node->v4.child[i]
                && !NODEPTR_CHILD_IS_REPEAT(&node->v4, i))
            {
                if (NODEPTR_CHILD_IS_LEAF(&node->v4, i)) {
                    LEAFIDX_FREE(ipset, node->v4.child[i]);
                } else {
                    to_visit[depth++] = node->v4.child[i];
                }
            }
        }
        NODEIDX_FREE(ipset, node_idx);
    }
}


/*
 *  status = ipsetFindV4(ipset, ip, prefix, &find_state);
 *  status = ipsetFindV6(ipset, ip, prefix, &find_state);
 *
 *    Searches for 'ip'/'prefix' in the Radix-tree based 'ipset'.
 *    'ip' is an integer presentation of the IP address in native byte
 *    order.
 *
 *    Returns SKIPSET_OK if it is found exactly or if a CIDR block
 *    containing it is found: searching for 10.0.0.2 and find
 *    10.0.0.0/24.
 *
 *    Returns SKIPSET_ERR_SUBSET when a subset of target is found:
 *    search for 10.0.0.0/24 and find 10.0.0.2.
 *
 *    Returns SKIPSET_ERR_EMPTY if the IPset is empty.
 *
 *    Returns SKIPSET_ERR_MULTILEAF if it is not found but the search
 *    failed at a position where a leaf can be inserted.
 *
 *    Returns SKIPSET_ERR_NOTFOUND if it is not found and the
 *    SKIPSET_ERR_MULTILEAF case does not apply.
 *
 *    When 'find_state' is non-NULL, its fields will be set to the
 *    final location visited in the tree.  Specifically, 'node_idx' is
 *    set to the index of the node where the search terminated;
 *    'bitpos' is set to the number of bits of the IP address that
 *    were searched; 'parent_idx' is set to the index of the parent of
 *    the node in 'node_idx'.  If 'node_idx' is the root of the tree,
 *    'parent_idx' will be UINT32_MAX; 'result' will be the same as
 *    the return status of the function.
 */
static int
ipsetFindV4(
    const skipset_t    *ipset,
    const uint32_t      ipv4,
    const uint32_t      prefix,
    ipset_find_t       *find_state)
{
    const ipset_node_v4_t *node;
    const ipset_leaf_v4_t *leaf = NULL;
    uint32_t parent_idx;
    uint32_t node_idx;
    uint32_t which_child;
    uint32_t j;
    uint8_t bitpos;
    int rv;

    /*
     *  The 'bitpos' value specifies the number of bits that match
     *  between the IP on the current node/leaf and the search IP
     *  (starting from the most significant bit).
     *
     *  On a node at any level in the tree, if bitpos is less than the
     *  prefix on that node, we cannot descend to the next level in
     *  the tree.  Otherwise, before descending, we check to see
     *  whether the node's prefix is greater than the search prefix;
     *  if it is, there is no need to continue and the function
     *  returns SUBSET.
     *
     *  Whether the descent into the tree stops due to reaching a leaf
     *  or due to not matching enough bits on a node, the return
     *  status depends on three values: (1)the number of bits that
     *  were matched, (2)the prefix on the node/leaf, and (3)the
     *  search prefix.  If bitpos is less than the search prefix, the
     *  search failed and NOTFOUND is returned.  If both bitpos and
     *  the search prefix are at least equal to the prefix on the
     *  node/leaf, the search returns OK.  For any other combination,
     *  the search returns SUBSET.
     *
     *  If the search is on the node and wants to descend into the
     *  tree but there is no child at that position, the search either
     *  returns SUBSET or MULTILEAF.  The search returns SUBSET if the
     *  search prefix covers multiple children on the node and at
     *  least one of those children is occupied.  Otherwise, the
     *  search returns MULTILEAF, denoting that a leaf can be safely
     *  added at this position.
     */

    assert(ipset);
    assert(prefix > 0 || ipv4 == 0);
    assert(prefix <= 32);
    assert(0 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);

    parent_idx = IPSET_NO_PARENT;
    node_idx = IPSET_ROOT_INDEX(ipset);
    which_child = IPSET_NUM_CHILDREN;
    bitpos = 0;
    rv = SKIPSET_ERR_SUBSET;

    if (IPSET_ISEMPTY(ipset)) {
        rv = SKIPSET_ERR_EMPTY;
        goto END;
    }

    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V4(ipset, node_idx);
        /* find number of bits this leaf's IP and the search IP have
         * in common */
        COUNT_MATCHING_BITS32(&bitpos, (ipv4 ^ (leaf->ip)));
        if (bitpos < leaf->prefix) {
            if (bitpos < prefix) {
                /* not found */
                rv = SKIPSET_ERR_NOTFOUND;
            } else {
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
            }
        } else {
            /* make certain bitpos is not greater than this leaf's
             * prefix */
            bitpos = leaf->prefix;
            if (prefix >= leaf->prefix) {
                rv = SKIPSET_OK;
            }
            /* else rv = SKIPSET_ERR_SUBSET; */
        }
        goto END;
    }

    do {
        assert(node_idx < ipset->s.v3->nodes.entry_count);
        node = NODE_PTR_V4(ipset, node_idx);
        if (bitpos < node->prefix) {
            COUNT_MATCHING_BITS32(&bitpos, (ipv4 ^ (node->ip)));
            if (bitpos < node->prefix) {
                /* cannot descend any farther into tree */
                if (bitpos < prefix) {
                    /* not found */
                    rv = SKIPSET_ERR_NOTFOUND;
                    goto END;
                }
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
                goto END;
            }
            /* else bitpos >= node->prefix */
            if (prefix <= node->prefix) {
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
                goto END;
            }
            /* else descend to next level */
        }

        /* go to the appropriate child */
        parent_idx = node_idx;
        which_child = WHICH_CHILD_V4(ipv4, node->prefix);
        node_idx = node->child[which_child];
        if (0 == node_idx) {
            if (NUM_BITS > prefix - node->prefix) {
                /* the 'prefix' covers multiple child[] entries; see
                 * if any others are occupied */
                for (j = 1;
                     ((j < (1u << (NUM_BITS - (prefix - node->prefix))))
                      && ((which_child + j) < IPSET_NUM_CHILDREN));
                     ++j)
                {
                    if (node->child[which_child + j]) {
                        /* rv = SKIPSET_ERR_SUBSET; */
                        goto END;
                    }
                }
            }
            node_idx = which_child;
            rv = SKIPSET_ERR_MULTILEAF;
            goto END;
        }
        if (BITMAP_GETBIT(node->child_is_leaf, which_child)) {
            leaf = LEAF_PTR_V4(ipset, node_idx);
            COUNT_MATCHING_BITS32(&bitpos, (ipv4 ^ (leaf->ip)));
            if (bitpos < leaf->prefix) {
                if (bitpos < prefix) {
                    /* not found */
                    rv = SKIPSET_ERR_NOTFOUND;
                } else {
                    bitpos = prefix;
                    /* rv = SKIPSET_ERR_SUBSET; */
                }
            } else {
                bitpos = leaf->prefix;
                if (prefix >= leaf->prefix) {
                    rv = SKIPSET_OK;
                }
                /* else rv = SKIPSET_ERR_SUBSET; */
            }
            goto END;
        }

        bitpos = node->prefix + NUM_BITS;

    } while (bitpos < prefix);

  END:
    if (find_state) {
        find_state->parent_idx = parent_idx;
        find_state->node_idx = node_idx;
        find_state->parents_child = which_child;
        find_state->bitpos = bitpos;
        find_state->result = rv;
        find_state->node_is_leaf = (leaf != NULL);
    }
    return rv;
}

#if SK_ENABLE_IPV6
static int
ipsetFindV6(
    const skipset_t    *ipset,
    const ipset_ipv6_t *ipv6,
    const uint32_t      prefix,
    ipset_find_t       *find_state)
{
    const ipset_node_v6_t *node;
    const ipset_leaf_v6_t *leaf = NULL;
    uint32_t parent_idx;
    uint32_t node_idx;
    uint32_t which_child;
    uint8_t bitpos;
    uint32_t j;
    int ip_idx;
    int rv;

    assert(ipset);
    assert(ipv6);
    assert(0 < prefix && prefix <= 128);
    assert(0 == ipset->is_iptree);
    assert(1 == ipset->is_ipv6);

    parent_idx = IPSET_NO_PARENT;
    node_idx = IPSET_ROOT_INDEX(ipset);
    which_child = IPSET_NUM_CHILDREN;
    bitpos = 0;
    ip_idx = 0;
    rv = SKIPSET_ERR_SUBSET;

    if (IPSET_ISEMPTY(ipset)) {
        rv = SKIPSET_ERR_EMPTY;
        goto END;
    }

    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V6(ipset, node_idx);
        /* find number of bits this leaf's IP and the search IP have
         * in common */
        if (ipv6->ip[0] == leaf->ip.ip[0]) {
            COUNT_MATCHING_BITS64(&bitpos, (ipv6->ip[1] ^ leaf->ip.ip[1]));
            bitpos += 64;
        } else {
            COUNT_MATCHING_BITS64(&bitpos, (ipv6->ip[0] ^ leaf->ip.ip[0]));
        }
        if (bitpos < leaf->prefix) {
            if (bitpos < prefix) {
                /* not found */
                rv = SKIPSET_ERR_NOTFOUND;
            } else {
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
            }
        } else {
            /* make certain bitpos is not greater than this leaf's
             * prefix */
            bitpos = leaf->prefix;
            if (prefix >= leaf->prefix) {
                rv = SKIPSET_OK;
            }
            /* else rv = SKIPSET_ERR_SUBSET; */
        }
        goto END;
    }

    do {
        assert(node_idx < ipset->s.v3->nodes.entry_count);
        node = NODE_PTR_V6(ipset, node_idx);
        if (bitpos < node->prefix) {
            COUNT_MATCHING_BITS64(&bitpos,
                                  (ipv6->ip[ip_idx] ^ node->ip.ip[ip_idx]));
            bitpos += (ip_idx * 64);
            if (bitpos < node->prefix) {
                if (64 == bitpos && 0 == ip_idx) {
                    ++ip_idx;
                    continue;
                }
                /* cannot descend any farther into tree */
                if (bitpos < prefix) {
                    /* not found */
                    rv = SKIPSET_ERR_NOTFOUND;
                    goto END;
                }
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
                goto END;
            }
            /* else bitpos >= node->prefix */
            if (prefix <= node->prefix) {
                bitpos = prefix;
                /* rv = SKIPSET_ERR_SUBSET; */
                goto END;
            }
        }

        /* go to the appropriate child */
        parent_idx = node_idx;
        which_child = WHICH_CHILD_V6(ipv6, node->prefix);
        node_idx = node->child[which_child];
        if (0 == node_idx) {
            if (NUM_BITS > prefix - node->prefix) {
                /* the 'prefix' covers multiple child[] entries; see
                 * if any others are occupied */
                for (j = 1;
                     ((j < (1u << (NUM_BITS - (prefix - node->prefix))))
                      && ((which_child + j) < IPSET_NUM_CHILDREN));
                     ++j)
                {
                    if (node->child[which_child + j]) {
                        /* rv = SKIPSET_ERR_SUBSET; */
                        goto END;
                    }
                }
            }
            node_idx = which_child;
            rv = SKIPSET_ERR_MULTILEAF;
            goto END;
        }
        if (BITMAP_GETBIT(node->child_is_leaf, which_child)) {
            leaf = LEAF_PTR_V6(ipset, node_idx);
            if ((1 == ip_idx) || (ipv6->ip[0] == leaf->ip.ip[0])) {
                COUNT_MATCHING_BITS64(&bitpos, (ipv6->ip[1] ^ leaf->ip.ip[1]));
                bitpos += 64;
            } else {
                COUNT_MATCHING_BITS64(&bitpos, (ipv6->ip[0] ^ leaf->ip.ip[0]));
            }
            if (bitpos < leaf->prefix) {
                if (bitpos < prefix) {
                    /* not found */
                    rv = SKIPSET_ERR_NOTFOUND;
                } else {
                    bitpos = prefix;
                    /* rv = SKIPSET_ERR_SUBSET; */
                }
            } else {
                bitpos = leaf->prefix;
                if (prefix >= leaf->prefix) {
                    rv = SKIPSET_OK;
                }
                /* else rv = SKIPSET_ERR_SUBSET; */
            }
            goto END;
        }

        bitpos = node->prefix + NUM_BITS;

    } while (bitpos < prefix);

  END:
    if (find_state) {
        find_state->parent_idx = parent_idx;
        find_state->node_idx = node_idx;
        find_state->parents_child = which_child;
        find_state->bitpos = bitpos;
        find_state->result = rv;
        find_state->node_is_leaf = (leaf != NULL);
    }
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  remove_count = ipsetFixNodeSingleChild(ipset, node_idx, non_recursive);
 *
 *    Determine if the node specified by 'node_idx' has multiple
 *    children.  If it does, do not modify 'ipset' and return 0.
 *
 *    If the node specified by 'node_idx' as one child---which may be
 *    a leaf or another node---modify the node's parent to replace the
 *    node with node's child and return 1.
 *
 *    If the node specified by 'node_idx' has no children, remove the
 *    node from the node's parent.  If 'non_recursive' is non-zero, do
 *    no further processing and return 1.  If 'non_recursive' is 0,
 *    repeat the process using the parent of the node that was just
 *    removed.  For this final case, the return status will be a count
 *    of the number of nodes removed.
 *
 *    I do not believe anything uses the return value; this function
 *    could be changed to "return" void.
 */
static int
ipsetFixNodeSingleChild(
    skipset_t          *ipset,
    uint32_t            node_idx,
    int                 non_recursive)
{
    ipset_find_t find_state;
    ipset_node_t *parent;
    ipset_node_t *node;
    uint32_t which_child;
    uint32_t child_idx = 0;
    uint32_t i;
    int remove_count = 0;

    assert(ipset);
    assert(0 == ipset->is_iptree);
    assert(node_idx > 0 && node_idx < ipset->s.v3->nodes.entry_count);

    node = NODE_PTR(ipset, node_idx);

    for (;;) {
        which_child = IPSET_NUM_CHILDREN;
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if ((node->v4.child[i])
                && !NODEPTR_CHILD_IS_REPEAT(&node->v4, i))
            {
                if (which_child != IPSET_NUM_CHILDREN) {
                    /* more than one child; we are done. */
                    return remove_count;
                }
                which_child = i;
            }
        }

        if (which_child < IPSET_NUM_CHILDREN) {
            /* the node has a single child; modify the node's parent
             * to replace the node with the node's child */
            if (!NODEPTR_CHILD_IS_LEAF(&node->v4, which_child)) {
                /* the single child is another node; the easiest way
                 * to handle this case is to copy the child over the
                 * node, and leave the parent untouched */
                node_idx = node->v4.child[which_child];
                memcpy(node, NODE_PTR(ipset, node_idx),
                       ipset->s.v3->nodes.entry_size);
                break;
            }

            child_idx = node->v4.child[which_child];
        }

        /* find the node in order to get a handle to the node's
         * parent */
        if (0 == node->v4.prefix) {
            /* cannot call ipsetFindVx() with a prefix of 0, but that
             * can only happen at the root */
            find_state.parent_idx = IPSET_NO_PARENT;
#if SK_ENABLE_IPV6
        } else if (ipset->is_ipv6) {
#ifndef NDEBUG
            int rv =
#endif
                ipsetFindV6(ipset, &node->v6.ip, node->v6.prefix, &find_state);
            assert(SKIPSET_OK == rv || SKIPSET_ERR_SUBSET == rv);
            assert(find_state.node_idx == node_idx && !find_state.node_is_leaf);
#endif  /* SK_ENABLE_IPV6 */
        } else {
#ifndef NDEBUG
            int rv =
#endif
                ipsetFindV4(ipset, node->v4.ip, node->v4.prefix, &find_state);
            assert(SKIPSET_OK == rv || SKIPSET_ERR_SUBSET == rv);
            assert(find_state.node_idx == node_idx && !find_state.node_is_leaf);
        }

        if (which_child < IPSET_NUM_CHILDREN) {
            /* wire the nodes's parent to the child (which is a leaf),
             * then free the node */
            if (IPSET_NO_PARENT == find_state.parent_idx) {
                /* this node was the root */
                IPSET_ROOT_INDEX_SET(ipset, child_idx, 1);
            } else {
                parent = NODE_PTR(ipset, find_state.parent_idx);
                parent->v4.child[find_state.parents_child] = child_idx;
                SET_BMAP_SET(parent->v4.child_is_leaf,
                             find_state.parents_child);
            }
            break;
        }
        /* delete the node from the parent */
        if (IPSET_NO_PARENT == find_state.parent_idx) {
            /* this node was the root */
            skIPSetRemoveAll(ipset);
            ++remove_count;
            return remove_count;
        }

        parent = NODE_PTR(ipset, find_state.parent_idx);
        parent->v4.child[find_state.parents_child] = 0;
        if (non_recursive) {
            break;
        }

        /* we have deleted the node from the parent.  see if the
         * parent now has a single child  */
        NODEIDX_FREE(ipset, node_idx);
        ++remove_count;
        node_idx = find_state.parent_idx;
        node = parent;
    }

    NODEIDX_FREE(ipset, node_idx);
    ++remove_count;
    return remove_count;
}


/*
 *    Call ipsetHentryCreate() (which see) to a new SiLK stream header
 *    entry for an IPset and add that header entry to the file's
 *    headers in 'hdr'.  Return an SKHEADER error code on failure.
 */
static int
ipsetHentryAddToFile(
    sk_file_header_t   *hdr,
    uint32_t            child_node,
    uint32_t            leaf_count,
    uint32_t            leaf_size,
    uint32_t            node_count,
    uint32_t            node_size,
    uint32_t            root_idx)
{
    int rv;
    sk_header_entry_t *ipset_hdr = NULL;

    ipset_hdr = ipsetHentryCreate(child_node, leaf_count, leaf_size,
                                  node_count, node_size, root_idx);
    if (NULL == ipset_hdr) {
        return SKHEADER_ERR_ALLOC;
    }

    rv = skHeaderAddEntry(hdr, ipset_hdr);
    if (rv) {
        ipsetHentryFree(ipset_hdr);
    }
    return rv;
}


/*
 *  hentry = ipsetHentryCopy(hentry);
 *
 *    Create and return a new header entry for IPset files that is a
 *    copy of the header entry 'hentry'.
 *
 *    This is the 'copy_fn' callback for skHentryTypeRegister().
 */
static sk_header_entry_t *
ipsetHentryCopy(
    const sk_header_entry_t    *hentry)
{
    const sk_hentry_ipset_t *ipset_hdr = (sk_hentry_ipset_t*)hentry;

    return ipsetHentryCreate(ipset_hdr->child_node, ipset_hdr->leaf_count,
                             ipset_hdr->leaf_size, ipset_hdr->node_count,
                             ipset_hdr->node_size, ipset_hdr->root_idx);
}


/*
 *    Create and return a new header entry for IPset files.
 *    'child_node' is the number of children per node, 'leaf_count' is
 *    the number of leaves, 'leaf_size' is the size of an individual
 *    leaf, 'node_count' is the number of (internal) nodes,
 *    'node_size' is the size of an individual node, and
 *    'root_index'is the index of the root of the tree.
 */
static sk_header_entry_t *
ipsetHentryCreate(
    uint32_t            child_node,
    uint32_t            leaf_count,
    uint32_t            leaf_size,
    uint32_t            node_count,
    uint32_t            node_size,
    uint32_t            root_idx)
{
    sk_hentry_ipset_t *ipset_hdr;

    ipset_hdr = (sk_hentry_ipset_t*)calloc(1, sizeof(sk_hentry_ipset_t));
    if (NULL == ipset_hdr) {
        return NULL;
    }
    ipset_hdr->he_spec.hes_id  = SK_HENTRY_IPSET_ID;
    ipset_hdr->he_spec.hes_len = sizeof(sk_hentry_ipset_t);
    ipset_hdr->child_node      = child_node;
    ipset_hdr->leaf_count      = leaf_count;
    ipset_hdr->leaf_size       = leaf_size;
    ipset_hdr->node_count      = node_count;
    ipset_hdr->node_size       = node_size;
    ipset_hdr->root_idx        = root_idx;

    return (sk_header_entry_t*)ipset_hdr;
}


/*
 *  ipsetHentryFree(hentry);
 *
 *    Release any memory that is used by the in-memory representation
 *    of the file header for IPset files.
 *
 *    This is the 'free_fn' callback for skHentryTypeRegister().
 */
static void
ipsetHentryFree(
    sk_header_entry_t  *hentry)
{
    if (hentry) {
        assert(skHeaderEntryGetTypeId(hentry) == SK_HENTRY_IPSET_ID);
        hentry->he_spec.hes_id = UINT32_MAX;
        free(hentry);
    }
}


#define ipsetHentryGetChildPerNode(hentry)              \
    (((sk_hentry_ipset_t*)(hentry))->child_node)

#define ipsetHentryGetLeafCount(hentry)                 \
    (((sk_hentry_ipset_t*)(hentry))->leaf_count)

#define ipsetHentryGetLeafSize(hentry)          \
    (((sk_hentry_ipset_t*)(hentry))->leaf_size)

#define ipsetHentryGetNodeCount(hentry)                 \
    (((sk_hentry_ipset_t*)(hentry))->node_count)

#define ipsetHentryGetNodeSize(hentry)          \
    (((sk_hentry_ipset_t*)(hentry))->node_size)

#define ipsetHentryGetRootIndex(hentry)         \
    (((sk_hentry_ipset_t*)(hentry))->root_idx)


/*
 *  size = ipsetHentryPacker(hentry, buf, bufsiz);
 *
 *    Pack the contents of the header entry for IPset files, 'hentry'
 *    into the buffer 'buf', whose size is 'bufsiz', for writing the
 *    file to disk.
 *
 *    This the 'pack_fn' callback for skHentryTypeRegister().
 */
static ssize_t
ipsetHentryPacker(
    const sk_header_entry_t    *in_hentry,
    uint8_t                    *out_packed,
    size_t                      bufsize)
{
    sk_hentry_ipset_t *ipset_hdr = (sk_hentry_ipset_t*)in_hentry;
    sk_hentry_ipset_t tmp_hdr;

    assert(in_hentry);
    assert(out_packed);
    assert(skHeaderEntryGetTypeId(ipset_hdr) == SK_HENTRY_IPSET_ID);

    if (bufsize >= sizeof(sk_hentry_ipset_t)) {
        skHeaderEntrySpecPack(&(ipset_hdr->he_spec), (uint8_t *)&tmp_hdr,
                              sizeof(tmp_hdr));
        tmp_hdr.child_node = htonl(ipset_hdr->child_node);
        tmp_hdr.leaf_count = htonl(ipset_hdr->leaf_count);
        tmp_hdr.leaf_size  = htonl(ipset_hdr->leaf_size);
        tmp_hdr.node_count = htonl(ipset_hdr->node_count);
        tmp_hdr.node_size  = htonl(ipset_hdr->node_size);
        tmp_hdr.root_idx   = htonl(ipset_hdr->root_idx);

        memcpy(out_packed, &tmp_hdr, sizeof(sk_hentry_ipset_t));
    }

    return sizeof(sk_hentry_ipset_t);
}


/*
 *  ipsetHentryPrint(hentry, fh);
 *
 *    Print a textual representation of a file's IPset header entry in
 *    'hentry' to the FILE pointer 'fh'.
 *
 *    This is the 'print_fn' callback for skHentryTypeRegister().
 */
static void
ipsetHentryPrint(
    const sk_header_entry_t    *hentry,
    FILE                       *fh)
{
    sk_hentry_ipset_t *ipset_hdr = (sk_hentry_ipset_t*)hentry;

    assert(skHeaderEntryGetTypeId(ipset_hdr) == SK_HENTRY_IPSET_ID);
    if ((0 == ipset_hdr->child_node) && (0 == ipset_hdr->root_idx)) {
        /* assume this is a RecordVersion 4 file */
        fprintf(fh, "IPv%d",
                ((sizeof(uint32_t) == ipset_hdr->leaf_size) ? 4 : 6));
    } else {
        fprintf(fh, ("%" PRIu32 "-way branch, root@%" PRIu32 ", "
                     "%" PRIu32 " x %" PRIu32 "b node%s, "
                     "%" PRIu32 " x %" PRIu32 "b leaves"),
                ipset_hdr->child_node, ipset_hdr->root_idx,
                ipset_hdr->node_count, ipset_hdr->node_size,
                ((ipset_hdr->node_count > 1) ? "s" : ""),
                ipset_hdr->leaf_count, ipset_hdr->leaf_size);
    }
}


/*
 *  hentry = ipsetHentryUnpacker(buf);
 *
 *    Unpack the data in 'buf' to create an in-memory representation
 *    of a file's IPset header entry.
 *
 *    This is the 'unpack_fn' callback for skHentryTypeRegister().
 */
static sk_header_entry_t *
ipsetHentryUnpacker(
    uint8_t            *in_packed)
{
    sk_hentry_ipset_t *ipset_hdr;

    assert(in_packed);

    /* create space for new header */
    ipset_hdr = (sk_hentry_ipset_t*)calloc(1, sizeof(sk_hentry_ipset_t));
    if (NULL == ipset_hdr) {
        return NULL;
    }

    /* copy the spec */
    skHeaderEntrySpecUnpack(&(ipset_hdr->he_spec), in_packed);
    assert(skHeaderEntryGetTypeId(ipset_hdr) == SK_HENTRY_IPSET_ID);

    /* copy the data */
    if (ipset_hdr->he_spec.hes_len != sizeof(sk_hentry_ipset_t)) {
        free(ipset_hdr);
        return NULL;
    }
    memcpy(&(ipset_hdr->child_node),
           &(in_packed[sizeof(sk_header_entry_spec_t)]),
           sizeof(sk_hentry_ipset_t) - sizeof(sk_header_entry_spec_t));
    ipset_hdr->child_node  = htonl(ipset_hdr->child_node);
    ipset_hdr->leaf_count  = htonl(ipset_hdr->leaf_count);
    ipset_hdr->leaf_size   = htonl(ipset_hdr->leaf_size);
    ipset_hdr->node_count  = htonl(ipset_hdr->node_count);
    ipset_hdr->node_size   = htonl(ipset_hdr->node_size);
    ipset_hdr->root_idx    = htonl(ipset_hdr->root_idx);

    return (sk_header_entry_t*)ipset_hdr;
}


/*
 *  status = ipsetInsertAddressIPTree(ipset, ip, prefix);
 *
 *    Helper function for skIPSetInsertAddress(); may also be called
 *    by other internal functions.
 *
 *    Also a helper function for legacy skIPTreeAddAddress().
 *
 *    Insert the CIDR block 'ip'/'prefix' into 'ipset'.
 */
static int
ipsetInsertAddressIPTree(
    skIPTree_t         *iptree,
    uint32_t            ipv4,
    uint32_t            prefix)
{
    /*
     *    The skIPNode_t contains an array of uint32_t's, where each
     *    uint32_t is treated as a bitmap for a /27.
     *
     *    This array contains the bits that correspond a CIDR prefix
     *    for one of these uint32_t values.  Prefix must be between 27
     *    and 32 inclusive.  The key to this array is (prefix - 27).
     */
    const uint32_t prefix_as_bits[] = {
        0xFFFFFFFF, 0xFFFF, 0xFF, 0xF, 0x3, 0x1
    };
    uint32_t ipv4_end;

    assert(iptree);
    assert(prefix > 0 || ipv4 == 0);
    assert(prefix <= 32);

    if (prefix <= 16) {
        ipv4_end = ((UINT32_MAX >> prefix) | ipv4) >> 16;
        ipv4 >>= 16;
        do {
            IPTREE_NODE_ALLOC(iptree, ipv4);
            memset(iptree->nodes[ipv4], 0xFF, sizeof(skIPNode_t));
        } while (ipv4++ < ipv4_end);

    } else {
        IPTREE_NODE_ALLOC(iptree, ipv4 >> 16);

        if (prefix >= 27) {
            iptree->nodes[ipv4 >> 16]->addressBlock[(ipv4 & 0xFFFF) >> 5]
                |= (prefix_as_bits[prefix - 27] << ((ipv4) & 0x1F));

        } else {
            /* 16 < prefix < 27 */
            memset(&iptree->nodes[ipv4>>16]->addressBlock[(ipv4 & 0xFFFF)>>5],
                   0xFF, (sizeof(skIPNode_t) >> (prefix - 16)));
        }
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetInsertAddressV4(ipset, ip, prefix, find_state);
 *  status = ipsetInsertAddressV6(ipset, ip, prefix, find_state);
 *
 *    Helper function for skIPSetInsertAddress(); may also be called
 *    by other internal functions.
 *
 *    Insert the CIDR block 'ip'/'prefix' into the Radix-Tree based
 *    'ipset'.  'find_state' may be NULL.  If not NULL, 'find_state'
 *    should be the result of calling ipsetFindVx() for the
 *    'ip'/'prefix'.  Do not call this function with a non-NULL
 *    'find_state' if ipsetFindVx() found the IP address.
 *
 *    Return SKIPSET_OK when the IP was successfully inserted, or
 *    SKIPSET_ERR_ALLOC if there is not enough memory to insert the
 *    IP.
 */
static int
ipsetInsertAddressV4(
    skipset_t          *ipset,
    const uint32_t      ipv4,
    const uint32_t      prefix,
    const ipset_find_t *find_state)
{
    ipset_find_t find_state_local;
    ipset_node_v4_t *parent = NULL;
    ipset_leaf_v4_t *leaf = NULL;
    ipset_node_v4_t *new_node;
    uint32_t new_node_idx;
    uint32_t new_leaf_idx[IPSET_NUM_CHILDREN];
    uint32_t which_child;
    uint32_t bitpos;
    uint32_t i;
    uint32_t j;
    int rv;

    assert(ipset);
    assert(prefix > 0 || ipv4 == 0);
    assert(prefix <= 32);
    assert(0 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);

    /* use the passed in 'find_state' if given */
    if (find_state) {
        rv = find_state->result;
    } else {
        rv = ipsetFindV4(ipset, ipv4, prefix, &find_state_local);
        /* if IP was found, we can return */
        if (SKIPSET_OK == rv) {
            return SKIPSET_OK;
        }
        find_state = &find_state_local;
    }
    ipset->is_dirty = 1;

    if (SKIPSET_ERR_EMPTY == rv) {
        /* tree was previously empty */
        /* create a new leaf to hold the IP. create an extra node and
         * extra leaf since node#0 and leaf#0 are always empty */
        if (ipsetNewEntries(ipset, 1, 2, &new_node_idx, new_leaf_idx)) {
            return SKIPSET_ERR_ALLOC;
        }
        assert(0 == new_node_idx);
        assert(0 == new_leaf_idx[0]);
        assert(1 == new_leaf_idx[1]);
        IPSET_ROOT_INDEX_SET(ipset, new_leaf_idx[1], 1);
        leaf = LEAF_PTR_V4(ipset, new_leaf_idx[IPSET_ROOT_INDEX(ipset)]);
        leaf->ip = ipv4;
        leaf->prefix = prefix;
        return SKIPSET_OK;
    }

    if (SKIPSET_ERR_SUBSET == rv) {
        /* we're adding an IP/PREFIX where part of the IP space
         * already exists in the IPSet.  Modify this node's values to
         * hold the larger block, and remove any nodes below here. */
        if (IPSET_NO_PARENT == find_state->parent_idx) {
            if (IPSET_ROOT_IS_LEAF(ipset)) {
                leaf = LEAF_PTR_V4(ipset, find_state->node_idx);
            } else {
                new_leaf_idx[0] = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
                leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
            }
            leaf->ip = ipv4;
            leaf->prefix = prefix;
            return SKIPSET_OK;
        }

        /* get a handle to the parent */
        parent = NODE_PTR_V4(ipset, find_state->parent_idx);

        if (NUM_BITS <= prefix - parent->prefix) {
            /* leaf has a single child[] entry on the parent */
            if (find_state->node_is_leaf) {
                /* we can modify the leaf and be done */
                leaf = LEAF_PTR_V4(ipset, find_state->node_idx);
            } else {
                /* need to replace the node with a leaf */
                new_leaf_idx[0]
                    = ipsetReplaceNodeWithLeaf(ipset, (ipset_node_t*)parent,
                                               find_state->parents_child);
                leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
            }
            leaf->ip = ipv4;
            leaf->prefix = prefix;
            return SKIPSET_OK;
        }

        /* this leaf will cover several child[] entries on the parent.
         * destroy any existing children and attempt to find a leaf on
         * this level to use  */
        new_leaf_idx[0] = 0;
        for (i = find_state->parents_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]
                && !NODEPTR_CHILD_IS_REPEAT(parent, i))
            {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    /* delete this subtree */
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                } else if (0 == new_leaf_idx[0]) {
                    /* found a leaf to use */
                    new_leaf_idx[0] = parent->child[i];
                } else {
                    /* do not need this leaf */
                    LEAFIDX_FREE(ipset, parent->child[i]);
                }
            }
        }

        if (0 == new_leaf_idx[0]) {
            /* no leaves available, need to allocate one */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
        }

        leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
        leaf->ip = ipv4;
        leaf->prefix = prefix;

        /* set child[] entries on 'parent' to point at the new leaf */
        /* set additional child[]s to also point at the leaf */
        for (i = find_state->parents_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            parent->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(parent, find_state->parents_child, i - 1);
        NODEPTR_CHILD_SET_REPEAT2(parent, 1+find_state->parents_child, i - 1);
        return SKIPSET_OK;
    }

    if (SKIPSET_ERR_MULTILEAF == rv) {
        /* get a handle to the current node */
        parent = NODE_PTR_V4(ipset, find_state->parent_idx);

        if (NUM_BITS <= prefix - parent->prefix) {
            /* need to add a single leaf and have a single child[]
             * entry on 'parent' point to that leaf */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
            /* get a handle to the newly created leaf and copy the new
             * IP there */
            leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
            leaf->ip = ipv4;
            leaf->prefix = prefix;

            /* set pointer on 'parent' to point at the new leaf */
            parent->child[find_state->parents_child] = new_leaf_idx[0];
            NODEPTR_CHILD_SET_LEAF(parent, find_state->parents_child);
            return SKIPSET_OK;
        }

        /* this leaf will cover several child[] entries on the parent.
         * see if any are occupied. */
        new_leaf_idx[0] = 0;
        for (i = find_state->parents_child + 1, j = 1u;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i] && NODEPTR_CHILD_IS_LEAF(parent, i)) {
                new_leaf_idx[0] = parent->child[i];
                break;
            }
        }
        if (new_leaf_idx[0] == 0) {
            /* no leaves available, need to allocate one */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
        }

        leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
        leaf->ip = ipv4;
        leaf->prefix = prefix;

        /* set child[] on 'parent' to point at the new leaf */
        parent->child[find_state->parents_child] = new_leaf_idx[0];

        /* set additional child[]s to also point at the leaf */
        for (i = find_state->parents_child + 1, j = 1u;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]) {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    /* delete this subtree */
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                } else if (parent->child[i] != new_leaf_idx[0]) {
                    /* do not need this leaf */
                    LEAFIDX_FREE(ipset, parent->child[i]);
                }
            }
            parent->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(parent, find_state->parents_child, i - 1);
        if (j > 1) {
            NODEPTR_CHILD_SET_REPEAT2(parent, 1 + find_state->parents_child,
                                      i - 1);
        }
        return SKIPSET_OK;
    }

    /* we must add a new node and a new leaf to the tree.  The leaf
     * holds the IP being inserted.  The node holds the CIDR block
     * containing the leaf and our current node---that is, it becomes
     * a new parent; we must also update the index on the current
     * node's parent to point to the new parent. */

    /* create the two new entries */
    if (ipsetNewEntries(ipset, 1, 1, &new_node_idx, new_leaf_idx)) {
        return SKIPSET_ERR_ALLOC;
    }

    /* get a handle to the newly created node */
    new_node = NODE_PTR_V4(ipset, new_node_idx);

    bitpos = find_state->bitpos & ~(NUM_BITS - 1);

    /* get a handle to the newly created leaf, copy the inserted IP
     * there, and link it to the new_node. */
    leaf = LEAF_PTR_V4(ipset, new_leaf_idx[0]);
    leaf->ip = ipv4;
    leaf->prefix = prefix;
    which_child = WHICH_CHILD_V4(ipv4, bitpos);
    if (NUM_BITS <= prefix - bitpos) {
        /* adding a single child[] entry */
        new_node->child[which_child] = new_leaf_idx[0];
        NODEPTR_CHILD_SET_LEAF(new_node, which_child);

    } else {
        /* this leaf will cover several child[] values on the node. */
        for (i = which_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - bitpos)));
             ++i, ++j)
        {
            new_node->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(new_node, which_child, i - 1);
        NODEPTR_CHILD_SET_REPEAT2(new_node, 1 + which_child, i - 1);
    }

    /* the following code is slightly different depending on whether
     * search stopped on a node or on a leaf */
    if (find_state->node_is_leaf) {
        /* get a handle to the current leaf that is being moved down
         * the tree */
        leaf = LEAF_PTR_V4(ipset, find_state->node_idx);

        /* copy the leaf's IP to the new parent, masking off the lower
         * bits */
        new_node->prefix = bitpos;
        new_node->ip = leaf->ip & ~(UINT32_MAX >> new_node->prefix);

        /* put the leaf under new_node */
        which_child = WHICH_CHILD_V4(leaf->ip, new_node->prefix);
        if (NUM_BITS <= leaf->prefix - new_node->prefix) {
            /* leaf occupies a single child[] entry */
            new_node->child[which_child] = find_state->node_idx;
            NODEPTR_CHILD_SET_LEAF(new_node, which_child);

        } else {
            for (i = which_child, j = 0;
                 j < (1u << (NUM_BITS - (leaf->prefix - new_node->prefix)));
                 ++i, ++j)
            {
                new_node->child[i] = find_state->node_idx;
            }
            NODEPTR_CHILD_SET_LEAF2(new_node, which_child, i - 1);
            NODEPTR_CHILD_SET_REPEAT2(new_node, 1 + which_child, i - 1);
        }

        /* get a handle to the parent, and update the child pointer on
         * the parent */
        if (find_state->parent_idx == IPSET_NO_PARENT) {
            IPSET_ROOT_INDEX_SET(ipset, new_node_idx, 0);
        } else {
            parent = NODE_PTR_V4(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V4(leaf->ip, parent->prefix);
            assert(parent->child[which_child] == find_state->node_idx);
            parent->child[which_child] = new_node_idx;
            NODEPTR_CHILD_CLEAR_LEAF(parent, which_child);
        }

    } else {
        /* get a handle to the current node that is being moved down
         * the tree */
        ipset_node_v4_t *node = NODE_PTR_V4(ipset, find_state->node_idx);

        /* copy the current node's IP to the new parent, masking off
         * the lower bits */
        new_node->prefix = bitpos;
        new_node->ip = node->ip & ~(UINT32_MAX >> bitpos);

        /* put the current node under new_node */
        which_child = WHICH_CHILD_V4(node->ip, new_node->prefix);
        new_node->child[which_child] = find_state->node_idx;

        /* get a handle to the parent, and update the child pointer on
         * the parent */
        if (find_state->parent_idx == IPSET_NO_PARENT) {
            IPSET_ROOT_INDEX_SET(ipset, new_node_idx, 0);
        } else {
            parent = NODE_PTR_V4(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V4(node->ip, parent->prefix);
            assert(parent->child[which_child] == find_state->node_idx);
            parent->child[which_child] = new_node_idx;
        }
    }

    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetInsertAddressV6(
    skipset_t          *ipset,
    const ipset_ipv6_t *ipv6,
    const uint32_t      prefix,
    const ipset_find_t *find_state)
{
    ipset_find_t find_state_local;
    ipset_node_v6_t *parent = NULL;
    ipset_leaf_v6_t *leaf = NULL;
    ipset_node_v6_t *new_node;
    uint32_t new_node_idx;
    uint32_t new_leaf_idx[IPSET_NUM_CHILDREN];
    uint32_t which_child;
    uint32_t bitpos;
    uint32_t i;
    uint32_t j;
    int rv;

    assert(ipset);
    assert(ipv6);
    assert(0 < prefix && prefix <= 128);
    assert(0 == ipset->is_iptree);
    assert(1 == ipset->is_ipv6);

    if (find_state) {
        rv = find_state->result;
    } else {
        rv = ipsetFindV6(ipset, ipv6, prefix, &find_state_local);
        /* if IP was found, we can return */
        if (SKIPSET_OK == rv) {
            return SKIPSET_OK;
        }
        find_state = &find_state_local;
    }
    ipset->is_dirty = 1;

    if (SKIPSET_ERR_EMPTY == rv) {
        /* tree was previously empty */
        /* create a new node to hold the IP */
        if (ipsetNewEntries(ipset, 1, 2, &new_node_idx, new_leaf_idx)) {
            return SKIPSET_ERR_ALLOC;
        }
        assert(0 == new_node_idx);
        assert(0 == new_leaf_idx[0]);
        assert(1 == new_leaf_idx[1]);
        IPSET_ROOT_INDEX_SET(ipset, new_leaf_idx[1], 1);
        leaf = LEAF_PTR_V6(ipset, new_leaf_idx[IPSET_ROOT_INDEX(ipset)]);
        IPSET_IPV6_COPY(&leaf->ip, ipv6);
        leaf->prefix = prefix;
        return SKIPSET_OK;
    }

    if (SKIPSET_ERR_SUBSET == rv) {
        /* we're adding an IP/PREFIX where part of the IP space
         * already exists in the IPSet.  Modify this node's values to
         * hold the larger block, and remove any nodes below here. */
        if (IPSET_NO_PARENT == find_state->parent_idx) {
            if (IPSET_ROOT_IS_LEAF(ipset)) {
                leaf = LEAF_PTR_V6(ipset, find_state->node_idx);
            } else {
                new_leaf_idx[0] = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
                leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
            }
            IPSET_IPV6_COPY(&leaf->ip, ipv6);
            leaf->prefix = prefix;
            return SKIPSET_OK;
        }

        /* get a handle to the parent */
        parent = NODE_PTR_V6(ipset, find_state->parent_idx);

        if (NUM_BITS <= prefix - parent->prefix) {
            /* leaf has a single child[] entry on the parent */
            if (find_state->node_is_leaf) {
                /* we can modify the leaf and be done */
                leaf = LEAF_PTR_V6(ipset, find_state->node_idx);
            } else {
                /* need to replace the node with a leaf */
                new_leaf_idx[0]
                    = ipsetReplaceNodeWithLeaf(ipset, (ipset_node_t*)parent,
                                               find_state->parents_child);
                leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
            }
            IPSET_IPV6_COPY(&leaf->ip, ipv6);
            leaf->prefix = prefix;
            return SKIPSET_OK;
        }

        /* this leaf will cover several child[] entries on the parent.
         * destroy any existing children and attempt to find a leaf on
         * this level to use  */
        new_leaf_idx[0] = 0;
        for (i = find_state->parents_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]
                && !NODEPTR_CHILD_IS_REPEAT(parent, i))
            {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    /* delete this subtree */
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                } else if (0 == new_leaf_idx[0]) {
                    /* found a leaf to use */
                    new_leaf_idx[0] = parent->child[i];
                } else {
                    /* do not need this leaf */
                    LEAFIDX_FREE(ipset, parent->child[i]);
                }
            }
        }

        if (0 == new_leaf_idx[0]) {
            /* no leaves available, need to allocate one */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
        }

        leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
        IPSET_IPV6_COPY(&leaf->ip, ipv6);
        leaf->prefix = prefix;

        /* set child[] entries on 'parent' to point at the new leaf */
        /* set additional child[]s to also point at the leaf */
        for (i = find_state->parents_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            parent->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(parent, find_state->parents_child, i - 1);
        NODEPTR_CHILD_SET_REPEAT2(parent, 1+find_state->parents_child, i - 1);
        return SKIPSET_OK;
    }

    if (SKIPSET_ERR_MULTILEAF == rv) {
        /* get a handle to the current node */
        parent = NODE_PTR_V6(ipset, find_state->parent_idx);

        if (NUM_BITS <= prefix - parent->prefix) {
            /* need to add a single leaf and have a single child[]
             * entry on 'parent' point to that leaf */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
            /* get a handle to the newly created leaf and copy the new
             * IP there */
            leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
            IPSET_IPV6_COPY(&leaf->ip, ipv6);
            leaf->prefix = prefix;

            /* set pointer on 'parent' to point at the new leaf */
            parent->child[find_state->parents_child] = new_leaf_idx[0];
            NODEPTR_CHILD_SET_LEAF(parent, find_state->parents_child);
            return SKIPSET_OK;
        }

        /* this leaf will cover several child[] entries on the parent.
         * see if any are occupied. */
        new_leaf_idx[0] = 0;
        for (i = find_state->parents_child + 1, j = 1u;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i] && NODEPTR_CHILD_IS_LEAF(parent, i)) {
                new_leaf_idx[0] = parent->child[i];
                break;
            }
        }
        if (new_leaf_idx[0] == 0) {
            /* no leaves available, need to allocate one */
            if (ipsetNewEntries(ipset, 0, 1, NULL, new_leaf_idx)) {
                return SKIPSET_ERR_ALLOC;
            }
        }

        leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
        IPSET_IPV6_COPY(&leaf->ip, ipv6);
        leaf->prefix = prefix;

        /* set child[] on 'parent' to point at the new leaf */
        parent->child[find_state->parents_child] = new_leaf_idx[0];

        /* set additional child[]s to also point at the leaf */
        for (i = find_state->parents_child + 1, j = 1u;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]) {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    /* delete this subtree */
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                } else if (parent->child[i] != new_leaf_idx[0]) {
                    /* do not need this leaf */
                    LEAFIDX_FREE(ipset, parent->child[i]);
                }
            }
            parent->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(parent, find_state->parents_child, i - 1);
        if (j > 1) {
            NODEPTR_CHILD_SET_REPEAT2(parent, 1 + find_state->parents_child,
                                      i - 1);
        }
        return SKIPSET_OK;
    }

    /* we must add a new node and a new leaf to the tree.  The leaf
     * holds the IP being inserted.  The node holds the CIDR block
     * containing the leaf and our current node---that is, it becomes
     * a new parent; we must also update the index on the current
     * node's parent to point to the new parent. */

    /* create the two new entries */
    if (ipsetNewEntries(ipset, 1, 1, &new_node_idx, new_leaf_idx)) {
        return SKIPSET_ERR_ALLOC;
    }

    /* get a handle to the newly created node */
    new_node = NODE_PTR_V6(ipset, new_node_idx);

    bitpos = find_state->bitpos & ~(NUM_BITS - 1);

    /* get a handle to the newly created leaf, copy the inserted IP
     * there, and link it to the new_node */
    leaf = LEAF_PTR_V6(ipset, new_leaf_idx[0]);
    IPSET_IPV6_COPY(&leaf->ip, ipv6);
    leaf->prefix = prefix;
    which_child = WHICH_CHILD_V6(ipv6, bitpos);
    if (NUM_BITS <= prefix - bitpos) {
        /* adding a single child[] entry */
        new_node->child[which_child] = new_leaf_idx[0];
        NODEPTR_CHILD_SET_LEAF(new_node, which_child);

    } else {
        /* this leaf will cover several child[] values on the node. */
        for (i = which_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - bitpos)));
             ++i, ++j)
        {
            new_node->child[i] = new_leaf_idx[0];
        }
        NODEPTR_CHILD_SET_LEAF2(new_node, which_child, i - 1);
        NODEPTR_CHILD_SET_REPEAT2(new_node, 1 + which_child, i - 1);
    }

    /* the following code is slightly different depending on whether
     * search stopped on a node or on a leaf */
    if (find_state->node_is_leaf) {
        /* get a handle to the current leaf that is being moved down
         * the tree */
        leaf = LEAF_PTR_V6(ipset, find_state->node_idx);

        /* copy the leaf's IP to the new parent, masking off the lower
         * bits */
        new_node->prefix = bitpos;
        IPSET_IPV6_COPY_AND_MASK(&new_node->ip, &leaf->ip, bitpos);

        /* put the leaf under new_node */
        which_child = WHICH_CHILD_V6(&leaf->ip, new_node->prefix);
        if (NUM_BITS <= leaf->prefix - new_node->prefix) {
            /* leaf occupies a single child[] entry */
            new_node->child[which_child] = find_state->node_idx;
            NODEPTR_CHILD_SET_LEAF(new_node, which_child);

        } else {
            for (i = which_child, j = 0;
                 j < (1u << (NUM_BITS - (leaf->prefix - new_node->prefix)));
                 ++i, ++j)
            {
                new_node->child[i] = find_state->node_idx;
            }
            NODEPTR_CHILD_SET_LEAF2(new_node, which_child, i - 1);
            NODEPTR_CHILD_SET_REPEAT2(new_node, 1 + which_child, i - 1);
        }

        /* get a handle to the parent, and update the child pointer on
         * the parent */
        if (find_state->parent_idx == IPSET_NO_PARENT) {
            IPSET_ROOT_INDEX_SET(ipset, new_node_idx, 0);
        } else {
            parent = NODE_PTR_V6(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V6(&leaf->ip, parent->prefix);
            assert(parent->child[which_child] == find_state->node_idx);
            parent->child[which_child] = new_node_idx;
            NODEPTR_CHILD_CLEAR_LEAF(parent, which_child);
        }

    } else {
        /* get a handle to the current node that is being moved down
         * the tree */
        ipset_node_v6_t *node = NODE_PTR_V6(ipset, find_state->node_idx);

        /* copy the current node's IP to the new parent, masking off
         * the lower bits */
        new_node->prefix = bitpos;
        IPSET_IPV6_COPY_AND_MASK(&new_node->ip, &node->ip, bitpos);

        /* put the current node under new_node */
        which_child = WHICH_CHILD_V6(&node->ip, new_node->prefix);
        new_node->child[which_child] = find_state->node_idx;

        /* get a handle to the parent, and update the child pointer on
         * the parent */
        if (find_state->parent_idx == IPSET_NO_PARENT) {
            IPSET_ROOT_INDEX_SET(ipset, new_node_idx, 0);
        } else {
            parent = NODE_PTR_V6(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V6(&node->ip, parent->prefix);
            assert(parent->child[which_child] == find_state->node_idx);
            parent->child[which_child] = new_node_idx;
        }
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */

/*
 *  status = ipsetInsertIPAddrIPTree(ipaddr, prefix, ipset);
 *  status = ipsetInsertIPAddrV4(ipaddr, prefix, ipset);
 *  status = ipsetInsertIPAddrV6(ipaddr, prefix, ipset);
 *
 *    Helper callback functions for the helpers of skIPSetRead() that
 *    use ipsetProcessStream...().  These callbacks are similar to
 *    ipsetUnionCallback*(), but these take an skipaddr_t.
 *
 *    Add the CIDR block specified by 'ipaddr'/'prefix' to 'ipset'.
 */
static int
ipsetInsertIPAddrIPTree(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetInsertAddressIPTree(((skipset_t*)v_ipset)->s.v2,
                                    skipaddrGetV4(ipaddr), prefix);
}

static int
ipsetInsertIPAddrV4(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetInsertAddressV4((skipset_t*)v_ipset, skipaddrGetV4(ipaddr),
                                prefix, NULL);
}

#if SK_ENABLE_IPV6
static int
ipsetInsertIPAddrV6(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    ipset_ipv6_t ipv6;
    IPSET_IPV6_FROM_ADDRV6(&ipv6, ipaddr);
    return ipsetInsertAddressV6((skipset_t*)v_ipset, &ipv6, prefix, NULL);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetInsertRangeIPTree(ipset, ipaddr_start, ipaddr_end);
 *
 *    Insert all IPv4 addresses from ipaddr_start to ipaddr_end
 *    inclusive into the IPset 'ipset'.
 */
static int
ipsetInsertRangeIPTree(
    skipset_t          *ipset,
    const skipaddr_t   *ipaddr_start,
    const skipaddr_t   *ipaddr_end)
{
    skipaddr_t ipaddr4_start;
    skipaddr_t ipaddr4_end;
    skipaddr_t ipaddr4_next;
    uint32_t prefix;
    int rv = SKIPSET_OK;

    assert(ipset);
    assert(1 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);

    /* must be a valid range of IPv4 addresses containing two or more
     * IP addresses */
    assert(skipaddrCompare(ipaddr_start, ipaddr_end) < 0);
    assert(!skipaddrIsV6(ipaddr_start) && !skipaddrIsV6(ipaddr_end));

#if  SK_ENABLE_IPV6
    if (skipaddrIsV6(ipaddr_start)) {
        if (skipaddrV6toV4(ipaddr_start, &ipaddr4_start)) {
            return SKIPSET_ERR_IPV6;
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        skipaddrCopy(&ipaddr4_start, ipaddr_start);
    }

#if  SK_ENABLE_IPV6
    if (skipaddrIsV6(ipaddr_end)) {
        if (skipaddrV6toV4(ipaddr_end, &ipaddr4_end)) {
            return SKIPSET_ERR_IPV6;
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        skipaddrCopy(&ipaddr4_end, ipaddr_end);
    }

    ipset->is_dirty = 1;

    do {
        prefix = skCIDRComputePrefix(&ipaddr4_start, &ipaddr4_end,
                                     &ipaddr4_next);
        rv = ipsetInsertAddressIPTree(
            ipset->s.v2, skipaddrGetV4(&ipaddr4_start), prefix);
        skipaddrCopy(&ipaddr4_start, &ipaddr4_next);
    } while (SKIPSET_OK == rv && !skipaddrIsZero(&ipaddr4_start));

    return rv;
}


/*
 *  status = ipsetIntersectCallback(ipaddr, prefix, state);
 *
 *    Callback function used by skIPSetIntersect().
 *
 *    This function will return SKIPSET_OK to continue walking over
 *    the IPs, SKIPSET_ERR_ALLOC for an allocation error, or
 *    SKIPSET_ERR_SUBSET when the iterator runs out of IPs to
 *    visit---which will stop the skIPSetWalk().
 */
static int
ipsetIntersectCallback(
    skipaddr_t         *start_addr,
    uint32_t            prefix,
    void               *v_state)
{
    ipset_intersect_t *state = (ipset_intersect_t*)v_state;
    skipaddr_t walk_addr[2];
    int walk_next = 0;

    /* get the start and end IPs for the CIDR block */
    skCIDR2IPRange(start_addr, prefix, &walk_addr[0], &walk_addr[1]);

    for (;;) {
        /* test (iter.final <= walk.final) */
        if (skipaddrCompare(&state->addr[1], &walk_addr[1]) <= 0) {

            /* test (iter.begin >= walk.begin) */
            if (skipaddrCompare(&state->addr[0], &walk_addr[0]) >= 0) {
                /* The iter block is completely contained in---or
                 * identical to---the walk block.  Add the iter
                 * block to the vector.
                 *
                 * iter block:             |---------|
                 * walk block: |---------------------------------|
                 */
                if (skVectorAppendValue(state->vec_add, state->addr)) {
                    return SKIPSET_ERR_ALLOC;
                }

                /* test (iter.final >= walk.begin) */
            } else if (skipaddrCompare(&state->addr[1], &walk_addr[0]) >= 0) {
                /* Add the IPs between walk.begin and iter.final.
                 *
                 * iter block:             |---------|
                 * walk block:                 |---------|
                 */
                skipaddrCopy(&state->addr[0], &walk_addr[0]);
                if (skVectorAppendValue(state->vec_add, state->addr)) {
                    return SKIPSET_ERR_ALLOC;
                }
            }

            /* Else, the iter block is completely below the current walk
             * block; and there is nothing to do.
             *
             * iter block:             |---------|
             * walk block:                         |---------|
             */

            /* If the end IPs are identical, refresh both blocks; else
             * go to next iter block */
            if (skipaddrCompare(&state->addr[1], &walk_addr[1]) == 0) {
                walk_next = 1;
            }

            if (skIPSetIteratorNext(&state->iter, &state->addr[0], &prefix)) {
                /* return some value so we stop walking over the IPs */
                return SKIPSET_ERR_SUBSET;
            }
            skCIDR2IPRange(&state->addr[0], prefix,
                           &state->addr[0], &state->addr[1]);
            if (walk_next) {
                break;
            }

        } else {

            /* test (iter.begin <= walk.begin) */
            if (skipaddrCompare(&state->addr[0], &walk_addr[0]) <= 0) {
                /* The walk is completely contained in the iter block.
                 * Add the walk block to the vector.
                 *
                 * iter block:             |---------|
                 * walk block:               |-----|
                 */
                if (skVectorAppendValue(state->vec_add, walk_addr)) {
                    return SKIPSET_ERR_ALLOC;
                }

                /* test (iter.begin <= walk.final) */
            } else if (skipaddrCompare(&state->addr[0], &walk_addr[1]) <= 0) {
                /* Add the IPs between iter.begin and walk.final.
                 *
                 * iter block:             |---------|
                 * walk block:         |---------|
                 */
                skipaddrCopy(&walk_addr[0], &state->addr[0]);
                if (skVectorAppendValue(state->vec_add, walk_addr)) {
                    return SKIPSET_ERR_ALLOC;
                }
            }

            /* Else, the iter block is completely above the walk block,
             * and there is nothing to do.
             *
             * iter block:             |---------|
             * walk block: |---------|
             */

            /* Go to next walk block */
            break;
        }
    }
    return SKIPSET_OK;
}


/*
 *  status = ipsetInsertWildcardIPTree(ipset, wildcard);
 *
 *    Helper function for skIPSetInsertIPWildcard() when the IPset is
 *    represented by a SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeAddIPWildcard().
 *
 *    Insert the IPs in the IPWildcard 'wildcard' into 'ipset'.
 */
static int
ipsetInsertWildcardIPTree(
    skIPTree_t             *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    skipaddr_t ipaddr;
    uint32_t ipv4;
    uint32_t prefix;
    int rv;

    assert(ipset);
    assert(ipwild);

    /* Iterate over the IPs from the wildcard */
    skIPWildcardIteratorBindV4(&iter, ipwild);
    while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
           == SK_ITERATOR_OK)
    {
        assert(prefix <= 32);
        ipv4 = skipaddrGetV4(&ipaddr);
        rv = ipsetInsertAddressIPTree(ipset, ipv4, prefix);
        if (rv) {
            return rv;
        }
    }
    return SKIPSET_OK;
}


/*
 *    Helper function for skIPSetIntersect() when both IPsets are
 *    implmented by SiLK-2 IPTrees.
 *
 *    Also a helper function for legacy skIPTreeIntersect().
 */
static int
ipsetIntersectIPTree(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    unsigned int i, j;

    assert(result_ipset);
    assert(ipset);

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (NULL == result_ipset->nodes[i]) {
            /* This /16 is completely off in 'result_ipset; no changes
             * necessary */

        } else if (NULL == ipset->nodes[i]) {
            /* Turn off this node in 'result_ipset' */
            free(result_ipset->nodes[i]);
            result_ipset->nodes[i] = NULL;

        } else {
            uint32_t keep_node = 0;
            /* Need to intersect the bits in the /16 */
            for (j = 0; keep_node == 0 && j < SKIP_BBLOCK_SIZE; ++j) {
                result_ipset->nodes[i]->addressBlock[j]
                    &= ipset->nodes[i]->addressBlock[j];
                keep_node = result_ipset->nodes[i]->addressBlock[j];
            }
            if (keep_node) {
                for ( ; j < SKIP_BBLOCK_SIZE; ++j) {
                    result_ipset->nodes[i]->addressBlock[j]
                        &= ipset->nodes[i]->addressBlock[j];
                }
            } else {
                free(result_ipset->nodes[i]);
                result_ipset->nodes[i] = NULL;
            }
        }
    }

    return SKIPSET_OK;
}


/*
 *    Modify the IPTree iterator values on 'iter' to point to the next
 *    /27-bitmap that has any bits set.
 *
 *    The search starts from the CURRENT values of the 'top_16' and
 *    'mid_11' members of the iterator.
 */
static void
ipsetIteratorIPTreeNextSlash27(
    skipset_iterator_t *iter)
{
    for ( ; iter->it.v2.top_16 < SKIP_BBLOCK_COUNT; ++iter->it.v2.top_16) {
        if (iter->it.v2.tree->nodes[iter->it.v2.top_16]) {
            for (; iter->it.v2.mid_11 < SKIP_BBLOCK_SIZE; ++iter->it.v2.mid_11)
            {
                if (iter->it.v2.tree->nodes[iter->it.v2.top_16]
                    ->addressBlock[iter->it.v2.mid_11])
                {
                    return;
                }
            }
            iter->it.v2.mid_11 = 0;
        }
    }
}


/*
 *  ipsetIteratorNextIPTree(iter, ipaddr, prefix);
 *
 *    Helper function for skIPSetIteratorNext() when the IPset is a
 *    SiLK-2 style IPTree.
 */
static int
ipsetIteratorNextIPTree(
    skipset_iterator_t *iter,
    skipaddr_t         *ipaddr,
    uint32_t           *prefix)
{
    uint32_t ipv4;
    uint32_t bmap;
    uint32_t max_slash27;
    uint32_t trail_zero;

    assert(1 == iter->is_iptree);

    if (iter->it.v2.count) {
        /* if the iterator already contains a CIDR block, return it */
        assert(1 == iter->cidr_blocks);
        goto END;
    }

    /* check stopping condition */
    if (iter->it.v2.top_16 >= SKIP_BBLOCK_COUNT) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    /* iterator should always be on a /27-bitmap with data */
    assert(iter->it.v2.mid_11 < SKIP_BBLOCK_SIZE);
    assert(iter->it.v2.bot_5 < 32);
    assert(iter->it.v2.tree->nodes[iter->it.v2.top_16]
           ->addressBlock[iter->it.v2.mid_11]);

    /* find position of least significant high bit in this /27-bitmap,
     * ignoring bits we have already checked */
    bmap = ((iter->it.v2.tree->nodes[iter->it.v2.top_16]
             ->addressBlock[iter->it.v2.mid_11])
            >> iter->it.v2.bot_5);
    assert(0 != bmap);
    trail_zero = ipsetCountTrailingZeros(bmap);
    bmap >>= trail_zero;
    iter->it.v2.bot_5 += trail_zero;
    /* Generate the IP address */
    ipv4 = (((iter->it.v2.top_16) << 16)
            | (iter->it.v2.mid_11 << 5)
            | iter->it.v2.bot_5);

    if (!iter->cidr_blocks || (ipv4 & 0x1)) {
        *prefix = 32;
        if ((bmap >> 1) && iter->it.v2.bot_5 < 31) {
            /* there are additional IPs in this /27-bitmap; no need to
             * search for the next valid /27 */
            ++iter->it.v2.bot_5;
            goto END;
        }
        /* reset bottom counter and increment middle counter; drop
         * into code below to find next valid /27-bitmap */
        iter->it.v2.bot_5 = 0;
        ++iter->it.v2.mid_11;

    } else if (UINT32_MAX != bmap) {
        /* this /27-bitmap is only partially filled */

        /* find number of consecutive high bits in 'bmap' that map
         * into a CIDR block */
        switch (iter->it.v2.bot_5) {
          case 0: case 16:
            if ((bmap & 0xFFFF) == 0xFFFF) {
                *prefix = 28;
                iter->it.v2.bot_5 += 16;
                bmap >>= 16;
                break;
            }
            /* FALLTHROUGH */
          case 8: case 24:
            if ((bmap & 0xFF) == 0xFF) {
                *prefix = 29;
                iter->it.v2.bot_5 += 8;
                bmap >>= 8;
                break;
            }
            /* FALLTHROUGH */
          case 4: case 12: case 20: case 28:
            if ((bmap & 0xF) == 0xF) {
                *prefix = 30;
                iter->it.v2.bot_5 += 4;
                bmap >>= 4;
                break;
            }
            /* FALLTHROUGH */
          case  2: case  6: case 10: case 14:
          case 18: case 22: case 26: case 30:
            if ((bmap & 0x3) == 0x3) {
                *prefix = 31;
                iter->it.v2.bot_5 += 2;
                bmap >>= 2;
                break;
            }
            /* FALLTHROUGH */
          default:
            *prefix = 32;
            ++iter->it.v2.bot_5;
            bmap >>= 1;
            break;
        }

        if (bmap && iter->it.v2.bot_5 < 32) {
            /* there are additional IPs in this /27-bitmap; no need to
             * search for the next valid /27 */
            goto END;
        }
        /* reset bottom counter and increment middle counter; drop
         * into code below to find next valid /27-bitmap */
        iter->it.v2.bot_5 = 0;
        ++iter->it.v2.mid_11;

    } else if (iter->it.v2.mid_11 & 0x1) {
        /* this /27 is full and the base IP is odd so it cannot grow;
         * increment counts and search for next /27-bitmap */
        assert(0 == iter->it.v2.bot_5);
        *prefix = 27;
        ++iter->it.v2.mid_11;

    } else {
        /* this /27 is full; attempt to join it with additional /27s
         * to make a larger CIDR block */
        assert(0 == iter->it.v2.bot_5);

        iter->it.v2.base_ip = ipv4;

        /* compute the maximum number of /27s that can be joined with
         * this one by counting the number of trailing zero bits on
         * the IP */
        if (0 == ipv4) {
            iter->it.v2.trail_zero = 32;
        } else {
            iter->it.v2.trail_zero = ipsetCountTrailingZeros(ipv4);
        }

        /* compute the maximum number of /27's that can be in this
         * CIDR block if it is completely full; the 'count' value on
         * the iterator maintains the number we actually see. */
        max_slash27 = (1 << (iter->it.v2.trail_zero - 5));
        iter->it.v2.count = 0;

        if (max_slash27 >= SKIP_BBLOCK_SIZE) {
            /* handle completely full nodes if we can */
            skIPNode_t full_node;

            assert(0 == iter->it.v2.mid_11);
            memset(&full_node, 0xFF, sizeof(full_node));
            do {
                if (memcmp(iter->it.v2.tree->nodes[iter->it.v2.top_16],
                           &full_node, sizeof(full_node)))
                {
                    /* node is not full */
                    break;
                }
                /* node is full */
                iter->it.v2.count += SKIP_BBLOCK_SIZE;
                ++iter->it.v2.top_16;
                assert(iter->it.v2.top_16 < SKIP_BBLOCK_COUNT
                       || iter->it.v2.count == max_slash27);
            } while (iter->it.v2.count < max_slash27
                     && iter->it.v2.tree->nodes[iter->it.v2.top_16]);
        }

        if (0 == iter->it.v2.count) {
            iter->it.v2.count = 1;
            ++iter->it.v2.mid_11;

            for (;;) {
                assert(iter->it.v2.mid_11 < SKIP_BBLOCK_SIZE);
                if (UINT32_MAX
                    != (iter->it.v2.tree->nodes[iter->it.v2.top_16]
                        ->addressBlock[iter->it.v2.mid_11]))
                {
                    /* cannot extend the CIDR block */
                    break;
                }
                ++iter->it.v2.count;
                ++iter->it.v2.mid_11;
                if (iter->it.v2.mid_11 == SKIP_BBLOCK_SIZE) {
                    /* cannot grow any more---a full node would have
                     * been found above; move to the next node and
                     * drop into the code below */
                    iter->it.v2.mid_11 = 0;
                    ++iter->it.v2.top_16;
                    break;
                }
                if (iter->it.v2.count == max_slash27) {
                    /* the CIDR block is at its maximum size; find the
                     * next /27-bitmap that has data */
                    break;
                }
                /* else keep growing the current CIDR block */
            }
        }
    }

    ipsetIteratorIPTreeNextSlash27(iter);

  END:
    if (iter->it.v2.count) {
        assert(1 == iter->cidr_blocks);
        assert(iter->it.v2.trail_zero >= 5);
        while (iter->it.v2.count < (1u << (iter->it.v2.trail_zero - 5))) {
            --iter->it.v2.trail_zero;
        }
        ipv4 = iter->it.v2.base_ip;
        *prefix = (32 - iter->it.v2.trail_zero);
        iter->it.v2.count -= (1 << (iter->it.v2.trail_zero - 5));
        iter->it.v2.base_ip |= (0x20u << (iter->it.v2.trail_zero - 5));
        --iter->it.v2.trail_zero;
    }

    switch (iter->v6policy) {
      case SK_IPV6POLICY_ONLY:
        /* since we do not support IPv6 addresses in the IPTree data
         * structure, there is nothing to return */
        skAbortBadCase(iter->v6policy);

      case SK_IPV6POLICY_FORCE:
#if SK_ENABLE_IPV6
        skipaddrSetV6FromUint32(ipaddr, &ipv4);
        *prefix += 96;
#endif  /* #if SK_ENABLE_IPV6 */
        break;

      case SK_IPV6POLICY_MIX:
      case SK_IPV6POLICY_ASV4:
      case SK_IPV6POLICY_IGNORE:
        skipaddrSetV4(ipaddr, &ipv4);
        break;
    }
    return SK_ITERATOR_OK;
}


/*
 *  ipsetIteratorNextRangeV4(iter);
 *  ipsetIteratorNextRangeV6(iter);
 *
 *    Helper functions for skIPSetIteratorNext().
 *
 *    Update the IPset iterator 'iter' to contain the starting and
 *    stopping IPs values for the CIDR block on the current leaf.
 *    Assumes the 'cur' field on the iterator is pointing at a valid
 *    leaf.
 */
static void
ipsetIteratorNextRangeV4(
    skipset_iterator_t *iter)
{
    ipset_leaf_v4_t *leaf = LEAF_PTR_V4(iter->ipset, iter->it.v3.cur);

    if (32 == leaf->prefix) {
        iter->it.v3.data[0] = iter->it.v3.data[2] = leaf->ip;
    } else {
        iter->it.v3.data[0] = leaf->ip;
        iter->it.v3.data[2] = (leaf->ip | (UINT32_MAX >> leaf->prefix));
    }
}

#if SK_ENABLE_IPV6
static void
ipsetIteratorNextRangeV6(
    skipset_iterator_t *iter)
{
    /*
     *    The data[4] array on the interator contains:
     *
     *    0, 1: Start of range, upper-64 and lower-64 bits
     *    2, 3: End of range, upper-64 and lower-64 bits
     */
    ipset_leaf_v6_t *leaf = LEAF_PTR_V6(iter->ipset, iter->it.v3.cur);

    if (SK_IPV6POLICY_ASV4 == iter->v6policy) {
        /* check stopping condition */
        if (leaf->ip.ip[0] != 0
            || ((UINT64_C(0xffffffff00000000) & leaf->ip.ip[1])
                != UINT64_C(0x0000ffff00000000)))
        {
            iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
            return;
        }
    }

    if (leaf->prefix > 64) {
        if (leaf->prefix == 128) {
            iter->it.v3.data[0] = iter->it.v3.data[2] = leaf->ip.ip[0];
            iter->it.v3.data[1] = iter->it.v3.data[3] = leaf->ip.ip[1];
        } else {
            iter->it.v3.data[0] = iter->it.v3.data[2] = leaf->ip.ip[0];
            iter->it.v3.data[1] = leaf->ip.ip[1];
            iter->it.v3.data[3] = (leaf->ip.ip[1]
                                   | (UINT64_MAX >> (leaf->prefix - 64)));
        }
    } else if (leaf->prefix == 64) {
        iter->it.v3.data[0] = iter->it.v3.data[2] = leaf->ip.ip[0];
        iter->it.v3.data[1] = 0;
        iter->it.v3.data[3] = UINT64_MAX;
    } else {
        iter->it.v3.data[0] = leaf->ip.ip[0];
        iter->it.v3.data[2] = (leaf->ip.ip[0] | (UINT64_MAX >> leaf->prefix));
        iter->it.v3.data[1] = 0;
        iter->it.v3.data[3] = UINT64_MAX;
    }
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  cmp = ipsetLeafCompareV4(leaf_a, leaf_b);
 *  cmp = ipsetLeafCompareV6(leaf_a, leaf_b);
 *
 *    Return -1, 0, 1 depending on whether the IP on leaf_a is less
 *    than, equal to, or greater than the IP on leaf_b.
 *
 *    This function compares the first IP in each leaf; it does not
 *    consider the case where one leaf contains a netblock that is a
 *    subset of the netblock on another leaf.
 */
static int
ipsetLeafCompareV4(
    const void         *va,
    const void         *vb)
{
    const uint32_t a = ((const ipset_leaf_v4_t *)va)->ip;
    const uint32_t b = ((const ipset_leaf_v4_t *)vb)->ip;
    if (a < b) {
        return -1;
    }
    return (a > b);
}

#if SK_ENABLE_IPV6
static int
ipsetLeafCompareV6(
    const void         *va,
    const void         *vb)
{
    const ipset_ipv6_t *a = &((const ipset_leaf_v6_t *)va)->ip;
    const ipset_ipv6_t *b = &((const ipset_leaf_v6_t *)vb)->ip;
    if (a->ip[0] < b->ip[0]) {
        return -1;
    }
    if (a->ip[0] > b->ip[0]) {
        return 1;
    }
    if (a->ip[1] < b->ip[1]) {
        return -1;
    }
    return (a->ip[1] > b->ip[1]);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetMaskAddLeavesV4(ipset, mask_prefix, leaf);
 *  status = ipsetMaskAddLeavesV6(ipset, mask_prefix, leaf);
 *
 *    Helper function for ipsetMaskVx().
 *
 *    Given 'leaf' that contains a CIDR block, remove 'leaf' from the
 *    'ipset' and add new leaves, where each new leaf is a single IP
 *    address (a /32 or /128), and the step size between the IPs is
 *    1<<(32-mask_prefix) or 1<<(128-mask_prefix).
 *
 *    Return SKIPSET_OK or SKIPSET_ERR_ALLOC.
 */
static int
ipsetMaskAddLeavesV4(
    skipset_t          *ipset,
    const uint32_t      mask_prefix,
    ipset_leaf_v4_t    *leaf)
{
    const uint32_t step = 1u << (32 - mask_prefix);
    uint32_t ipv4;
    uint32_t final;
    int rv;

    /* get the ip address */
    ipv4 = leaf->ip;

    /* compute the final ip address for our stopping condition */
    final = ((ipv4 | (UINT32_MAX >> leaf->prefix))
             & ~(UINT32_MAX >> mask_prefix));

    /* set the prefix so this leaf is a single IP */
    leaf->prefix = 32;

    while (ipv4 < final) {
        ipv4 += step;
        rv = ipsetInsertAddressV4(ipset, ipv4, 32, NULL);
        if (rv) {
            return rv;
        }
    }
    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetMaskAddLeavesV6(
    skipset_t          *ipset,
    const uint32_t      mask_prefix,
    ipset_leaf_v6_t    *leaf)
{
    ipset_ipv6_t ipv6;
    ipset_ipv6_t final;
    ipset_ipv6_t step;
    int rv;

    /* get the first address in this block */
    ipv6.ip[0] = leaf->ip.ip[0];
    ipv6.ip[1] = leaf->ip.ip[1];

    /* code in the bodies of the following if/else differ by size of
     * prefix */
    if (mask_prefix <= 64) {
        /* this affects only the most significant 64 bits */
        assert(leaf->prefix < 64);

        /* determine the final address in this block */
        final.ip[0] = ((ipv6.ip[0] | (UINT64_MAX >> leaf->prefix))
                       & ((mask_prefix < 64)
                          ? ~(UINT64_MAX >> mask_prefix)
                          : UINT64_MAX));

        /* get the step size */
        step.ip[0] = UINT64_C(1) << (64 - mask_prefix);

        /* modify starting leaf to be a single IP */
        leaf->prefix = 128;

        while (ipv6.ip[0] < final.ip[0]) {
            ipv6.ip[0] += step.ip[0];
            rv = ipsetInsertAddressV6(ipset, &ipv6, 128, NULL);
            if (rv) { return rv; }
        }

    } else if (leaf->prefix > 64) {
        /* this affects only the least significant 64 bits */
        assert(mask_prefix > 64);

        /* determine the final address in this block */
        final.ip[1] = ((ipv6.ip[1] | (UINT64_MAX >> (leaf->prefix - 64)))
                       & ~(UINT64_MAX >> (mask_prefix - 64)));

        /* get the step size */
        step.ip[1] = UINT64_C(1) << (128 - mask_prefix);

        /* modify starting leaf to be a single IP */
        leaf->prefix = 128;

        while (ipv6.ip[1] < final.ip[1]) {
            ipv6.ip[1] += step.ip[1];
            rv = ipsetInsertAddressV6(ipset, &ipv6, 128, NULL);
            if (rv) { return rv; }
        }

    } else {
        assert(mask_prefix > 64);
        assert(leaf->prefix <= 64);

        /* determine the final address in this block */
        final.ip[0] = ipv6.ip[0] | ((leaf->prefix < 64)
                                    ? (UINT64_MAX >> leaf->prefix)
                                    : 0);
        final.ip[1] = ~(UINT64_MAX >> (mask_prefix - 64));

        /* get the step size */
        step.ip[1] = UINT64_C(1) << (128 - mask_prefix);

        /* modify starting leaf to be a single IP */
        leaf->prefix = 128;

        while (ipv6.ip[0] < final.ip[0]) {
            if (ipv6.ip[1] <= UINT64_MAX - step.ip[1]) {
                ipv6.ip[1] += step.ip[1];
            } else {
                /* handle rollover */
                ++ipv6.ip[0];
                ipv6.ip[1] -= (UINT64_MAX - step.ip[1]) + 1;
            }
            rv = ipsetInsertAddressV6(ipset, &ipv6, 128, NULL);
            if (rv) { return rv; }
        }
        while (ipv6.ip[1] < final.ip[1]) {
            ipv6.ip[1] += step.ip[1];
            rv = ipsetInsertAddressV6(ipset, &ipv6, 128, NULL);
            if (rv) { return rv; }
        }
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Helper function for skIPSetMask() when the IPset is implmented
 *    by a SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeMask().
 */
static int
ipsetMaskIPTree(
    skIPTree_t         *ipset,
    uint32_t            mask)
{
    unsigned int i, j, k;

    assert(ipset);

    if (mask <= 16) {
        /* operate on multiple blocks */
        const unsigned int step = 1 << (16 - mask);

        if (0 == mask) {
            /* no op */
            return SKIPSET_OK;
        }
        for (i = 0; i < SKIP_BBLOCK_COUNT; i += step) {
            /* use 'k' to visit each /16 in this /N (stored in 'i')
             * until we find one that contains data. if data is found,
             * set the first bit in 'i' to 1 and delete all blocks 'k'
             * where 'k' > 'i'. */
            for (k = i; k < i + step; ++k) {
                if (NULL != ipset->nodes[k]) {
                    /* assumes any non-NULL IPTree node contains at
                     * least one high bit */
                    if (k > i) {
                        ipset->nodes[i] = ipset->nodes[k];
                        ipset->nodes[k] = NULL;
                    }
                    memset(ipset->nodes[i], 0, sizeof(skIPNode_t));
                    ipset->nodes[i]->addressBlock[0] = 1;
                    break;
                }
            }
            /* handle any remaining /16s in this /N */
            for (++k; k < i + step; ++k) {
                if (NULL != ipset->nodes[k]) {
                    free(ipset->nodes[k]);
                    ipset->nodes[k] = NULL;
                }
            }
        }

    } else if (mask <= 27) {
        /* operate on multiple uint32_t's in each block */
        const unsigned int step = 1 << (27 - mask);
        const size_t len = sizeof(skIPNode_t) >> (mask - 16);
        skIPNode_t empty;
        memset(&empty, 0, len);

        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (NULL == ipset->nodes[i]) {
                /* no change */

            } else {
                for (j = 0; j < SKIP_BBLOCK_SIZE; j += step) {
                    if (memcmp(&ipset->nodes[i]->addressBlock[j], &empty, len))
                    {
                        memset(&ipset->nodes[i]->addressBlock[j], 0, len);
                        ipset->nodes[i]->addressBlock[j] = 1;
                    }
                }
            }
        }

    } else if (mask < 32) {
        /* operate on bits within each uint32_t */
        const unsigned int step = 1 << (32 - mask);
        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (NULL == ipset->nodes[i]) {
                /* no change */

            } else {
                for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                    for (k = 0; k < 32; k += step) {
                        if (GET_MASKED_BITS(
                                ipset->nodes[i]->addressBlock[j], k, step))
                        {
                            SET_MASKED_BITS(
                                ipset->nodes[i]->addressBlock[j], 1, k, step);
                        }
                    }
                }
            }
        }
    }

    return SKIPSET_OK;
}

/*
 *  status = ipsetMaskV4(ipset, mask_prefix)
 *  status = ipsetMaskV6(ipset, mask_prefix)
 *
 *    Helper function for skIPSetMask().
 *
 *    For each block of size 'mask_prefix', if any IPs in that block
 *    are set, remove all IPs in the block and replace with with a
 *    single IP.
 */
static int
ipsetMaskV4(
    skipset_t          *ipset,
    const uint32_t      mask_prefix)
{
    ipset_node_v4_t *node;
    ipset_leaf_v4_t *leaf;
    uint32_t child_idx;
    uint32_t node_idx;
    uint32_t new_leaf_idx;
    uint32_t children_per_leaf;
    uint32_t ipv4;
    uint32_t i;
    uint32_t j;
    uint32_t depth;
    uint32_t to_visit[IPSET_MAX_DEPTH_V4];
    int rv = SKIPSET_OK;

    ipset->is_dirty = 1;

    /* handle case where root is a leaf */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V4(ipset, IPSET_ROOT_INDEX(ipset));
        if (leaf->prefix >= mask_prefix) {
            /* leaf spans fewer IPs than specified by 'mask_prefix'.
             * Modify the leaf's IP and prefix and return */
            leaf->ip &= ~(UINT32_MAX >> mask_prefix);
            leaf->prefix = 32;
            return SKIPSET_OK;
        }
        /* else, this leaf's prefix is more course (holds more IPs)
         * than what we want; we must split the leaf into multiple
         * nodes and leaves */
        return ipsetMaskAddLeavesV4(ipset, mask_prefix, leaf);
    }

    /* handle case where root contains a node whose prefix is
     * more-precise than the 'mask_prefix' */
    node = NODE_PTR_V4(ipset, IPSET_ROOT_INDEX(ipset));
    if (node->prefix >= mask_prefix) {
        ipv4 = node->ip;
        new_leaf_idx = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
        leaf = LEAF_PTR_V4(ipset, new_leaf_idx);
        leaf->ip = ipv4 &  ~(UINT32_MAX >> mask_prefix);
        leaf->prefix = 32;
        return SKIPSET_OK;
    }

    /* visit the nodes in the tree */
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR_V4(ipset, node_idx);

        if (mask_prefix - node->prefix > NUM_BITS) {
            /* this node is not at the bottom level of the tree; add
             * child nodes of this node to the 'to_visit' list. modify
             * any leaves to hold a single IP */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if ((0 == node->child[i])
                    || NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    /* no-op */
                } else if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                    /* node; add to vist list unless its prefix is
                     * larger than the mask, in which case replace
                     * with a leaf */
                    if (NODE_PTR_V4(ipset, node->child[i])->prefix
                        <= mask_prefix)
                    {
                        to_visit[depth++] = node->child[i];
                    } else {
                        ipv4 = NODE_PTR_V4(ipset,node->child[i])->ip;
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V4(ipset, node->child[i]);
                        leaf->ip = ipv4 & ~(UINT32_MAX >> mask_prefix);
                        leaf->prefix = 32;
                    }
                } else {
                    leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    if (leaf->prefix >= mask_prefix) {
                        leaf->ip &= ~(UINT32_MAX >> mask_prefix);
                        leaf->prefix = 32;
                    } else {
                        /* this leaf's prefix is more course (holds
                         * more IPs) than what we want; similar to
                         * code above that handle leaf at the root */

                        if (NUM_BITS > leaf->prefix - node->prefix) {
                            /* leaf occupies multiple child[] entries;
                             * clear all but the current one */
                            for (j = 1;
                                 ((j < (1u << (NUM_BITS -
                                               (leaf->prefix - node->prefix))))
                                  && ((i + j) < IPSET_NUM_CHILDREN));
                                 ++j)
                            {
                                node->child[i+j] = 0;
                            }
                            NODEPTR_CHILD_CLEAR_LEAF2(node, i + 1, i + j - 1);
                            NODEPTR_CHILD_CLEAR_REPEAT2(node, i + 1, i + j - 1);
                        }
                        rv = ipsetMaskAddLeavesV4(ipset, mask_prefix, leaf);
                        if (rv) { return rv; }
                        node = NODE_PTR_V4(ipset, node_idx);
                    }
                }
            }

        } else if (mask_prefix - node->prefix == NUM_BITS) {
            /* this node is on the bottom level of the tree, and every
             * occupied child[] will become an independent leaf */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]) {
                    if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                    } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                        NODEPTR_CHILD_CLEAR_REPEAT(node, i);
                    }
                    leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    leaf->ip = ((node->ip
                                 | (i << (32 - NUM_BITS - node->prefix)))
                                & ~(UINT32_MAX >> mask_prefix));
                    leaf->prefix = 32;
                }
            }

            /* if node has a single child, we need to replace the node
             * with the child on the node's parent */
            ipsetFixNodeSingleChild(ipset, node_idx, 1);

        } else {
            /* this node is on the bottom level of the tree. multiple
             * child[] entries will become a single leaf */
            children_per_leaf = 1u << (NUM_BITS- (mask_prefix - node->prefix));
            child_idx = UINT32_MAX;
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                for (j = 0; j < children_per_leaf; ++j) {
                    --i;
                    if (node->child[i]) {
                        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            ipsetDestroySubtree(ipset, node->child[i], 1);
                            node->child[i] = 0;
                        } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            node->child[i] = 0;
                        } else if (child_idx >= IPSET_NUM_CHILDREN) {
                            child_idx = i;
                        } else {
                            LEAFIDX_FREE(ipset, node->child[child_idx]);
                            NODEPTR_CHILD_CLEAR_LEAF(node, child_idx);
                            node->child[child_idx] = 0;
                            child_idx = i;
                        }
                    }
                }

                /* the if() is entered when 'i' is looking at the
                 * start of a group of child[] entries and any of the
                 * child[] entries for this group of entries was
                 * occupied. */
                if (child_idx != UINT32_MAX) {
                    if (IPSET_NUM_CHILDREN == child_idx) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                    } else if (child_idx != i) {
                        node->child[i] = node->child[child_idx];
                        node->child[child_idx] = 0;
                    }
                    leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    leaf->ip = ((node->ip
                                 | (i << (32 - NUM_BITS - node->prefix)))
                                & ~(UINT32_MAX >> mask_prefix));
                    leaf->prefix = 32;
                    NODEPTR_CHILD_SET_LEAF(node, i);
                    NODEPTR_CHILD_CLEAR_LEAF2(node, i+1,
                                              i + children_per_leaf - 1);
                    NODEPTR_CHILD_CLEAR_REPEAT2(node, i,
                                                i + children_per_leaf - 1);

                    /* reset for next group */
                    child_idx = UINT32_MAX;
                }
            }

            /* if node has a single child, we need to replace the node
             * with the child on the node's parent */
            ipsetFixNodeSingleChild(ipset, node_idx, 1);
        }
    }

    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetMaskV6(
    skipset_t          *ipset,
    const uint32_t      mask_prefix)
{
    ipset_node_v6_t *node;
    ipset_leaf_v6_t *leaf;
    uint32_t child_idx;
    uint32_t node_idx;
    uint32_t new_leaf_idx;
    uint32_t children_per_leaf;
    ipset_ipv6_t ipv6;
    uint32_t i;
    uint32_t j;
    uint32_t depth;
    uint32_t to_visit[IPSET_MAX_DEPTH_V6];
    int rv = SKIPSET_OK;

    ipset->is_dirty = 1;

    /* handle case where root is a leaf */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
        if (leaf->prefix >= mask_prefix) {
            /* leaf spans fewer IPs than specified by 'mask_prefix'.
             * Modify the leaf's IP and prefix and return */
            IPSET_IPV6_APPLY_CIDR(&leaf->ip, mask_prefix);
            leaf->prefix = 128;
            return SKIPSET_OK;
        }
        /* else, this leaf's prefix is more course (holds more IPs)
         * than what we want; we must split the leaf into multiple
         * nodes and leaves */
        return ipsetMaskAddLeavesV6(ipset, mask_prefix, leaf);
    }

    /* handle case where root contains a node whose prefix is
     * more-precise than the 'mask_prefix' */
    node = NODE_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
    if (node->prefix >= mask_prefix) {
        IPSET_IPV6_COPY(&ipv6, &node->ip);
        new_leaf_idx = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
        leaf = LEAF_PTR_V6(ipset, new_leaf_idx);
        IPSET_IPV6_COPY_AND_MASK(&leaf->ip, &ipv6, mask_prefix);
        leaf->prefix = 128;
        return SKIPSET_OK;
    }

    /* visit the nodes in the tree */
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR_V6(ipset, node_idx);

        if (mask_prefix - node->prefix > NUM_BITS) {
            /* this node is not at the bottom level of the tree; add
             * child nodes of this node to the 'to_visit' list. modify
             * any leaves to hold a single IP. */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if ((0 == node->child[i])
                    || NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    /* no-op */
                } else if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                    /* node; add to vist list unless its prefix is
                     * larger than the mask, in which case replace
                     * with a leaf */
                    if (NODE_PTR_V6(ipset, node->child[i])->prefix
                        <= mask_prefix)
                    {
                        to_visit[depth++] = node->child[i];
                    } else {
                        IPSET_IPV6_COPY(&ipv6,
                                        &NODE_PTR_V6(ipset,node->child[i])->ip);
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V6(ipset, node->child[i]);
                        IPSET_IPV6_COPY_AND_MASK(&leaf->ip, &ipv6, mask_prefix);
                        leaf->prefix = 128;
                    }
                } else {
                    leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    if (leaf->prefix >= mask_prefix) {
                        IPSET_IPV6_APPLY_CIDR(&leaf->ip, mask_prefix);
                        leaf->prefix = 128;
                    } else {
                        /* this leaf's prefix is more course (holds
                         * more IPs) than what we want; similar to
                         * code above that handle leaf at the root */

                        if (NUM_BITS > leaf->prefix - node->prefix) {
                            /* leaf occupies multiple child[] entries;
                             * clear all but the current one */
                            for (j = 1;
                                 ((j < (1u << (NUM_BITS -
                                               (leaf->prefix - node->prefix))))
                                  && ((i + j) < IPSET_NUM_CHILDREN));
                                 ++j)
                            {
                                node->child[i+j] = 0;
                            }
                            NODEPTR_CHILD_CLEAR_LEAF2(node, i + 1, i + j - 1);
                            NODEPTR_CHILD_CLEAR_REPEAT2(node, i + 1, i + j - 1);
                        }
                        rv = ipsetMaskAddLeavesV6(ipset, mask_prefix, leaf);
                        if (rv) { return rv; }
                        node = NODE_PTR_V6(ipset, node_idx);
                    }
                }
            }

        } else if (mask_prefix - node->prefix == NUM_BITS) {
            /* this node is on the bottom level of the tree, and every
             * occupied child[] will become an independent leaf */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]) {
                    if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                    } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                        NODEPTR_CHILD_CLEAR_REPEAT(node, i);
                    }
                    leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    leaf->prefix = 128;
                    if (node->prefix <= 64 - NUM_BITS) {
                        leaf->ip.ip[0] = ((node->ip.ip[0]
                                           | (((uint64_t)i)
                                              << (64-NUM_BITS- node->prefix)))
                                          & ((mask_prefix < 64)
                                             ? ~(UINT64_MAX >> mask_prefix)
                                             : UINT64_MAX));
                        leaf->ip.ip[1] = 0;
                    } else {
                        leaf->ip.ip[0] = node->ip.ip[0];
                        leaf->ip.ip[1] = ((node->ip.ip[1]
                                           | (((uint64_t)i)
                                              << (128-NUM_BITS- node->prefix)))
                                          & ~(UINT64_MAX >> (mask_prefix-64)));
                    }
                }
            }

            /* if node has a single child, we need to replace the node
             * with the child on the node's parent */
            ipsetFixNodeSingleChild(ipset, node_idx, 1);

        } else {
            /* this node is on the bottom level of the tree. multiple
             * child[] entries will become a single leaf */
            children_per_leaf = 1u << (NUM_BITS- (mask_prefix - node->prefix));
            child_idx = UINT32_MAX;
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                for (j = 0; j < children_per_leaf; ++j) {
                    --i;
                    if (node->child[i]) {
                        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            ipsetDestroySubtree(ipset, node->child[i], 1);
                            node->child[i] = 0;
                        } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            node->child[i] = 0;
                        } else if (child_idx >= IPSET_NUM_CHILDREN) {
                            child_idx = i;
                        } else {
                            LEAFIDX_FREE(ipset, node->child[child_idx]);
                            NODEPTR_CHILD_CLEAR_LEAF(node, child_idx);
                            node->child[child_idx] = 0;
                            child_idx = i;
                        }
                    }
                }

                /* the if() is entered when 'i' is looking at the
                 * start of a group of child[] entries and any of the
                 * child[] entries for this group of entries was
                 * occupied. */
                if (child_idx != UINT32_MAX) {
                    if (IPSET_NUM_CHILDREN == child_idx) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                    } else if (child_idx != i) {
                        node->child[i] = node->child[child_idx];
                        node->child[child_idx] = 0;
                    }
                    leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    leaf->prefix = 128;
                    if (node->prefix <= 64 - NUM_BITS) {
                        leaf->ip.ip[0] = ((node->ip.ip[0]
                                           | (((uint64_t)i)
                                              << (64-NUM_BITS- node->prefix)))
                                          & ((mask_prefix < 64)
                                             ? ~(UINT64_MAX >> mask_prefix)
                                             : UINT64_MAX));
                        leaf->ip.ip[1] = 0;
                    } else {
                        leaf->ip.ip[0] = node->ip.ip[0];
                        leaf->ip.ip[1] = ((node->ip.ip[1]
                                           | (((uint64_t)i)
                                              << (128-NUM_BITS- node->prefix)))
                                          & ~(UINT64_MAX >> (mask_prefix-64)));
                    }
                    NODEPTR_CHILD_SET_LEAF(node, i);
                    NODEPTR_CHILD_CLEAR_LEAF2(node, i+1,
                                              i + children_per_leaf - 1);
                    NODEPTR_CHILD_CLEAR_REPEAT2(node, i,
                                                i + children_per_leaf - 1);

                    child_idx = UINT32_MAX;
                }
            }

            /* if node has a single child, we need to replace the node
             * with the child on the node's parent */
            ipsetFixNodeSingleChild(ipset, node_idx, 1);
        }
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetMaskAndFillIPTree(ipset, mask_prefix)
 *
 *    Helper function for skIPSetMaskAndFill().
 *
 *    For each block of size 'mask_prefix', if any IPs in that block
 *    are set, fill the entire block.
 */
static int
ipsetMaskAndFillIPTree(
    skipset_t          *ipset,
    const uint32_t      mask_prefix)
{
    unsigned int i, j, k;
    skIPTree_t *iptree;

    assert(ipset);
    assert(1 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);
    assert(mask_prefix < 32 && mask_prefix > 0);

    ipset->is_dirty = 1;

    iptree = ipset->s.v2;

    if (mask_prefix <= 16) {
        /* operate on multiple blocks */
        const unsigned int step = 1 << (16 - mask_prefix);

        if (0 == mask_prefix) {
            /* no op */
            return SKIPSET_OK;
        }
        for (i = 0; i < SKIP_BBLOCK_COUNT; i += step) {
            /* use 'k' to visit each /16 in this /N (stored in 'i')
             * until we find one that contains data. if data is found,
             * set each /16 to a completely full node. */

            /* assumes any non-NULL IPTree node contains at least one
             * high bit */
            for (k = i; (k < i + step) && (NULL == iptree->nodes[k]); ++k)
                ;               /* empty */
            if (k < i + step) {
                for (k = i; k < i + step; ++k) {
                    IPTREE_NODE_ALLOC(iptree, k);
                    memset(iptree->nodes[k]->addressBlock, 0xff,
                           sizeof(iptree->nodes[k]->addressBlock));
                }
            }
        }

    } else if (mask_prefix <= 27) {
        /* operate on multiple uint32_t's in each block */
        const unsigned int step = 1 << (27 - mask_prefix);
        const size_t len = sizeof(skIPNode_t) >> (mask_prefix - 16);
        skIPNode_t empty;
        memset(&empty, 0, len);

        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (NULL == iptree->nodes[i]) {
                /* no change */

            } else {
                for (j = 0; j < SKIP_BBLOCK_SIZE; j += step) {
                    if (memcmp(&iptree->nodes[i]->addressBlock[j], &empty,len))
                    {
                        memset(&iptree->nodes[i]->addressBlock[j], 0xFF, len);
                    }
                }
            }
        }

    } else if (mask_prefix < 32) {
        /* operate on bits within each uint32_t */
        const unsigned int step = 1 << (32 - mask_prefix);
        const int32_t full = UINT32_MAX >> (32 - step);

        for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
            if (NULL == iptree->nodes[i]) {
                /* no change */

            } else {
                for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                    for (k = 0; k < 32; k += step) {
                        if (GET_MASKED_BITS(iptree->nodes[i]->addressBlock[j],
                                            k, step))
                        {
                            SET_MASKED_BITS(iptree->nodes[i]->addressBlock[j],
                                            full, k, step);
                        }
                    }
                }
            }
        }
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetMaskAndFillV4(ipset, mask_prefix)
 *  status = ipsetMaskAndFillV6(ipset, mask_prefix)
 *
 *    Helper function for skIPSetMaskAndFill().
 *
 *    For each block of size 'mask_prefix', if any IPs in that block
 *    are set, fill the entire block.
 */
static int
ipsetMaskAndFillV4(
    skipset_t          *ipset,
    const uint32_t      mask_prefix)
{
    ipset_node_v4_t *node;
    ipset_leaf_v4_t *leaf;
    uint32_t child_idx;
    uint32_t node_idx;
    uint32_t new_leaf_idx;
    uint32_t children_per_leaf;
    uint32_t ipv4;
    uint32_t i;
    uint32_t j;
    uint32_t depth;
    uint32_t to_visit[IPSET_MAX_DEPTH_V4];

    ipset->is_dirty = 1;

    /* handle case where root is a leaf */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V4(ipset, IPSET_ROOT_INDEX(ipset));
        if (leaf->prefix > mask_prefix) {
            /* leaf spans fewer IPs than specified by 'mask_prefix'.
             * Modify the leaf's IP and prefix and return */
            leaf->ip &= ~(UINT32_MAX >> mask_prefix);
            leaf->prefix = mask_prefix;
            return SKIPSET_OK;
        }
        /* else, this leaf's prefix is more course (holds more IPs)
         * than the mask_prefix, and there is no need to change it. */
        return SKIPSET_OK;
    }

    /* handle case where root contains a node whose prefix is
     * more-precise than the 'mask_prefix' */
    node = NODE_PTR_V4(ipset, IPSET_ROOT_INDEX(ipset));
    if (node->prefix >= mask_prefix) {
        ipv4 = node->ip;
        new_leaf_idx = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
        leaf = LEAF_PTR_V4(ipset, new_leaf_idx);
        leaf->ip = ipv4 &  ~(UINT32_MAX >> mask_prefix);
        leaf->prefix = mask_prefix;
        return SKIPSET_OK;
    }

    /* visit the nodes in the tree */
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR_V4(ipset, node_idx);

        if (mask_prefix - node->prefix > NUM_BITS) {
            /* this node is not at the bottom level of the tree; add
             * child nodes of this node to the 'to_visit' list. modify
             * any leaves to hold a single block */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if ((0 == node->child[i])
                    || NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    /* no-op */
                } else if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                    /* node; add to vist list unless its prefix is
                     * larger than or equal to the mask, in which case
                     * replace with a leaf */
                    if (NODE_PTR_V4(ipset, node->child[i])->prefix
                        < mask_prefix)
                    {
                        to_visit[depth++] = node->child[i];
                    } else {
                        ipv4 = NODE_PTR_V4(ipset,node->child[i])->ip;
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V4(ipset, node->child[i]);
                        leaf->ip = ipv4 & ~(UINT32_MAX >> mask_prefix);
                        leaf->prefix = mask_prefix;
                    }
                } else {
                    leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    if (leaf->prefix > mask_prefix) {
                        leaf->ip &= ~(UINT32_MAX >> mask_prefix);
                        leaf->prefix = mask_prefix;
                    }
                }
            }

        } else if (mask_prefix - node->prefix == NUM_BITS) {
            /* this node is on the bottom level of the tree, and every
             * occupied child[] will become an independent leaf */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    } else {
                        leaf = LEAF_PTR_V4(ipset, node->child[i]);
                        if (leaf->prefix <= mask_prefix) {
                            continue;
                        }
                    }
                    leaf->ip = ((node->ip
                                 | (i << (32 - NUM_BITS - node->prefix)))
                                & ~(UINT32_MAX >> mask_prefix));
                    leaf->prefix = mask_prefix;
                }
            }

        } else {
            /* this node is on the bottom level of the tree. multiple
             * child[] entries will become a single leaf */
            children_per_leaf = 1u << (NUM_BITS- (mask_prefix - node->prefix));
            child_idx = UINT32_MAX;
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                for (j = 0; j < children_per_leaf; ++j) {
                    --i;
                    if (node->child[i]) {
                        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            ipsetDestroySubtree(ipset, node->child[i], 1);
                        } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                            leaf = LEAF_PTR_V4(ipset, node->child[i]);
                            if (leaf->prefix <= mask_prefix) {
                                assert(0 == j);
                                i -= children_per_leaf - 1;
                                break;
                            }
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            node->child[i] = 0;
                        } else if (child_idx >= IPSET_NUM_CHILDREN) {
                            child_idx = i;
                        } else {
                            LEAFIDX_FREE(ipset, node->child[child_idx]);
                            node->child[child_idx] = 0;
                            child_idx = i;
                        }
                    }
                }

                /* the if() is entered when 'i' is looking at the
                 * start of a group of child[] entries and any of the
                 * child[] entries for this group of entries was
                 * occupied. */
                if (child_idx != UINT32_MAX) {
                    if (IPSET_NUM_CHILDREN == child_idx) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                    } else if (child_idx != i) {
                        node->child[i] = node->child[child_idx];
                    }
                    leaf = LEAF_PTR_V4(ipset, node->child[i]);
                    leaf->ip = ((node->ip
                                 | (i << (32 - NUM_BITS - node->prefix)))
                                & ~(UINT32_MAX >> mask_prefix));
                    leaf->prefix = mask_prefix;
                    NODEPTR_CHILD_SET_LEAF2(node, i,
                                            i + children_per_leaf - 1);
                    NODEPTR_CHILD_SET_REPEAT2(node, i+1,
                                              i + children_per_leaf - 1);
                    for (j = 1; j < children_per_leaf; ++j) {
                        node->child[i + j] = node->child[i];
                    }
                    /* reset for next group */
                    child_idx = UINT32_MAX;
                }
            }
        }
    }

    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetMaskAndFillV6(
    skipset_t          *ipset,
    const uint32_t      mask_prefix)
{
    ipset_node_v6_t *node;
    ipset_leaf_v6_t *leaf;
    uint32_t child_idx;
    uint32_t node_idx;
    uint32_t new_leaf_idx;
    uint32_t children_per_leaf;
    ipset_ipv6_t ipv6;
    uint32_t i;
    uint32_t j;
    uint32_t depth;
    uint32_t to_visit[IPSET_MAX_DEPTH_V6];

    ipset->is_dirty = 1;

    /* handle case where root is a leaf */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        leaf = LEAF_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
        if (leaf->prefix > mask_prefix) {
            /* leaf spans fewer IPs than specified by 'mask_prefix'.
             * Modify the leaf's IP and prefix and return */
            IPSET_IPV6_APPLY_CIDR(&leaf->ip, mask_prefix);
            leaf->prefix = mask_prefix;
            return SKIPSET_OK;
        }
        /* else, this leaf's prefix is more course (holds more IPs)
         * than the mask_prefix, and there is no need to change it */
        return SKIPSET_OK;
    }

    /* handle case where root contains a node whose prefix is
     * more-precise than the 'mask_prefix' */
    node = NODE_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
    if (node->prefix >= mask_prefix) {
        IPSET_IPV6_COPY(&ipv6, &node->ip);
        new_leaf_idx = ipsetReplaceNodeWithLeaf(ipset, NULL, 0);
        leaf = LEAF_PTR_V6(ipset, new_leaf_idx);
        IPSET_IPV6_COPY_AND_MASK(&leaf->ip, &ipv6, mask_prefix);
        leaf->prefix = mask_prefix;
        return SKIPSET_OK;
    }

    /* visit the nodes in the tree */
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR_V6(ipset, node_idx);

        if (mask_prefix - node->prefix > NUM_BITS) {
            /* this node is not at the bottom level of the tree; add
             * child nodes of this node to the 'to_visit' list. modify
             * any leaves to hold a single block. */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if ((0 == node->child[i])
                    || NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    /* no-op */
                } else if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                    /* node; add to vist list unless its prefix is
                     * larger than or equal to the mask, in which case
                     * replace with a leaf */
                    if (NODE_PTR_V6(ipset, node->child[i])->prefix
                        < mask_prefix)
                    {
                        to_visit[depth++] = node->child[i];
                    } else {
                        IPSET_IPV6_COPY(&ipv6,
                                        &NODE_PTR_V6(ipset,node->child[i])->ip);
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V6(ipset, node->child[i]);
                        IPSET_IPV6_COPY_AND_MASK(&leaf->ip, &ipv6, mask_prefix);
                        leaf->prefix = mask_prefix;
                    }
                } else {
                    leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    if (leaf->prefix > mask_prefix) {
                        IPSET_IPV6_APPLY_CIDR(&leaf->ip, mask_prefix);
                        leaf->prefix = mask_prefix;
                    }
                }
            }

        } else if (mask_prefix - node->prefix == NUM_BITS) {
            /* this node is on the bottom level of the tree, and every
             * occupied child[] will become an independent leaf */
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                        ipsetReplaceNodeWithLeaf(ipset,(ipset_node_t*)node,i);
                        leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    } else {
                        leaf = LEAF_PTR_V6(ipset, node->child[i]);
                        if (leaf->prefix <= mask_prefix) {
                            continue;
                        }
                    }
                    leaf->prefix = mask_prefix;
                    if (node->prefix <= 64 - NUM_BITS) {
                        leaf->ip.ip[0] = ((node->ip.ip[0]
                                           | (((uint64_t)i)
                                              << (64-NUM_BITS- node->prefix)))
                                          & ((mask_prefix < 64)
                                             ? ~(UINT64_MAX >> mask_prefix)
                                             : UINT64_MAX));
                        leaf->ip.ip[1] = 0;
                    } else {
                        leaf->ip.ip[0] = node->ip.ip[0];
                        leaf->ip.ip[1] = ((node->ip.ip[1]
                                           | (((uint64_t)i)
                                              << (128-NUM_BITS- node->prefix)))
                                          & ~(UINT64_MAX >> (mask_prefix-64)));
                    }
                }
            }

        } else {
            /* this node is on the bottom level of the tree. multiple
             * child[] entries will become a single leaf */
            children_per_leaf = 1u << (NUM_BITS- (mask_prefix - node->prefix));
            child_idx = UINT32_MAX;
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                for (j = 0; j < children_per_leaf; ++j) {
                    --i;
                    if (node->child[i]) {
                        if (!NODEPTR_CHILD_IS_LEAF(node, i)) {
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                            ipsetDestroySubtree(ipset, node->child[i], 1);
                        } else if (NODEPTR_CHILD_IS_REPEAT(node, i)) {
                            leaf = LEAF_PTR_V6(ipset, node->child[i]);
                            if (leaf->prefix <= mask_prefix) {
                                assert(0 == j);
                                i -= children_per_leaf - 1;
                                break;
                            }
                            if (UINT32_MAX == child_idx) {
                                child_idx = IPSET_NUM_CHILDREN;
                            }
                        } else if (child_idx >= IPSET_NUM_CHILDREN) {
                            child_idx = i;
                        } else {
                            LEAFIDX_FREE(ipset, node->child[child_idx]);
                            NODEPTR_CHILD_CLEAR_LEAF(node, child_idx);
                            child_idx = i;
                        }
                    }
                }

                /* the if() is entered when 'i' is looking at the
                 * start of a group of child[] entries and any of the
                 * child[] entries for this group of entries was
                 * occupied. */
                if (child_idx != UINT32_MAX) {
                    if (IPSET_NUM_CHILDREN == child_idx) {
                        if (ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx)){
                            return SKIPSET_ERR_ALLOC;
                        }
                        node->child[i] = new_leaf_idx;
                    } else if (child_idx != i) {
                        node->child[i] = node->child[child_idx];
                    }
                    leaf = LEAF_PTR_V6(ipset, node->child[i]);
                    leaf->prefix = mask_prefix;
                    if (node->prefix <= 64 - NUM_BITS) {
                        leaf->ip.ip[0] = ((node->ip.ip[0]
                                           | (((uint64_t)i)
                                              << (64-NUM_BITS- node->prefix)))
                                          & ((mask_prefix < 64)
                                             ? ~(UINT64_MAX >> mask_prefix)
                                             : UINT64_MAX));
                        leaf->ip.ip[1] = 0;
                    } else {
                        leaf->ip.ip[0] = node->ip.ip[0];
                        leaf->ip.ip[1] = ((node->ip.ip[1]
                                           | (((uint64_t)i)
                                              << (128-NUM_BITS- node->prefix)))
                                          & ~(UINT64_MAX >> (mask_prefix-64)));
                    }
                    NODEPTR_CHILD_SET_LEAF2(node, i,
                                            i + children_per_leaf - 1);
                    NODEPTR_CHILD_SET_REPEAT2(node, i+1,
                                              i + children_per_leaf - 1);
                    for (j = 1; j < children_per_leaf; ++j) {
                        node->child[i + j] = node->child[i];
                    }

                    child_idx = UINT32_MAX;
                }
            }
        }
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetNewEntries(ipset, num_nodes, num_leaves, node_indexes, leaf_indexes);
 *
 *    Determine where 'num_nodes' new nodes and 'num_leaves' new
 *    leaves can be stored and return the index(es) to that/those
 *    location(s) in the arrays specified by the 'node_indexes' and
 *    'leaf_indexes' parameters.  The new nodes and leaves will be
 *    zeroed before returning.
 *
 *    When a size value is 0, its corresponding array may be NULL.
 *
 *    If a value is 0, its array will not be modified, so any pointers
 *    into that array remain valid.  Specifically, if you have a
 *    handle to a node and request new leaves, the handle to the node
 *    remains valid.
 *
 *    Uses space at the end of the currently allocated arrays first,
 *    then returns entries from the free list.  Finally, calls
 *    ipsetAllocEntries() if no nodes or leaves are available.  Return
 *    0 on success, or SKIPSET_ERR_ALLOC on failure.
 *
 *    If the leaves buffer is reallocated, this function sets the
 *    'realloc_leaves' bit on the 'ipset'.
 */
static int
ipsetNewEntries(
    skipset_t          *ipset,
    uint32_t            num_nodes,
    uint32_t            num_leaves,
    uint32_t           *node_indexes,
    uint32_t           *leaf_indexes)
#ifndef IPSET_DEBUG_MEMORY
{
    /* this is the normal function defintion of ipsetNewEntries() */

    assert(ipset);
    assert(ipset->s.v3->nodes.entry_capacity >= ipset->s.v3->nodes.entry_count);
    assert(ipset->s.v3->leaves.entry_capacity
           >= ipset->s.v3->leaves.entry_count);

    if (num_leaves <= (ipset->s.v3->leaves.entry_capacity
                       - ipset->s.v3->leaves.entry_count))
    {
        /* grab leaves from end of the "fresh" memory */
        while (num_leaves) {
            *leaf_indexes = ipset->s.v3->leaves.entry_count;
            ++ipset->s.v3->leaves.entry_count;
            ++leaf_indexes;
            --num_leaves;
        }
        if (num_nodes) {
            goto ALLOC_NODES;
        }
        return SKIPSET_OK;
    }
    while (num_leaves && (ipset->s.v3->leaves.entry_count
                          < ipset->s.v3->leaves.entry_capacity))
    {
        /* grab as many leaves from end of the "fresh" memory as we can */
        *leaf_indexes = ipset->s.v3->leaves.entry_count;
        ++ipset->s.v3->leaves.entry_count;
        ++leaf_indexes;
        --num_leaves;
    }
    while (num_leaves && ipset->s.v3->leaves.free_list) {
        /* grab as many leaves from the free list as we can */
        ipset_leaf_t *leaf;
        *leaf_indexes = ipset->s.v3->leaves.free_list;
        leaf = LEAF_PTR(ipset, *leaf_indexes);
        ipset->s.v3->leaves.free_list = LEAFPTR_FREE_LIST(leaf);
        memset(leaf, 0, ipset->s.v3->leaves.entry_size);
        ++leaf_indexes;
        --num_leaves;
    }
    if (num_leaves) {
        /* allocate new memory and use it; set the flag to denote that
         * new leaves have been allocated. */
        if (ipset->s.v3->leaves.entry_capacity > 0) {
            ipset->s.v3->realloc_leaves = 1;
        }
        do {
            if (ipsetAllocEntries(&ipset->s.v3->leaves, 0)) {
                return SKIPSET_ERR_ALLOC;
            }
            while (num_leaves && (ipset->s.v3->leaves.entry_count
                                  < ipset->s.v3->leaves.entry_capacity))
            {
                *leaf_indexes = ipset->s.v3->leaves.entry_count;
                ++ipset->s.v3->leaves.entry_count;
                ++leaf_indexes;
                --num_leaves;
            }
        } while (num_leaves);
    }

  ALLOC_NODES:
    if (num_nodes
        <= (ipset->s.v3->nodes.entry_capacity - ipset->s.v3->nodes.entry_count))
    {
        /* grab nodes from end of the "fresh" memory */
        while (num_nodes) {
            *node_indexes = ipset->s.v3->nodes.entry_count;
            ++ipset->s.v3->nodes.entry_count;
            ++node_indexes;
            --num_nodes;
        }
        return SKIPSET_OK;
    }
    while (num_nodes && (ipset->s.v3->nodes.entry_count
                         < ipset->s.v3->nodes.entry_capacity))
    {
        /* grab as many nodes from end of the "fresh" memory as we can */
        *node_indexes = ipset->s.v3->nodes.entry_count;
        ++ipset->s.v3->nodes.entry_count;
        ++node_indexes;
        --num_nodes;
    }
    while (num_nodes && ipset->s.v3->nodes.free_list) {
        /* grab as many nodes from the free list as we can */
        ipset_node_t *node;
        *node_indexes = ipset->s.v3->nodes.free_list;
        node = NODE_PTR(ipset, *node_indexes);
        ipset->s.v3->nodes.free_list = NODEPTR_FREE_LIST(node);
        memset(node, 0, ipset->s.v3->nodes.entry_size);
        ++node_indexes;
        --num_nodes;
    }
    while (num_nodes) {
        /* allocate new memory and use it */
        if (ipsetAllocEntries(&ipset->s.v3->nodes, 0)) {
            return SKIPSET_ERR_ALLOC;
        }
        while (num_nodes && (ipset->s.v3->nodes.entry_count
                             < ipset->s.v3->nodes.entry_capacity))
        {
            *node_indexes = ipset->s.v3->nodes.entry_count;
            ++ipset->s.v3->nodes.entry_count;
            ++node_indexes;
            --num_nodes;
        }
    }

    return SKIPSET_OK;
}
#else  /* #ifndef IPSET_DEBUG_MEMORY */
{
    /*
     *  This is a debugging defintion of ipsetNewEntries().
     *
     *  This definition uses the free list first, so we properly
     *  handle cases where a call to ipsetNewEntries() follows a call
     *  to ipsetDestroySubtree().  (The calling code does not expect
     *  the ipsetNewEntries() call to fail in this case.)
     *
     *  If additional nodes and/or leaves are required, the function
     *  moves the location of the nodes and/or leaves array(s).  The
     *  objective is to find places the in code that are holding a
     *  stale pointer---that is, places that do not properly handle
     *  the case where a realloc may occur.
     *
     *  In addition, the function allocates only as many nodes/leaves
     *  as are requested, so writing beyond the array can be detected
     *  by memory checkers.
     */

    void *new_mem;
    uint32_t new_size;

    assert(ipset);
    assert(ipset->s.v3->nodes.entry_capacity >= ipset->s.v3->nodes.entry_count);
    assert(ipset->s.v3->leaves.entry_capacity
           >= ipset->s.v3->leaves.entry_count);

    if (num_leaves) {
        while (num_leaves && ipset->s.v3->leaves.free_list) {
            ipset_leaf_t *leaf;
            *leaf_indexes = ipset->s.v3->leaves.free_list;
            leaf = LEAF_PTR(ipset, *leaf_indexes);
            ipset->s.v3->leaves.free_list = LEAFPTR_FREE_LIST(leaf);
            memset(leaf, 0, ipset->s.v3->leaves.entry_size);
            ++leaf_indexes;
            --num_leaves;
        }
        if (num_leaves) {
            if (ipset->s.v3->leaves.entry_capacity
                && ((ipset->s.v3->leaves.entry_capacity + num_leaves)
                    % IPSET_INITIAL_ENTRY_COUNT) < num_leaves)
            {
                ipset->s.v3->realloc_leaves = 1;
            }
            new_size = ipset->s.v3->leaves.entry_capacity + num_leaves;
            if (new_size > SIZE_MAX / ipset->s.v3->leaves.entry_size) {
                return SKIPSET_ERR_ALLOC;
            }
            new_mem = malloc(new_size * ipset->s.v3->leaves.entry_size);
            if (!new_mem) {
                return SKIPSET_ERR_ALLOC;
            }
            if (ipset->s.v3->leaves.buf) {
                memcpy(new_mem, ipset->s.v3->leaves.buf,
                       (ipset->s.v3->leaves.entry_count
                        * ipset->s.v3->leaves.entry_size));
                free(ipset->s.v3->leaves.buf);
            }
            ipset->s.v3->leaves.buf = new_mem;
            ipset->s.v3->leaves.entry_capacity = new_size;
            do {
                *leaf_indexes = ipset->s.v3->leaves.entry_count;
                memset(LEAF_PTR(ipset, *leaf_indexes), 0,
                       ipset->s.v3->leaves.entry_size);
                ++ipset->s.v3->leaves.entry_count;
                ++leaf_indexes;
                --num_leaves;
                assert(ipset->s.v3->leaves.entry_capacity
                       >= ipset->s.v3->leaves.entry_count);
            } while (num_leaves);
        }
    }

    if (num_nodes) {
        while (num_nodes && ipset->s.v3->nodes.free_list) {
            ipset_node_t *node;
            *node_indexes = ipset->s.v3->nodes.free_list;
            node = NODE_PTR(ipset, *node_indexes);
            ipset->s.v3->nodes.free_list = NODEPTR_FREE_LIST(node);
            memset(node, 0, ipset->s.v3->nodes.entry_size);
            ++node_indexes;
            --num_nodes;
        }
        if (num_nodes) {
            new_size = ipset->s.v3->nodes.entry_capacity + num_nodes;
            if (new_size > SIZE_MAX / ipset->s.v3->nodes.entry_size) {
                return SKIPSET_ERR_ALLOC;
            }
            new_mem = malloc(new_size * ipset->s.v3->nodes.entry_size);
            if (!new_mem) {
                return SKIPSET_ERR_ALLOC;
            }
            if (ipset->s.v3->nodes.buf) {
                memcpy(new_mem, ipset->s.v3->nodes.buf,
                       (ipset->s.v3->nodes.entry_count
                        * ipset->s.v3->nodes.entry_size));
                free(ipset->s.v3->nodes.buf);
            }
            ipset->s.v3->nodes.buf = new_mem;
            ipset->s.v3->nodes.entry_capacity = new_size;
            do {
                *node_indexes = ipset->s.v3->nodes.entry_count;
                memset(NODE_PTR(ipset, *node_indexes), 0,
                       ipset->s.v3->nodes.entry_size);
                ++ipset->s.v3->nodes.entry_count;
                ++node_indexes;
                --num_nodes;
                assert(ipset->s.v3->nodes.entry_capacity
                       >= ipset->s.v3->nodes.entry_count);
            } while (num_nodes);
        }
    }

    return SKIPSET_OK;
}
#endif  /* #else of #ifndef IPSET_DEBUG_MEMORY */


/*
 *  status = ipsetOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Parse an option that was registered by skIPSetOptionsRegister().
 *    Return 0 on success, or non-zero on failure.
 */
static int
ipsetOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    skipset_options_t *ipset_opts = (skipset_options_t*)cData;
    uint32_t tmp32;
    int rv;

    assert(ipset_options_record_version[0].name);

    switch (opt_index) {
      case OPT_IPSET_RECORD_VERSION:
        rv = skStringParseUint32(&tmp32, opt_arg, IPSET_REC_VERSION_MIN,
                                 IPSET_REC_VERSION_MAX);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          ipset_options_record_version[0].name, opt_arg,
                          skStringParseStrerror(rv));
            return -1;
        }
        if (1 == tmp32) {
            skAppPrintErr("Invalid %s '%s': Illegal version number",
                          ipset_options_record_version[0].name,
                          opt_arg);
            return -1;
        }
        ipset_opts->record_version = (uint16_t)tmp32;
        break;

      case OPT_IPSET_INVOCATION_STRIP:
        ipset_opts->invocation_strip = 1;
        break;

      default:
        skAbortBadCase(opt_index);
    }

    return 0;
}


/*
 *  status = ipsetPrintCallback(ip, prefix, &print_state);
 *
 *    Helper function for skIPSetPrint().
 *
 *    Print a textual representation of the 'ip' and 'prefix'.  The
 *    stream to print to and the format to use are present in the
 *    'print_state' argument.
 */
static int
ipsetPrintCallback(
    skipaddr_t         *ip,
    uint32_t            prefix,
    void               *v_print_state)
{
    ipset_print_t *print_state = (ipset_print_t*)v_print_state;
    char ipbuf[SKIPADDR_STRLEN+1];
    int rv = SKIPSET_OK;

    /* print ip and its prefix, then return */
    skipaddrString(ipbuf, ip, print_state->ip_format);
    if (skipaddrIsV6(ip) ? (prefix == 128) : (prefix == 32)) {
        if (skStreamPrint(print_state->stream, "%s\n", ipbuf)) {
            rv = SKIPSET_ERR_FILEIO;
        }
    } else {
        if (skStreamPrint(print_state->stream, ("%s/%" PRIu32 "\n"),
                          ipbuf, prefix))
        {
            rv = SKIPSET_ERR_FILEIO;
        }
    }

    return rv;
}


/*
 *  status = ipsetProcessStreamBmapSlash24(baseip, bmap, swap_flag,proc_state);
 *  status = ipsetProcessStreamBmapSlash120(baseip, bmap,swap_flag,proc_state);
 *
 *    Helper function for ipsetProcessStreamClassc(),
 *    ipsetProcessStreamCidrbmapV4(), ipsetProcessStreamCidrbmapV6(),
 *    and ipsetProcessStreamSlash64().
 *
 *    Process the bitmap of 256 bits in 'bmap' that represents the
 *    IPv4 /24 or the IPv6 /120 in 'baseip'.  For each address or CIDR
 *    block in the bitmap, use ipsetProcessStreamCallback() to invoke
 *    the callback function specified in 'proc_state'.  When the
 *    'swap_flag' parameter is true, the values in 'bmap' are not in
 *    native byte order.
 */
static int
ipsetProcessStreamBmapSlash24(
    uint32_t            slash24,
    uint32_t            bmap[8],
    int                 swap_flag,
    ipset_walk_t       *proc_stream_state)
{
    uint32_t ipv4;
    uint32_t trail_zero;
    uint32_t i;
    int rv = SKIPSET_OK;

    /* loop over the uint32_t in this block */
    i = 0;
    while (i < 8) {
        if (0 == bmap[i]) {
            ++i;
            continue;
        }
        ipv4 = slash24 | (i << 5);
        if (UINT32_MAX == bmap[i]) {
            /* Check for a longer run of high bits by checking the
             * value in adjacent uint32_t's. */
            if ((i & 0x1) || (UINT32_MAX != bmap[i+1])) {
                /* either i is odd or cannot create a run of 64 */
                rv = (ipsetProcessStreamCallback(
                          NULL, &ipv4, 27, proc_stream_state));
                ++i;
            } else if ((i & 0x3)
                       || memcmp(&bmap[i+2], bmap256_full, sizeof(uint32_t)*2))
            {
                /* either i is 2 or 6 or cannot create a run of 128 */
                rv = (ipsetProcessStreamCallback(
                          NULL, &ipv4, 26, proc_stream_state));
                i += 2;
            } else {
                rv = (ipsetProcessStreamCallback(
                          NULL, &ipv4, 25, proc_stream_state));
                i += 4;
            }
            if (rv) { goto END; }
        } else {
            if (swap_flag) {
                bmap[i] = BSWAP32(bmap[i]);
            }
            while (bmap[i]) {
                /* find position of least significant bit */
                trail_zero = ipsetCountTrailingZeros(bmap[i]);
                ipv4 += trail_zero;
                bmap[i] >>= trail_zero;
                /* find number of consecutive high bits that map into a
                 * CIDR block */
                switch (ipv4 & 0x1F) {
                  case 0: case 16:
                    if ((bmap[i] & 0xFFFF) == 0xFFFF) {
                        rv = (ipsetProcessStreamCallback(
                                  NULL, &ipv4, 28, proc_stream_state));
                        bmap[i] >>= 16;
                        ipv4 += 16;
                        break;
                    }
                    /* FALLTHROUGH */
                  case 8: case 24:
                    if ((bmap[i] & 0xFF) == 0xFF) {
                        rv = (ipsetProcessStreamCallback(
                                  NULL, &ipv4, 29, proc_stream_state));
                        bmap[i] >>= 8;
                        ipv4 += 8;
                        break;
                    }
                    /* FALLTHROUGH */
                  case 4: case 12: case 20: case 28:
                    if ((bmap[i] & 0xF) == 0xF) {
                        rv = (ipsetProcessStreamCallback(
                                  NULL, &ipv4, 30, proc_stream_state));
                        bmap[i] >>= 4;
                        ipv4 += 4;
                        break;
                    }
                    /* FALLTHROUGH */
                  case  2: case  6: case 10: case 14:
                  case 18: case 22: case 26: case 30:
                    if ((bmap[i] & 0x3) == 0x3) {
                        rv = (ipsetProcessStreamCallback(
                                  NULL, &ipv4, 31, proc_stream_state));
                        bmap[i] >>= 2;
                        ipv4 += 2;
                        break;
                    }
                    /* FALLTHROUGH */
                  default:
                    rv = (ipsetProcessStreamCallback(
                              NULL, &ipv4, 32, proc_stream_state));
                    bmap[i] >>= 1;
                    ++ipv4;
                    break;
                }
                if (rv) { goto END; }
            }
        }
    }
  END:
    return rv;
}

#if SK_ENABLE_IPV6
/* an IPv6 version of previous function */
static int
ipsetProcessStreamBmapSlash120(
    const ipset_ipv6_t *slash120,
    uint32_t            bmap[8],
    int                 swap_flag,
    ipset_walk_t       *proc_stream_state)
{
    ipset_ipv6_t ipv6;
    uint32_t trail_zero;
    uint32_t i;
    int rv = SKIPSET_OK;

    ipv6.ip[0] = slash120->ip[0];

    i = 0;
    while (i < 8) {
        if (0 == bmap[i]) {
            ++i;
            continue;
        }
        ipv6.ip[1] = slash120->ip[1] | (i << 5);
        if (UINT32_MAX == bmap[i]) {
            if ((i & 0x1) || (UINT32_MAX != bmap[i+1])) {
                rv = (ipsetProcessStreamCallback(
                          &ipv6, NULL, 123, proc_stream_state));
                ++i;
            } else if ((i & 0x3)
                       || memcmp(&bmap[i+2], bmap256_full,
                                 sizeof(uint32_t)*2))
            {
                rv = (ipsetProcessStreamCallback(
                          &ipv6, NULL, 122, proc_stream_state));
                i += 2;
            } else {
                rv = (ipsetProcessStreamCallback(
                          &ipv6, NULL, 121, proc_stream_state));
                i += 4;
            }
            if (rv) { goto END; }
        } else {
            if (swap_flag) {
                bmap[i] = BSWAP32(bmap[i]);
            }
            while (bmap[i]) {
                trail_zero = ipsetCountTrailingZeros(bmap[i]);
                ipv6.ip[1] += trail_zero;
                bmap[i] >>= trail_zero;
                switch (ipv6.ip[1] & 0x1F) {
                  case 0: case 16:
                    if ((bmap[i] & 0xFFFF) == 0xFFFF) {
                        rv = (ipsetProcessStreamCallback(
                                  &ipv6, NULL, 124, proc_stream_state));
                        bmap[i] >>= 16;
                        ipv6.ip[1] += 16;
                        break;
                    }
                    /* FALLTHROUGH */
                  case 8: case 24:
                    if ((bmap[i] & 0xFF) == 0xFF) {
                        rv = (ipsetProcessStreamCallback(
                                  &ipv6, NULL, 125, proc_stream_state));
                        bmap[i] >>= 8;
                        ipv6.ip[1] += 8;
                        break;
                    }
                    /* FALLTHROUGH */
                  case 4: case 12: case 20: case 28:
                    if ((bmap[i] & 0xF) == 0xF) {
                        rv = (ipsetProcessStreamCallback(
                                  &ipv6, NULL, 126, proc_stream_state));
                        bmap[i] >>= 4;
                        ipv6.ip[1] += 4;
                        break;
                    }
                    /* FALLTHROUGH */
                  case  2: case  6: case 10: case 14:
                  case 18: case 22: case 26: case 30:
                    if ((bmap[i] & 0x3) == 0x3) {
                        rv = (ipsetProcessStreamCallback(
                                  &ipv6, NULL, 127, proc_stream_state));
                        bmap[i] >>= 2;
                        ipv6.ip[1] += 2;
                        break;
                    }
                    /* FALLTHROUGH */
                  default:
                    rv = (ipsetProcessStreamCallback(
                              &ipv6, NULL, 128, proc_stream_state));
                    bmap[i] >>= 1;
                    ++ipv6.ip[1];
                    break;
                }
                if (rv) { goto END; }
            }
        }
    }
  END:
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetProcessStreamCallback(ipv6, ipv4, prefix, proc_stream_state);
 *
 *    Helper function for ipsetProcessStreamClassc(),
 *    ipsetProcessStreamRadix(), ipsetProcessStreamCallbackV4(), and
 *    ipsetProcessStreamCidrbmapV6().
 *
 *    Convert the IP address in 'ipv4' or 'ipv6' to an skipaddr_t and
 *    invoke the callback function specified in 'proc_stream_state'.
 *
 *    The 'cidr_block' member of 'proc_stream_state' determines
 *    whether the callback is invoked for the entire CIDR block or for
 *    each IP in the block.  In addition, the 'v6policy' member
 *    controls how to represent the IP address.
 *
 *    The code in assert()s that 'ipv6' is in the ::ffff:0:0/96
 *    netblock when 'v6policy' is SK_IPV6POLICY_ASV4.
 */
static int
ipsetProcessStreamCallback(
    const ipset_ipv6_t *v6_start,
    const uint32_t     *v4_start,
    uint32_t            prefix,
    ipset_walk_t       *proc_stream_state)
{
#if SK_ENABLE_IPV6
    ipset_ipv6_t tmp_ipv6;
    uint32_t tmp_ipv4;
#endif
    skipaddr_t ipaddr;
    int rv;

    assert((v6_start && !v4_start)
           || (!v6_start && v4_start));
    assert(proc_stream_state);

    if ((proc_stream_state->cidr_blocks)
        || (v4_start &&  32 == prefix)
        || (v6_start && 128 == prefix))
    {
#if SK_ENABLE_IPV6
        if (v6_start) {
            assert(prefix <= 128);
            assert(NULL == v4_start);
            if (proc_stream_state->v6policy >= SK_IPV6POLICY_MIX) {
                IPSET_IPV6_TO_ADDR(v6_start, &ipaddr);
            } else {
                assert(SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy);
                IPSET_IPV6_TO_ADDR_V4(v6_start, &ipaddr);
                assert(prefix >= 96);
                prefix -= 96;
            }
        } else if (SK_IPV6POLICY_FORCE == proc_stream_state->v6policy) {
            assert(prefix <= 32);
            assert(NULL == v6_start);
            assert(v4_start);
            skipaddrSetV6FromUint32(&ipaddr, v4_start);
            prefix += 96;
        } else
#endif  /* SK_ENABLE_IPV6 */
        {
            assert(prefix <= 32);
            assert(NULL == v6_start);
            assert(v4_start);
            assert(proc_stream_state->v6policy <= SK_IPV6POLICY_MIX);
            skipaddrSetV4(&ipaddr, v4_start);
        }
        /* invoke the callback */
        return proc_stream_state->callback(&ipaddr, prefix,
                                           proc_stream_state->cb_data);
    }
    /* else we must invoke the callback on every IP */

    /* first adjust the IP address according to the ipv6-policy */
    switch (proc_stream_state->v6policy) {
      case SK_IPV6POLICY_MIX:
        break;

      case SK_IPV6POLICY_IGNORE:
        assert(NULL == v6_start);
#if SK_ENABLE_IPV6
        skAbort();
#endif
        break;

      case SK_IPV6POLICY_ONLY:
        assert(NULL == v4_start);
#if !SK_ENABLE_IPV6
        skAbort();
#endif
        break;

      case SK_IPV6POLICY_ASV4:
#if SK_ENABLE_IPV6
        if (v6_start) {
            assert(prefix >= 96 && prefix <= 128);
            prefix -= 96;
            IPSET_IPV6_TO_ADDR_V4(v6_start, &ipaddr);
            tmp_ipv4 = skipaddrGetV4(&ipaddr);
            v4_start = &tmp_ipv4;
            v6_start = NULL;
        }
#endif  /* SK_ENABLE_IPV6 */
        break;

      case SK_IPV6POLICY_FORCE:
#if !SK_ENABLE_IPV6
        skAbort();
#else
        if (v4_start) {
            assert(prefix <= 32);
            skipaddrSetV4(&ipaddr, v4_start);
            IPSET_IPV6_FROM_ADDRV4(&tmp_ipv6, &ipaddr);
            v6_start = &tmp_ipv6;
            v4_start = NULL;
        }
#endif  /* SK_ENABLE_IPV6 */
        break;
    }

#if SK_ENABLE_IPV6
    if (v6_start) {
        ipset_ipv6_t ipv6;
        ipset_ipv6_t fin6;

        assert(NULL == v4_start);

        /* convert CIDR block to start (ipv6) and final (fin6) */
        if (prefix > 64) {
            assert(prefix <= 128);
            ipv6.ip[0] = fin6.ip[0] = v6_start->ip[0];
            ipv6.ip[1] = v6_start->ip[1];
            fin6.ip[1] = (v6_start->ip[1] | (UINT64_MAX >> (prefix - 64)));
        } else if (prefix == 64) {
            ipv6.ip[0] = fin6.ip[0] = v6_start->ip[0];
            ipv6.ip[1] = 0;
            fin6.ip[1] = UINT64_MAX;
        } else {
            ipv6.ip[0] = v6_start->ip[0];
            fin6.ip[0] = (v6_start->ip[0] | (UINT64_MAX >> prefix));
            ipv6.ip[1] = 0;
            fin6.ip[1] = UINT64_MAX;
        }
        for (;;) {
            IPSET_IPV6_TO_ADDR(&ipv6, &ipaddr);
            rv = proc_stream_state->callback(&ipaddr, 128,
                                             proc_stream_state->cb_data);
            if (rv) {
                break;
            }
            if (ipv6.ip[0] < fin6.ip[0]) {
                if (ipv6.ip[1] < UINT64_MAX) {
                    ++ipv6.ip[1];
                } else {
                    ++ipv6.ip[0];
                    ipv6.ip[1] = 0;
                }
            } else if (ipv6.ip[1] < fin6.ip[1]) {
                ++ipv6.ip[1];
            } else {
                break;
            }
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        uint64_t num_ips;

        assert(prefix <= 32);
        assert(NULL == v6_start);
        assert(v4_start);

        num_ips = UINT64_C(1) << (32 - prefix);

        skipaddrSetV4(&ipaddr, v4_start);
        do {
            rv = proc_stream_state->callback(&ipaddr, 32,
                                             proc_stream_state->cb_data);
            skipaddrIncrement(&ipaddr);
        } while (0 == rv && --num_ips > 0);
    }
    return rv;
}


/*
 *  status = ipsetProcessStreamCidrbmapV4(stream, hdr, proc_stream_state);
 *  status = ipsetProcessStreamCidrbmapV6(stream, hdr, proc_stream_state);
 *
 *    Helper function for skIPSetProcessStream() and
 *    ipsetReadCidrbmapInto...().
 *
 *    Treat 'stream' as an IPset in the IPSET_REC_VERSION_CIDRBMAP
 *    format and process all the IPs and CIDR blocks it contains
 *    without reading the entire IPset into memory.  The header of the
 *    stream is in 'hdr'.  The callback to invoke is available in
 *    'proc_stream_state'.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetProcessStreamCidrbmapV4(
    skstream_t                 *stream,
    sk_file_header_t           *hdr,
    ipset_walk_t               *proc_stream_state)
{
    sk_header_entry_t *hentry;
    uint8_t read_buf[sizeof(uint32_t) + sizeof(uint8_t)];
    uint32_t bmap[IPTREE_WORDS_PER_SLASH24];
    int swap_flag;
    uint32_t slash24;
    ssize_t b;
    int rv;

    /* sanity check input */
    assert(stream);
    assert(hdr);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_CIDRBMAP,
                                IPSET_REC_VERSION_CIDRBMAP, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }
    if (sizeof(uint32_t) != ipsetHentryGetLeafSize(hentry)) {
        skAbort();
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    while ((b = skStreamRead(stream, read_buf, sizeof(read_buf)))
           == sizeof(read_buf))
    {
        if (swap_flag) {
            slash24 = BSWAP32(*(uint32_t*)read_buf);
        } else {
            slash24 = *(uint32_t*)read_buf;
        }
        /* handle the prefix bit */
        if (read_buf[sizeof(uint32_t)] <= 32) {
            /* IPv4 and one byte that is CIDR block */
            rv = ipsetProcessStreamCallback(NULL, &slash24,
                                            read_buf[sizeof(uint32_t)],
                                            proc_stream_state);
            if (rv) { goto END; }
        } else if (read_buf[sizeof(uint32_t)] != SET_CIDRBMAP_MAP256) {
            ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                               read_buf[sizeof(uint32_t)]);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        } else {
            /* IPv4 base address and 256-bit bitmap */
            if ((b = skStreamRead(stream, bmap, sizeof(bmap)))
                != sizeof(bmap))
            {
                ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                            " bytes returned %" SK_PRIdZ),
                                   sizeof(bmap), b);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            /* handle the block */
            rv = ipsetProcessStreamBmapSlash24(slash24, bmap, swap_flag,
                                               proc_stream_state);
            if (rv) { goto END; }
        }
    }
    if (b != 0) {
        /* read error */
        ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                    " bytes returned %" SK_PRIdZ),
                           sizeof(read_buf), b);
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    /* Success */
    rv = SKIPSET_OK;

  END:
    return rv;
}

#if SK_ENABLE_IPV6
static int
ipsetProcessStreamCidrbmapV6(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    ipset_walk_t       *proc_stream_state)
{
    sk_header_entry_t *hentry;
    uint8_t read_buf[IPSET_LEN_V6 + sizeof(uint8_t)];
    uint32_t bmap[IPTREE_WORDS_PER_SLASH24];
    int swap_flag;
    ipset_ipv6_t slash120;
    ssize_t b;
    int no_more_ipv4 = 0;
    int rv;

    /* sanity check input */
    assert(stream);
    assert(hdr);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_CIDRBMAP,
                                IPSET_REC_VERSION_CIDRBMAP, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }
    if (IPSET_LEN_V6 != ipsetHentryGetLeafSize(hentry)) {
        skAbort();
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    while ((b = skStreamRead(stream, read_buf, sizeof(read_buf)))
           == sizeof(read_buf))
    {
        IPSET_IPV6_FROM_ARRAY(&slash120, read_buf);

        if (SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy) {
            if (0 == read_buf[IPSET_LEN_V6]
                || read_buf[IPSET_LEN_V6] > SET_CIDRBMAP_MAP256)
            {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[IPSET_LEN_V6]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            if (slash120.ip[0] > 0
                || slash120.ip[1] > UINT64_C(0x0000ffffffffffff))
            {
                no_more_ipv4 = 1;
                break;
            }
            if (slash120.ip[1] < UINT64_C(0x0000ffff00000000)) {
                /* IP is below ::ffff:0:0 */
                if (read_buf[IPSET_LEN_V6] == SET_CIDRBMAP_MAP256) {
                    /* Read and skip the 256-bit bitmap */
                    if ((b = skStreamRead(stream, bmap, sizeof(bmap)))
                        != sizeof(bmap))
                    {
                        ipsetReadStrerrror(stream,
                                           ("Attempting to read %" SK_PRIuZ
                                            " bytes returned %" SK_PRIdZ),
                                           sizeof(bmap), b);
                        rv = SKIPSET_ERR_FILEIO;
                        goto END;
                    }
                }
                continue;
            }
        }
        /* handle the prefix bit */
        if (read_buf[IPSET_LEN_V6] <= 128) {
            if (0 == read_buf[IPSET_LEN_V6]) {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[IPSET_LEN_V6]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            /* IPv6 and one byte CIDR prefix */
            rv = ipsetProcessStreamCallback(&slash120, NULL,
                                            read_buf[IPSET_LEN_V6],
                                            proc_stream_state);
            if (rv) { goto END; }
        } else if (read_buf[IPSET_LEN_V6] != SET_CIDRBMAP_MAP256) {
            ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                               read_buf[IPSET_LEN_V6]);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        } else {
            /* IPv6 base address and 256-bit bitmap */
            if ((b = skStreamRead(stream, bmap, sizeof(bmap)))
                != sizeof(bmap))
            {
                ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                            " bytes returned %" SK_PRIdZ),
                                   sizeof(bmap), b);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            /* handle the block */
            rv = ipsetProcessStreamBmapSlash120(&slash120, bmap, swap_flag,
                                                proc_stream_state);
            if (rv) { goto END; }
        }
    }
    if (b != 0) {
        if (no_more_ipv4 && b == sizeof(read_buf)) {
            /* not an error;  we exited the loop via a break; */
        } else {
            /* read error */
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                        " bytes returned %" SK_PRIdZ),
                               sizeof(read_buf), b);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
    }

    /* Success */
    rv = SKIPSET_OK;

  END:
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetProcessStreamCidrbmap(stream, hdr, proc_stream_state);
 *
 *    Helper function for skIPSetProcessStream().
 *
 *    Treat 'stream' as an IPset in the IPSET_REC_VERSION_CIDRBMAP
 *    format and process all the IPs and CIDR blocks it contains
 *    without reading the entire IPset into memory.  The header of the
 *    stream is in 'hdr'.  The callback to invoke is available in
 *    'proc_stream_state'.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetProcessStreamCidrbmap(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    ipset_walk_t       *proc_stream_state)
{
    sk_header_entry_t *hentry;

    /* sanity check input */
    assert(stream);
    assert(hdr);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_CIDRBMAP,
                                IPSET_REC_VERSION_CIDRBMAP, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }

    /* read and verify the header */
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }
    /* most sizes are zero */
    if (0 != ipsetHentryGetChildPerNode(hentry)
        || 0 != ipsetHentryGetRootIndex(hentry)
        || 0 != ipsetHentryGetNodeCount(hentry)
        || 0 != ipsetHentryGetNodeSize(hentry)
        || 0 != ipsetHentryGetLeafCount(hentry))
    {
        skAbort();
    }
    if (sizeof(uint32_t) == ipsetHentryGetLeafSize(hentry)) {
        return ipsetProcessStreamCidrbmapV4(stream, hdr, proc_stream_state);
    }
#if SK_ENABLE_IPV6
    if (IPSET_LEN_V6 == ipsetHentryGetLeafSize(hentry)) {
        return ipsetProcessStreamCidrbmapV6(stream, hdr, proc_stream_state);
    }
#endif

    /* Unrecognized record size */
    skAbort();
}


/*
 *  status = ipsetProcessStreamClassc(stream, hdr, proc_stream_state);
 *
 *    Helper function for skIPSetProcessStream() and
 *    ipsetReadClasscIntoRadix()
 *
 *    Treat 'stream' as an IPset in the IPSET_REC_VERSION_CLASSC
 *    format and process all the IPs and CIDR blocks it contains
 *    without reading the entire IPset into memory.  The header of the
 *    stream is in 'hdr'.  The callback to invoke is available in
 *    'proc_stream_state'.
 *
 *    See '#define IPSET_REC_VERSION_CLASSC' for description of the
 *    file format.
 */
static int
ipsetProcessStreamClassc(
    skstream_t                 *stream,
    sk_file_header_t           *hdr,
    ipset_walk_t               *proc_stream_state)
{
    int swap_flag;
    uint32_t contig_start;
    uint32_t contig_length;
    uint32_t contig_max;
    uint32_t contig_cidr;
    uint32_t block24[1+IPTREE_WORDS_PER_SLASH24];
    uint32_t trail_zero;
    uint32_t slash24;
    uint32_t msb;
    ssize_t b;
    int isfull;
    int rv;

    /* sanity check input */
    assert(stream);
    assert(hdr);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, 0,
                                IPSET_REC_VERSION_CLASSC, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }

    contig_start = contig_length = contig_max = contig_cidr = 0;

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    while ((b = skStreamRead(stream, block24, sizeof(block24)))
           == sizeof(block24))
    {
        /* the /24 value is the first value in the array */
        slash24 = (((swap_flag) ? BSWAP32(block24[0]) : block24[0])
                   & 0xFFFFFF00);

        /* determine whether the is block full (all ones) */
        isfull = !memcmp(&block24[1], bmap256_full, sizeof(bmap256_full));

        if (contig_length) {
            /* we handling a contiguous run of full /24s */
            if (isfull && ((contig_start + 256 * contig_length) == slash24)) {
                /* grow the number of /24s */
                ++contig_length;
                if (contig_length == contig_max) {
                    /* cannot grow this block any more */
                    rv = (ipsetProcessStreamCallback(
                              NULL, &contig_start, contig_cidr,
                              proc_stream_state));
                    if (rv) { goto END; }
                    contig_length = 0;
                }
                continue;
            }

            /* either blocks are not contigous or current block is not
             * full; before we handle the current block, handle the
             * previous block of contiguous IPS */
            do {
                /* get position of most significant bit of the number
                 * of /24s in the range, and subtract that from 24 to
                 * get the CIDR block */
                msb = skIntegerLog2(contig_length);
                rv = (ipsetProcessStreamCallback(
                          NULL, &contig_start, 24 - msb, proc_stream_state));
                if (rv) { goto END; }
                /* compute the start of the next CIDR block and the
                 * number of /24s yet to process */
                contig_start += (1u << (8 + msb));
                contig_length -= (1u << msb);
            } while (contig_length);
            /* drop into code below to handle this new block */
        }

        if (isfull) {
            /* start a new run of contiguous IPs */
            contig_start = slash24;
            contig_length = 1;
            /* determine largest block that can be created */
            /* if slash24 is 0 then the max number of /24s is 1<<24,
             * but we use 1<<23 to ensure the prefix value is not 0 */
            trail_zero = ipsetCountTrailingZeros(slash24);
            if (trail_zero > 8) {
                contig_max = (1u << (trail_zero - 8));
                contig_cidr = 32 - trail_zero;
            } else {
                /* the third octet is odd, so this /24 cannot be made
                 * any larger */
                assert(trail_zero == 8);
                rv = (ipsetProcessStreamCallback(
                          NULL, &slash24, 24, proc_stream_state));
                if (rv) { goto END; }
                contig_length = 0;
            }
            continue;
        }

        /* handle the block */
        rv = ipsetProcessStreamBmapSlash24(slash24, &block24[1], swap_flag,
                                           proc_stream_state);
    }
    if (b == -1) {
        /* read error */
        ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                    " bytes returned %" SK_PRIdZ),
                           sizeof(block24), b);
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    /* close any partial CIDR block */
    while (contig_length) {
        /* get position of most significant bit of the number of /24s
         * in the range, and subtract that from 24 to get the CIDR
         * block */
        msb = skIntegerLog2(contig_length);
        rv = (ipsetProcessStreamCallback(
                  NULL, &contig_start, 24 - msb, proc_stream_state));
        if (rv) { goto END; }
        /* compute the start of the next CIDR block and the number of
         * /24s yet to process */
        contig_start += (1u << (8 + msb));
        contig_length -= (1u << msb);
    }

    rv = SKIPSET_OK;

  END:
    return rv;
}


/*
 *  status = ipsetProcessStreamRadix(stream, hdr, proc_stream_state);
 *
 *    Helper function for skIPSetProcessStream() and
 *    ipsetReadRadixIntoIPTree().
 *
 *    Treat 'stream' as an IPset in the IPSET_REC_VERSION_RADIX
 *    format and process all the IPs and CIDR blocks it contains
 *    without reading the entire IPset into memory.  The header of the
 *    stream is in 'hdr'.  The callback to invoke is available in
 *    'proc_stream_state'.
 *
 *    See '#define IPSET_REC_VERSION_RADIX' for description of the
 *    file format.
 */
static int
ipsetProcessStreamRadix(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    ipset_walk_t       *proc_stream_state)
{
#if SK_ENABLE_IPV6
    int is_ipv6;
#endif
#ifndef NDEBUG
    size_t count = 0;
#endif
    sk_header_entry_t *hentry;
    ssize_t bytes;
    ssize_t b;
    int no_more_ipv4 = 0;
    int rv;

    /* sanity check input */
    assert(stream);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_RADIX,
                                IPSET_REC_VERSION_RADIX, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }

    /* Verify that children/node is what we expect */
    if (IPSET_NUM_CHILDREN != ipsetHentryGetChildPerNode(hentry)) {
        skAbort();
    }

    /* See if leaf and node sizes are for IPv4 or IPv6.  We must check
     * IPv4 first, since the size of the IPv4 and IPv6 structs are
     * identical when SiLK is built without IPv6 support */
    if (sizeof(ipset_leaf_v4_t) == ipsetHentryGetLeafSize(hentry)
        && sizeof(ipset_node_v4_t) == ipsetHentryGetNodeSize(hentry))
    {
#if SK_ENABLE_IPV6
        is_ipv6 = 0;
    }
    else if (sizeof(ipset_leaf_v6_t) == ipsetHentryGetLeafSize(hentry)
             && sizeof(ipset_node_v6_t) == ipsetHentryGetNodeSize(hentry))
    {
        is_ipv6 = 1;
#endif  /* SK_ENABLE_IPV6 */
    } else {
        /* Unrecognized record sizes */
        return SKIPSET_ERR_FILEHEADER;
    }

    /* skip over the nodes since we only need the IPs in the leaves */
    bytes = (ipsetHentryGetNodeCount(hentry)
             * ipsetHentryGetNodeSize(hentry));
    b = skStreamRead(stream, NULL, bytes);
    if (b != bytes) {
        ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIdZ
                                    " bytes returned %" SK_PRIdZ), bytes, b);
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    /* skip the first leaf, which contains no data */
    bytes = ipsetHentryGetLeafSize(hentry);
    b = skStreamRead(stream, NULL, bytes);
    if (b != bytes) {
        if (b == 0 && ipsetHentryGetLeafCount(hentry) == 0) {
            rv = SKIPSET_OK;
        } else {
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIdZ
                                        " bytes returned %" SK_PRIdZ),
                               bytes, b);
            rv = SKIPSET_ERR_FILEIO;
        }
        goto END;
    }
#ifndef NDEBUG
    ++count;
#endif

#if SK_ENABLE_IPV6
    if (is_ipv6) {
        ipset_leaf_v6_t leaf;
        uint32_t ipv4;

        if (proc_stream_state->v6policy >= SK_IPV6POLICY_MIX) {
            /* process as IPv6 addresses */
            while ((b = skStreamRead(stream, &leaf, bytes)) == bytes) {
#ifndef NDEBUG
                ++count;
#endif
                if (!skHeaderIsNativeByteOrder(hdr)) {
                    leaf.ip.ip[0] = BSWAP64(leaf.ip.ip[0]);
                    leaf.ip.ip[1] = BSWAP64(leaf.ip.ip[1]);
                }
                rv = (ipsetProcessStreamCallback(
                          &leaf.ip, NULL, leaf.prefix, proc_stream_state));
                if (rv) { goto END; }
            }
        } else {
            /* process the IPv4 part of the radix tree; that is,
             * process the ::ffff:0:0/96 netblock */
            while ((b = skStreamRead(stream, &leaf, bytes)) == bytes) {
#ifndef NDEBUG
                ++count;
#endif
                if (!skHeaderIsNativeByteOrder(hdr)) {
                    leaf.ip.ip[1] = BSWAP64(leaf.ip.ip[1]);
                }
                if (leaf.ip.ip[1] < UINT64_C(0x0000ffff00000000)) {
                    continue;
                }
                if (leaf.ip.ip[0] > 0
                    || leaf.ip.ip[1] > UINT64_C(0x0000ffffffffffff))
                {
                    no_more_ipv4 = 1;
                    break;
                }
                ipv4 = (uint32_t)(leaf.ip.ip[1] & UINT64_C(0x00000000ffffffff));
                rv = (ipsetProcessStreamCallback(
                          NULL, &ipv4, leaf.prefix - 96, proc_stream_state));
                if (rv) { goto END; }
            }
#ifndef NDEBUG
            /* read any remaining leaves so the assert() passes */
            if (b == bytes) {
                while ((b = skStreamRead(stream, &leaf, bytes)) == bytes) {
                    ++count;
                }
            }
#endif  /* NDEBUG */
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        ipset_leaf_v4_t leaf;
        while ((b = skStreamRead(stream, &leaf, bytes)) == bytes) {
#ifndef NDEBUG
            ++count;
#endif
            if (!skHeaderIsNativeByteOrder(hdr)) {
                leaf.ip = BSWAP32(leaf.ip);
            }
            rv = (ipsetProcessStreamCallback(
                      NULL, &leaf.ip, leaf.prefix, proc_stream_state));
            if (rv) { goto END; }
        }
    }
    if (b != 0) {
        if (no_more_ipv4 && b == bytes) {
            /* not an error;  we exited the loop via a break; */
        } else {
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIdZ
                                        " bytes returned %" SK_PRIdZ),
                               bytes, b);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
    }
    assert(ipsetHentryGetLeafCount(hentry) == count);

    rv = SKIPSET_OK;

  END:
    return rv;
}


#if SK_ENABLE_IPV6
/*
 *  status = ipsetProcessStreamSlash64(stream, hdr, proc_stream_state);
 *
 *    Helper function for skIPSetProcessStream() and
 *    ipsetReadSlash64().
 *
 *    Treat 'stream' as an IPset in the IPSET_REC_VERSION_SLASH64
 *    format and process all the IPs and CIDR blocks it contains
 *    without reading the entire IPset into memory.  The header of the
 *    stream is in 'hdr'.  The callback to invoke is available in
 *    'proc_stream_state'.
 *
 *    See '#define IPSET_REC_VERSION_SLASH64' for description of the
 *    file format.
 */
static int
ipsetProcessStreamSlash64(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    ipset_walk_t       *proc_stream_state)
{
    sk_header_entry_t *hentry;
    uint8_t read_buf[sizeof(uint64_t) + sizeof(uint8_t)];
    uint32_t bmap[IPTREE_WORDS_PER_SLASH24];
    /* ensure the file is valid */
    enum state_st {
        ANY_ALLOWED, UPPER_REQUIRED, LOWER_REQUIRED
    } state;
    int swap_flag;
    ipset_ipv6_t slash120;
    int no_more_ipv4;
    ssize_t b;
    int rv;

    /*  UINT64_FROM_READ_BUF(value): Set 'value' to the uint64_t value
     *  in 'read_buf', byte swapping if necessary. */
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
#define UINT64_FROM_READ_BUF(value)                     \
    memcpy(&(value), read_buf, sizeof(uint64_t));       \
    if (swap_flag) {                                    \
        (value) = BSWAP64(value);                       \
    }
#else
#define UINT64_FROM_READ_BUF(value)                     \
    if (swap_flag) {                                    \
        (value) = BSWAP64(*(uint64_t *)read_buf);       \
    } else {                                            \
        (value) = *(uint64_t *)read_buf;                \
    }
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */

    /* sanity check input */
    assert(stream);
    assert(hdr);
    assert(proc_stream_state);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_SLASH64,
                                IPSET_REC_VERSION_SLASH64, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }
    if (IPSET_LEN_V6 != ipsetHentryGetLeafSize(hentry)) {
        skAbort();
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    state = UPPER_REQUIRED;

    no_more_ipv4 = 0;
    while ((b = skStreamRead(stream, read_buf, sizeof(read_buf)))
           == sizeof(read_buf))
    {
        if (read_buf[sizeof(uint64_t)] <= 64) {
            /* Upper 64 bits of IPv6 and one byte CIDR prefix */
            if (LOWER_REQUIRED == state || 0 == read_buf[sizeof(uint64_t)]) {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[sizeof(uint64_t)]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            state = UPPER_REQUIRED;
            if (SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy) {
                /* there cannot be any more IPv4 addresses */
                no_more_ipv4 = 1;
                break;
            }
            UINT64_FROM_READ_BUF(slash120.ip[0]);
            slash120.ip[1] = 0;
            rv = ipsetProcessStreamCallback(&slash120, NULL,
                                            read_buf[sizeof(uint64_t)],
                                            proc_stream_state);
            if (rv) { goto END; }
        } else if (read_buf[sizeof(uint64_t)] <= 128) {
            /* Lower 64 bits of IPv6 and one byte CIDR prefix */
            if (UPPER_REQUIRED == state) {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[sizeof(uint64_t)]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            state = ANY_ALLOWED;
            UINT64_FROM_READ_BUF(slash120.ip[1]);
            if (SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy) {
                if (slash120.ip[1] < UINT64_C(0x0000ffff00000000)) {
                    continue;
                }
                if (slash120.ip[1] > UINT64_C(0x0000ffffffffffff)) {
                    no_more_ipv4 = 1;
                    break;
                }
            }
            rv = ipsetProcessStreamCallback(&slash120, NULL,
                                            read_buf[sizeof(uint64_t)],
                                            proc_stream_state);
            if (rv) { goto END; }
        } else if (read_buf[sizeof(uint64_t)] == SET_SLASH64_IS_SLASH64) {
            /* Upper 64 bits of IPv6 */
            if (LOWER_REQUIRED == state) {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[sizeof(uint64_t)]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            state = LOWER_REQUIRED;
            UINT64_FROM_READ_BUF(slash120.ip[0]);
            if (SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy
                && slash120.ip[0] != 0)
            {
                no_more_ipv4 = 1;
                break;
            }
        } else if (read_buf[sizeof(uint64_t)] != SET_CIDRBMAP_MAP256) {
            ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                               read_buf[sizeof(uint64_t)]);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        } else {
            /* Lower 64 bits of IPv6 and 256-bit bitmap */
            if (UPPER_REQUIRED == state) {
                ipsetReadStrerrror(stream, "Unexpected value for prefix %u",
                                   read_buf[sizeof(uint64_t)]);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            state = ANY_ALLOWED;
            UINT64_FROM_READ_BUF(slash120.ip[1]);
            if ((b = skStreamRead(stream, bmap, sizeof(bmap)))
                != sizeof(bmap))
            {
                ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                            " bytes returned %" SK_PRIdZ),
                                   sizeof(bmap), b);
                rv = SKIPSET_ERR_FILEIO;
                goto END;
            }
            if (SK_IPV6POLICY_ASV4 == proc_stream_state->v6policy) {
                if (slash120.ip[1] < UINT64_C(0x0000ffff00000000)) {
                    continue;
                }
                if (slash120.ip[1] > UINT64_C(0x0000ffffffffffff)) {
                    no_more_ipv4 = 1;
                    break;
                }
            }
            /* handle the block */
            rv = ipsetProcessStreamBmapSlash120(&slash120, bmap, swap_flag,
                                                proc_stream_state);
            if (rv) { goto END; }
        }
    }
    if (b != 0) {
        if (no_more_ipv4 && b == sizeof(read_buf)) {
            /* not an error;  we exited the loop via a break; */
        } else {
            /* read error */
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                        " bytes returned %" SK_PRIdZ),
                               sizeof(read_buf), b);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
    }

    /* Success */
    rv = SKIPSET_OK;

  END:
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetReadCidrbmapIntoIPTree(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset containing only IPv4 addresses in the
 *    IPSET_REC_VERSION_CIDRBMAP format from 'stream' and create a
 *    SiLK-2 IPTree data structure.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetReadCidrbmapIntoIPTree(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 0, 0);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrIPTree;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_ASV4;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamCidrbmapV4(stream, hdr, &proc_stream_state);
    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}


/*
 *  status = ipsetReadCidrbmapIntoRadixV4(&ipset, stream, hdr, is_ipv6);
 *  status = ipsetReadCidrbmapIntoRadixV6(&ipset, stream, hdr, is_ipv6);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset in the IPSET_REC_VERSION_CIDRBMAP format from
 *    'stream' and create a radix-tree IPset data structure.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetReadCidrbmapIntoRadixV4(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 0, 1);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrV4;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_MIX;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamCidrbmapV4(stream, hdr, &proc_stream_state);
    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}

#if SK_ENABLE_IPV6
static int
ipsetReadCidrbmapIntoRadixV6(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 1, 1);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrV6;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_FORCE;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamCidrbmapV6(stream, hdr, &proc_stream_state);
    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetReadClasscIntoIPTree(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetRead().
 *
 *    Also a helper function for the legacy skIPTreeRead() function.
 *
 *    Read an IPset in the IPSET_REC_VERSION_CLASSC format from
 *    'stream' and create a SiLK-2 IPTree data structure.
 *
 *    See '#define IPSET_REC_VERSION_CLASSC' for description of the
 *    file format.
 */
static int
ipsetReadClasscIntoIPTree(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    int swap_flag;
    uint32_t block24[1 + IPTREE_WORDS_PER_SLASH24];
    uint32_t slash24;
    uint32_t slash16;
    ssize_t b;
    unsigned int i;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, 0,
                                IPSET_REC_VERSION_CLASSC, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    rv = ipsetCreate(&ipset, 0, 0);
    if (rv != SKIPSET_OK) {
        goto END;
    }

    while ((b = skStreamRead(stream, block24, sizeof(block24)))
           == sizeof(block24))
    {
        if (swap_flag) {
            for (i = 0; i < 1+IPTREE_WORDS_PER_SLASH24; ++i) {
                block24[i] = BSWAP32(block24[i]);
            }
        }

        /* Put the first two octets of the base IP into slash16, and
         * allocate the space for the /16 if we need to */
        slash16 = (block24[0] >> 16);
        if (NULL == ipset->s.v2->nodes[slash16]) {
            ipset->s.v2->nodes[slash16]
                = (skIPNode_t*)calloc(1, sizeof(skIPNode_t));
            if (NULL == ipset->s.v2->nodes[slash16]) {
                rv = SKIPSET_ERR_ALLOC;
                goto END;
            }
        }

        /* Locate where this /24 occurs inside the larger /16, then
         * copy it into place.  Following is equivalent to
         * (((block24[0] >> 8) & 0xFF) * 8); */
        slash24 = ((block24[0] & 0x0000FF00) >> 5);
        memcpy((ipset->s.v2->nodes[slash16]->addressBlock + slash24),
               block24 + 1, IPTREE_WORDS_PER_SLASH24 * sizeof(uint32_t));
    }
    if (b != 0) {
        /* read error */
        ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIuZ
                                    " bytes returned %" SK_PRIdZ),
                           sizeof(block24), b);
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    *ipset_out = ipset;
    rv = SKIPSET_OK;

  END:
    if (rv != SKIPSET_OK) {
        skIPSetDestroy(&ipset);
    }
    return rv;
}


/*
 *  status = ipsetReadClasscIntoRadix(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset in the IPSET_REC_VERSION_CLASSC format from
 *    'stream' and create a radix-tree IPset data structure.
 *
 *    See '#define IPSET_REC_VERSION_CLASSC' for description of the
 *    file format.
 */
static int
ipsetReadClasscIntoRadix(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 0, 1);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrV4;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_MIX;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamClassc(stream, hdr, &proc_stream_state);

    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}


/*
 *  status = ipsetReadRadixIntoIPTree(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset in the IPSET_REC_VERSION_RADIX format containing
 *    only IPv4 addresses from 'stream' and create a SiLK-2 IPTree
 *    data structure.
 *
 *    See '#define IPSET_REC_VERSION_RADIX' for description of the
 *    file format.
 */
static int
ipsetReadRadixIntoIPTree(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 0, 0);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrIPTree;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_ASV4;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamRadix(stream, hdr, &proc_stream_state);
    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}


/*
 *  status = ipsetReadRadixIntoRadix(&ipset, stream, hdr, is_ipv6);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset in the IPSET_REC_VERSION_RADIX format from
 *    'stream' and create a radix-tree IPset data structure.
 *
 *    See '#define IPSET_REC_VERSION_RADIX' for description of the
 *    file format.
 */
static int
ipsetReadRadixIntoRadix(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    int                 is_ipv6)
{
    skipset_t *ipset = NULL;
    sk_header_entry_t *hentry;
    ssize_t bytes;
    ssize_t b;
    size_t i;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    if (skStreamCheckSilkHeader(stream, FT_IPSET, IPSET_REC_VERSION_RADIX,
                                IPSET_REC_VERSION_RADIX, NULL))
    {
        skAbort();
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        skAbort();
    }
    hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
    if (NULL == hentry) {
        skAbort();
    }

    /* create the set */
    rv = ipsetCreate(&ipset, is_ipv6, 1);
    if (rv != SKIPSET_OK) {
        goto END;
    }

    /* if no nodes or only node#0, root is a leaf */
    IPSET_ROOT_INDEX_SET(ipset, ipsetHentryGetRootIndex(hentry),
                         (ipsetHentryGetNodeCount(hentry) <= 1));

    if (skStreamIsSeekable(stream)
        && skHeaderIsNativeByteOrder(hdr)
        && (SK_COMPMETHOD_NONE == skHeaderGetCompressionMethod(hdr)))
    {
        /* attempt to mmap() the file */

        /* get file size and offset where the data begins */
        off_t file_size = skFileSize(skStreamGetPathname(stream));
        off_t data_start = skStreamTell(stream);
        uint8_t *buf;

        if ((0 < data_start) && (data_start < file_size)
            && (UINT32_MAX > file_size))
        {
            ipset->s.v3->mapped_size = (size_t)file_size;
            ipset->s.v3->mapped_file = mmap(0, ipset->s.v3->mapped_size,
                                            PROT_READ, MAP_SHARED,
                                            skStreamGetDescriptor(stream), 0);
            if (MAP_FAILED == ipset->s.v3->mapped_file) {
                ipset->s.v3->mapped_file = NULL;
                ipset->s.v3->mapped_size = 0;
            } else {
                /* this is the start of the file */
                buf = (uint8_t*)ipset->s.v3->mapped_file;

                /* move to start of data section (the nodes) */
                buf += data_start;
                ipset->s.v3->nodes.buf = buf;
                ipset->s.v3->nodes.entry_count
                    = ipsetHentryGetNodeCount(hentry);

                /* move over the nodes (to the leaves)  */
                buf += (ipsetHentryGetNodeCount(hentry)
                        * ipset->s.v3->nodes.entry_size);
                ipset->s.v3->leaves.buf = buf;
                ipset->s.v3->nodes.entry_count
                    = ipsetHentryGetLeafCount(hentry);

                /* move over the leaves to the end of the file */
                buf += (ipsetHentryGetLeafCount(hentry)
                        * ipset->s.v3->leaves.entry_size);
                if (buf >= ((uint8_t*)ipset->s.v3->mapped_file
                            + ipset->s.v3->mapped_size))
                {
                    /* error */
                    munmap(ipset->s.v3->mapped_file, ipset->s.v3->mapped_size);
                    ipset->s.v3->mapped_file = NULL;
                    ipset->s.v3->mapped_size = 0;

                    ipset->s.v3->nodes.buf = NULL;
                    ipset->s.v3->nodes.entry_count = 0;

                    ipset->s.v3->leaves.buf = NULL;
                    ipset->s.v3->nodes.entry_count = 0;
                }
            }
        }
    }

    if (NULL == ipset->s.v3->mapped_file) {
        /* Allocate and read the nodes */
        rv = ipsetAllocEntries(&ipset->s.v3->nodes,
                               ipsetHentryGetNodeCount(hentry));
        if (rv) {
            goto END;
        }

        bytes = (ipsetHentryGetNodeCount(hentry)
                 * ipset->s.v3->nodes.entry_size);
        b = skStreamRead(stream, ipset->s.v3->nodes.buf, bytes);
        if (b != bytes && b != 0) {
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIdZ
                                        " bytes returned %" SK_PRIdZ),
                               bytes, b);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
        ipset->s.v3->nodes.entry_count = ipsetHentryGetNodeCount(hentry);

        /* now, if the data is not in native byte order, we need to
         * byte-swap the values */
        if (!skHeaderIsNativeByteOrder(hdr)) {
#if SK_ENABLE_IPV6
            if (ipset->is_ipv6) {
                ipset_node_v6_t *node;
                for (i = 0, node = (ipset_node_v6_t*)ipset->s.v3->nodes.buf;
                     i < ipset->s.v3->nodes.entry_count;
                     ++i, ++node)
                {
                    node->child[0] = BSWAP32(node->child[0]);
                    node->child[1] = BSWAP32(node->child[1]);
                    node->ip.ip[0] = BSWAP64(node->ip.ip[0]);
                    node->ip.ip[1] = BSWAP64(node->ip.ip[1]);
                }
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                ipset_node_v4_t *node;
                for (i = 0, node = (ipset_node_v4_t*)ipset->s.v3->nodes.buf;
                     i < ipset->s.v3->nodes.entry_count;
                     ++i, ++node)
                {
                    node->child[0] = BSWAP32(node->child[0]);
                    node->child[1] = BSWAP32(node->child[1]);
                    node->ip = BSWAP32(node->ip);
                }
            }
        }

        /* Allocate and read the leaves */
        rv = ipsetAllocEntries(&ipset->s.v3->leaves,
                               ipsetHentryGetLeafCount(hentry));
        if (rv) {
            goto END;
        }

        bytes = (ipsetHentryGetLeafCount(hentry)
                 * ipset->s.v3->leaves.entry_size);
        b = skStreamRead(stream, ipset->s.v3->leaves.buf, bytes);
        if (b != bytes && b != 0) {
            ipsetReadStrerrror(stream, ("Attempting to read %" SK_PRIdZ
                                        " bytes returned %" SK_PRIdZ),
                               bytes, b);
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
        ipset->s.v3->leaves.entry_count = ipsetHentryGetLeafCount(hentry);

        /* now, if the data is not in native byte order, we need to
         * byte-swap the values */
        if (!skHeaderIsNativeByteOrder(hdr)) {
#if SK_ENABLE_IPV6
            if (ipset->is_ipv6) {
                ipset_leaf_v6_t *leaf;
                for (i = 0, leaf = (ipset_leaf_v6_t*)ipset->s.v3->leaves.buf;
                     i < ipset->s.v3->leaves.entry_count;
                     ++i, ++leaf)
                {
                    leaf->ip.ip[0] = BSWAP64(leaf->ip.ip[0]);
                    leaf->ip.ip[1] = BSWAP64(leaf->ip.ip[1]);
                }
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                ipset_leaf_v4_t *leaf;
                for (i = 0, leaf = (ipset_leaf_v4_t*)ipset->s.v3->leaves.buf;
                     i < ipset->s.v3->leaves.entry_count;
                     ++i, ++leaf)
                {
                    leaf->ip = BSWAP32(leaf->ip);
                }
            }
        }
    }

    /* check that the file is valid */
    rv = ipsetVerify(ipset);
    if (rv) {
        goto END;
    }

    *ipset_out = ipset;
    rv = SKIPSET_OK;

  END:
    if (rv != SKIPSET_OK) {
        skIPSetDestroy(&ipset);
    }
    return rv;
}


#if SK_ENABLE_IPV6
/*
 *  status = ipsetReadSlash64(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetRead().
 *
 *    Read an IPset in the IPSET_REC_VERSION_SLASH64 format from
 *    'stream' and create an IPv6 Radix data structure.
 *
 *    See '#define IPSET_REC_VERSION_SLASH64' for description of the
 *    file format.
 *
 *    This function uses ipsetProcessStreamSlash64() to read the
 *    IPset.
 */
static int
ipsetReadSlash64(
    skipset_t         **ipset_out,
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    skipset_t *ipset = NULL;
    ipset_walk_t proc_stream_state;
    int rv;

    /* sanity check input */
    assert(ipset_out);
    assert(stream);
    assert(hdr);

    rv = ipsetCreate(&ipset, 1, 1);
    if (rv != SKIPSET_OK) {
        return rv;
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = ipsetInsertIPAddrV6;
    proc_stream_state.cb_data = ipset;
    proc_stream_state.v6policy = SK_IPV6POLICY_FORCE;
    proc_stream_state.cidr_blocks = 1;

    rv = ipsetProcessStreamSlash64(stream, hdr, &proc_stream_state);
    if (SKIPSET_OK == rv) {
        skIPSetClean(ipset);
        *ipset_out = ipset;
    } else {
        skIPSetDestroy(&ipset);
    }
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetReadStreamHeader(stream, &hdr, &is_ipv6);
 *
 *    Read the header of 'stream' and verify that it contains an
 *    IPset.  Store the file's header in the memory referenced by
 *    'hdr'.  Set the value referenced by 'is_ipv6' to 1 if the stream
 *    is capable of holding IPv6 addresses, and to 0 otherwise.
 *
 *    Return SKIPSET_OK if the stream is valid, on an error code if
 *    not.
 */
static int
ipsetReadStreamHeader(
    skstream_t         *stream,
    sk_file_header_t  **hdr,
    int                *is_ipv6)
{
    sk_header_entry_t *hentry;
    sk_file_version_t record_version;
    int rv;

    assert(stream);
    assert(hdr);
    assert(is_ipv6);

    rv = skStreamReadSilkHeader(stream, hdr);
    if (rv) {
        if (SKSTREAM_ERR_COMPRESS_UNAVAILABLE == rv) {
            return SKIPSET_ERR_FILEHEADER;
        }
        return SKIPSET_ERR_FILEIO;
    }

    /* Ensure we are reading a file we understand */
    rv = skStreamCheckSilkHeader(stream, FT_IPSET,
                                 0, IPSET_REC_VERSION_MAX, NULL);
    switch (rv) {
      case SKSTREAM_OK:
        break;
      case SKSTREAM_ERR_UNSUPPORT_FORMAT:
        /* not an IPset file */
        return SKIPSET_ERR_FILETYPE;
      case SKSTREAM_ERR_UNSUPPORT_VERSION:
        /* newer than we understand */
        return SKIPSET_ERR_FILEVERSION;
      default:
        return SKIPSET_ERR_FILEHEADER;
    }
    if (skHeaderGetRecordLength(*hdr) != 1) {
        return SKIPSET_ERR_FILEHEADER;
    }
    record_version = skHeaderGetRecordVersion(*hdr);

    if (record_version < IPSET_REC_VERSION_RADIX) {
        /* the format we call IPSET_REC_VERSION_CLASSC */
        *is_ipv6 = 0;
    } else if (record_version == IPSET_REC_VERSION_RADIX) {
        hentry = skHeaderGetFirstMatch(*hdr, SK_HENTRY_IPSET_ID);
        if (NULL == hentry) {
            return SKIPSET_ERR_FILEHEADER;
        }
        /* Verify that children/node is what we expect */
        if (IPSET_NUM_CHILDREN != ipsetHentryGetChildPerNode(hentry)) {
            return SKIPSET_ERR_FILEHEADER;
        }

        /* See if leaf and node sizes are for IPv4 or IPv6.  We must
         * check IPv4 first, since the size of the IPv4 and IPv6
         * structs are identical when SiLK is built without IPv6
         * support */
        if (sizeof(ipset_leaf_v4_t) == ipsetHentryGetLeafSize(hentry)
            && sizeof(ipset_node_v4_t) == ipsetHentryGetNodeSize(hentry))
        {
            *is_ipv6 = 0;
        }
        else if (sizeof(ipset_leaf_v6_t) == ipsetHentryGetLeafSize(hentry)
                 && sizeof(ipset_node_v6_t) == ipsetHentryGetNodeSize(hentry))
        {
            *is_ipv6 = 1;
        } else {
            /* Unrecognized record sizes */
            return SKIPSET_ERR_FILEHEADER;
        }
    } else if (record_version == IPSET_REC_VERSION_CIDRBMAP) {
        /* read and verify the header */
        hentry = skHeaderGetFirstMatch(*hdr, SK_HENTRY_IPSET_ID);
        if (NULL == hentry) {
            return SKIPSET_ERR_FILEHEADER;
        }
        /* most sizes are zero */
        if (0 != ipsetHentryGetChildPerNode(hentry)
            || 0 != ipsetHentryGetRootIndex(hentry)
            || 0 != ipsetHentryGetNodeCount(hentry)
            || 0 != ipsetHentryGetNodeSize(hentry)
            || 0 != ipsetHentryGetLeafCount(hentry))
        {
            return SKIPSET_ERR_FILEHEADER;
        }
        if (sizeof(uint32_t) == ipsetHentryGetLeafSize(hentry)) {
            *is_ipv6 = 0;
        } else if (IPSET_LEN_V6 == ipsetHentryGetLeafSize(hentry)) {
            *is_ipv6 = 1;
        } else {
            /* Unrecognized record size */
            return SKIPSET_ERR_FILEHEADER;
        }
    } else if (record_version == IPSET_REC_VERSION_SLASH64){
        /* read and verify the header */
        hentry = skHeaderGetFirstMatch(*hdr, SK_HENTRY_IPSET_ID);
        if (NULL == hentry) {
            return SKIPSET_ERR_FILEHEADER;
        }
        /* most sizes are zero */
        if (0 != ipsetHentryGetChildPerNode(hentry)
            || 0 != ipsetHentryGetRootIndex(hentry)
            || 0 != ipsetHentryGetNodeCount(hentry)
            || 0 != ipsetHentryGetNodeSize(hentry)
            || 0 != ipsetHentryGetLeafCount(hentry))
        {
            return SKIPSET_ERR_FILEHEADER;
        }
        /* format only supports IPv6 */
        if (IPSET_LEN_V6 == ipsetHentryGetLeafSize(hentry)) {
            *is_ipv6 = 1;
        } else {
            /* Unrecognized record size */
            return SKIPSET_ERR_FILEHEADER;
        }
    } else {
        skAppPrintErr("Unknown header version %d", record_version);
        skAbort();
    }
#if  !SK_ENABLE_IPV6
    if (*is_ipv6) {
        /* IPv6 IPSet not supported by this build of SiLK */
        return SKIPSET_ERR_IPV6;
    }
#endif  /* SK_ENABLE_IPV6 */

    return SKIPSET_OK;
}


/*
 *    Print the reason an IPset could not be read when the
 *    SILK_IPSET_PRINT_READ_ERROR environment variable is set.
 */
static void
ipsetReadStrerrror(
    skstream_t         *stream,
    const char         *format,
    ...)
{
    char buf[3 * PATH_MAX];
    const char *env;
    va_list args;

    va_start(args, format);
    env = getenv("SILK_IPSET_PRINT_READ_ERROR");
    if (!env || !env[0] || 0 == strcmp(env, "0")) {
        va_end(args);
        return;
    }
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    skAppPrintErr("Error reading IPset from '%s': %s",
                  skStreamGetPathname(stream), buf);
}


/*
 *  rv = ipsetRemoveAddressIPTree(ipset, ipv4, prefix);
 *
 *    Helper function for skIPSetRemoveAddress(); may also be called
 *    by other internal functions.
 */
static int
ipsetRemoveAddressIPTree(
    skipset_t          *ipset,
    uint32_t            ipv4,
    uint32_t            prefix)
{
    /* for a description of 'prefix_as_bits', see
     * ipsetInsertAddressIPTree() */
    const uint32_t prefix_as_bits[] = {
        0xFFFFFFFF, 0xFFFF, 0xFF, 0xF, 0x3, 0x1
    };
    uint32_t ipv4_end;
    skIPNode_t empty_node;
    skIPTree_t *iptree;

    assert(ipset);
    assert(1 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);
    assert(prefix > 0 || ipv4 == 0);
    assert(prefix <= 32);

    iptree = ipset->s.v2;

    if (prefix <= 16) {
        ipv4_end = ((UINT32_MAX >> prefix) | ipv4) >> 16;
        ipv4 >>= 16;
        do {
            if (NULL != iptree->nodes[ipv4]) {
                free(iptree->nodes[ipv4]);
                iptree->nodes[ipv4] = NULL;
            }
        } while (ipv4++ < ipv4_end);

    } else if (NULL != iptree->nodes[ipv4 >> 16]) {
        if (prefix >= 27) {
            iptree->nodes[ipv4 >> 16]->addressBlock[(ipv4 & 0xFFFF) >> 5]
                &= ~(prefix_as_bits[prefix - 27] << ((ipv4) & 0x1F));

        } else {
            /* 16 < prefix < 27 */
            memset(&iptree->nodes[ipv4>>16]->addressBlock[(ipv4 & 0xFFFF)>>5],
                   0, (sizeof(skIPNode_t) >> (prefix - 16)));
        }

        /* free node if block is empty */
        memset(&empty_node, 0, sizeof(empty_node));
        if (0 == memcmp(&empty_node, iptree->nodes[ipv4 >> 16],
                        sizeof(skIPNode_t)))
        {
            free(iptree->nodes[ipv4 >> 16]);
            iptree->nodes[ipv4 >> 16] = NULL;
        }
    }

    return SKIPSET_OK;
}


/*
 *  rv = ipsetRemoveAddressV4(ipset, ipv4, prefix, find_state);
 *  rv = ipsetRemoveAddressV6(ipset, ipv6, prefix, find_state);
 *
 *    Helper function for skIPSetRemoveAddress(); may also be called
 *    by other internal functions.
 *
 *    Remove the CIDR block ipv4/prefix or ipv6/prefix from the IPset.
 *
 *    'find_state' should be NULL or the result of calling
 *    ipsetFindV4() or ipsetFindV6() on the ip/prefix pair.  When
 *    'find_state' is NULL, this function does the address search
 *    itself.
 *
 *    Return SKIPSET_OK if the address block was successfully removed
 *    or if the address block does not appear in the IPset.  Return
 *    SKIPSET_ERR_ALLOC if there is a memory allocation error.
 */
static int
ipsetRemoveAddressV4(
    skipset_t          *ipset,
    const uint32_t      ipv4,
    const uint32_t      prefix,
    const ipset_find_t *find_state)
{
    ipset_find_t find_state_local;
    ipset_node_v4_t *parent = NULL;
    ipset_leaf_v4_t *leaf;
    uint32_t which_child;
    uint32_t i;
    uint32_t j;
    int rv;

    assert(ipset);
    assert(sizeof(ipset_node_v4_t) == ipset->s.v3->nodes.entry_size);
    assert(prefix > 0 || ipv4 == 0);
    assert(prefix <= 32);
    assert(0 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);

    /* use the passed in 'find_state' if given */
    if (find_state) {
        rv = find_state->result;
    } else {
        rv = ipsetFindV4(ipset, ipv4, prefix, &find_state_local);
        /* if IP was not found, we can return */
        if (SKIPSET_ERR_NOTFOUND == rv
            || SKIPSET_ERR_EMPTY == rv
            || SKIPSET_ERR_MULTILEAF == rv)
        {
            return SKIPSET_OK;
        }
        find_state = &find_state_local;
    }
    ipset->is_dirty = 1;

    /* if we matched a CIDR block in the IPset that is larger than the
     * block/address we want to remove, we must break the CIDR
     * block. */
    if ((SKIPSET_OK == rv) && (find_state->bitpos < prefix)) {
        uint32_t old_ipv4, mid_ipv4, old_prefix;

        assert(1 == find_state->node_is_leaf);

        leaf = LEAF_PTR_V4(ipset, find_state->node_idx);
        old_ipv4 = leaf->ip;
        old_prefix = leaf->prefix;

        /* remove the current IP */
        if (IPSET_NO_PARENT == find_state->parent_idx) {
            skIPSetRemoveAll(ipset);
        } else {
            parent = NODE_PTR_V4(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V4(leaf->ip, parent->prefix);
            if (NUM_BITS <= leaf->prefix - parent->prefix) {
                /* leaf occupies a single child[] entry */
                parent->child[which_child] = 0;
                NODEPTR_CHILD_CLEAR_LEAF(parent, which_child);
            } else {
                for (i = which_child, j = 0;
                     j < (1u << (NUM_BITS - (leaf->prefix - parent->prefix)));
                     ++i, ++j)
                {
                    parent->child[i] = 0;
                }
                NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
                NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);
            }
            LEAFIDX_FREE(ipset, find_state->node_idx);
        }

        /* insert all IPs not part of the removed block */
        do {
            ++old_prefix;
            /* find midpoint of this block */
            mid_ipv4 = old_ipv4 | (1u << (32 - old_prefix));
            if (ipv4 < mid_ipv4) {
                /* insert upper half of old CIDR block */
                rv = ipsetInsertAddressV4(ipset, mid_ipv4, old_prefix, NULL);
                /* no change to old_ipv4 */
            } else {
                /* insert lower half of old CIDR block */
                rv = ipsetInsertAddressV4(ipset, old_ipv4, old_prefix, NULL);
                /* adjust old_ipv4 to the base of the upper half */
                old_ipv4 = mid_ipv4;
            }
        } while (0 == rv && old_prefix < prefix);

        /* all done */
        return rv;
    }

    /* otherwise, we exactly matched the node we want to remove, or we
     * are removing a CIDR block that is only partially populated.
     * These cases are handled the same way: modify the parent of the
     * node to remove the node we found. */

    /* handle the simple case */
    if (IPSET_NO_PARENT == find_state->parent_idx) {
        return skIPSetRemoveAll(ipset);
    }
    parent = NODE_PTR_V4(ipset, find_state->parent_idx);

    if (SKIPSET_ERR_SUBSET == rv
        && (NUM_BITS > prefix - parent->prefix))
    {
        /* need to clear multiple child[] entries */
        which_child = WHICH_CHILD_V4(ipv4, parent->prefix);
        for (i = which_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]) {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                    parent->child[i] = 0;
                } else if (NODEPTR_CHILD_IS_REPEAT(parent, i)) {
                    parent->child[i] = 0;
                } else {
                    LEAFIDX_FREE(ipset, parent->child[i]);
                    parent->child[i] = 0;
                }
            }
        }
        NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
        NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);

        /* handle case where node has a single child */
        ipsetFixNodeSingleChild(ipset, find_state->parent_idx, 0);
        return SKIPSET_OK;
    }

    if (!find_state->node_is_leaf) {
        /* remove this node from the parent, and delete the node and
         * everything below it */
        parent->child[find_state->parents_child] = 0;
        ipsetDestroySubtree(ipset, find_state->node_idx, 1);
    } else {
        /* remove this leaf from the parent */
        leaf = LEAF_PTR_V4(ipset, find_state->node_idx);
        if (NUM_BITS <= leaf->prefix - parent->prefix) {
            /* leaf occupies a single child[] entry */
            parent->child[find_state->parents_child] = 0;
            NODEPTR_CHILD_CLEAR_LEAF(parent, find_state->parents_child);
        } else {
            /* leaf occupies multiple child[] entries */
            which_child = WHICH_CHILD_V4(leaf->ip, parent->prefix);
            for (i = which_child, j = 0;
                 j < (1u << (NUM_BITS - (leaf->prefix - parent->prefix)));
                 ++i, ++j)
            {
                parent->child[i] = 0;
            }
            NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
            NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);
        }
        LEAFIDX_FREE(ipset, find_state->node_idx);
    }

    /* handle case where node has a single child */
    ipsetFixNodeSingleChild(ipset, find_state->parent_idx, 0);
    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetRemoveAddressV6(
    skipset_t          *ipset,
    const ipset_ipv6_t *ipv6,
    const uint32_t      prefix,
    const ipset_find_t *find_state)
{
    ipset_find_t find_state_local;
    ipset_node_v6_t *parent = NULL;
    ipset_leaf_v6_t *leaf;
    uint32_t which_child;
    uint32_t i;
    uint32_t j;
    int rv;

    assert(ipset);
    assert(sizeof(ipset_node_v6_t) == ipset->s.v3->nodes.entry_size);
    assert(0 < prefix && prefix <= 128);
    assert(0 == ipset->is_iptree);
    assert(1 == ipset->is_ipv6);

    /* use the passed in 'find_state' if given */
    if (find_state) {
        rv = find_state->result;
    } else {
        rv = ipsetFindV6(ipset, ipv6, prefix, &find_state_local);
        /* if IP was not found, we can return */
        if (SKIPSET_ERR_NOTFOUND == rv
            || SKIPSET_ERR_EMPTY == rv
            || SKIPSET_ERR_MULTILEAF == rv)
        {
            return SKIPSET_OK;
        }
        find_state = &find_state_local;
    }
    ipset->is_dirty = 1;

    /* if we matched a CIDR block in the IPset that is larger than the
     * block/address we want to remove, we must break the CIDR
     * block. */
    if ((SKIPSET_OK == rv) && (find_state->bitpos < prefix)) {
        ipset_ipv6_t old_ipv6, mid_ipv6;
        uint32_t old_prefix;

        assert(1 == find_state->node_is_leaf);

        leaf = LEAF_PTR_V6(ipset, find_state->node_idx);
        IPSET_IPV6_COPY(&old_ipv6, &leaf->ip);
        old_prefix = leaf->prefix;

        /* remove the current IP */
        if (IPSET_NO_PARENT == find_state->parent_idx) {
            skIPSetRemoveAll(ipset);
        } else {
            parent = NODE_PTR_V6(ipset, find_state->parent_idx);
            which_child = WHICH_CHILD_V6(&leaf->ip, parent->prefix);
            if (NUM_BITS <= leaf->prefix - parent->prefix) {
                /* leaf occupies a single child[] entry */
                parent->child[which_child] = 0;
                NODEPTR_CHILD_CLEAR_LEAF(parent, which_child);
            } else {
                for (i = which_child, j = 0;
                     j < (1u << (NUM_BITS - (leaf->prefix - parent->prefix)));
                     ++i, ++j)
                {
                    parent->child[i] = 0;
                }
                NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
                NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);
            }
            LEAFIDX_FREE(ipset, find_state->node_idx);
        }

        /* insert all IPs not part of the removed block */
        IPSET_IPV6_COPY(&mid_ipv6, &old_ipv6);
        do {
            ++old_prefix;
            if (old_prefix <= 64) {
                /* find midpoint of this block */
                mid_ipv6.ip[0]
                    = old_ipv6.ip[0] | (UINT64_C(1) << (64 - old_prefix));
                if (ipv6->ip[0] < mid_ipv6.ip[0]) {
                    /* insert upper half of old CIDR block */
                    rv = ipsetInsertAddressV6(ipset, &mid_ipv6, old_prefix,
                                              NULL);
                    /* no change to old_ipv6 */
                    if (64 == old_prefix) {
                        /* reset mid_ipv6 so it is correct for lower
                         * half of the IP */
                        mid_ipv6.ip[0] = old_ipv6.ip[0];
                    }
                } else {
                    /* insert lower hald of old CIDR block */
                    rv = ipsetInsertAddressV6(ipset, &old_ipv6, old_prefix,
                                              NULL);
                    /* adjust old_ipv6 to the base of the upper half */
                    old_ipv6.ip[0] = mid_ipv6.ip[0];
                }
            } else {
                mid_ipv6.ip[1]
                    = old_ipv6.ip[1] | (UINT64_C(1) << (128 - old_prefix));
                if (ipv6->ip[1] < mid_ipv6.ip[1]) {
                    rv = ipsetInsertAddressV6(ipset, &mid_ipv6, old_prefix,
                                              NULL);
                } else {
                    rv = ipsetInsertAddressV6(ipset, &old_ipv6, old_prefix,
                                              NULL);
                    old_ipv6.ip[1] = mid_ipv6.ip[1];
                }
            }
        } while (0 == rv && old_prefix < prefix);

        /* done */
        return rv;
    }

    /* otherwise, we exactly matched the node we want to remove, or we
     * are removing a CIDR block that is only partially populated.
     * These cases are handled the same way: modify the parent of the
     * node to remove the node we found. */

    /* handle the simple case */
    if (IPSET_NO_PARENT == find_state->parent_idx) {
        return skIPSetRemoveAll(ipset);
    }

    parent = NODE_PTR_V6(ipset, find_state->parent_idx);

    if (SKIPSET_ERR_SUBSET == rv
        && (NUM_BITS > prefix - parent->prefix))
    {
        /* need to clear multiple child[] entries */
        which_child = WHICH_CHILD_V6(ipv6, parent->prefix);
        for (i = which_child, j = 0;
             j < (1u << (NUM_BITS - (prefix - parent->prefix)));
             ++i, ++j)
        {
            if (parent->child[i]) {
                if (!NODEPTR_CHILD_IS_LEAF(parent, i)) {
                    ipsetDestroySubtree(ipset, parent->child[i], 1);
                    parent->child[i] = 0;
                } else if (NODEPTR_CHILD_IS_REPEAT(parent, i)) {
                    parent->child[i] = 0;
                } else {
                    LEAFIDX_FREE(ipset, parent->child[i]);
                    parent->child[i] = 0;
                }
            }
        }
        NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
        NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);

        /* handle case where node has a single child */
        ipsetFixNodeSingleChild(ipset, find_state->parent_idx, 0);
        return SKIPSET_OK;
    }

    if (!find_state->node_is_leaf) {
        /* remove this node from the parent, and delete the node and
         * everything below it */
        parent->child[find_state->parents_child] = 0;
        ipsetDestroySubtree(ipset, find_state->node_idx, 1);
    } else {
        /* remove this leaf from the parent */
        leaf = LEAF_PTR_V6(ipset, find_state->node_idx);
        if (NUM_BITS <= leaf->prefix - parent->prefix) {
            /* leaf occupies a single child[] entry */
            parent->child[find_state->parents_child] = 0;
            NODEPTR_CHILD_CLEAR_LEAF(parent, find_state->parents_child);
        } else {
            /* leaf occupies multiple child[] entries */
            which_child = WHICH_CHILD_V6(&leaf->ip, parent->prefix);
            for (i = which_child, j = 0;
                 j < (1u << (NUM_BITS - (leaf->prefix - parent->prefix)));
                 ++i, ++j)
            {
                parent->child[i] = 0;
            }
            NODEPTR_CHILD_CLEAR_LEAF2(parent, which_child, i - 1);
            NODEPTR_CHILD_CLEAR_REPEAT2(parent, which_child, i - 1);
        }
        LEAFIDX_FREE(ipset, find_state->node_idx);
    }

    /* handle case where node has a single child */
    ipsetFixNodeSingleChild(ipset, find_state->parent_idx, 0);
    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *    Helper function for skIPSetRemoveAll() when the IPset is a
 *    SiLK-2 IPTree.
 *
 *    Also a helper function for legacy skIPTreeRemoveAll().
 */
static void
ipsetRemoveAllIPTree(
    skIPTree_t         *ipset)
{
    unsigned int i;

    /* delete all the nodes */
    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (ipset->nodes[i] != NULL) {
            free(ipset->nodes[i]);
        }
    }
    memset(ipset, 0, sizeof(skIPTree_t));
}


/*
 *  new_leaf_id = ipsetReplaceNodeWithLeaf(ipset, parent, which_child);
 *
 *    Replace the node at position child['which_child'] on the node
 *    'parent' with a leaf.  Return the index of the new leaf.
 *
 *    If 'parent' is NULL, the node at the root of the 'ipset' is
 *    replaced with a leaf.
 *
 *    This function always succeeds, since destroying the node and its
 *    subtree provides leaf entries on the free_list.
 */
static uint32_t
ipsetReplaceNodeWithLeaf(
    skipset_t          *ipset,
    ipset_node_t       *parent,
    uint32_t            which_child)
{
    uint32_t new_leaf_idx;

    assert(ipset);
    assert(which_child < IPSET_NUM_CHILDREN);

    if (NULL == parent) {
        assert(0 == IPSET_ROOT_IS_LEAF(ipset));
        ipsetDestroySubtree(ipset, IPSET_ROOT_INDEX(ipset), 1);
        ASSERT_OK(ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx));
        IPSET_ROOT_INDEX_SET(ipset, new_leaf_idx, 1);
    } else {
        assert(0 == NODEPTR_CHILD_IS_LEAF(&parent->v4, which_child));
        ipsetDestroySubtree(ipset, parent->v4.child[which_child], 1);
        ASSERT_OK(ipsetNewEntries(ipset, 0, 1, NULL, &new_leaf_idx));
        parent->v4.child[which_child] = new_leaf_idx;
        NODEPTR_CHILD_SET_LEAF(&parent->v4, which_child);
    }

    return new_leaf_idx;
}



/*
 *  ipsetSortLeaves(ipset);
 *
 *    Sort the leaves so they occur in ascending order in memory.
 */
static void
ipsetSortLeaves(
    skipset_t          *ipset)
{
    uint32_t to_visit[IPSET_MAX_DEPTH];
#if   IPSET_NUM_CHILDREN < 256
    uint8_t children[IPSET_MAX_DEPTH];
#else
    uint16_t children[IPSET_MAX_DEPTH];
#endif
    uint32_t child_idx;
    uint32_t depth;
    uint32_t cur;
    ipset_node_t *node;

    /* first, ensure the tree is compact */
    ipsetCompact(ipset);

    /* nothing to do if the root is a leaf */
    if (IPSET_ROOT_IS_LEAF(ipset)) {
        return;
    }

    /* the new index to assign to each leaf */
    child_idx = 0;

    /* visit the leaves in the tree to update the indexes */
    depth = 0;
    to_visit[depth] = IPSET_ROOT_INDEX(ipset);
    children[depth++] = 0;

    cur = 0;
    while (depth) {
      VISIT_NODE:
        node = NODE_PTR(ipset, to_visit[cur]);
        for ( ; children[cur] < IPSET_NUM_CHILDREN; ++children[cur]) {
            if (0 == node->v4.child[children[cur]]) {
                /* no-op */
            } else if (!NODEPTR_CHILD_IS_LEAF(&node->v4, children[cur])) {
                /* this is a node; push this node onto the visit list
                 * and break out of the for() loop to visit the node
                 * immediately */
                to_visit[depth] = node->v4.child[children[cur]];
                children[depth++] = 0;
                /* we're done with this entry on the node */
                ++children[cur];
                ++cur;
                goto VISIT_NODE;
            } else if (NODEPTR_CHILD_IS_REPEAT(&node->v4, children[cur])) {
                /* leaf is a repeat, use current child_idx */
                node->v4.child[children[cur]] = child_idx;
            } else {
                /* this is a new leaf */
                ++child_idx;
                node->v4.child[children[cur]] = child_idx;
            }
        }
        assert(IPSET_NUM_CHILDREN == children[cur]);
        --cur;
        --depth;
    }

    /* child_idx is number of leaves if we ignore the entry at 0 */
    if (child_idx+1 != ipset->s.v3->leaves.entry_count) {
        skAbort();
    }

    /* sort the leaves, ignoring the entry at position 0 */
#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        skQSort(ipset->s.v3->leaves.buf + ipset->s.v3->leaves.entry_size,
                child_idx, ipset->s.v3->leaves.entry_size, ipsetLeafCompareV6);
    } else
#endif
    {
        skQSort(ipset->s.v3->leaves.buf + ipset->s.v3->leaves.entry_size,
                child_idx, ipset->s.v3->leaves.entry_size, ipsetLeafCompareV4);
    }
}


/*
 *  status = ipsetSubtractCallbackV4(ipv4, prefix, ipset);
 *  status = ipsetSubtractCallbackV6(ipv6, prefix, ipset);
 *  status = ipsetSubtractCallback(ipaddr, prefix, ipset);
 *
 *    Helper callback function for skIPSetSubtract().
 *
 *    Removes the CIDR block specified by 'ipaddr'/'prefix' from
 *    'ipset'.
 */
static int
ipsetSubtractCallbackV4(
    uint32_t            ipv4,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetRemoveAddressV4((skipset_t*)v_ipset, ipv4, prefix, NULL);
}

#if SK_ENABLE_IPV6
static int
ipsetSubtractCallbackV6(
    const ipset_ipv6_t *ipv6,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetRemoveAddressV6((skipset_t*)v_ipset, ipv6, prefix, NULL);
}
#endif  /* SK_ENABLE_IPV6 */

static int
ipsetSubtractCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return skIPSetRemoveAddress((skipset_t*)v_ipset, ipaddr, prefix);
}

/*
 *    Helper function for skIPSetSubtract() when both IPsets are
 *    implmented by SiLK-2 IPTrees.
 *
 *    Also a helper function for legacy skIPTreeSubtract().
 */
static int
ipsetSubtractIPTree(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    unsigned int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (NULL == ipset->nodes[i] || NULL == result_ipset->nodes[i]) {
            /* no change required */

        } else {
            /* Need to intersect with the complement in the /16 */
            uint32_t keep_node = 0;

            for (j = 0; keep_node == 0 && j < SKIP_BBLOCK_SIZE; ++j) {
                result_ipset->nodes[i]->addressBlock[j]
                    &= ~(ipset->nodes[i]->addressBlock[j]);
                keep_node = result_ipset->nodes[i]->addressBlock[j];
            }
            if (keep_node) {
                for ( ; j < SKIP_BBLOCK_SIZE; ++j) {
                    result_ipset->nodes[i]->addressBlock[j]
                        &= ~(ipset->nodes[i]->addressBlock[j]);
                }
            } else {
                free(result_ipset->nodes[i]);
                result_ipset->nodes[i] = NULL;
            }
        }
        /* ELSE This /16 is off in at least one ipset.  Leave it alone. */
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetUnionCallbackIPTree(ipv4, prefix, ipset);
 *  status = ipsetUnionCallbackV4(ipv4, prefix, ipset);
 *  status = ipsetUnionCallbackV6(ipv6, prefix, ipset);
 *  status = ipsetUnionCallback(ipaddr, prefix, ipset);
 *
 *    Helper callback function for skIPSetUnion().
 *
 *    Adds the CIDR block specified by 'ipaddr'/'prefix' to 'ipset'.
 */
static int
ipsetUnionCallbackIPTree(
    uint32_t            ipv4,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetInsertAddressIPTree(((skipset_t*)v_ipset)->s.v2, ipv4, prefix);
}

static int
ipsetUnionCallbackV4(
    uint32_t            ipv4,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetInsertAddressV4((skipset_t*)v_ipset, ipv4, prefix, NULL);
}

#if SK_ENABLE_IPV6
static int
ipsetUnionCallbackV6(
    const ipset_ipv6_t *ipv6,
    uint32_t            prefix,
    void               *v_ipset)
{
    return ipsetInsertAddressV6((skipset_t*)v_ipset, ipv6, prefix, NULL);
}
#endif  /* SK_ENABLE_IPV6 */

static int
ipsetUnionCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_ipset)
{
    return skIPSetInsertAddress((skipset_t*)v_ipset, ipaddr, prefix);
}

/*
 *    Helper function for skIPSetUnion() when combining two IPsets
 *    that are implmented as SiLK-2 IPTrees.
 *
 *    Also a helper function for legacy skIPTreeUnion().
 */
static int
ipsetUnionIPTree(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    unsigned int i, j;

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        if (NULL == ipset->nodes[i]) {
            /* no change required in 'result_ipset' */

        } else if (NULL == result_ipset->nodes[i]) {
            /* create a new block on 'result_ipset' and make it
             * identical to that from 'ipset' */
            IPTREE_NODE_ALLOC(result_ipset, i);
            memcpy(result_ipset->nodes[i], ipset->nodes[i],
                   sizeof(skIPNode_t));

        } else {
            /* merge the values */
            for (j = 0; j < SKIP_BBLOCK_SIZE; ++j) {
                result_ipset->nodes[i]->addressBlock[j]
                    |= ipset->nodes[i]->addressBlock[j];
            }
        }
    }
    return SKIPSET_OK;
}


/*
 *    When the following macro is defined, ipsetVerify() prints a
 *    message to stderr saying why verification of the IPset failed.
 *    If it is not defined, no reason is given.
 *
 *    The arguments to the macro should appear in double parentheses,
 *    and the first argument should be VF3.  Example:
 *
 *    VERIFAIL((VF3, "root index is invalid"));
 */
/* #define VERIFAIL(args) ipsetVerifail args */

#ifndef VERIFAIL
#define VERIFAIL(args)
#else
#define VF3 ipset, __FILE__, __LINE__

/*
 *    Print a message saying why verification failed.
 */
static void
ipsetVerifail(
    const skipset_t    *ipset,
    const char         *file,
    int                 line,
    const char         *format,
    ...)
    SK_CHECK_PRINTF(4, 5);

static void
ipsetVerifail(
    const skipset_t    *ipset,
    const char         *file,
    int                 line,
    const char         *format,
    ...)
{
    va_list args;

    va_start(args, format);
    fprintf(stderr, "%s:%d: IPset %p is not valid: ",
            file, line, (void*)ipset);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}
#endif  /* #else of #ifndef VERIFAIL */


/*
 *  status = ipsetVerify(ipset);
 *
 *    Verify that all the indexes in a Radix-Tree based IPset are
 *    valid---that is, less than number of allocated nodes and leaves.
 *    Return SKIPSET_OK on success, or SKIPSET_ERR_CORRUPT on failure.
 *    Verify that every prefix is less than the maximum.
 */
static int
ipsetVerify(
    const skipset_t    *ipset)
{
    uint32_t to_visit[IPSET_MAX_DEPTH];
    uint32_t bitmap_size;
    sk_bitmap_t *bitmap = NULL;
    const ipset_node_t *node;
    const ipset_leaf_t *leaf;
    const ipset_node_t *n2;
    uint32_t node_idx;
    uint32_t depth;
    uint32_t i;

    int rv = SKIPSET_ERR_CORRUPT;

    if (NULL == ipset || 1 == ipset->is_iptree) {
        return SKIPSET_OK;
    }
    if (ipset->s.v3->nodes.entry_count > ipset->s.v3->nodes.entry_capacity) {
        VERIFAIL((VF3, "nodes_count(%u) > nodes_capacity(%u)",
                  ipset->s.v3->nodes.entry_count,
                  ipset->s.v3->nodes.entry_capacity));
        return rv;
    }
    if (ipset->s.v3->leaves.entry_count > ipset->s.v3->leaves.entry_capacity) {
        VERIFAIL((VF3, "leaves_count(%u) > leaves_capacity(%u)",
                  ipset->s.v3->leaves.entry_count,
                  ipset->s.v3->leaves.entry_capacity));
        return rv;
    }

    if (IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }

    if (ipset->s.v3->root_is_leaf) {
        if (IPSET_ROOT_INDEX(ipset) >= ipset->s.v3->leaves.entry_count) {
            VERIFAIL((VF3, "leaf_index(%u) >= leaves_count(%u) [root]",
                      IPSET_ROOT_INDEX(ipset),
                      ipset->s.v3->leaves.entry_count));
            return rv;
        }
        leaf = LEAF_PTR(ipset, IPSET_ROOT_INDEX(ipset));
        if (((leaf->v4.prefix > 32) && !ipset->is_ipv6)
            || (leaf->v4.prefix > 128))
        {
            VERIFAIL((VF3, "leaf(%u) prefix is invalid %u [root]",
                      IPSET_ROOT_INDEX(ipset), leaf->v4.prefix));
            return rv;
        }
        return SKIPSET_OK;
    }

    if (IPSET_ROOT_INDEX(ipset) >= ipset->s.v3->nodes.entry_count) {
        VERIFAIL((VF3, "node_index(%u) >= nodes_count(%u) [root]",
                  IPSET_ROOT_INDEX(ipset), ipset->s.v3->nodes.entry_count));
        return rv;
    }
    n2 = NODE_PTR(ipset, IPSET_ROOT_INDEX(ipset));
    if (((n2->v4.prefix > 32) && !ipset->is_ipv6)
        || (n2->v4.prefix > 128))
    {
        VERIFAIL((VF3, "node(%u) prefix is invalid %u [root]",
                  IPSET_ROOT_INDEX(ipset), n2->v4.prefix));
        return rv;
    }

    /* create a bitmap to note which nodes and leaves are on the free
     * list and to check for diamonds in the structure.  assume the
     * IPset is okay if we cannot allocate the bitmap */
    if (ipset->s.v3->nodes.entry_count > ipset->s.v3->leaves.entry_count) {
        bitmap_size = ipset->s.v3->nodes.entry_count;
    } else {
        bitmap_size = ipset->s.v3->leaves.entry_count;
    }
    if (skBitmapCreate(&bitmap, bitmap_size)) {
        VERIFAIL((VF3, "cannot create bitmap"));
        return SKIPSET_OK;
    }

    /* check the tree for a node linked to by multiple nodes, for
     * invalid node indexes, and for invalid prefixes */
    depth = 0;
    skBitmapSetBit(bitmap, IPSET_ROOT_INDEX(ipset));
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);
    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR(ipset, node_idx);
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if (node->v4.child[i] && !NODEPTR_CHILD_IS_LEAF(&node->v4, i)) {
                if (node->v4.child[i] >= ipset->s.v3->nodes.entry_count) {
                    VERIFAIL((VF3, ("node_index(%u) >= nodes_count(%u)"
                                    " [child %u of %u]"),
                              node->v4.child[i],
                              ipset->s.v3->nodes.entry_count, i, node_idx));
                    goto END;
                }
                if (skBitmapGetBit(bitmap, node->v4.child[i])) {
                    VERIFAIL((VF3, "duplicate node(%u) [child %u of %u]",
                              node->v4.child[i], i, node_idx));
                    goto END;
                }
                n2 = NODE_PTR(ipset, node->v4.child[i]);
                if (((n2->v4.prefix > 32) && !ipset->is_ipv6)
                    || (n2->v4.prefix > 128) || (0 == n2->v4.prefix))
                {
                    VERIFAIL((VF3, ("node(%u) prefix is invalid %u"
                                    " [child %u of %u]"),
                              node->v4.child[i], n2->v4.prefix, i, node_idx));
                    goto END;
                }
                skBitmapSetBit(bitmap, node->v4.child[i]);
                to_visit[depth++] = node->v4.child[i];
            }
        }
    }

    /* check for duplicates on the node free list and for elements on
     * free list that are also in the tree; use depth to keep track of
     * how far into the list we go */
    depth = 0;
    for (node_idx = ipset->s.v3->nodes.free_list;
         0 != node_idx;
         node_idx = NODEIDX_FREE_LIST(ipset, node_idx))
    {
        ++depth;
        if (node_idx >= ipset->s.v3->nodes.entry_count) {
            VERIFAIL((VF3, ("node_index(%u) >= nodes_count(%u)"
                            " [free list item %u]"),
                      node_idx, ipset->s.v3->nodes.entry_count, depth));
            goto END;
        }
        if (!skBitmapGetBit(bitmap, node_idx)) {
            skBitmapSetBit(bitmap, node_idx);
        } else {
            /* is this a duplicate of a node in the tree or on the
             * free list? */
            skBitmapClearAllBits(bitmap);
            for (node_idx = ipset->s.v3->nodes.free_list;
                 0 != node_idx && depth > 0;
                 node_idx = NODEIDX_FREE_LIST(ipset, node_idx))
            {
                --depth;
                if (skBitmapGetBit(bitmap, node_idx)) {
                    VERIFAIL((VF3, "duplicate free node_index(%u)", node_idx));
                    goto END;
                }
                skBitmapSetBit(bitmap, node_idx);
            }
            VERIFAIL((VF3, "node_index(%u) also on free list", node_idx));
            goto END;
        }
    }

    /* check the tree for a leaf linked to by multiple nodes, for
     * invalid leaf indexes, and for invalid prefixes */
    skBitmapClearAllBits(bitmap);
    depth = 0;
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);
    while (depth) {
        node_idx = to_visit[--depth];
        node = NODE_PTR(ipset, node_idx);
        for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
            if (0 == node->v4.child[i]) {
                /* no-op */
            } else if (!NODEPTR_CHILD_IS_LEAF(&node->v4, i)) {
                to_visit[depth++] = node->v4.child[i];
            } else if (NODEPTR_CHILD_IS_REPEAT(&node->v4, i)) {
                if (0 == i) {
                    skAbort();
                }
                if (node->v4.child[i] != node->v4.child[i - 1]) {
                    VERIFAIL((VF3, ("on node %u, bad id on child %u (%u)"
                                    " marked as repeat of previous (%u)"),
                              node_idx, i, node->v4.child[i],
                              node->v4.child[i-1]));
                    goto END;
                }
            } else {
                if (node->v4.child[i] >= ipset->s.v3->leaves.entry_count) {
                    VERIFAIL((VF3, ("leaf_index(%u) >= leaves_count(%u)"
                                    " [child %u of %u]"),
                              node->v4.child[i],
                              ipset->s.v3->leaves.entry_count, i, node_idx));
                    goto END;
                }
                if (skBitmapGetBit(bitmap, node->v4.child[i])) {
                    VERIFAIL((VF3, "duplicate leaf(%u) [child %u of %u]",
                              node->v4.child[i], i, node_idx));
                    goto END;
                }
                leaf = LEAF_PTR(ipset, node->v4.child[i]);
                if (((leaf->v4.prefix > 32) && !ipset->is_ipv6)
                    || (leaf->v4.prefix > 128) || (0 == leaf->v4.prefix))
                {
                    VERIFAIL((VF3, ("leaf(%u) prefix is invalid %u"
                                    " [child %u of %u]"),
                              node->v4.child[i], leaf->v4.prefix, i,node_idx));
                    goto END;
                }
                skBitmapSetBit(bitmap, node->v4.child[i]);
            }
        }
    }

    /* check for duplicates on the leaf free list and for elements on
     * free list that are also in the tree; use depth to keep track of
     * how far into the list we go */
    depth = 0;
    for (node_idx = ipset->s.v3->leaves.free_list;
         0 != node_idx;
         node_idx = LEAFIDX_FREE_LIST(ipset, node_idx))
    {
        ++depth;
        if (node_idx >= ipset->s.v3->leaves.entry_count) {
            VERIFAIL((VF3, ("leaf_index(%u) >= leaves_count(%u)"
                            " [free list item %u]"),
                      node_idx, ipset->s.v3->leaves.entry_count, depth));
            goto END;
        }
        if (!skBitmapGetBit(bitmap, node_idx)) {
            skBitmapSetBit(bitmap, node_idx);
        } else {
            /* is this a duplicate of a leaf in the tree or on the
             * free list? */
            skBitmapClearAllBits(bitmap);
            for (node_idx = ipset->s.v3->leaves.free_list;
                 0 != node_idx;
                 node_idx = LEAFIDX_FREE_LIST(ipset, node_idx))
            {
                --depth;
                if (skBitmapGetBit(bitmap, node_idx)) {
                    VERIFAIL((VF3, "duplicate free leaf_index(%u)", node_idx));
                    goto END;
                }
                skBitmapSetBit(bitmap, node_idx);
            }
            VERIFAIL((VF3, "leaf_index(%u) also on free list", node_idx));
            goto END;
        }
    }

    rv = SKIPSET_OK;

  END:
    if (bitmap) {
        skBitmapDestroy(&bitmap);
    }
    return rv;
}


/*
 *  status = ipsetWalkInternalV4(ipset, callback, cb_data);
 *  status = ipsetWalkInternalV6(ipset, callback, cb_data);
 *
 *    These are internal functions for walking over the contents a
 *    Radix-Tree based IPset.  They are NOT helper functions for
 *    skIPSetWalk().  The helper functions for skIPSetWalk() are named
 *    ipsetWalkV4() and ipsetWalkV6().
 *
 *    These function visit the leaves in an IPset in order from lowest
 *    to highest.  They will use the iterator if the IPset is clean,
 *    or recursively walk the nodes if the IPset is dirty.
 *
 *    These functions always invoke the 'callback' with the IP/prefix
 *    pair---that is they do not visit individual IP addresses.
 *
 *    The callback will be invoked with the IP in the form stored
 *    internally by the IPset, eliminating the conversion to/from an
 *    skipaddr_t that skIPSetWalk() performs.
 *
 *    The function stops visiting the leaves when the callback returns
 *    a value other than SKIPSET_OK.
 *
 *    Return SKIPSET_OK if the IPset is empty; otherwise, return the
 *    value returned by the final call to the callback.
 */
static int
ipsetWalkInternalV4(
    const skipset_t    *ipset,
    ipset_walk_v4_fn_t  callback,
    void               *cb_data)
{
    uint8_t is_leaf[IPSET_MAX_DEPTH_V4];
    uint32_t to_visit[IPSET_MAX_DEPTH_V4];
    const ipset_node_v4_t *node;
    const ipset_leaf_v4_t *leaf;
    uint32_t depth;
    uint32_t i;
    int rv = SKIPSET_OK;

    assert(ipset);
    assert(0 == ipset->is_iptree);
    assert(0 == ipset->is_ipv6);
    assert(callback);

    if (IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }

    /* use the iterator if we can */
    if (!ipset->is_dirty) {
        uint32_t cur = IPSET_ITER_FIRST_LEAF;
        while (0 == rv && cur < ipset->s.v3->leaves.entry_count) {
            leaf = LEAF_PTR_V4(ipset, cur);
            rv = callback(leaf->ip, leaf->prefix, cb_data);
            ++cur;
        }
        return rv;
    }

    depth = 0;
    is_leaf[depth] = IPSET_ROOT_IS_LEAF(ipset);
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        if (is_leaf[--depth]) {
            /* handle a leaf node */
            leaf = LEAF_PTR_V4(ipset, to_visit[depth]);
            rv = callback(leaf->ip, leaf->prefix, cb_data);
            if (0 != rv) {
                break;
            }
        } else {
            /* push children onto the stack in reverse order */
            node = NODE_PTR_V4(ipset, to_visit[depth]);
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                    to_visit[depth++] = node->child[i];
                }
            }
        }
    }
    return rv;
}

#if SK_ENABLE_IPV6
static int
ipsetWalkInternalV6(
    const skipset_t    *ipset,
    ipset_walk_v6_fn_t  callback,
    void               *cb_data)
{
    uint8_t is_leaf[IPSET_MAX_DEPTH_V6];
    uint32_t to_visit[IPSET_MAX_DEPTH_V6];
    const ipset_node_v6_t *node;
    const ipset_leaf_v6_t *leaf;
    uint32_t depth;
    uint32_t i;
    int rv = SKIPSET_OK;

    assert(ipset);
    assert(0 == ipset->is_iptree);
    assert(1 == ipset->is_ipv6);
    assert(callback);

    if (IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }

    /* use the iterator if we can */
    if (!ipset->is_dirty) {
        uint32_t cur = IPSET_ITER_FIRST_LEAF;
        while (0 == rv && cur < ipset->s.v3->leaves.entry_count) {
            leaf = LEAF_PTR_V6(ipset, cur);
            rv = callback(&leaf->ip, leaf->prefix, cb_data);
            ++cur;
        }
        return rv;
    }

    depth = 0;
    is_leaf[depth] = IPSET_ROOT_IS_LEAF(ipset);
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    while (depth) {
        if (is_leaf[--depth]) {
            /* handle a leaf node */
            leaf = LEAF_PTR_V6(ipset, to_visit[depth]);
            rv = callback(&leaf->ip, leaf->prefix, cb_data);
            if (0 != rv) {
                break;
            }
        } else {
            /* push children onto the stack in reverse order */
            node = NODE_PTR_V6(ipset, to_visit[depth]);
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                    to_visit[depth++] = node->child[i];
                }
            }
        }
    }
    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetWalkV4(ipset, walk_state);
 *  status = ipsetWalkV6(ipset, walk_state);
 *
 *    Helper function for skIPSetWalk().
 *
 *    These function visit the leaves in an IPset in order from lowest
 *    to highest.  They will use the iterator if the IPset is clean,
 *    or walk the nodes if the IPset is dirty.
 *
 *    Depending on 'walk_state', the callback is invoked on the CIDR
 *    blocks as stored in the tree or on individual IP addresses.
 *
 *    The callback will be invoked with the IP converted to an
 *    skipaddr_t.  The 'walk_state' determines whether the skipaddr_t
 *    contains an IPv4 or IPv6 representation of the IP address.
 *
 *    The function stops visiting the leaves when the callback returns
 *    a value other than SKIPSET_OK.
 *
 *    Return SKIPSET_OK if the IPset is empty; otherwise, return the
 *    value returned by the final call to the callback.
 *
 *    Do not confuse these helper functions for skIPSetWalk() with the
 *    internal functions for walking over an IPset, which are
 *    ipsetWalkInternalV4() and ipsetWalkInternalV6().
 */
static int
ipsetWalkV4(
    const skipset_t    *ipset,
    const ipset_walk_t *walk_state)
{
    uint8_t is_leaf[IPSET_MAX_DEPTH_V4];
    uint32_t to_visit[IPSET_MAX_DEPTH_V4];
    const ipset_node_v4_t *node;
    const ipset_leaf_v4_t *leaf;
    skipaddr_t ipaddr;
    uint32_t depth;
    uint32_t ipv4;
    uint32_t fin4;
    uint32_t i;
    int rv = 0;

    assert(ipset);
    assert(walk_state);
    assert(walk_state->callback);
    assert(walk_state->v6policy != SK_IPV6POLICY_ONLY);

    depth = 0;
    is_leaf[depth] = IPSET_ROOT_IS_LEAF(ipset);
    to_visit[depth++] = IPSET_ROOT_INDEX(ipset);

    if (walk_state->cidr_blocks) {
        while (depth) {
            if (!is_leaf[--depth]) {
                node = NODE_PTR_V4(ipset, to_visit[depth]);
                for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                    --i;
                    if (node->child[i]
                        && !NODEPTR_CHILD_IS_REPEAT(node, i))
                    {
                        is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                        to_visit[depth++] = node->child[i];
                    }
                }
            } else {
                /* handle a leaf node */
                leaf = LEAF_PTR_V4(ipset, to_visit[depth]);
#if SK_ENABLE_IPV6
                if (SK_IPV6POLICY_FORCE == walk_state->v6policy) {
                    skipaddrSetV6FromUint32(&ipaddr, &leaf->ip);
                    rv = walk_state->callback(&ipaddr, 96 + leaf->prefix,
                                              walk_state->cb_data);
                } else
#endif  /* SK_ENABLE_IPV6 */
                {
                    skipaddrSetV4(&ipaddr, &leaf->ip);
                    rv = walk_state->callback(&ipaddr, leaf->prefix,
                                              walk_state->cb_data);
                }
                if (0 != rv) {
                    break;
                }
            }
        }
        return rv;
    }

    /* Walk over IPset, running the callback function with each
     * individual IP address */
    while (depth) {
        if (!is_leaf[--depth]) {
            node = NODE_PTR_V4(ipset, to_visit[depth]);
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                    to_visit[depth++] = node->child[i];
                }
            }

#if SK_ENABLE_IPV6
        } else if (SK_IPV6POLICY_FORCE == walk_state->v6policy) {
            /* handle a leaf node where IPv6 addresses are to be
             * returned */
            leaf = LEAF_PTR_V4(ipset, to_visit[depth]);
            if (32 == leaf->prefix) {
                skipaddrSetV6FromUint32(&ipaddr, &leaf->ip);
                rv = walk_state->callback(&ipaddr, 128, walk_state->cb_data);
            } else {
                /* else visit each IP in the block */
                ipv4 = leaf->ip;
                fin4 = leaf->ip | (UINT32_MAX >> leaf->prefix);

                do {
                    skipaddrSetV6FromUint32(&ipaddr, &ipv4);
                    rv = walk_state->callback(&ipaddr, 128,
                                              walk_state->cb_data);
                } while ((0 == rv) && (ipv4++ < fin4));
            }
            if (0 != rv) {
                break;
            }
#endif  /* SK_ENABLE_IPV6 */

        } else {
            /* handle a leaf node */
            leaf = LEAF_PTR_V4(ipset, to_visit[depth]);
            if (32 == leaf->prefix) {
                skipaddrSetV4(&ipaddr, &leaf->ip);
                rv = walk_state->callback(&ipaddr, leaf->prefix,
                                          walk_state->cb_data);
            } else {
                /* else visit each IP in the block */
                ipv4 = leaf->ip;
                fin4 = leaf->ip | (UINT32_MAX >> leaf->prefix);
                do {
                    skipaddrSetV4(&ipaddr, &ipv4);
                    rv = walk_state->callback(&ipaddr, 32, walk_state->cb_data);
                } while ((0 == rv) && (ipv4++ < fin4));
            }
            if (0 != rv) {
                break;
            }
        }
    }
    return rv;
}

#if SK_ENABLE_IPV6
static int
ipsetWalkV6(
    const skipset_t    *ipset,
    const ipset_walk_t *walk_state)
{
    uint8_t is_leaf[IPSET_MAX_DEPTH_V6];
    uint32_t to_visit[IPSET_MAX_DEPTH_V6];
    const ipset_node_v6_t *node;
    const ipset_leaf_v6_t *leaf;
    skipaddr_t ipaddr;
    uint32_t depth;
    ipset_ipv6_t ipv6;
    ipset_ipv6_t fin6;
    int i;
    int rv = 0;

    assert(ipset);
    assert(walk_state);
    assert(walk_state->callback);
    assert(walk_state->v6policy != SK_IPV6POLICY_IGNORE);

    if (SK_IPV6POLICY_ASV4 != walk_state->v6policy) {
        /* visit all the nodes in the tree */
        depth = 0;
        is_leaf[depth] = IPSET_ROOT_IS_LEAF(ipset);
        to_visit[depth++] = IPSET_ROOT_INDEX(ipset);
    } else {
        /* limit to the nodes under ::ffff:0:0/96 */
        ipset_find_t find_state;

        ipv6.ip[0] = 0;
        ipv6.ip[1] = UINT64_C(0xffff00000000);

        rv = ipsetFindV6(ipset, &ipv6, 96, &find_state);
        if (SKIPSET_OK != rv && SKIPSET_ERR_SUBSET != rv) {
            /* no IPv4 addresses in the IPset */
            return SKIPSET_OK;
        }
        depth = 0;
        is_leaf[depth] = find_state.node_is_leaf;
        to_visit[depth++] = find_state.node_idx;
        rv = 0;
    }

    if (walk_state->cidr_blocks) {
        while (depth) {
            if (!is_leaf[--depth]) {
                node = NODE_PTR_V6(ipset, to_visit[depth]);
                for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                    --i;
                    if (node->child[i]
                        && !NODEPTR_CHILD_IS_REPEAT(node, i))
                    {
                        is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                        to_visit[depth++] = node->child[i];
                    }
                }
            } else {
                /* handle a leaf node */
                leaf = LEAF_PTR_V6(ipset, to_visit[depth]);
                if (SK_IPV6POLICY_ASV4 == walk_state->v6policy) {
                    IPSET_IPV6_TO_ADDR_V4(&leaf->ip, &ipaddr);
                    rv = walk_state->callback(&ipaddr, leaf->prefix - 96,
                                              walk_state->cb_data);
                } else {
                    IPSET_IPV6_TO_ADDR(&leaf->ip, &ipaddr);
                    rv = walk_state->callback(&ipaddr, leaf->prefix,
                                              walk_state->cb_data);
                }
                if (0 != rv) {
                    break;
                }
            }
        }
        return rv;
    }

    /* Walk over IPset, running the callback function with each
     * individual IP address */
    while (depth) {
        if (!is_leaf[--depth]) {
            node = NODE_PTR_V6(ipset, to_visit[depth]);
            for (i = IPSET_NUM_CHILDREN; i > 0; ) {
                --i;
                if (node->child[i]
                    && !NODEPTR_CHILD_IS_REPEAT(node, i))
                {
                    is_leaf[depth] = NODEPTR_CHILD_IS_LEAF(node, i);
                    to_visit[depth++] = node->child[i];
                }
            }

        } else if (SK_IPV6POLICY_ASV4 == walk_state->v6policy) {
            /* handle a leaf node where IPv4 addresses are to be
             * returned */
            leaf = LEAF_PTR_V6(ipset, to_visit[depth]);
            if (128 == leaf->prefix) {
                IPSET_IPV6_TO_ADDR_V4(&leaf->ip, &ipaddr);
                rv = walk_state->callback(&ipaddr, 32, walk_state->cb_data);
            } else {
                /* else visit each IP in the block; convert CIDR block
                 * to current IP (ipv4) and final IP (fin4) */
                uint32_t ipv4;
                uint32_t fin4;

                assert(96 <= leaf->prefix);
                assert(0 == leaf->ip.ip[0]);
                assert(UINT64_C(0x0000ffff00000000)
                       == (UINT64_C(0xffffffff00000000) & leaf->ip.ip[1]));
                ipv4 = (uint32_t)(UINT64_C(0x00000000ffffffff)
                                  & leaf->ip.ip[1]);
                fin4 = ipv4 | (UINT32_MAX >> (leaf->prefix - 96));

                do {
                    skipaddrSetV4(&ipaddr, &ipv4);
                    rv = walk_state->callback(&ipaddr, 32,
                                              walk_state->cb_data);
                } while ((0 == rv) && (ipv4++ < fin4));
            }
            if (0 != rv) {
                break;
            }

        } else {
            /* handle a leaf node */
            leaf = LEAF_PTR_V6(ipset, to_visit[depth]);
            if (128 == leaf->prefix) {
                IPSET_IPV6_TO_ADDR(&leaf->ip, &ipaddr);
                rv = walk_state->callback(&ipaddr, leaf->prefix,
                                          walk_state->cb_data);
            } else {
                /* else visit each IP in the block; convert CIDR block
                 * to current IP (ipv6) and final IP (fin6) */
                if (leaf->prefix > 64) {
                    ipv6.ip[0] = fin6.ip[0] = leaf->ip.ip[0];
                    ipv6.ip[1] = leaf->ip.ip[1];
                    fin6.ip[1] = (leaf->ip.ip[1]
                                  | (UINT64_MAX >> (leaf->prefix - 64)));
                } else if (leaf->prefix == 64) {
                    ipv6.ip[0] = fin6.ip[0] = leaf->ip.ip[0];
                    ipv6.ip[1] = 0;
                    fin6.ip[1] = UINT64_MAX;
                } else {
                    ipv6.ip[0] = leaf->ip.ip[0];
                    fin6.ip[0] = (leaf->ip.ip[0]
                                  | (UINT64_MAX >> leaf->prefix));
                    ipv6.ip[1] = 0;
                    fin6.ip[1] = UINT64_MAX;
                }

                for (;;) {
                    IPSET_IPV6_TO_ADDR(&ipv6, &ipaddr);
                    rv = walk_state->callback(&ipaddr,128,walk_state->cb_data);
                    if (rv) {
                        return rv;
                    }
                    if (ipv6.ip[1] < fin6.ip[1]) {
                        ++ipv6.ip[1];
                    } else if (ipv6.ip[0] < fin6.ip[0]) {
                        if (ipv6.ip[1] == UINT64_MAX) {
                            ++ipv6.ip[0];
                            ipv6.ip[1] = 0;
                        } else {
                            ++ipv6.ip[1];
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }

    return rv;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetWriteCidrbmapFromIPTree(ipset, stream);
 *
 *    Helper function for skIPSetWrite() via ipsetWriteCidrbmap().
 *
 *    Write an IPset from the SiLK-2 IPTree data structure to 'stream'
 *    in the IPSET_REC_VERSION_CIDRBMAP format.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetWriteCidrbmapFromIPTree(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    uint8_t write_buf[sizeof(uint32_t) + sizeof(uint8_t)];
    skIPNode_t *slash16;
    uint32_t i;
    uint32_t j;
    ssize_t rv;
    struct build_cidr_st {
        /* starting ip for this netblock */
        uint32_t start;
        /* number of trailing 0s; used to set CIDR mask */
        uint32_t trail_zero;
        /* maximum number of /24s this block can hold */
        uint32_t max_block;
        /* number of the max_block we have seen so far */
        uint32_t count;
    } build_cidr;

#define WRITE_BUILD_CIDR                                                \
    while (build_cidr.count) {                                          \
        --build_cidr.trail_zero;                                        \
        if (build_cidr.count >= (1u << (build_cidr.trail_zero - 8))) {  \
            *(uint32_t*)write_buf = build_cidr.start;                   \
            write_buf[sizeof(uint32_t)]                                 \
                = (uint8_t)(32 - build_cidr.trail_zero);                \
            rv = skStreamWrite(stream, write_buf, sizeof(write_buf));   \
            if (rv != sizeof(write_buf)) {                              \
                return SKIPSET_ERR_FILEIO;                              \
            }                                                           \
            build_cidr.count -= (1 << (build_cidr.trail_zero - 8));     \
            build_cidr.start |= (0x100 << (build_cidr.trail_zero - 8)); \
        }                                                               \
    }

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || !ipset->is_iptree || ipset->is_ipv6) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CIDRBMAP) {
        skAbort();
    }

    memset(&build_cidr, 0, sizeof(build_cidr));

    for (i = 0; i < SKIP_BBLOCK_COUNT; ++i) {
        /* slash16 represents a /16 */
        slash16 = ipset->s.v2->nodes[i];
        if (NULL == slash16) {
            /* no data in this /16; write any CIDR range that was
             * being built */
            WRITE_BUILD_CIDR;
            continue;
        }

        /* There is data in this /16, walk over the addressBlocks by
         * 8s, which is equivalent to visiting each /24. */
        for (j = 0; j < SKIP_BBLOCK_SIZE; j += IPTREE_WORDS_PER_SLASH24) {

            if (0 == memcmp(slash16->addressBlock + j,
                            bmap256_zero, sizeof(bmap256_zero)))
            {
                /* no data in this /24; write existing CIDR block */
                WRITE_BUILD_CIDR;
                continue;
            }
            if (0 == memcmp(slash16->addressBlock + j,
                            bmap256_full, sizeof(bmap256_full)))
            {
                /* this /24 is full; if CIDR block is being built,
                 * this block must be contiguous with it */
                if (build_cidr.count) {
                    ++build_cidr.count;
                    if (build_cidr.count == build_cidr.max_block) {
                        /* cidr block is at its maximum size */
                        *(uint32_t*)write_buf = build_cidr.start;
                        write_buf[sizeof(uint32_t)]
                            = (uint8_t)(32 - build_cidr.trail_zero);
                        rv = skStreamWrite(stream,write_buf,sizeof(write_buf));
                        if (rv != sizeof(write_buf)) {
                            return SKIPSET_ERR_FILEIO;
                        }
                        build_cidr.count = 0;
                    }
                    continue;
                }

                /* no existing CIDR block to join; start a new one */
                build_cidr.start = ((i << 16) | (j << 5)) & 0xFFFFFF00;
                if (build_cidr.start & 0x100) {
                    /* the third octet is odd, so this block cannot be
                     * combined with another */
                    *(uint32_t*)write_buf = build_cidr.start;
                    write_buf[sizeof(uint32_t)] = 24;
                    rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                    if (rv != sizeof(write_buf)) {
                        return SKIPSET_ERR_FILEIO;
                    }
                    continue;
                }

                /* compute the maximum number of blocks that can be
                 * joined with this one by computing the number of
                 * trailing 0s on the IP. */
                if (0 == build_cidr.start) {
                    build_cidr.trail_zero = 32;
                } else {
                    build_cidr.trail_zero
                        = ipsetCountTrailingZeros(build_cidr.start);
                }
                build_cidr.max_block = (1 << (build_cidr.trail_zero - 8));
                build_cidr.count = 1;
                continue;
            }

            /* there is some data in this /24.  First, handle any CIDR
             * range that was being build.  Then, write this block as
             * a base address and bitmap. */
            WRITE_BUILD_CIDR;

            /* write the IP and the 'bitmap-follows' value  */
            *(uint32_t*)write_buf = (((i << 16) | (j << 5)) & 0xFFFFFF00);
            write_buf[sizeof(uint32_t)] = SET_CIDRBMAP_MAP256;
            rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
            if (rv != sizeof(write_buf)) {
                return SKIPSET_ERR_FILEIO;
            }
            /* write the complete /24: 8 uint32_t's */
            rv = skStreamWrite(stream, slash16->addressBlock + j,
                               sizeof(bmap256_zero));
            if (rv != sizeof(bmap256_zero)) {
                return SKIPSET_ERR_FILEIO;
            }
        }
    }

    rv = skStreamFlush(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetWriteCidrbmapFromRadixV4(&ipset, stream, hdr);
 *  status = ipsetWriteCidrbmapFromRadixV6(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetWrite() via ipsetWriteCidrbmap().
 *
 *    Write an IPset from the radix-tree IPset data structure to
 *    'stream' in the IPSET_REC_VERSION_CIDRBMAP format.
 *
 *    See '#define IPSET_REC_VERSION_CIDRBMAP' for description of the
 *    file format.
 */
static int
ipsetWriteCidrbmapFromRadixV4(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    skipset_iterator_t iter;
    enum status_en {
        Empty, First_IP, Bitmap
    };
    struct state_st {
        /* starting ip for this netblock, or an unmasked IP if
         * 'status' is First_IP. */
        uint32_t        base_ip;
        /* the 256-bit bitmap */
        uint32_t        bmap[IPTREE_WORDS_PER_SLASH24];
        /* the prefix for 'base_ip' if 'status' is First_IP */
        uint8_t         prefix;
        /* what this structure currently holds */
        enum status_en  status;
    } state;
    /* the bitmap holds 256 bits or a /24 */
    const uint32_t bmap_prefix = 24;
    /* each uint32_t in the bitmap holds a /27 */
    const uint32_t word_prefix = 27;
    uint8_t write_buf[sizeof(uint32_t) + 1];
    uint32_t ipv4;
    skipaddr_t ipaddr;
    uint32_t prefix;
    uint32_t buf_idx;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || ipset->is_iptree || ipset->is_ipv6) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CIDRBMAP) {
        skAbort();
    }

    memset(&state, 0, sizeof(state));
    state.status = Empty;

    ASSERT_OK(skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_ASV4));
    while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK){
        ipv4 = skipaddrGetV4(&ipaddr);
        if (state.status != Empty && (prefix <= bmap_prefix
                                      || (state.base_ip ^ ipv4) > 0xFF))
        {
            /* 'ipv4' is not in the same /24 as 'state'; write the IP
             * or bitmap currently in 'state' */
            if (First_IP == state.status) {
                /* write the single ip and prefix */
                *(uint32_t*)write_buf = state.base_ip;
                write_buf[sizeof(uint32_t)] = (uint8_t)state.prefix;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
            } else {
                /* write base ip, 'bitmap-follows' value for the
                 * prefix, and the bitmap */
                *(uint32_t*)write_buf = state.base_ip;
                write_buf[sizeof(uint32_t)] = SET_CIDRBMAP_MAP256;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
                rv = skStreamWrite(stream, state.bmap, sizeof(state.bmap));
                if (rv != sizeof(state.bmap)) {
                    return SKIPSET_ERR_FILEIO;
                }
            }
            state.status = Empty;
        }

        if (Empty == state.status) {
            if (prefix <= bmap_prefix) {
                /* netblock is larger than fits into a bitmap; write
                 * the block as an IP and prefix */
                *(uint32_t*)write_buf = ipv4;
                write_buf[sizeof(uint32_t)] = (uint8_t)prefix;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
            } else {
                /* initialize 'state' with this IP and look for more
                 * IPs in this /24. */
                state.status = First_IP;
                state.base_ip = ipv4;
                state.prefix = (uint8_t)prefix;
            }
            continue;
        }

        assert(prefix > bmap_prefix);
        if (First_IP == state.status) {
            /* found a second IP in this /24; convert 'state' to hold
             * a bitmap */
            state.status = Bitmap;
            memset(state.bmap, 0, sizeof(state.bmap));

            buf_idx = ((state.base_ip & 0xFF) >> 5);
            if (state.prefix <= word_prefix) {
                /* prefix spans one or more uint32_t's */
                memset(&(state.bmap[buf_idx]), 0xff,
                       (sizeof(uint32_t) << (word_prefix - state.prefix)));
            } else {
                state.bmap[buf_idx]
                    |= (((1 << (1 << (32 - state.prefix))) - 1)
                        << (state.base_ip & 0x1f));
            }
            /* mask base_ip as a /24 */
            state.base_ip = state.base_ip & 0xFFFFFF00;
        }
        assert(Bitmap == state.status);
        assert((ipv4 & 0xFFFFFF00) == state.base_ip);

        /* add the current IP/prefix to the bitmap */
        buf_idx = ((ipv4 & 0xFF) >> 5);
        if (prefix <= word_prefix) {
            /* set several uint32_t's */
            memset(&(state.bmap[buf_idx]), 0xff,
                   (sizeof(uint32_t) << (word_prefix - prefix)));
        } else {
            state.bmap[buf_idx] |= (((1 << (1 << (32 - prefix))) - 1)
                                    << (ipv4 & 0x1f));
        }
    }

    /* write any IP or bitmap still in 'state' */
    switch (state.status) {
      case Empty:
        break;
      case First_IP:
        *(uint32_t*)write_buf = state.base_ip;
        write_buf[sizeof(uint32_t)] = (uint8_t)state.prefix;
        rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
        if (rv != sizeof(write_buf)) {
            return SKIPSET_ERR_FILEIO;
        }
        break;
      case Bitmap:
        *(uint32_t*)write_buf = state.base_ip;
        write_buf[sizeof(uint32_t)] = SET_CIDRBMAP_MAP256;
        rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
        if (rv != sizeof(write_buf)) {
            return SKIPSET_ERR_FILEIO;
        }
        rv = skStreamWrite(stream, state.bmap, sizeof(state.bmap));
        if (rv != sizeof(state.bmap)) {
            return SKIPSET_ERR_FILEIO;
        }
        break;
    }

    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetWriteCidrbmapFromRadixV6(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    skipset_iterator_t iter;
    enum status_en {
        Empty, First_IP, Bitmap
    };
    struct state_st {
        /* starting ip for this netblock, or an unmasked IP if
         * 'status' is 'First_IP'. */
        ipset_ipv6_t    base_ip;
        /* the 256-bit bitmap */
        uint32_t        bmap[IPTREE_WORDS_PER_SLASH24];
        /* the prefix for 'base_ip' if 'status' is First_IP */
        uint8_t         prefix;
        /* what this structure currently holds */
        enum status_en  status;
    } state;
    /* the bitmap holds 256 bits or a /120 */
    const uint32_t bmap_prefix = 120;
    /* each uint32_t in the bitmap holds a /123 */
    const uint32_t word_prefix = 123;
    uint8_t write_buf[IPSET_LEN_V6 + sizeof(uint8_t)];
    ipset_ipv6_t ipv6;
    skipaddr_t ipaddr;
    uint32_t prefix;
    uint32_t buf_idx;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || ipset->is_iptree || !ipset->is_ipv6) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CIDRBMAP) {
        skAbort();
    }

    memset(&state, 0, sizeof(state));
    state.status = Empty;

    ASSERT_OK(skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_FORCE));
    while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK) {
        IPSET_IPV6_FROM_ADDRV6(&ipv6, &ipaddr);
        if (state.status != Empty
            && (prefix <= bmap_prefix
                || (state.base_ip.ip[0] != ipv6.ip[0])
                || ((state.base_ip.ip[1] ^ ipv6.ip[1]) > 0xFF)))
        {
            /* 'ipv6' is not in the same /120 as 'state'; write the IP
             * or bitmap currently in 'state' */
            if (First_IP == state.status) {
                /* write the single ip and prefix */
                IPSET_IPV6_TO_ARRAY(&state.base_ip, write_buf);
                write_buf[IPSET_LEN_V6] = (uint8_t)state.prefix;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
            } else {
                /* write base ip, 'bitmap-follows' value for the
                 * prefix, and the bitmap */
                assert(Bitmap == state.status);
                IPSET_IPV6_TO_ARRAY(&state.base_ip, write_buf);
                write_buf[IPSET_LEN_V6] = SET_CIDRBMAP_MAP256;
                rv = skStreamWrite(stream, &write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
                rv = skStreamWrite(stream, state.bmap, sizeof(state.bmap));
                if (rv != sizeof(state.bmap)) {
                    return SKIPSET_ERR_FILEIO;
                }
            }
            state.status = Empty;
        }

        if (Empty == state.status) {
            if (prefix <= bmap_prefix) {
                /* netblock is larger than fits into a bitmap; write
                 * the block as an IP and prefix */
                IPSET_IPV6_TO_ARRAY(&ipv6, write_buf);
                write_buf[IPSET_LEN_V6] = (uint8_t)prefix;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
            } else {
                /* initialize 'state' with this IP and look for more
                 * IPs in this /120. */
                state.status = First_IP;
                IPSET_IPV6_COPY(&state.base_ip, &ipv6);
                state.prefix = (uint8_t)prefix;
            }
            continue;
        }
        assert(prefix > bmap_prefix);
        if (First_IP == state.status) {
            /* found a second IP in this /120; convert 'state' to hold
             * a bitmap */
            state.status = Bitmap;
            memset(state.bmap, 0, sizeof(state.bmap));

            buf_idx = ((state.base_ip.ip[1] & 0xFF) >> 5);
            if (state.prefix <= word_prefix) {
                /* prefix spans one or more uint32_t's */
                memset(&(state.bmap[buf_idx]), 0xff,
                       (sizeof(uint32_t) << (word_prefix-state.prefix)));
            } else {
                state.bmap[buf_idx]
                    |= (((1 << (1 << (128 - state.prefix))) - 1)
                        << (state.base_ip.ip[1] & 0x1f));
            }
            /* mask base_ip as a /120 */
            state.base_ip.ip[1] = (state.base_ip.ip[1] & ~UINT64_C(0xFF));
        }
        assert(Bitmap == state.status);
        assert(ipv6.ip[0] == state.base_ip.ip[0]);
        assert((ipv6.ip[1] & ~UINT64_C(0xFF)) == state.base_ip.ip[1]);

        /* add the current IP/prefix to the bitmap */
        buf_idx = ((ipv6.ip[1] & 0xFF) >> 5);
        if (prefix <= word_prefix) {
            /* set several uint32_t's */
            memset(&(state.bmap[buf_idx]), 0xff,
                   (sizeof(uint32_t) << (word_prefix - prefix)));
        } else {
            state.bmap[buf_idx] |= (((1 << (1 << (128 - prefix))) - 1)
                                    << (ipv6.ip[1] & 0x1f));
        }
    }

    /* write any IP or bitmap still in 'state' */
    switch (state.status) {
      case Empty:
        break;
      case First_IP:
        IPSET_IPV6_TO_ARRAY(&state.base_ip, write_buf);
        write_buf[IPSET_LEN_V6] = (uint8_t)state.prefix;
        rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
        if (rv != sizeof(write_buf)) {
            return SKIPSET_ERR_FILEIO;
        }
        break;
      case Bitmap:
        IPSET_IPV6_TO_ARRAY(&state.base_ip, write_buf);
        write_buf[IPSET_LEN_V6] = SET_CIDRBMAP_MAP256;
        rv = skStreamWrite(stream, &write_buf, sizeof(write_buf));
        if (rv != sizeof(write_buf)) {
            return SKIPSET_ERR_FILEIO;
        }
        rv = skStreamWrite(stream, state.bmap, sizeof(state.bmap));
        if (rv != sizeof(state.bmap)) {
            return SKIPSET_ERR_FILEIO;
        }
        break;
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetWriteCidrbmap(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetWrite().
 *
 *    Write an IPset to 'stream' in the IPSET_REC_VERSION_CIDRBMAP
 *    format.
 *
 *    This function writes the header then calls another helper
 *    function depending on the data structure being used.
 */
static int
ipsetWriteCidrbmap(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    int rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CIDRBMAP) {
        skAbort();
    }

    /* Add the appropriate header */
    rv = ipsetHentryAddToFile(hdr, 0, 0,
                              ipset->is_ipv6 ? IPSET_LEN_V6 : sizeof(uint32_t),
                              0, 0, 0);
    if (rv) {
        skAppPrintErr("%s", skHeaderStrerror(rv));
        return SKIPSET_ERR_FILEIO;
    }
    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    if (ipset->is_iptree) {
        return ipsetWriteCidrbmapFromIPTree(ipset, stream);
    }
#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        return ipsetWriteCidrbmapFromRadixV6(ipset, stream);
    }
#endif
    return ipsetWriteCidrbmapFromRadixV4(ipset, stream);
}


/*
 *  status = ipsetWriteClasscFromIPTree(ipset, stream);
 *
 *    Helper function for skIPSetWrite() via ipsetWriteClassc().
 *
 *    Write an IPset from the SiLK-2 IPTree data structure to 'stream'
 *    in the IPSET_REC_VERSION_CLASSC format.
 *
 *    See '#define IPSET_REC_VERSION_CLASSC' for description of the
 *    file format.
 */
static int
ipsetWriteClasscFromIPTree(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    skIPNode_t *slash16;
    uint32_t slash24;
    uint32_t i;
    uint32_t j;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || !ipset->is_iptree || ipset->is_ipv6) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CLASSC) {
        skAbort();
    }

    for (i = 0; i < SKIP_BBLOCK_COUNT; i++) {
        /* slash16 represents a /16 */
        slash16 = ipset->s.v2->nodes[i];
        if (NULL == slash16) {
            continue;
        }

        /* There is data in this /16, walk over the addressBlocks by
         * 8s, which is equivalent to visiting each /24. */
        for (j = 0; j < SKIP_BBLOCK_SIZE; j += IPTREE_WORDS_PER_SLASH24) {
            if (memcmp(slash16->addressBlock + j,
                       bmap256_zero, sizeof(bmap256_zero)))
            {
                /* there is data in this /24; write the base address. */
                slash24 = ((i << 16) | (j << 5)) & 0xFFFFFF00;
                rv = skStreamWrite(stream, &slash24, sizeof(uint32_t));
                if (rv != sizeof(uint32_t)) {
                    return SKIPSET_ERR_FILEIO;
                }
                /* write the complete /24: 8 uint32_t's */
                rv = skStreamWrite(stream, slash16->addressBlock + j,
                                   sizeof(bmap256_zero));
                if (rv != sizeof(bmap256_zero)) {
                    return SKIPSET_ERR_FILEIO;
                }
            }
        }
    }

    rv = skStreamFlush(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetWriteClasscFromRadixCallbackV4(ipv4, prefix, &state);
 *  status = ipsetWriteClasscFromRadixCallback(ipaddr, prefix, &state);
 *
 *    Callback function used by ipsetWriteClasscFromRadix().
 *
 *    This function is the callback invoked by skIPSetWalk().  When
 *    the current 'ipaddr' and 'prefix' are part of the same /24
 *    contained in 'state'->buffer, the IPs are added to that buffer.
 *    Otherwise, the buffer is printed if it contains data, and then
 *    the buffer is initialized with new data.
 */
static int
ipsetWriteClasscFromRadixCallbackV4(
    uint32_t            ipv4,
    uint32_t            prefix,
    void               *v_state)
{
    ipset_write_silk2_t *state = (ipset_write_silk2_t*)v_state;
    uint32_t slash24;
    uint32_t buf_idx;
    int i;
    ssize_t rv;

    /* get the /24 that holds this IP */
    slash24 = ipv4 & 0xFFFFFF00;

    if (prefix <= 24) {
        /* write the buffer if it contains data */
        if (state->buffer_is_dirty) {
            rv = skStreamWrite(state->stream, state->buffer,
                               sizeof(state->buffer));
            if (rv != sizeof(state->buffer)) {
                return SKIPSET_ERR_FILEIO;
            }
            state->buffer_is_dirty = 0;
        }

        /* initialize the buffer to all-1s */
        memset(state->buffer, 0xff, sizeof(state->buffer));

        /* loop over all /24s in this block and print each one */
        for (i = 0; i < (1 << (24 - prefix)); ++i, slash24 += 256) {
            state->buffer[0] = slash24;

            rv = skStreamWrite(state->stream, state->buffer,
                               sizeof(state->buffer));
            if (rv != sizeof(state->buffer)) {
                return SKIPSET_ERR_FILEIO;
            }
        }

        return SKIPSET_OK;
    }

    if (!state->buffer_is_dirty) {
        /* initialize the block to hold this /24 */
        memset(state->buffer, 0, sizeof(state->buffer));
        state->buffer[0] = slash24;
        state->buffer_is_dirty = 1;
    } else if (state->buffer[0] != slash24) {
        /* the /24s are different---print the block and reset it */
        rv = skStreamWrite(state->stream, state->buffer,sizeof(state->buffer));
        if (rv != sizeof(state->buffer)) {
            return SKIPSET_ERR_FILEIO;
        }
        memset(state->buffer, 0, sizeof(state->buffer));
        state->buffer[0] = slash24;
    }
    /* else data is in the same /24 */

    /* add our IPs to the bitmap */
    buf_idx = 1 + ((ipv4 & 0xFF) >> 5);

    if (prefix <= 27) {
        /* set several uint32_t's */
        memset(&(state->buffer[buf_idx]), 0xff,
               ((1 << (27 - prefix)) * sizeof(uint32_t)));
    } else {
        state->buffer[buf_idx] |= ((UINT32_MAX >> (32 - (1 << (32 - prefix))))
                                   << (ipv4 & 0x1f & (0x1f << (32 - prefix))));
    }

    return SKIPSET_OK;
}

#if SK_ENABLE_IPV6
static int
ipsetWriteClasscFromRadixCallback(
    skipaddr_t         *ipaddr,
    uint32_t            prefix,
    void               *v_state)
{
    uint32_t ipv4;

    /* get the IPv4 address */
    if (skipaddrGetAsV4(ipaddr, &ipv4)) {
        return SKIPSET_ERR_IPV6;
    }
    return ipsetWriteClasscFromRadixCallbackV4(ipv4, prefix, v_state);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  status = ipsetWriteClasscFromRadix(ipset, stream);
 *
 *    Helper function for skIPSetWrite() via ipsetWriteClassc().
 *
 *    Write an IPset from the radix-tree IPset data structure to
 *    'stream' in the IPSET_REC_VERSION_CLASSC format.
 *
 *    See '#define IPSET_REC_VERSION_CLASSC' for description of the
 *    file format.
 */
static int
ipsetWriteClasscFromRadix(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    ipset_write_silk2_t write_state;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || ipset->is_iptree || skIPSetContainsV6(ipset)) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CLASSC) {
        skAbort();
    }

    memset(&write_state, 0, sizeof(write_state));
    write_state.stream = stream;

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        rv = skIPSetWalk(ipset, 1, SK_IPV6POLICY_ASV4,
                         &ipsetWriteClasscFromRadixCallback,
                         (void*)&write_state);
    } else
#endif
    {
        rv = ipsetWalkInternalV4(ipset, ipsetWriteClasscFromRadixCallbackV4,
                                 (void*)&write_state);
    }
    if (rv != 0) {
        return rv;
    }

    if (write_state.buffer_is_dirty) {
        rv = skStreamWrite(stream, write_state.buffer,
                           sizeof(write_state.buffer));
        if (rv != sizeof(write_state.buffer)) {
            return SKIPSET_ERR_FILEIO;
        }
    }

    rv = skStreamFlush(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    return SKIPSET_OK;
}


/*
 *  status = ipsetWriteClassc(&ipset, stream);
 *
 *    Helper function for skIPSetWrite().
 *
 *    Write an IPset to 'stream' in the IPSET_REC_VERSION_CLASSC
 *    format.
 *
 *    This function writes the header then calls another helper
 *    function depending on the data structure being used.
 */
static int
ipsetWriteClassc(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    int rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty || skIPSetContainsV6(ipset)) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_CLASSC) {
        skAbort();
    }

    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    if (ipset->is_iptree) {
        return ipsetWriteClasscFromIPTree(ipset, stream);
    }
    return ipsetWriteClasscFromRadix(ipset, stream);
}


/*
 *  status = ipsetWriteRadix(ipset, stream);
 *
 *    Helper function for skIPSetWrite().
 *
 *    Write an IPset to 'stream' in the IPSET_REC_VERSION_RADIX
 *    format.
 *
 *    See '#define IPSET_REC_VERSION_RADIX' for description of the
 *    file format.
 */
static int
ipsetWriteRadix(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    skipset_t *set3 = NULL;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_RADIX) {
        skAbort();
    }

    /* we must convert the IPTree to a Radix-Tree when writing an
     * IPTree-based IPset to the IPSET_REC_VERSION_RADIX format */
    if (ipset->is_iptree) {
        skipset_iterator_t iter;
        skipaddr_t ipaddr;
        uint32_t prefix;

        /* create a Radix-based IPv4 IPset */
        rv = ipsetCreate(&set3, 0, 1);
        if (rv) {
            goto END;
        }

        /* add the elements from 'ipset' to 'set3' */
        ASSERT_OK(skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_ASV4));
        while (skIPSetIteratorNext(&iter, &ipaddr, &prefix) == SK_ITERATOR_OK){
            rv = ipsetInsertAddressV4(
                set3, skipaddrGetV4(&ipaddr), prefix, NULL);
            if (rv) {
                goto END;
            }
        }
        rv = skIPSetClean(set3);
        if (rv) {
            goto END;
        }

        ipset = set3;
    }

    if (ipset->is_iptree) {
        skAbort();
    }

    /* Add the appropriate header */
    rv = ipsetHentryAddToFile(hdr, IPSET_NUM_CHILDREN,
                              ipset->s.v3->leaves.entry_count,
                              ipset->s.v3->leaves.entry_size,
                              ipset->s.v3->nodes.entry_count,
                              ipset->s.v3->nodes.entry_size,
                              IPSET_ROOT_INDEX(ipset));
    if (rv) {
        skAppPrintErr("%s", skHeaderStrerror(rv));
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }
    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    /* write the arrays */
    if (ipset->s.v3->nodes.entry_count) {
        rv = skStreamWrite(stream, ipset->s.v3->nodes.buf,
                           (ipset->s.v3->nodes.entry_size
                            * ipset->s.v3->nodes.entry_count));
        if ((size_t)rv != (ipset->s.v3->nodes.entry_size
                           * ipset->s.v3->nodes.entry_count))
        {
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
    }
    if (ipset->s.v3->leaves.entry_count) {
        rv = skStreamWrite(stream, ipset->s.v3->leaves.buf,
                           (ipset->s.v3->leaves.entry_size
                            * ipset->s.v3->leaves.entry_count));
        if ((size_t)rv != (ipset->s.v3->leaves.entry_size
                           * ipset->s.v3->leaves.entry_count))
        {
            rv = SKIPSET_ERR_FILEIO;
            goto END;
        }
    }

    rv = skStreamFlush(stream);
    if (rv) {
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    /* success */
    rv = SKIPSET_OK;

  END:
    skIPSetDestroy(&set3);
    return rv;
}


#if SK_ENABLE_IPV6
/*
 *  status = ipsetWriteSlash64(&ipset, stream, hdr);
 *
 *    Helper function for skIPSetWrite().
 *
 *    Write an IPset to 'stream' in the IPSET_REC_VERSION_SLASH64
 *    format.
 *
 *    See '#define IPSET_REC_VERSION_SLASH64' for description of the
 *    file format.
 */
static int
ipsetWriteSlash64(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    skipset_iterator_t iter;
    enum status_en {
        Empty, First_IP, Bitmap
    };
    struct state_st {
        /* starting ip for this netblock bitmap when 'status' is
         * Bitmap, an unmasked IP when 'status' is First_IP, or the
         * start of the outer block when 'outer_written' is set. */
        ipset_ipv6_t    base_ip;
        /* the 256-bit bitmap */
        uint32_t        bmap[IPTREE_WORDS_PER_SLASH24];
        /* the prefix for 'base_ip' when 'status' is First_IP */
        uint8_t         prefix;
        /* what this structure currently holds */
        enum status_en  status;
        /* true when the iterator is exhausted */
        uint8_t         is_last;
    } state;
    /* the bitmap holds 256 bits or a /120 */
    const uint32_t bmap_prefix = 120;
    /* each uint32_t in the bitmap holds a /123 */
    const uint32_t word_prefix = 123;
    uint8_t write_buf[sizeof(uint64_t) + sizeof(uint8_t)];
    ipset_ipv6_t ipv6;
    skipaddr_t ipaddr;
    uint32_t prefix;
    uint32_t buf_idx;
    ssize_t rv;

    /* sanity check input */
    assert(ipset);
    assert(stream);
    if (ipset->is_dirty) {
        skAbort();
    }
    if (ipset->is_iptree) {
        skAbort();
    }
    if (!ipset->is_ipv6) {
        skAbort();
    }
    hdr = skStreamGetSilkHeader(stream);
    if (skHeaderGetRecordVersion(hdr) != IPSET_REC_VERSION_SLASH64) {
        skAbort();
    }

    /* Add the appropriate header */
    rv = ipsetHentryAddToFile(hdr, 0, 0, IPSET_LEN_V6, 0, 0, 0);
    if (rv) {
        skAppPrintErr("%s", skHeaderStrerror(rv));
        return SKIPSET_ERR_FILEIO;
    }
    rv = skStreamWriteSilkHeader(stream);
    if (rv) {
        return SKIPSET_ERR_FILEIO;
    }

    /* get the first IP */
    ASSERT_OK(skIPSetIteratorBind(&iter, ipset, 1, SK_IPV6POLICY_FORCE));
    if (skIPSetIteratorNext(&iter, &ipaddr, &prefix) != SK_ITERATOR_OK) {
        return SKIPSET_OK;
    }
    IPSET_IPV6_FROM_ADDRV6(&ipv6, &ipaddr);

    /* initialize state and ensure base_ip does not match ipv6 */
    memset(&state, 0, sizeof(state));
    state.base_ip.ip[0] = ~ipv6.ip[0];
    state.base_ip.ip[1] = ~ipv6.ip[1];
    state.status = Empty;

    for (;;) {
        if (state.status != Empty
            && (prefix <= bmap_prefix
                || (state.base_ip.ip[0] != ipv6.ip[0])
                || ((state.base_ip.ip[1] ^ ipv6.ip[1]) > 0xFF)))
        {
            /* 'ipv6' is not in the same /120 as 'state'; write the IP
             * or bitmap currently in 'state' */
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
            memcpy(write_buf, &state.base_ip.ip[1], sizeof(uint64_t));
#else
            *(uint64_t *)write_buf = state.base_ip.ip[1];
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */
            write_buf[sizeof(uint64_t)] = ((First_IP == state.status)
                                           ? state.prefix
                                           : SET_CIDRBMAP_MAP256);
            rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
            if (rv != (ssize_t)sizeof(write_buf)) {
                return SKIPSET_ERR_FILEIO;
            }
            if (Bitmap == state.status) {
                /* write the bitmap */
                rv = skStreamWrite(stream, state.bmap, sizeof(state.bmap));
                if (rv != sizeof(state.bmap)) {
                    return SKIPSET_ERR_FILEIO;
                }
            }
            state.status = Empty;
        }

        if (Empty == state.status) {
            if (prefix <= 64) {
                if (state.is_last) {
                    break;
                }
                /* write the upper 64 bits of the IP and prefix */
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
                memcpy(write_buf, &ipv6.ip[0], sizeof(uint64_t));
#else
                *(uint64_t *)write_buf = ipv6.ip[0];
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */
                write_buf[sizeof(uint64_t)] = (uint8_t)prefix;
                rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                if (rv != (ssize_t)sizeof(write_buf)) {
                    return SKIPSET_ERR_FILEIO;
                }
                state.base_ip.ip[0] = ipv6.ip[0];
            } else {
                if (state.base_ip.ip[0] == ipv6.ip[0]) {
                    /* only need to copy lower uint64 */
                    state.base_ip.ip[1] = ipv6.ip[1];
                } else {
                    IPSET_IPV6_COPY(&state.base_ip, &ipv6);
                    /* write the upper 64 bits of the IP */
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
                    memcpy(write_buf, &state.base_ip.ip[0], sizeof(uint64_t));
#else
                    *(uint64_t *)write_buf = state.base_ip.ip[0];
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */
                    write_buf[sizeof(uint64_t)] = SET_SLASH64_IS_SLASH64;
                    rv = skStreamWrite(stream, write_buf, sizeof(write_buf));
                    if (rv != (ssize_t)sizeof(write_buf)) {
                        return SKIPSET_ERR_FILEIO;
                    }
                }
                state.prefix = (uint8_t)prefix;
                state.status = First_IP;
            }
        } else {
            if (First_IP == state.status) {
                /* convert 'state' to hold a bitmap */
                state.status = Bitmap;
                memset(state.bmap, 0, sizeof(state.bmap));

                buf_idx = ((state.base_ip.ip[1] & 0xFF) >> 5);
                if (state.prefix <= word_prefix) {
                    /* prefix spans one or more uint32_t's */
                    memset(&(state.bmap[buf_idx]), 0xff,
                           sizeof(uint32_t) << (word_prefix - state.prefix));
                } else {
                    state.bmap[buf_idx]
                        |= (((1 << (1 << (128 - state.prefix))) - 1)
                            << (state.base_ip.ip[1] & 0x1f));
                }
                /* mask base_ip as a /120 */
                state.base_ip.ip[1]
                    = (state.base_ip.ip[1] & ~UINT64_C(0xFF));
            }
            assert(Bitmap == state.status);
            assert(ipv6.ip[0] == state.base_ip.ip[0]);
            assert((ipv6.ip[1] & ~UINT64_C(0xFF)) == state.base_ip.ip[1]);

            /* add the current IP/prefix to the bitmap */
            buf_idx = ((ipv6.ip[1] & 0xFF) >> 5);
            if (prefix <= word_prefix) {
                /* set several uint32_t's */
                memset(&(state.bmap[buf_idx]), 0xff,
                       (sizeof(uint32_t) << (word_prefix - prefix)));
            } else {
                state.bmap[buf_idx] |= (((1 << (1 << (128 - prefix))) - 1)
                                        << (ipv6.ip[1] & 0x1f));
            }
        }

        /* get the next IP */
        if (skIPSetIteratorNext(&iter, &ipaddr, &prefix) != SK_ITERATOR_OK) {
            prefix = 0;
            state.is_last = 1;
        }
        IPSET_IPV6_FROM_ADDRV6(&ipv6, &ipaddr);
    }

    return SKIPSET_OK;
}
#endif  /* SK_ENABLE_IPV6 */


/* ****  PUBLIC FUNCTION DEFINITIONS BEGIN HERE  **** */

void
skIPSetAutoConvertDisable(
    skipset_t          *ipset)
{
    ipset->no_autoconvert = 1;
}

void
skIPSetAutoConvertEnable(
    skipset_t          *ipset)
{
    ipset->no_autoconvert = 0;
}

int
skIPSetAutoConvertIsEnabled(
    const skipset_t    *ipset)
{
    return !ipset->no_autoconvert;
}


/* Return true if 'ipset' contains 'ipaddr' */
int
skIPSetCheckAddress(
    const skipset_t    *ipset,
    const skipaddr_t   *ipaddr)
{
    uint32_t ipv4;

    if (ipset->is_iptree) {
#if SK_ENABLE_IPV6
        if (skipaddrIsV6(ipaddr)) {
            /* attempt to convert to IPv4 */
            if (skipaddrGetAsV4(ipaddr, &ipv4)) {
                /* conversion failed; this IP is not in the IPSet */
                return 0;
            }
        } else
#endif
        {
            ipv4 = skipaddrGetV4(ipaddr);
        }
        return IPTREE_CHECK_ADDRESS(ipset->s.v2, ipv4);
    }

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipset_ipv6_t ipv6;

        IPSET_IPV6_FROM_ADDRV4(&ipv6, ipaddr);
        return (ipsetFindV6(ipset, &ipv6, 128, NULL) == SKIPSET_OK);
    }
    /* else IPset is IPv4 */

    if (skipaddrIsV6(ipaddr)) {
        if (skipaddrGetAsV4(ipaddr, &ipv4)) {
            /* conversion failed; this IP is not in the IPSet */
            return 0;
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        ipv4 = skipaddrGetV4(ipaddr);
    }

    return (ipsetFindV4(ipset, ipv4, 32, NULL) == SKIPSET_OK);
}


/* Return true if 'ipset1' and 'ipset2' have any IPs in common. */
int
skIPSetCheckIPSet(
    const skipset_t    *ipset1,
    const skipset_t    *ipset2)
{
    const skipset_t *walk_set = NULL;
    const skipset_t *search_set = NULL;
    uint32_t leaf_count1;
    uint32_t leaf_count2;
    int rv = SKIPSET_OK;

    /* check input */
    if (!ipset1 || !ipset2) {
        return 0;
    }

    if (ipset1->is_iptree) {
        if (ipset2->is_iptree) {
            /* both are SiLK-2 IPTrees */
            return ipsetCheckIPSetIPTree(ipset1->s.v2, ipset2->s.v2);
        }

        walk_set = ipset1;
        search_set = ipset2;

    } else if (ipset2->is_iptree) {
        walk_set = ipset2;
        search_set = ipset1;

    } else {
        /* handle trivial case */
        if (IPSET_ISEMPTY(ipset1) || IPSET_ISEMPTY(ipset2)) {
            return 0;
        }

        /*
         *  The current implementation walks over the IPset that has the
         *  fewest leaves asking whether those IPs are in the other IPset.
         *  If we could guarantee that at least one IPset was clean, we
         *  could implement the check similar to how skIPSetIntersect()
         *  works with an iterator and a walker.  This would allow the
         *  code to stop walking one IPset once it knew the other IPset
         *  was out of IPs.
         */

        /* check which set as the fewest number of leaves */
        leaf_count1 = ipsetCountOccupiedLeaves(ipset1);
        leaf_count2 = ipsetCountOccupiedLeaves(ipset2);
        if (leaf_count1 < leaf_count2) {
            walk_set = ipset1;
            search_set = ipset2;
        } else {
            walk_set = ipset2;
            search_set = ipset1;
        }
    }

    /* visit the IPs on the walk_set */
#if SK_ENABLE_IPV6
    if (search_set->is_ipv6) {
        rv = skIPSetWalk(walk_set, 1, SK_IPV6POLICY_FORCE,
                         &ipsetCheckIPSetCallbackV6, (void*)search_set);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        rv = skIPSetWalk(walk_set, 1, SK_IPV6POLICY_ASV4,
                         &ipsetCheckIPSetCallbackV4, (void*)search_set);
    }
    switch (rv) {
      case SKIPSET_OK:
        /* reached end of walk_set with no matches */
        break;

      case SKIPSET_ERR_SUBSET:
        /* found IPs in common */
        return 1;

      default:
        skAbortBadCase(rv);
    }

    return 0;
}


/* Return true if 'ipset' contains any IPs represened by 'ipwild' */
int
skIPSetCheckIPWildcard(
    const skipset_t        *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    skipaddr_t ipaddr;
    uint32_t prefix;

    if (ipset->is_iptree) {
        return ipsetCheckWildcardIPTree(ipset->s.v2, ipwild);
    }

    /* Iterate over the IPs from the wildcard */
#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipset_ipv6_t ipv6;

        skIPWildcardIteratorBindV6(&iter, ipwild);
        if (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
            != SK_ITERATOR_OK)
        {
            return 0;
        }
        if (0 == prefix) {
            /* wildcard was x:x:x:x:x:x:x:x */
            if (!skipaddrIsZero(&ipaddr)) {
                skAppPrintErr("Wildcard iterator bug: prefix == 0 but IP != 0");
                skAbort();
            }
            return !IPSET_ISEMPTY(ipset);
        }

        do {
            assert(0 < prefix && prefix <= 128);
            IPSET_IPV6_FROM_ADDRV6(&ipv6, &ipaddr);
            switch (ipsetFindV6(ipset, &ipv6, prefix, NULL)) {
              case SKIPSET_OK:
              case SKIPSET_ERR_SUBSET:
                return 1;
              default:
                break;
            }
        } while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
                 == SK_ITERATOR_OK);
        /* no intersesction */
        return 0;
    }
    /* else IPset is IPv4 */

    if (skIPWildcardIsV6(ipwild)) {
        /* only visit the ::ffff:0:0/96 netblock and return as IPv4 */
        skIPWildcardIteratorBindV4(&iter, ipwild);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* both wildcard and IPset are IPv4 */
        skIPWildcardIteratorBind(&iter, ipwild);
    }

    if (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
        != SK_ITERATOR_OK)
    {
        return 0;
    }
    assert(!skipaddrIsV6(&ipaddr));
    if (0 == prefix) {
        /* wildcard was x.x.x.x */
        if (!skipaddrIsZero(&ipaddr)) {
            skAppPrintErr("Wildcard iterator bug: prefix == 0 but IP != 0");
            skAbort();
        }
        return !IPSET_ISEMPTY(ipset);
    }

    do {
        assert(prefix <= 32);
        assert(!skipaddrIsV6(&ipaddr));
        switch (ipsetFindV4(ipset, skipaddrGetV4(&ipaddr), prefix, NULL)) {
          case SKIPSET_OK:
          case SKIPSET_ERR_SUBSET:
            return 1;
          default:
            break;
        }
    } while (skIPWildcardIteratorNextCidr(&iter, &ipaddr, &prefix)
             == SK_ITERATOR_OK);
    /* no intersesction */
    return 0;
}


/* Return true if the specified address on 'rwrec' is in the 'ipset' */
int
skIPSetCheckRecord(
    const skipset_t    *ipset,
    const rwRec        *rwrec,
    int                 src_dst_nh)
{
    uint32_t ipv4;

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipset_ipv6_t ipv6;

        switch (src_dst_nh) {
          case 1:
            rwRecMemGetSIPv6(rwrec, &ipv6);
            break;
          case 2:
            rwRecMemGetDIPv6(rwrec, &ipv6);
            break;
          case 4:
            rwRecMemGetNhIPv6(rwrec, &ipv6);
            break;
          default:
            skAbortBadCase(src_dst_nh);
        }
        ipv6.ip[0] = ntoh64(ipv6.ip[0]);
        ipv6.ip[1] = ntoh64(ipv6.ip[1]);

        return (ipsetFindV6(ipset, &ipv6, 128, NULL) == SKIPSET_OK);
    }
    /* else IPset is IPv4 */

    if (rwRecIsIPv6(rwrec)) {
        /* try to handle addresses as IPv4 */
        skipaddr_t ipaddr;

        switch (src_dst_nh) {
          case 1:
            rwRecMemGetSIP(rwrec, &ipaddr);
            break;
          case 2:
            rwRecMemGetDIP(rwrec, &ipaddr);
            break;
          case 4:
            rwRecMemGetNhIP(rwrec, &ipaddr);
            break;
          default:
            skAbortBadCase(src_dst_nh);
        }
        if (skipaddrGetAsV4(&ipaddr, &ipv4)) {
            /* conversion failed; this IP is not in the IPSet */
            return 0;
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* neither IPSet nor rwRec are V6 */
        switch (src_dst_nh) {
          case 1:
            ipv4 = rwRecGetSIPv4(rwrec);
            break;
          case 2:
            ipv4 = rwRecGetDIPv4(rwrec);
            break;
          case 4:
            ipv4 = rwRecGetNhIPv4(rwrec);
            break;
          default:
            skAbortBadCase(src_dst_nh);
        }
    }

    if (ipset->is_iptree) {
        return IPTREE_CHECK_ADDRESS(ipset->s.v2, ipv4);
    }
    return (ipsetFindV4(ipset, ipv4, 32, NULL) == SKIPSET_OK);
}


/* Make the ipset use as few nodes as possible and make sure the ipset
 * uses a contiguous region of memory. */
int
skIPSetClean(
    skipset_t          *ipset)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (ipset->is_iptree) {
        ipset->is_dirty = 0;
        return SKIPSET_OK;
    }
    if (!ipset->is_dirty) {
        return SKIPSET_OK;
    }
    if (0 == ipset->s.v3->nodes.entry_count) {
        skIPSetRemoveAll(ipset);
        ipset->is_dirty = 0;
        return SKIPSET_OK;
    }

    IPSET_COPY_ON_WRITE(ipset);

    if (ipsetVerify(ipset)) {
        return SKIPSET_ERR_CORRUPT;
    }
    ipsetCombineAdjacentCIDR(ipset);
    /* ipsetCompact(ipset); -- ipsetSortLeaves() calles this */
    ipsetSortLeaves(ipset);
    assert(0 == ipsetVerify(ipset));

    ipset->is_dirty = 0;

    return SKIPSET_OK;
}


/* Return true if 'ipset' contains any IPs that cannot be represented
 * as an IPv4 address. */
int
skIPSetContainsV6(
    const skipset_t    *ipset)
{
#if !SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        skAbort();
    }
    return 0;
#else  /* SK_ENABLE_IPV6 */

    if (!ipset->is_ipv6) {
        return 0;
    }
    assert(0 == ipset->is_iptree);
    if (IPSET_ISEMPTY(ipset)) {
        return 0;
    }

    /* For the IPset to containly only IPv4 addresses, the root node
     * must be something like "::ffff:0.0.0.0/96" or more specific,
     * such as "::ffff.10.11.12.0/120" */

    if (IPSET_ROOT_IS_LEAF(ipset)) {
        const ipset_leaf_v6_t *leaf;

        leaf = LEAF_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
        if (leaf->prefix < 96) {
            return 1;
        }
        return (leaf->ip.ip[0] != 0
                || ((leaf->ip.ip[1] >> 32) != 0x0000ffff));

    } else {
        const ipset_node_v6_t *node;

        node = NODE_PTR_V6(ipset, IPSET_ROOT_INDEX(ipset));
        if (node->prefix < 96) {
            return 1;
        }
        return (node->ip.ip[0] != 0
                || ((node->ip.ip[1] >> 32) != 0x0000ffff));
    }
#endif  /* SK_ENABLE_IPV6 */
}


/* Convert 'ipset' to hold IPs of the specific version. */
int
skIPSetConvert(
    skipset_t          *ipset,
    int                 target_ip_version)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

#if !SK_ENABLE_IPV6
    if (4 != target_ip_version) {
        return SKIPSET_ERR_IPV6;
    }
    if (1 == ipset->is_ipv6) {
        skAbort();
    }
    return SKIPSET_OK;

#else  /* SK_ENABLE_IPV6 */

    switch (target_ip_version) {
      case 4:
        if (!ipset->is_ipv6) {
            /* IPset is already IPv4 */
            return SKIPSET_OK;
        }
        if (skIPSetContainsV6(ipset)) {
            /* can't convert when IPv6 addresses are present */
            return SKIPSET_ERR_IPV6;
        }
        break;

      case 6:
        if (ipset->is_ipv6) {
            /* IPset is already IPv6 */
            return SKIPSET_OK;
        }
        break;

      default:
        return SKIPSET_ERR_BADINPUT;
    }

    if (ipset->is_iptree) {
        return ipsetConvertIPTreetoV6(ipset);
    }

    IPSET_COPY_ON_WRITE(ipset);

    /* ensure the tree is compact */
    skIPSetClean(ipset);

    if (ipset->is_ipv6) {
        return ipsetConvertV6toV4(ipset);
    }
    return ipsetConvertV4toV6(ipset);
#endif  /* SK_ENABLE_IPV6 */
}


/* Return number of IPs in the IPset */
uint64_t
skIPSetCountIPs(
    const skipset_t    *ipset,
    double             *count)
{
    ipset_count_t count_state;

    if (!ipset) {
        return 0;
    }
    if (ipset->is_iptree) {
        uint64_t c;

        c = ipsetCountIPTree(ipset->s.v2);
        if (count) {
            *count = (double)c;
        }
        return c;
    }

    memset(&count_state, 0, sizeof(ipset_count_t));

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipsetWalkInternalV6(ipset, ipsetCountCallbackV6, (void*)&count_state);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        ipsetWalkInternalV4(ipset, ipsetCountCallbackV4, (void*)&count_state);
    }

    if (count_state.upper) {
        if (count) {
            *count = ((double)count_state.upper * ((double)UINT64_MAX + 1.0)
                      + (double)count_state.lower);
        }
        return UINT64_MAX;
    }

    if (count) {
        *count = (double)count_state.lower;
    }
    return count_state.lower;
}


/* Fill 'buf' with number of IPs in the set */
char *
skIPSetCountIPsString(
    const skipset_t    *ipset,
    char               *buf,
    size_t              buflen)
{
    uint64_t i_count;
    double   d_count;
    ssize_t sz;

#if SK_ENABLE_IPV6
    if (ipset && ipset->is_ipv6) {
        ipset_count_t count_state;

        memset(&count_state, 0, sizeof(count_state));
        ipsetWalkInternalV6(ipset, ipsetCountCallbackV6, (void*)&count_state);
        return ipsetCountToString(&count_state, buf, buflen);
    }
#endif  /* SK_ENABLE_IPV6 */

    i_count = skIPSetCountIPs(ipset, &d_count);
    if (i_count == UINT64_MAX) {
        sz = snprintf(buf, buflen, ("%.0f"), d_count);
    } else {
        sz = snprintf(buf, buflen, ("%" PRIu64), i_count);
    }
    if ((size_t)sz >= buflen) {
        return NULL;
    }
    return buf;
}


/* Create a new IPset */
int
skIPSetCreate(
    skipset_t         **ipset,
    int                 support_ipv6)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

#if !SK_ENABLE_IPV6
    if (support_ipv6) {
        return SKIPSET_ERR_IPV6;
    }
#endif  /* SK_ENABLE_IPV6 */

    if (IPSET_USE_IPTREE) {
        return ipsetCreate(ipset, support_ipv6, 0);
    }
    return ipsetCreate(ipset, support_ipv6, 1);
}


/* Destroy an IPset. */
void
skIPSetDestroy(
    skipset_t         **ipset)
{
    if (!ipset || !*ipset) {
        return;
    }

    if ((*ipset)->is_iptree) {
        ipsetDestroyIPTree((*ipset)->s.v2);
        free(*ipset);
        *ipset = NULL;
        return;
    }

    if (getenv(IPSET_ENVAR_DESTROY_PRINT)) {
        skIPSetDebugPrint(*ipset);
    }

    if ((*ipset)->s.v3->mapped_file) {
        munmap((*ipset)->s.v3->mapped_file, (*ipset)->s.v3->mapped_size);
        (*ipset)->s.v3->mapped_file = NULL;
        (*ipset)->s.v3->mapped_size = 0;
    } else {
        skIPSetRemoveAll(*ipset);
        if ((*ipset)->s.v3->nodes.buf) {
            free((*ipset)->s.v3->nodes.buf);
            (*ipset)->s.v3->nodes.buf = NULL;
            (*ipset)->s.v3->nodes.entry_count = 0;
        }
        if ((*ipset)->s.v3->leaves.buf) {
            free((*ipset)->s.v3->leaves.buf);
            (*ipset)->s.v3->leaves.buf = NULL;
            (*ipset)->s.v3->leaves.entry_count = 0;
        }
    }

    free((*ipset)->s.v3);
    free(*ipset);
    *ipset = NULL;
}


/* Insert the IP address into the IPset. */
int
skIPSetInsertAddress(
    skipset_t          *ipset,
    const skipaddr_t   *ipaddr,
    uint32_t            prefix)
{
    ipset_find_t find_state;
    uint32_t ipv4;
    int rv;

#if  SK_ENABLE_IPV6
    /* handle auto-conversion */
    if (skipaddrIsV6(ipaddr) && !ipset->is_ipv6) {
        if (skipaddrGetAsV4(ipaddr, &ipv4)
            || (prefix <= 96 && 0 != prefix))
        {
            /* cannot convert IPv6 address to IPv4 */
            if (ipset->no_autoconvert) {
                return SKIPSET_ERR_IPV6;
            }
            rv = skIPSetConvert(ipset, 6);
            if (rv) {
                return rv;
            }
        }
    }

    if (ipset->is_ipv6) {
        ipset_ipv6_t ipv6;

        if (skipaddrIsV6(ipaddr)) {
            /* both set and address are V6 */
            IPSET_IPV6_FROM_ADDRV6(&ipv6, ipaddr);
            if (128 == prefix) {
                /* no-op */
            } else if (0 == prefix) {
                prefix = 128;
            } else if (prefix > 128) {
                return SKIPSET_ERR_PREFIX;
            } else {
                IPSET_IPV6_APPLY_CIDR(&ipv6, prefix);
            }
        } else {
            /* set is V6 and address is V4 */
            IPSET_IPV6_FROM_ADDRV4(&ipv6, ipaddr);
            if (0 == prefix || 32 == prefix) {
                prefix = 128;
            } else if (prefix > 32) {
                return SKIPSET_ERR_PREFIX;
            } else {
                prefix += 96;
                /* apply mask */
                IPSET_IPV6_APPLY_CIDR(&ipv6, prefix);
            }
        }
        rv = ipsetFindV6(ipset, &ipv6, prefix, &find_state);
        if (SKIPSET_OK == rv) {
            return rv;
        }
        IPSET_COPY_ON_WRITE(ipset);
        rv = ipsetInsertAddressV6(ipset, &ipv6, prefix, &find_state);
        if (rv) {
            return rv;
        }
        IPSET_MAYBE_COMBINE(ipset);
        return rv;
    }

    /* To get here, IPset must be IPv4 */
    if (skipaddrIsV6(ipaddr)) {
        /* set is V4 and address is V6 */
        /* attempt to convert V6 ipaddr to V4 */
        if (skipaddrGetAsV4(ipaddr, &ipv4)) {
            /* cannot store V6 ipaddr in a V4 IPSet */
            return SKIPSET_ERR_IPV6;
        }
        if (0 == prefix || 128 == prefix) {
            prefix = 32;
        } else if (prefix > 128) {
            return SKIPSET_ERR_PREFIX;
        } else if (prefix <= 96) {
            return SKIPSET_ERR_IPV6;
        } else {
            prefix -= 96;
            /* apply mask */
            ipv4 &= ~(UINT32_MAX >> prefix);
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* both set and address are V4 */
        ipv4 = skipaddrGetV4(ipaddr);
        if (prefix == 32) {
            /* no-op */
        } else if (0 == prefix) {
            prefix = 32;
        } else if (prefix > 32) {
            return SKIPSET_ERR_PREFIX;
        } else {
            /* apply mask */
            ipv4 &= ~(UINT32_MAX >> prefix);
        }
    }

    if (ipset->is_iptree) {
        ipset->is_dirty = 1;
        return ipsetInsertAddressIPTree(ipset->s.v2, ipv4, prefix);
    }

    rv = ipsetFindV4(ipset, ipv4, prefix, &find_state);
    if (SKIPSET_OK == rv) {
        return rv;
    }
    IPSET_COPY_ON_WRITE(ipset);
    rv = ipsetInsertAddressV4(ipset, ipv4, prefix, &find_state);
    if (rv) {
        return rv;
    }
    IPSET_MAYBE_COMBINE(ipset);
    return rv;
}


/* Add each IP in the IPWildcard to the IPset. */
int
skIPSetInsertIPWildcard(
    skipset_t              *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    skipaddr_t ip;
    uint32_t prefix;
    int rv = SKIPSET_OK;

#if  SK_ENABLE_IPV6
    /* handle auto-conversion */
    if (skIPWildcardIsV6(ipwild) && !ipset->is_ipv6) {
        if (ipset->no_autoconvert) {
            return SKIPSET_ERR_IPV6;
        }
        rv = skIPSetConvert(ipset, 6);
        if (rv) {
            return rv;
        }
    }
#endif  /* SK_ENABLE_IPV6 */

    if (ipset->is_iptree) {
        ipset->is_dirty = 1;

        return ipsetInsertWildcardIPTree(ipset->s.v2, ipwild);
    }

    /* Insert the netblocks contained in the wildcard */
#if  SK_ENABLE_IPV6
    if (ipset->is_ipv6 && !skIPWildcardIsV6(ipwild)) {
        skIPWildcardIteratorBindV6(&iter, ipwild);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        skIPWildcardIteratorBind(&iter, ipwild);
    }

    if (skIPWildcardIteratorNextCidr(&iter, &ip, &prefix)
        != SK_ITERATOR_OK)
    {
        return rv;
    }
    if (0 == prefix) {
        /* wildcard was x.x.x.x or x:x:x:x:x:x:x:x */
        if (!skipaddrIsZero(&ip)) {
            skAppPrintErr("Wildcard iterator bug: prefix == 0 but IP != 0");
            skAbort();
        }
        /* code thinks prefix of 0 means "default", so must insert two
         * CIDR blocks of prefix 1 */
        prefix = 1;
        rv = skIPSetInsertAddress(ipset, &ip, prefix);
        if (rv) { return rv; }
        skCIDRComputeEnd(&ip, prefix, &ip);
        skipaddrIncrement(&ip);
        return skIPSetInsertAddress(ipset, &ip, prefix);
    }

    /* it would be more efficient to inline skIPSetInsertAddress()
     * here; but often there is only one CIDR block in a wildcard */
    do {
        rv = skIPSetInsertAddress(ipset, &ip, prefix);
    } while (skIPWildcardIteratorNextCidr(&iter, &ip, &prefix)==SK_ITERATOR_OK
             && SKIPSET_OK == rv);

    return rv;
}


int
skIPSetInsertRange(
    skipset_t          *ipset,
    const skipaddr_t   *ipaddr_start,
    const skipaddr_t   *ipaddr_end)
{
    skipaddr_t this_start;
    skipaddr_t next_start;
    uint32_t prefix;
    int rv;

    rv = skipaddrCompare(ipaddr_start, ipaddr_end);
    if (rv > 0) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (0 == rv) {
        /* single ip */
        return skIPSetInsertAddress(ipset, ipaddr_start, 0);
    }

    if (ipset->is_iptree) {
#if !SK_ENABLE_IPV6
        return ipsetInsertRangeIPTree(ipset, ipaddr_start, ipaddr_end);
#else
        if (!skipaddrIsV6(ipaddr_start) && !skipaddrIsV6(ipaddr_end)) {
            return ipsetInsertRangeIPTree(ipset, ipaddr_start, ipaddr_end);
        }
        if (ipset->no_autoconvert) {
            return SKIPSET_ERR_IPV6;
        }
        rv = ipsetConvertIPTreetoV6(ipset);
        if (rv) {
            return rv;
        }
#endif  /* #else of #if !SK_ENABLE_IPV6 */
    }

    /* get a modifiable version of the beginning IP */
    skipaddrCopy(&this_start, ipaddr_start);

    do {
        prefix = skCIDRComputePrefix(&this_start, ipaddr_end, &next_start);
        rv = skIPSetInsertAddress(ipset, &this_start, prefix);
        if (rv) {
            return rv;
        }
        skipaddrCopy(&this_start, &next_start);
    } while (!skipaddrIsZero(&this_start));

    return SKIPSET_OK;
}


/* Make 'result_ipset' hold the intersection of itself with 'ipset' */
int
skIPSetIntersect(
    skipset_t          *result_ipset,
    const skipset_t    *ipset)
{
    ipset_intersect_t state;
    uint32_t prefix;
    skipaddr_t tmp_ip;
    int rv = SKIPSET_OK;
    int i;

    /* check input */
    if (!result_ipset || !ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

    if (result_ipset->is_iptree && ipset->is_iptree) {
        /* both are in the SiLK-2 format (IPTree) */
        result_ipset->is_dirty = 1;
        ipsetIntersectIPTree(result_ipset->s.v2, ipset->s.v2);
        return SKIPSET_OK;
    }

    /* handle trivial cases */
    if (!result_ipset->is_iptree && IPSET_ISEMPTY(result_ipset)) {
        return SKIPSET_OK;
    }
    if (!ipset->is_iptree && IPSET_ISEMPTY(ipset)) {
        skIPSetRemoveAll(result_ipset);
        return SKIPSET_OK;
    }

    /* ensure we can use the iterator for the result_ipset */
    if (result_ipset->is_dirty) {
        skIPSetClean(result_ipset);
    }

    /* clear memory */
    memset(&state, 0, sizeof(ipset_intersect_t));

    /* create a vector to hold the blocks that the two IPsets have in
     * common; after visiting the IPsets, the result_ipset will be
     * updated with the IPs in this vector */
    state.vec_add = skVectorNew(sizeof(state.addr));
    if (NULL == state.vec_add) {
        return SKIPSET_ERR_ALLOC;
    }

    /* bind the iterator for the result_ipset, get its first CIDR
     * block, and convert the block to start and end IPs */
    ASSERT_OK(skIPSetIteratorBind(
                  &state.iter, result_ipset, 1, SK_IPV6POLICY_MIX));
    if (skIPSetIteratorNext(&state.iter, &state.addr[0], &prefix)
        != SK_ITERATOR_OK)
    {
        skIPSetRemoveAll(result_ipset);
        goto END;
    }
    skCIDR2IPRange(&state.addr[0], prefix, &state.addr[0], &state.addr[1]);

    /* visit the IPs on the ipset */
    rv = skIPSetWalk(ipset, 1, (result_ipset->is_ipv6
                                ? SK_IPV6POLICY_FORCE : SK_IPV6POLICY_MIX),
                     ipsetIntersectCallback, (void*)&state);
    if (SKIPSET_ERR_ALLOC == rv) {
        goto END;
    }
    rv = SKIPSET_OK;

    /* remove all IPs from the result IPset */
    skIPSetRemoveAll(result_ipset);

    /* loop over the start_addr/final_addr IP pairs in the vec_add
     * vector, convert them to CIDR blocks, and add them to the result
     * IPset. */
    for (i = 0; (0 == skVectorGetValue(state.addr, state.vec_add, i)); ++i) {
        do {
            prefix = skCIDRComputePrefix(&state.addr[0], &state.addr[1],
                                         &tmp_ip);
            rv = skIPSetInsertAddress(result_ipset, &state.addr[0], prefix);
            if (rv != SKIPSET_OK) {
                goto END;
            }
            skipaddrCopy(&state.addr[0], &tmp_ip);
        } while (!skipaddrIsZero(&tmp_ip));
    }

  END:
    if (state.vec_add) {
        skVectorDestroy(state.vec_add);
    }
    return rv;
}


/* Return true if 'ipset' can hold IPv6 addresses */
int
skIPSetIsV6(
    const skipset_t    *ipset)
{
    return ipset->is_ipv6;
}


/* Bind the iterator to an IPset */
int
skIPSetIteratorBind(
    skipset_iterator_t *iter,
    const skipset_t    *ipset,
    uint32_t            cidr_blocks,
    sk_ipv6policy_t     v6_policy)
{
    if (!ipset || !iter) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (ipset->is_dirty && !ipset->is_iptree) {
        return SKIPSET_ERR_REQUIRE_CLEAN;
    }

    memset(iter, 0, sizeof(skipset_iterator_t));
    iter->ipset = ipset;
    iter->v6policy = v6_policy;
    iter->cidr_blocks = (cidr_blocks ? 1 : 0);
    iter->is_iptree = ipset->is_iptree;

    if (iter->is_iptree) {
        iter->it.v2.tree = ipset->s.v2;
    }
    skIPSetIteratorReset(iter);

    return 0;
}


/* Return the next CIDR block associated with the IPset */
int
skIPSetIteratorNext(
    skipset_iterator_t *iter,
    skipaddr_t         *ipaddr,
    uint32_t           *prefix)
{
    ipset_leaf_v4_t *leaf4;
    uint32_t ipv4;

    if (iter->is_iptree) {
        return ipsetIteratorNextIPTree(iter, ipaddr, prefix);
    }

    if (iter->it.v3.cur >= iter->ipset->s.v3->leaves.entry_count) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    assert(0 == iter->ipset->is_dirty);

#if SK_ENABLE_IPV6
    if (iter->ipset->is_ipv6) {
        ipset_leaf_v6_t *leaf6;
        ipset_ipv6_t *ipv6;
        ipset_ipv6_t *fin6;

        if (iter->cidr_blocks) {
            leaf6 = LEAF_PTR_V6(iter->ipset, iter->it.v3.cur);
            if (SK_IPV6POLICY_ASV4 == iter->v6policy) {
                /* check stopping condition */
                if (leaf6->ip.ip[0] != 0
                    || ((UINT64_C(0xffffffff00000000) & leaf6->ip.ip[1])
                        != UINT64_C(0x0000ffff00000000)))
                {
                    iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
                    return SK_ITERATOR_NO_MORE_ENTRIES;
                }
                IPSET_IPV6_TO_ADDR_V4(&leaf6->ip, ipaddr);
                *prefix = leaf6->prefix - 96;
            } else {
                IPSET_IPV6_TO_ADDR(&leaf6->ip, ipaddr);
                *prefix = leaf6->prefix;
            }
            ++iter->it.v3.cur;

        } else {
            /* return value is value on the iterator */
            ipv6 = (ipset_ipv6_t*)&iter->it.v3.data[0];
            fin6 = (ipset_ipv6_t*)&iter->it.v3.data[2];
            if (SK_IPV6POLICY_ASV4 == iter->v6policy) {
                IPSET_IPV6_TO_ADDR_V4(ipv6, ipaddr);
                *prefix = 32;
            } else {
                IPSET_IPV6_TO_ADDR(ipv6, ipaddr);
                *prefix = 128;
            }

            /* point iterator at next value */
            if (ipv6->ip[1] < fin6->ip[1]) {
                ++ipv6->ip[1];
            } else if (ipv6->ip[0] < fin6->ip[0]) {
                if (ipv6->ip[1] == UINT64_MAX) {
                    ++ipv6->ip[0];
                    ipv6->ip[1] = 0;
                } else {
                    ++ipv6->ip[1];
                }
            } else {
                ++iter->it.v3.cur;
                if (iter->it.v3.cur < iter->ipset->s.v3->leaves.entry_count) {
                    ipsetIteratorNextRangeV6(iter);
                }
            }
        }
        return SK_ITERATOR_OK;
    }

    if (SK_IPV6POLICY_FORCE == iter->v6policy) {
        if (iter->cidr_blocks) {
            leaf4 = LEAF_PTR_V4(iter->ipset, iter->it.v3.cur);
            skipaddrSetV6FromUint32(ipaddr, &leaf4->ip);
            *prefix = 96 + leaf4->prefix;
            ++iter->it.v3.cur;

        } else {
            /* return value is value on the iterator */
            ipv4 = (uint32_t)iter->it.v3.data[0];
            skipaddrSetV6FromUint32(ipaddr, &ipv4);
            *prefix = 128;

            /* point iterator at next value */
            if (iter->it.v3.data[0] < iter->it.v3.data[2]) {
                ++iter->it.v3.data[0];
            } else {
                ++iter->it.v3.cur;
                if (iter->it.v3.cur < iter->ipset->s.v3->leaves.entry_count) {
                    ipsetIteratorNextRangeV4(iter);
                }
            }
        }
        return SK_ITERATOR_OK;
    }
#endif  /* SK_ENABLE_IPV6 */

    if (iter->cidr_blocks) {
        leaf4 = LEAF_PTR_V4(iter->ipset, iter->it.v3.cur);
        skipaddrSetV4(ipaddr, &leaf4->ip);
        *prefix = leaf4->prefix;
        ++iter->it.v3.cur;

    } else {
        /* return value is value on the iterator */
        ipv4 = (uint32_t)iter->it.v3.data[0];
        skipaddrSetV4(ipaddr, &ipv4);
        *prefix = 32;

        /* point iterator at next value */
        if (iter->it.v3.data[0] < iter->it.v3.data[2]) {
            ++iter->it.v3.data[0];
        } else {
            ++iter->it.v3.cur;
            if (iter->it.v3.cur < iter->ipset->s.v3->leaves.entry_count) {
                ipsetIteratorNextRangeV4(iter);
            }
        }
    }

    return SK_ITERATOR_OK;
}


/* Reset iterator so we can visit the IPs again */
void
skIPSetIteratorReset(
    skipset_iterator_t *iter)
{
    assert(iter);

    if (iter->is_iptree) {
        if (SK_IPV6POLICY_ONLY == iter->v6policy) {
            iter->it.v2.top_16 = SKIP_BBLOCK_COUNT;
            return;
        }

        iter->it.v2.count = 0;
        iter->it.v2.trail_zero = 0;
        iter->it.v2.base_ip = 0;
        iter->it.v2.top_16 = 0;
        iter->it.v2.mid_11 = 0;
        iter->it.v2.bot_5 = 0;
        ipsetIteratorIPTreeNextSlash27(iter);
        return;
    }

    iter->it.v3.cur = IPSET_ITER_FIRST_LEAF;
    if (IPSET_ISEMPTY(iter->ipset)) {
        return;
    }

#if SK_ENABLE_IPV6
    if (iter->ipset->is_ipv6) {
        if (iter->v6policy == SK_IPV6POLICY_IGNORE) {
            /* caller wants only IPv4 addresses, and there are none in
             * an IPv6 IPset. */
            iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
            return;
        }
        if (iter->v6policy == SK_IPV6POLICY_ASV4) {
            /* find the left-most leaf under ::ffff:0:0/96 */
            ipset_find_t find_state;
            ipset_ipv6_t ipv6;
            const ipset_node_v6_t *node;
            uint32_t i;
            int rv;

            ipv6.ip[0] = 0;
            ipv6.ip[1] = UINT64_C(0xffff00000000);

            rv = ipsetFindV6(iter->ipset, &ipv6, 96, &find_state);
            if (SKIPSET_OK != rv && SKIPSET_ERR_SUBSET != rv) {
                /* no IPv4 addresses in the IPset */
                iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
                return;
            }

            if (find_state.node_is_leaf) {
                iter->it.v3.cur = find_state.node_idx;
            } else {
                node = NODE_PTR_V6(iter->ipset, find_state.node_idx);
                for (;;) {
                    for (i=0; i < IPSET_NUM_CHILDREN && !node->child[i]; ++i)
                        ;       /* empty */
                    if (NODEPTR_CHILD_IS_LEAF(node, i)) {
                        iter->it.v3.cur = node->child[i];
                        break;
                    }
                    node = NODE_PTR_V6(iter->ipset, node->child[i]);
                }
            }
        }
        assert(iter->it.v3.cur < iter->ipset->s.v3->leaves.entry_count);
        if (!iter->cidr_blocks) {
            ipsetIteratorNextRangeV6(iter);
        }
        return;
    }
    /* else, IPset contains IPv4 addresses */

    if (iter->v6policy == SK_IPV6POLICY_ONLY) {
        /* caller wants only IPv6 addresses, and there are none in an
         * IPv4 IPset. */
        iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
        return;
    }

#else  /* #if SK_ENABLE_IPV6 */

    if (iter->v6policy > SK_IPV6POLICY_MIX) {
        /* caller wants IPv6 addresses, which are not supported in
         * IPv4-only SiLK. */
        iter->it.v3.cur = iter->ipset->s.v3->leaves.entry_count;
        return;
    }

#endif  /* #else of #if SK_ENABLE_IPV6 */

    assert(iter->it.v3.cur < iter->ipset->s.v3->leaves.entry_count);
    if (!iter->cidr_blocks) {
        ipsetIteratorNextRangeV4(iter);
    }
}


/* Read IPSet from filename---a wrapper around skIPSetRead(). */
int
skIPSetLoad(
    skipset_t         **ipset,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int rv;

    if (filename == NULL || ipset == NULL) {
        return -1;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIPSET_ERR_OPEN;
        goto END;
    }

    rv = skIPSetRead(ipset, stream);
    if (rv) {
        goto END;
    }

  END:
    skStreamDestroy(&stream);
    return rv;
}


/* For each occupied block of size 'mask_prefix', set a single IP. */
int
skIPSetMask(
    skipset_t          *ipset,
    uint32_t            mask_prefix)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        /* verify mask_prefix value is valid */
        if (mask_prefix >= 128 || mask_prefix == 0) {
            return SKIPSET_ERR_PREFIX;
        }

        if (IPSET_ISEMPTY(ipset)) {
            return SKIPSET_OK;
        }
        IPSET_COPY_ON_WRITE(ipset);

        return ipsetMaskV6(ipset, mask_prefix);
    }
#endif  /* SK_ENABLE_IPV6 */

    /* verify mask_prefix value is valid */
    if (mask_prefix >= 32 || mask_prefix == 0) {
        return SKIPSET_ERR_PREFIX;
    }

    if (ipset->is_iptree) {
        ipset->is_dirty = 1;
        return ipsetMaskIPTree(ipset->s.v2, mask_prefix);
    }

    if (IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }
    IPSET_COPY_ON_WRITE(ipset);

    return ipsetMaskV4(ipset, mask_prefix);
}


/* For each occupied block of size 'mask_prefix', set all IPs. */
int
skIPSetMaskAndFill(
    skipset_t          *ipset,
    uint32_t            mask_prefix)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        /* verify mask_prefix value is valid */
        if (mask_prefix >= 128 || mask_prefix == 0) {
            return SKIPSET_ERR_PREFIX;
        }

        if (IPSET_ISEMPTY(ipset)) {
            return SKIPSET_OK;
        }
        IPSET_COPY_ON_WRITE(ipset);

        return ipsetMaskAndFillV6(ipset, mask_prefix);
    }
#endif  /* SK_ENABLE_IPV6 */

    /* verify mask_prefix value is valid */
    if (mask_prefix >= 32 || mask_prefix == 0) {
        return SKIPSET_ERR_PREFIX;
    }

    if (ipset->is_iptree) {
        return ipsetMaskAndFillIPTree(ipset, mask_prefix);
    }

    if (IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }
    IPSET_COPY_ON_WRITE(ipset);

    return ipsetMaskAndFillV4(ipset, mask_prefix);
}


/* Set the parameters to use when writing an IPset */
void
skIPSetOptionsBind(
    skipset_t                  *ipset,
    const skipset_options_t    *set_options)
{
    assert(ipset);

    ipset->options = set_options;
}


/* Initialize 'ipset_opts' and register options */
int
skIPSetOptionsRegister(
    skipset_options_t  *ipset_opts)
{
    assert(ipset_opts);
    assert(sizeof(ipset_options)/sizeof(struct option)
           == sizeof(ipset_options_help)/sizeof(char*));

    if (skIPSetOptionsRegisterRecordVersion(ipset_opts, NULL)) {
        return -1;
    }

    if (skOptionsRegister(ipset_options, ipsetOptionsHandler,
                          (clientData)ipset_opts)
        || skOptionsNotesRegister(ipset_opts->existing_silk_files
                                  ? &ipset_opts->note_strip
                                  : NULL)
        || skCompMethodOptionsRegister(&ipset_opts->comp_method))
    {
        return -1;
    }
    return 0;
}


int
skIPSetOptionsRegisterRecordVersion(
    skipset_options_t  *ipset_opts,
    const char         *option_name)
{
    const char *envar;
    uint32_t tmp32 = 0;

    assert(ipset_opts);

    if (ipset_options_record_version[0].name) {
        skAppPrintErr("skIPSetOptionsRegister called multiple times");
        return -1;
    }

    /* set default record version */
    ipset_opts->record_version = IPSET_REC_VERSION_DEFAULT;
    ipset_opts->invocation_strip = 0;
    ipset_opts->comp_method = 0;
    ipset_opts->note_strip = 0;

    /* use the environment to override the default version */
    envar = getenv(IPSET_REC_VERSION_ENVAR);
    if (envar
        && 0 == skStringParseUint32(&tmp32, envar, IPSET_REC_VERSION_MIN,
                                    IPSET_REC_VERSION_MAX)
        && 1 != tmp32)
    {
        ipset_opts->record_version = (uint16_t)tmp32;
    }

    /* set name of record-version option */
    if (NULL == option_name) {
        ipset_options_record_version[0].name
            = strdup(ipset_options_record_version_default_name);
    } else {
        ipset_options_record_version[0].name = strdup(option_name);
    }
    if (NULL == ipset_options_record_version[0].name) {
        skAppPrintOutOfMemory("strdup");
        return -1;
    }

    if (skOptionsRegister(ipset_options_record_version, ipsetOptionsHandler,
                          (clientData)ipset_opts))
    {
        free((void*)ipset_options_record_version[0].name);
        ipset_options_record_version[0].name = NULL;
        return -1;
    }
    return 0;
}


/* Clean up memory used by the IPset options */
void
skIPSetOptionsTeardown(
    void)
{
    free((void*)ipset_options_record_version[0].name);
    ipset_options_record_version[0].name = NULL;
    skOptionsNotesTeardown();
}


/* Print the usage strings for the options that the library registers */
void
skIPSetOptionsUsage(
    FILE               *fh)
{
    unsigned int i;

    skIPSetOptionsUsageRecordVersion(fh);

    for (i = 0; ipset_options[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n",
                ipset_options[i].name, SK_OPTION_HAS_ARG(ipset_options[i]),
                ipset_options_help[i]);
    }
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
}

void
skIPSetOptionsUsageRecordVersion(
    FILE               *fh)
{
    if (NULL == ipset_options_record_version[0].name) {
        return;
    }
    fprintf(fh, ("--%s %s. Specify version when writing IPset records.\n"),
            ipset_options_record_version[0].name,
            SK_OPTION_HAS_ARG(ipset_options_record_version[0]));
    fprintf(fh, ("\t0 - Default."
                 " Uses %d for IPv4 IPsets and %d for IPv6 IPsets.\n"),
            IPSET_REC_VERSION_DEFAULT_IPV4, IPSET_REC_VERSION_DEFAULT_IPV6);
    fprintf(fh, ("\t2 - Stores IPv4 only (error if IPv6)."
                 " Available in all releases.\n"));
    fprintf(fh, ("\t3 - Stores IPv4 or IPv6. Available since SiLK 3.0.\n"));
    fprintf(fh, ("\t4 - Stores IPv4 or IPv6. Available since SiLK 3.7.\n"));
    fprintf(fh, ("\t5 - Stores IPv6 only (uses 4 for IPv4)."
                 " Available since SiLK 3.14.\n"));
}


/* Print the IPs in ipset to 'stream'. */
void
skIPSetPrint(
    const skipset_t    *ipset,
    skstream_t         *stream,
    skipaddr_flags_t    ip_format,
    int                 as_cidr)
{
    ipset_print_t print_state;

    print_state.ipset = ipset;
    print_state.stream = stream;
    print_state.ip_format = ip_format;

    skIPSetWalk(ipset, (as_cidr ? 1 : 0), SK_IPV6POLICY_MIX,
                &ipsetPrintCallback, (void*)&print_state);
}


/*
 *  ipsetDebugPrintAddrV4(ip, prefix);
 *  ipsetDebugPrintAddrV6(ip, prefix);
 *
 *    Helper functions for the various skIPSetDebugPrint*() functions
 *    to print an IP address and its prefix.
 */
static void
ipsetDebugPrintAddrV4(
    uint32_t            ipv4,
    uint32_t            prefix)
{
    int i;

    /* print IP (2 ways) */
    for (i = 24; i >= 0; i -= 8) {
        fprintf(stderr, "%02x%c",
                0xFF & (ipv4 >> i), (i ? '.' : '/'));
    }
    fprintf(stderr, "%2u [", prefix);
    for (i = 24; i >= 0; i -= 8) {
        fprintf(stderr, "%3d%c",
                0xFF & (ipv4 >> i), (i ? '.' : '/'));
    }
    fprintf(stderr, "%2u]", prefix);
}

#if SK_ENABLE_IPV6
static void
ipsetDebugPrintAddrV6(
    const ipset_ipv6_t *ipv6,
    uint32_t            prefix)
{
    uint32_t i;
    uint32_t j;

    /* print IP */
    fprintf(stderr, "[");
    for (j = 0; j < 2; ++j) {
        for (i = 48; i > 0; i -= 16) {
            fprintf(stderr, ("%4" PRIx64 ":"),
                    0xFFFF & (ipv6->ip[j] >> i));
        }
        fprintf(stderr, ("%4" PRIx64 "%c"),
                (0xFFFF & ipv6->ip[j]), (j ? '/' : ':'));
    }
    fprintf(stderr, "%3u]", prefix);
}
#endif  /* SK_ENABLE_IPV6 */


/*
 *  ipsetDebugPrintChildren(node, width);
 *
 *    A helper function for the various skIPSetDebugPrint*()
 *    functions.  This function takes a node and prints the indexes of
 *    the children that the node points to.
 */
static void
ipsetDebugPrintChildren(
    const ipset_node_t *node,
    int                 width)
{
    uint32_t i;

    /* print children's IDs, followed by N for node, L for
     * leaf, or R for repeated leaf */
    for (i = 0; i < IPSET_NUM_CHILDREN; ++i) {
        if (0 == node->v4.child[i]) {
            fprintf(stderr, " %*c ", width, '-');
        } else {
            fprintf(stderr, " %*u%c",
                    width, node->v4.child[i],
                    (!NODEPTR_CHILD_IS_LEAF(&node->v4, i)
                     ? 'N'
                     : (NODEPTR_CHILD_IS_REPEAT(&node->v4, i)
                        ? 'R' : 'L')));
        }
    }
}


/*
 *  ipsetDebugPrintLeaf(ipset, leaf);
 *
 *    Print the IP address on a leaf.
 */
static void
ipsetDebugPrintLeaf(
    const skipset_t    *ipset,
    const ipset_leaf_t *leaf)
{
    if (ipset->is_ipv6) {
#if SK_ENABLE_IPV6
        ipsetDebugPrintAddrV6(&leaf->v6.ip, leaf->v6.prefix);
#endif  /* SK_ENABLE_IPV6 */
        fprintf(stderr, "\n");
    } else {
        ipsetDebugPrintAddrV4(leaf->v4.ip, leaf->v4.prefix);
        fprintf(stderr, "\n");
    }
}


/*
 *  ipsetDebugPrintNode(ipset, node);
 *
 *    Print the IP address and child values from a node.
 */
static void
ipsetDebugPrintNode(
    const skipset_t    *ipset,
    const ipset_node_t *node)
{
    int width = 0;

    if (ipset->s.v3->leaves.entry_count) {
        width = 2 + (int)log10(ipset->s.v3->leaves.entry_count);
    }

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipsetDebugPrintAddrV6(&node->v6.ip, node->v6.prefix);
        fprintf(stderr, "  ");
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        ipsetDebugPrintAddrV4(node->v4.ip, node->v4.prefix);
        fprintf(stderr, "  ");
    }

    ipsetDebugPrintChildren(node, width);

    fprintf(stderr, "\n");
}


/*
 *  ipsetDebugPrintByIndex(ipset, node_idx, is_leaf);
 *
 *    Print information about a node or a leaf whose index is
 *    'node_idx'.
 */
static void
ipsetDebugPrintByIndex(
    const skipset_t    *ipset,
    uint32_t            node_idx,
    int                 is_leaf)
{
    if (is_leaf) {
        if (node_idx < ipset->s.v3->leaves.entry_count) {
            ipsetDebugPrintLeaf(ipset, LEAF_PTR(ipset, node_idx));
        } else {
            fprintf(stderr, "%" PRIu32 "L is too large\n", node_idx);
        }
    } else {
        if (node_idx < ipset->s.v3->nodes.entry_count) {
            ipsetDebugPrintNode(ipset, NODE_PTR(ipset, node_idx));
        } else {
            fprintf(stderr, "%" PRIu32 "N is too large\n", node_idx);
        }
    }
}


/* Debugging print function. */
void
skIPSetDebugPrint(
    const skipset_t    *ipset)
{
    const ipset_node_t *node;
    const ipset_leaf_t *leaf;
    uint32_t node_idx;
    uint32_t bitmap_size;
    sk_bitmap_t *isfree;
    int width = 0;

    if (ipset->is_iptree) {
        return;
    }

    if (ipset->s.v3->leaves.entry_count) {
        width = 2 + (int)log10(ipset->s.v3->leaves.entry_count);
    }

    /* print root ID */
    fprintf(stderr,
            ">> %*sROOT %u%c      NODE_FREE %uN      LEAF_FREE %uL\n",
            width, "", (unsigned)IPSET_ROOT_INDEX(ipset),
            (IPSET_ROOT_IS_LEAF(ipset) ? 'L' : 'N'),
            (unsigned)ipset->s.v3->nodes.free_list,
            (unsigned)ipset->s.v3->leaves.free_list);

    if (IPSET_ISEMPTY(ipset)) {
        return;
    }

    /* this function creates a bitmap to note which nodes and leaves
     * are on the free list.  this is the size of the bitmap */
    if (ipset->s.v3->nodes.entry_count > ipset->s.v3->leaves.entry_count) {
        bitmap_size = ipset->s.v3->nodes.entry_count;
    } else {
        bitmap_size = ipset->s.v3->leaves.entry_count;
    }

    /* create the bitmap */
    if (skBitmapCreate(&isfree, bitmap_size)) {
        /* unable to create bitmap; use simple printing (this also
         * allows us to use the functions and avoid warnings from
         * gcc) */

        /* print nodes */
        for (node_idx = 0;
             node_idx < ipset->s.v3->nodes.entry_count;
             ++node_idx)
        {
            fprintf(stderr, "** %*uN  ", width, node_idx);
            ipsetDebugPrintByIndex(ipset, node_idx, 0);
        }

        /* print leaves */
        fprintf(stderr, "\n");
        for (node_idx = 0;
             node_idx < ipset->s.v3->leaves.entry_count;
             ++node_idx)
        {
            fprintf(stderr, "** %*uL  ", width, node_idx);
            ipsetDebugPrintByIndex(ipset, node_idx, 1);
        }

        return;
    }

    /* fill the bitmap for nodes on the free list */
    for (node_idx = ipset->s.v3->nodes.free_list;
         0 != node_idx;
         node_idx = NODEIDX_FREE_LIST(ipset, node_idx))
    {
        assert(node_idx < ipset->s.v3->nodes.entry_count);
        skBitmapSetBit(isfree, node_idx);
    }

    /* print the nodes */
    for (node_idx = 0; node_idx < ipset->s.v3->nodes.entry_count; ++node_idx) {
        node = NODE_PTR(ipset, node_idx);
        fprintf(stderr, "** %*uN  ", width, node_idx);
#if SK_ENABLE_IPV6
        if (ipset->is_ipv6) {
            ipsetDebugPrintAddrV6(&node->v6.ip, node->v6.prefix);
        } else
#endif
        {
            ipsetDebugPrintAddrV4(node->v4.ip, node->v4.prefix);
        }

        /* note whether this entry is on free-list */
        fprintf(stderr, "  %c",
                (skBitmapGetBit(isfree, node_idx) ? 'F' : ' '));

        ipsetDebugPrintChildren(node, width);
        fprintf(stderr, "\n");
    }

    skBitmapClearAllBits(isfree);

    /* mark leaves that are on the free list */
    for (node_idx = ipset->s.v3->leaves.free_list;
         0 != node_idx;
         node_idx = LEAFIDX_FREE_LIST(ipset, node_idx))
    {
        assert(node_idx < ipset->s.v3->leaves.entry_count);
        skBitmapSetBit(isfree, node_idx);
    }

    /* print the leaves */
    fprintf(stderr, "\n");
    for (node_idx = 0; node_idx < ipset->s.v3->leaves.entry_count; ++node_idx) {
        leaf = LEAF_PTR(ipset, node_idx);
        fprintf(stderr, "** %*uL  ", width, node_idx);
#if SK_ENABLE_IPV6
        if (ipset->is_ipv6) {
            ipsetDebugPrintAddrV6(&leaf->v6.ip, leaf->v6.prefix);
        } else
#endif
        {
            ipsetDebugPrintAddrV4(leaf->v4.ip, leaf->v4.prefix);
        }
        /* note whether this entry is on free-list */
        fprintf(stderr, "%s",
                (skBitmapGetBit(isfree, node_idx) ? "  F\n" : "\n"));
    }

    skBitmapDestroy(&isfree);
}


int
skIPSetProcessStream(
    skstream_t                 *stream,
    skipset_procstream_init_t   cb_init_func,
    void                       *cb_init_func_ctx,
    skipset_procstream_parm_t  *proc_stream_settings)
{
    sk_file_header_t *hdr;
    ipset_walk_t proc_stream_state;
    int is_ipv6 = 0;
    int rv;

    if (NULL == stream || NULL == proc_stream_settings) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (NULL == proc_stream_settings->cb_entry_func && NULL == cb_init_func) {
        return SKIPSET_ERR_BADINPUT;
    }

    rv = ipsetReadStreamHeader(stream, &hdr, &is_ipv6);
    if (rv) {
        return rv;
    }

    if (cb_init_func) {
        skipset_t *fake_set = NULL;
        rv = skIPSetCreate(&fake_set, is_ipv6);
        if (SKIPSET_OK == rv) {
            rv = cb_init_func(fake_set, hdr, cb_init_func_ctx,
                              proc_stream_settings);
            skIPSetDestroy(&fake_set);
        }
        if (rv) {
            return rv;
        }
    }
    if (NULL == proc_stream_settings->cb_entry_func) {
        return SKIPSET_OK;
    }

    switch (proc_stream_settings->v6_policy) {
      case SK_IPV6POLICY_ONLY:
        if (!is_ipv6) {
            /* caller wants only IPv6 addresses; there are none */
            return SKIPSET_OK;
        }
        break;
      case SK_IPV6POLICY_IGNORE:
        if (is_ipv6) {
            /* caller wants only IPv4 addresses; there are none */
            return SKIPSET_OK;
        }
        break;
      case SK_IPV6POLICY_FORCE:
      case SK_IPV6POLICY_ASV4:
      case SK_IPV6POLICY_MIX:
        break;
#ifdef NDEBUG
      default:
        skAbortBadCase(proc_stream_settings->v6_policy);
#endif
    }

    memset(&proc_stream_state, 0, sizeof(proc_stream_state));
    proc_stream_state.callback = proc_stream_settings->cb_entry_func;
    proc_stream_state.cb_data = proc_stream_settings->cb_entry_func_ctx;
    proc_stream_state.v6policy = proc_stream_settings->v6_policy;
    proc_stream_state.cidr_blocks = proc_stream_settings->visit_cidr;

    if (skHeaderGetRecordVersion(hdr) < IPSET_REC_VERSION_RADIX) {
        /* Handle files in IPSET_REC_VERSION_CLASSC format */
        return ipsetProcessStreamClassc(stream, hdr, &proc_stream_state);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_RADIX) {
        return ipsetProcessStreamRadix(stream, hdr, &proc_stream_state);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_CIDRBMAP) {
        return ipsetProcessStreamCidrbmap(stream, hdr, &proc_stream_state);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_SLASH64) {
#if !SK_ENABLE_IPV6
        skAbort();
#else
        return ipsetProcessStreamSlash64(stream, hdr, &proc_stream_state);
#endif  /* SK_ENABLE_IPV6 */
    }

    skAbort();
}


static int
ipsetProcessStreamCountInit(
    const skipset_t                    *ipset,
    const sk_file_header_t      UNUSED(*hdr),
    void                        UNUSED(*init_func_ctx),
    skipset_procstream_parm_t          *param)
{
#if !SK_ENABLE_IPV6
    /* unused param */
    (void)ipset;
#else
    if (ipset->is_ipv6) {
        param->v6_policy = SK_IPV6POLICY_FORCE;
        param->cb_entry_func = ipsetCountStreamCallbackV6;
        return 0;
    }
#endif  /* SK_ENABLE_IPV6 */
    param->v6_policy = SK_IPV6POLICY_ASV4;
    param->cb_entry_func = ipsetCountStreamCallbackV4;
    return 0;
}


int
skIPSetProcessStreamCountIPs(
    skstream_t         *stream,
    char               *count_buf,
    size_t              count_buf_size)
{
    skipset_procstream_parm_t param;
    ipset_count_t count;
    int rv;

    memset(&count, 0, sizeof(count));

    memset(&param, 0, sizeof(param));
    param.visit_cidr = 1;
    param.cb_entry_func_ctx = &count;

    rv = skIPSetProcessStream(stream, ipsetProcessStreamCountInit,
                              NULL, &param);
    if (rv) {
        return rv;
    }

    if (NULL == ipsetCountToString(&count, count_buf, count_buf_size)) {
        return SKIPSET_ERR_BADINPUT;
    }

    return SKIPSET_OK;
}


int
skIPSetRead(
    skipset_t         **ipset_out,
    skstream_t         *stream)
{
    sk_file_header_t *hdr;
    sk_header_entry_t *hentry;
    int is_ipv6;
    int rv;

    if (!stream || !ipset_out) {
        return SKIPSET_ERR_BADINPUT;
    }
    *ipset_out = NULL;

    rv = ipsetReadStreamHeader(stream, &hdr, &is_ipv6);
    if (rv) {
        return rv;
    }

    /* Go to helper function depending on record version */

    if (skHeaderGetRecordVersion(hdr) < IPSET_REC_VERSION_RADIX) {
        /* Handle files in IPSET_REC_VERSION_CLASSC format */
        if (IPSET_USE_IPTREE) {
            return ipsetReadClasscIntoIPTree(ipset_out, stream, hdr);
        }
        return ipsetReadClasscIntoRadix(ipset_out, stream, hdr);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_RADIX) {
        hentry = skHeaderGetFirstMatch(hdr, SK_HENTRY_IPSET_ID);
        if (NULL == hentry) {
            skAbort();
        }
        /* check for an empty IPset */
        if (0 == ipsetHentryGetNodeCount(hentry)
            && 0 == ipsetHentryGetLeafCount(hentry))
        {
            if (!is_ipv6 && IPSET_USE_IPTREE) {
                return ipsetCreate(ipset_out, 0, 0);
            }
            return ipsetCreate(ipset_out, is_ipv6, 1);
        }
        if (!is_ipv6 && IPSET_USE_IPTREE) {
            /* Read IPv4-only file into the IPTree format */
            return ipsetReadRadixIntoIPTree(ipset_out, stream, hdr);
        }
        return ipsetReadRadixIntoRadix(ipset_out, stream, hdr, is_ipv6);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_CIDRBMAP) {
#if SK_ENABLE_IPV6
        if (is_ipv6) {
            return ipsetReadCidrbmapIntoRadixV6(ipset_out, stream, hdr);
        }
#endif
        if (IPSET_USE_IPTREE) {
            /* Read IPv4-only file into the IPTree format */
            return ipsetReadCidrbmapIntoIPTree(ipset_out, stream, hdr);
        }
        return ipsetReadCidrbmapIntoRadixV4(ipset_out, stream, hdr);
    }
    if (skHeaderGetRecordVersion(hdr) == IPSET_REC_VERSION_SLASH64) {
#if SK_ENABLE_IPV6
        if (!is_ipv6) {
            skAbort();
        }
        return ipsetReadSlash64(ipset_out, stream, hdr);
#endif  /* SK_ENABLE_IPV6 */
    }

    skAbort();
}


/* the prototype for this function is in skheader_priv.h */
int
skIPSetRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id)
{
    assert(SK_HENTRY_IPSET_ID == entry_id);
    return (skHentryTypeRegister(
                entry_id, &ipsetHentryPacker, &ipsetHentryUnpacker,
                &ipsetHentryCopy, &ipsetHentryFree, &ipsetHentryPrint));
}


int
skIPSetRemoveAddress(
    skipset_t          *ipset,
    const skipaddr_t   *ipaddr,
    uint32_t            prefix)
{
    ipset_find_t find_state;
    uint32_t ipv4;
    int rv;

#if  SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        ipset_ipv6_t ipv6;

        if (skipaddrIsV6(ipaddr)) {
            /* both set and address are V6 */
            IPSET_IPV6_FROM_ADDRV6(&ipv6, ipaddr);
            if (128 == prefix) {
                /* no-op */
            } else if (0 == prefix) {
                prefix = 128;
            } else if (prefix > 128) {
                return SKIPSET_ERR_PREFIX;
            } else {
                IPSET_IPV6_APPLY_CIDR(&ipv6, prefix);
            }
        } else {
            /* set is V6 and address is V4 */
            IPSET_IPV6_FROM_ADDRV4(&ipv6, ipaddr);
            if (0 == prefix || 32 == prefix) {
                prefix = 128;
            } else if (prefix > 32) {
                return SKIPSET_ERR_PREFIX;
            } else {
                prefix += 96;
                /* apply mask */
                IPSET_IPV6_APPLY_CIDR(&ipv6, prefix);
            }
        }
        rv = ipsetFindV6(ipset, &ipv6, prefix, &find_state);
        /* if IP was not found, we can return */
        if (SKIPSET_ERR_NOTFOUND == rv
            || SKIPSET_ERR_EMPTY == rv
            || SKIPSET_ERR_MULTILEAF == rv)
        {
            return SKIPSET_OK;
        }
        IPSET_COPY_ON_WRITE(ipset);
        rv = ipsetRemoveAddressV6(ipset, &ipv6, prefix, &find_state);
        if (rv) {
            return rv;
        }
        IPSET_MAYBE_COMBINE(ipset);
        return rv;
    }

    /* To get here, IPset must be IPv4 */
    if (skipaddrIsV6(ipaddr)) {
        /* set is V4 and address is V6 */
        /* attempt to convert V6 ipaddr to V4 */
        if (skipaddrGetAsV4(ipaddr, &ipv4)) {
            /* an V6 ipaddr is not going to be in a V4 IPSet */
            return SKIPSET_OK;
        }
        if (0 == prefix || 128 == prefix) {
            prefix = 32;
        } else if (prefix > 128) {
            return SKIPSET_ERR_PREFIX;
        } else if (prefix <= 96) {
            return SKIPSET_OK;
        } else {
            prefix -= 96;
            /* apply mask */
            ipv4 &= ~(UINT32_MAX >> prefix);
        }
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* both set and address are V4 */
        ipv4 = skipaddrGetV4(ipaddr);
        if (prefix == 32) {
            /* no-op */
        } else if (0 == prefix) {
            prefix = 32;
        } else if (prefix > 32) {
            return SKIPSET_ERR_PREFIX;
        } else {
            /* apply mask */
            ipv4 &= ~(UINT32_MAX >> prefix);
        }
    }

    if (ipset->is_iptree) {
        return ipsetRemoveAddressIPTree(ipset, ipv4, prefix);
    }

    rv = ipsetFindV4(ipset, ipv4, prefix, &find_state);
    /* if IP was not found, we can return */
    if (SKIPSET_ERR_NOTFOUND == rv
        || SKIPSET_ERR_EMPTY == rv
        || SKIPSET_ERR_MULTILEAF == rv)
    {
        return SKIPSET_OK;
    }
    IPSET_COPY_ON_WRITE(ipset);
    rv = ipsetRemoveAddressV4(ipset, ipv4, prefix, &find_state);
    if (rv) {
        return rv;
    }
    IPSET_MAYBE_COMBINE(ipset);
    return rv;
}


int
skIPSetRemoveAll(
    skipset_t          *ipset)
{
    if (!ipset) {
        return SKIPSET_ERR_BADINPUT;
    }

    if (ipset->is_iptree) {
        ipset->is_dirty = 1;
        ipsetRemoveAllIPTree(ipset->s.v2);
        return SKIPSET_OK;
    }

    IPSET_COPY_ON_WRITE(ipset);

    IPSET_ROOT_INDEX_SET(ipset, 0, 0);

    if (ipset->s.v3->nodes.buf) {
        memset(ipset->s.v3->nodes.buf, 0, (ipset->s.v3->nodes.entry_capacity
                                           * ipset->s.v3->nodes.entry_size));
        ipset->s.v3->nodes.entry_count = 0;
        ipset->is_dirty = 0;
    }
    if (ipset->s.v3->leaves.buf) {
        memset(ipset->s.v3->leaves.buf, 0, (ipset->s.v3->leaves.entry_capacity
                                            * ipset->s.v3->leaves.entry_size));
        ipset->s.v3->leaves.entry_count = 0;
        ipset->is_dirty = 0;
        ipset->s.v3->realloc_leaves = 0;
    }
    return SKIPSET_OK;
}


/* Remove each IP in the IPWildcard from the IPset */
int
skIPSetRemoveIPWildcard(
    skipset_t              *ipset,
    const skIPWildcard_t   *ipwild)
{
    skIPWildcardIterator_t iter;
    skipaddr_t ip;
    uint32_t prefix;
    int rv = SKIPSET_OK;

    /* Remove the netblocks contained in the wildcard */
#if  SK_ENABLE_IPV6
    if (ipset->is_ipv6 && !skIPWildcardIsV6(ipwild)) {
        skIPWildcardIteratorBindV6(&iter, ipwild);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        skIPWildcardIteratorBind(&iter, ipwild);
    }

    if (skIPWildcardIteratorNextCidr(&iter, &ip, &prefix)
        != SK_ITERATOR_OK)
    {
        return rv;
    }
    if (0 == prefix) {
        /* wildcard was x.x.x.x or x:x:x:x:x:x:x:x */
        if (!skipaddrIsZero(&ip)) {
            skAppPrintErr("Wildcard iterator bug: prefix == 0 but IP != 0");
            skAbort();
        }
        return skIPSetRemoveAll(ipset);
    }

    /* it would be more efficient to inline skIPSetRemoveAddress()
     * here; but often there is only one CIDR block in a wildcard */
    do {
        rv = skIPSetRemoveAddress(ipset, &ip, prefix);
    } while (skIPWildcardIteratorNextCidr(&iter, &ip, &prefix)==SK_ITERATOR_OK
             && SKIPSET_OK == rv);

    return rv;
}


/* Write 'ipset' to 'filename'--a wrapper around skIPSetWrite(). */
int
skIPSetSave(
    const skipset_t    *ipset,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int rv;

    if (filename == NULL || ipset == NULL) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (ipset->is_dirty) {
        return SKIPSET_ERR_REQUIRE_CLEAN;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        /* skStreamPrintLastErr(stream, rv, &skAppPrintErr); */
        rv = SKIPSET_ERR_FILEIO;
        goto END;
    }

    rv = skIPSetWrite(ipset, stream);

  END:
    skStreamDestroy(&stream);
    return rv;
}


/* Convert 'error_code' to a string. */
const char *
skIPSetStrerror(
    int                 error_code)
{
    static char errbuf[128];

    switch ((skipset_return_t)error_code) {
      case SKIPSET_OK:
        return "Success";
      case SKIPSET_ERR_EMPTY:
        return "IPset is empty";
      case SKIPSET_ERR_PREFIX:
        return "Invalid prefix";
      case SKIPSET_ERR_NOTFOUND:
        return "Value not found in IPset";
      case SKIPSET_ERR_ALLOC:
        return "Unable to allocate memory";
      case SKIPSET_ERR_BADINPUT:
        return "Empty input value";
      case SKIPSET_ERR_FILEIO:
        return "Error in read/write";
      case SKIPSET_ERR_FILETYPE:
        return "Input is not an IPset";
      case SKIPSET_ERR_FILEHEADER:
        return "File header values incompatible with this compile of SiLK";
      case SKIPSET_ERR_FILEVERSION:
        return "IPset version unsupported by this SiLK release";
      case SKIPSET_ERR_OPEN:
        return "Error opening file";
      case SKIPSET_ERR_IPV6:
        return "IPset does not allow IPv6 addresses";
      case SKIPSET_ERR_REQUIRE_CLEAN:
        return "Function requires a clean IPset";
      case SKIPSET_ERR_CORRUPT:
        return "IPset state is inconsistent (corrupt file?)";
      case SKIPSET_ERR_SUBSET:
        return "Part of netblock exists in IPset";
      case SKIPSET_ERR_MULTILEAF:
        return "Search ended at missing branch";
    }

    snprintf(errbuf, sizeof(errbuf),
             "Unrecognized IPset error code %d", error_code);
    return errbuf;
}


/* Turn off IPs of 'result_ipset' that are on in 'ipset'. */
int
skIPSetSubtract(
    skipset_t          *result_ipset,
    const skipset_t    *ipset)
{
    int rv;

    if (!result_ipset) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (!ipset) {
        return SKIPSET_OK;
    }

    if (ipset->is_iptree) {
        if (result_ipset->is_iptree) {
            /* both are in the SiLK-2 format (IPTree) */
            result_ipset->is_dirty = 1;
            return ipsetSubtractIPTree(result_ipset->s.v2, ipset->s.v2);
        }
        /* result_ipset is SiLK-3 and other is SiLK-2.  Walk over the
         * entries of the SiLK-2 IPset and remove from the SiLK-3
         * IPset. */
        IPSET_COPY_ON_WRITE(result_ipset);
        return skIPSetWalk(ipset, 1, SK_IPV6POLICY_MIX,
                           &ipsetSubtractCallback, (void*)result_ipset);
    }
    if (result_ipset->is_iptree) {
        /* only the result_ipset is in SiLK-2 format */
        return skIPSetWalk(ipset, 1, SK_IPV6POLICY_ASV4,
                           &ipsetSubtractCallback, (void*)result_ipset);
    }

    IPSET_COPY_ON_WRITE(result_ipset);

#if SK_ENABLE_IPV6
    if (result_ipset->is_ipv6) {
        if (ipset->is_ipv6) {
            /* both are IPv6 */
            rv = ipsetWalkInternalV6(ipset, ipsetSubtractCallbackV6,
                                     (void*)result_ipset);
        } else {
            rv = skIPSetWalk(ipset, 1, SK_IPV6POLICY_FORCE,
                             &ipsetSubtractCallback, (void*)result_ipset);
        }
    } else if (ipset->is_ipv6) {
        rv = skIPSetWalk(ipset, 1, SK_IPV6POLICY_ASV4,
                         &ipsetSubtractCallback, (void*)result_ipset);
    } else
#endif
    {
        /* both are IPv4 */
        rv = ipsetWalkInternalV4(ipset, ipsetSubtractCallbackV4,
                                 (void*)result_ipset);
    }
    if (rv) {
        return rv;
    }
    IPSET_MAYBE_COMBINE(result_ipset);
    return rv;
}


/* Turn on IPs of 'result_ipset' that are on in 'ipset'. */
int
skIPSetUnion(
    skipset_t          *result_ipset,
    const skipset_t    *ipset)
{
    int rv;

    if (!result_ipset) {
        return SKIPSET_ERR_BADINPUT;
    }
    if (!ipset) {
        return SKIPSET_OK;
    }

    if (ipset->is_iptree) {
        if (result_ipset->is_iptree) {
            /* both are in the SiLK-2 format (IPTree) */
            result_ipset->is_dirty = 1;
            return ipsetUnionIPTree(result_ipset->s.v2, ipset->s.v2);
        }
        /* result_ipset is SiLK-3 and other is SiLK-2.  Walk over the
         * entries of the SiLK-2 IPset and add to the SiLK-3 IPset. */
        IPSET_COPY_ON_WRITE(result_ipset);
        return skIPSetWalk(ipset, 1, SK_IPV6POLICY_MIX,
                           &ipsetUnionCallback, (void*)result_ipset);
    }
    if (result_ipset->is_iptree) {
        /* only the result_ipset is in SiLK-2 format */
#if !SK_ENABLE_IPV6
        return ipsetWalkInternalV4(ipset, ipsetUnionCallbackIPTree,
                                   (void*)result_ipset);
#else
        if (!skIPSetContainsV6(ipset)) {
            if (ipset->is_ipv6) {
                return skIPSetWalk(ipset, 1, SK_IPV6POLICY_ASV4,
                                   &ipsetUnionCallback, (void*)result_ipset);
            }
            return ipsetWalkInternalV4(ipset, ipsetUnionCallbackIPTree,
                                       (void*)result_ipset);
        }
        if (result_ipset->no_autoconvert) {
            return SKIPSET_ERR_IPV6;
        }
        rv = ipsetConvertIPTreetoV6(result_ipset);
        if (rv) {
            return rv;
        }
#endif  /* #else of #if !SK_ENABLE_IPV6 */
    }

    if (result_ipset->no_autoconvert && !result_ipset->is_ipv6
        && skIPSetContainsV6(ipset))
    {
        return SKIPSET_ERR_IPV6;
    }
    IPSET_COPY_ON_WRITE(result_ipset);

#if SK_ENABLE_IPV6
    if (result_ipset->is_ipv6 || ipset->is_ipv6) {
        if (result_ipset->is_ipv6 == ipset->is_ipv6) {
            /* both are IPv6 */
            rv = ipsetWalkInternalV6(ipset, ipsetUnionCallbackV6,
                                     (void*)result_ipset);
        } else {
            rv = skIPSetWalk(ipset, 1, SK_IPV6POLICY_FORCE,
                             &ipsetUnionCallback, (void*)result_ipset);
        }
    } else
#endif
    {
        /* both are IPv4 */
        rv = ipsetWalkInternalV4(ipset, ipsetUnionCallbackV4,
                                 (void*)result_ipset);
    }
    if (rv) {
        return rv;
    }
    IPSET_MAYBE_COMBINE(result_ipset);
    return rv;
}


/* Invoke the 'callback' function on all IPs in the 'ipset' */
int
skIPSetWalk(
    const skipset_t    *ipset,
    uint32_t            cidr_blocks,
    sk_ipv6policy_t     v6_policy,
    skipset_walk_fn_t   callback,
    void               *cb_data)
{
    ipset_walk_t walk_state;
    skipaddr_t ipaddr;
    uint32_t prefix;
    int rv;

    if (!ipset || !callback) {
        return SKIPSET_ERR_BADINPUT;
    }

    if (!ipset->is_iptree && IPSET_ISEMPTY(ipset)) {
        return SKIPSET_OK;
    }

    /* use the iterator if we can */
    if (ipset->is_iptree || !ipset->is_dirty) {
        skipset_iterator_t iter;

        rv = skIPSetIteratorBind(&iter, ipset, cidr_blocks, v6_policy);
        while (rv == 0
               && (skIPSetIteratorNext(&iter, &ipaddr, &prefix)
                   == SK_ITERATOR_OK))
        {
            rv = callback(&ipaddr, prefix, cb_data);
        }
        return rv;
    }

    memset(&walk_state, 0, sizeof(ipset_walk_t));
    walk_state.cidr_blocks = (uint8_t)(cidr_blocks ? 1 : 0);
    walk_state.v6policy    = v6_policy;
    walk_state.callback    = callback;
    walk_state.cb_data     = cb_data;

#if SK_ENABLE_IPV6
    if (ipset->is_ipv6) {
        if (v6_policy == SK_IPV6POLICY_IGNORE) {
            /* caller wants only IPv4 addresses, and there are none in
             * an IPv6 IPset. */
            return SKIPSET_OK;
        }
        return ipsetWalkV6(ipset, &walk_state);
    }
    if (v6_policy == SK_IPV6POLICY_ONLY) {
        /* caller wants only IPv6 addresses, and there are none in an
         * IPv4 IPset. */
        return SKIPSET_OK;
    }
    return ipsetWalkV4(ipset, &walk_state);

#else  /* #if SK_ENABLE_IPV6 */

    if (ipset->is_ipv6) {
        /* impossible to have an IPv6 set */
        skAbort();
    }
    if (v6_policy > SK_IPV6POLICY_MIX) {
        /* caller wants IPv6 addresses, which are not supported in
         * IPv4-only SiLK */
        return SKIPSET_OK;
    }
    return ipsetWalkV4(ipset, &walk_state);

#endif  /* #else of #if SK_ENABLE_IPV6 */
}


int
skIPSetWrite(
    const skipset_t    *ipset,
    skstream_t         *stream)
{
    const skipset_options_t *opts;
    sk_file_version_t record_version = 0;
    sk_file_header_t *hdr;
    ssize_t rv;

    if (!ipset || !stream) {
        return SKIPSET_ERR_BADINPUT;
    }

    /* do not write an unclean ipset */
    if (ipset->is_dirty) {
        return SKIPSET_ERR_REQUIRE_CLEAN;
    }

    opts = ipset->options;

    /* Use the version that is explicitly requested.  If none
     * requested, use DEFAULT_IPV4 for IPv4 IPsets and DEFAULT_IPV6
     * for IPv6 IPsets. */
    if (NULL == opts
        || IPSET_REC_VERSION_DEFAULT == opts->record_version)
    {
        if (skIPSetContainsV6(ipset)) {
            record_version = IPSET_REC_VERSION_DEFAULT_IPV6;
        } else {
            record_version = IPSET_REC_VERSION_DEFAULT_IPV4;
        }
    } else if (skIPSetContainsV6(ipset)) {
        switch (opts->record_version) {
          case IPSET_REC_VERSION_CLASSC:
            /* Cannot write an IPv6 IPset into a this format */
            return SKIPSET_ERR_IPV6;
          case IPSET_REC_VERSION_RADIX:
          case IPSET_REC_VERSION_CIDRBMAP:
          case IPSET_REC_VERSION_SLASH64:
            record_version = opts->record_version;
            break;
          default:
            break;
        }
    } else {
        switch (opts->record_version) {
          case IPSET_REC_VERSION_CLASSC:
          case IPSET_REC_VERSION_RADIX:
          case IPSET_REC_VERSION_CIDRBMAP:
            record_version = opts->record_version;
            break;
          case IPSET_REC_VERSION_SLASH64:
            /* this is an IPv6 only format; use the Cidrbmap format
             * for IPv4 IPsets */
            record_version = IPSET_REC_VERSION_CIDRBMAP;
            break;
          default:
            break;
        }
    }
    if (0 == record_version) {
        return SKIPSET_ERR_BADINPUT;
    }

    /* prep the header */
    hdr = skStreamGetSilkHeader(stream);
    skHeaderSetByteOrder(hdr, SILK_ENDIAN_NATIVE);
    skHeaderSetFileFormat(hdr, FT_IPSET);
    skHeaderSetRecordVersion(hdr, record_version);
    skHeaderSetRecordLength(hdr, 1);

    if (opts) {
        if (opts->note_strip) {
            skHeaderRemoveAllMatching(hdr, SK_HENTRY_ANNOTATION_ID);
        }
        if (opts->invocation_strip) {
            skHeaderRemoveAllMatching(hdr, SK_HENTRY_INVOCATION_ID);
        } else if (opts->argc && opts->argv) {
            rv = skHeaderAddInvocation(hdr, 1, opts->argc, opts->argv);
            if (rv) {
                return SKIPSET_ERR_FILEIO;
            }
        }
        if ((rv = skHeaderSetCompressionMethod(hdr, opts->comp_method))
            || (rv = skOptionsNotesAddToStream(stream)))
        {
            return SKIPSET_ERR_FILEIO;
        }
    }

    if (IPSET_REC_VERSION_CLASSC == record_version) {
        return ipsetWriteClassc(ipset, stream);
    }
    if (IPSET_REC_VERSION_RADIX == record_version) {
        return ipsetWriteRadix(ipset, stream);
    }
    if (IPSET_REC_VERSION_CIDRBMAP == record_version) {
        return ipsetWriteCidrbmap(ipset, stream);
    }
    if (IPSET_REC_VERSION_SLASH64 == record_version) {
#if !SK_ENABLE_IPV6
        skAbort();
#else
        return ipsetWriteSlash64(ipset, stream);
#endif  /* SK_ENABLE_IPV6 */
    }

    skAbort();
}


/* ****  SUPPORT FOR LEGACY IPTREE API BEGINS HERE  **** */


#include <silk/iptree.h>


/* FUNCTION DEFINITIONS */

/*
 *    Helper function for skIPTreeSave() and skIPSetWrite().
 *
 *    Initialize a temporary skipset_t, set its IPTree pointer to the
 *    'iptree' parameter, set its skipset_options_t to write a
 *    IPSET_REC_VERSION_CLASSC IPset, and call skIPSetWrite() to write
 *    the skIPTree_t.
 */
static int
iptreeSaveOrWrite(
    const skIPTree_t   *iptree,
    const char         *filename,
    skstream_t         *stream)
{
    skipset_t ipset;
    skipset_options_t opts;
    int rv;

    assert(iptree);
    assert((filename && !stream) || (stream && !filename));

    memset(&ipset, 0, sizeof(ipset));
    ipset.s.v2 = (skIPTree_t*)iptree;
    ipset.is_iptree = 1;
    ipset.no_autoconvert = 1;
    ipset.options = &opts;

    memset(&opts, 0, sizeof(opts));
    opts.record_version = IPSET_REC_VERSION_CLASSC;

    if (filename) {
        rv = skIPSetSave(&ipset, filename);
    } else {
        sk_file_header_t *hdr;

        hdr = skStreamGetSilkHeader(stream);
        if (hdr) {
            opts.comp_method = skHeaderGetCompressionMethod(hdr);
        }
        rv = skIPSetWrite(&ipset, stream);
    }

    switch (rv) {
      case SKIPSET_OK:
        break;
      case SKIPSET_ERR_FILEIO:
        return SKIP_ERR_OPEN;
      default:
        skAbortBadCase(rv);
    }

    return SKIP_OK;
}


/* Add addr to ipset */
int
skIPTreeAddAddress(
    skIPTree_t         *ipset,
    uint32_t            addr)
{
    assert(ipset);
    if (!ipset) {
        return SKIP_ERR_BADINPUT;
    }
    return (ipsetInsertAddressIPTree(ipset, addr, 32)
            ? SKIP_ERR_ALLOC
            : SKIP_OK);
}


/* Add the addresses in an IPWildcard to ipset */
int
skIPTreeAddIPWildcard(
    skIPTree_t             *ipset,
    const skIPWildcard_t   *ipwild)
{
    assert(ipset);
    if (!ipset) {
        return SKIP_ERR_BADINPUT;
    }
    return (ipsetInsertWildcardIPTree(ipset, ipwild)
            ? SKIP_ERR_ALLOC
            : SKIP_OK);
}


/* Return 1 if the address is present in the ipset */
int
skIPTreeCheckAddress(
    const skIPTree_t   *ipset,
    uint32_t            ipv4)
{
    assert(ipset);
    return IPTREE_CHECK_ADDRESS(ipset, ipv4);
}


/* Return 1 if the two IPsets have any IPs in common */
int
skIPTreeCheckIntersectIPTree(
    const skIPTree_t   *ipset1,
    const skIPTree_t   *ipset2)
{
    return ipsetCheckIPSetIPTree(ipset1, ipset2);
}


/* Return 1 if the IPset and IPWildcard have any IPs in common */
int
skIPTreeCheckIntersectIPWildcard(
    const skIPTree_t       *ipset,
    const skIPWildcard_t   *ipwild)
{
    return ipsetCheckWildcardIPTree(ipset, ipwild);
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
    uint32_t tBuffer[1 + IPTREE_WORDS_PER_SLASH24];
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

    /* Only accept SiLK-2 files */
    rv = skStreamCheckSilkHeader(
        stream, FT_IPSET, 0, IPSET_REC_VERSION_CLASSC, NULL);
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
    return ipsetCountIPTree(ipset);
}


/* Allocate an IPset and set contents to empty */
int
skIPTreeCreate(
    skIPTree_t        **iptree)
{
    skipset_t *ipset;

    if (NULL == iptree) {
        return SKIP_ERR_BADINPUT;
    }
    if (ipsetCreate(&ipset, 0, 0)) {
        return SKIP_ERR_ALLOC;
    }

    /* Steal the IPTree from the IPset and destroy the IPset */
    *iptree = ipset->s.v2;
    ipset->s.v2 = NULL;
    skIPSetDestroy(&ipset);
    return SKIP_OK;
}


/* Frees space associated with *ipset. */
void
skIPTreeDelete(
    skIPTree_t        **ipset)
{
    if (NULL == ipset || NULL == *ipset) {
        return;
    }
    ipsetDestroyIPTree(*ipset);
    *ipset = NULL;
}


/* Turn off bits of 'result_ipset' that are off in 'ipset'. */
void
skIPTreeIntersect(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    (void)ipsetIntersectIPTree(result_ipset, ipset);
}


/* Mask the IPs in ipset so only one is set per every (32-mask) bits */
void
skIPTreeMask(
    skIPTree_t         *ipset,
    uint32_t            mask)
{
    (void)ipsetMaskIPTree(ipset, mask);
}


/* Read IPset from filename---a wrapper around skIPTreeRead(). */
int
skIPTreeLoad(
    skIPTree_t        **iptree,
    const char         *filename)
{
    skstream_t *stream = NULL;
    int rv;

    if (filename == NULL || iptree == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream)))
    {
        rv = SKIP_ERR_OPEN;
        goto END;
    }

    rv = skIPTreeRead(iptree, stream);

  END:
    skStreamDestroy(&stream);
    return rv;
}


/* Print a textual prepresentation of the IP Tree. */
void
skIPTreePrint(
    const skIPTree_t   *iptree,
    skstream_t         *stream,
    skipaddr_flags_t    ip_format,
    int                 as_cidr)
{
    skipset_t ipset;

    if (NULL == iptree || NULL == stream) {
        return;
    }
    memset(&ipset, 0, sizeof(ipset));
    ipset.s.v2 = (skIPTree_t*)iptree;
    ipset.is_iptree = 1;
    ipset.no_autoconvert = 1;

    skIPSetPrint(&ipset, stream, ip_format, as_cidr);
}


/* Allocate 'ipset' and read it from the data stream 'stream'. */
int
skIPTreeRead(
    skIPTree_t        **iptree,
    skstream_t         *stream)
{
    skipset_t *ipset;
    sk_file_header_t *hdr;
    ssize_t rv;

    if (stream == NULL || iptree == NULL) {
        return SKIP_ERR_BADINPUT;
    }
    *iptree = NULL;

    rv = skStreamReadSilkHeader(stream, &hdr);
    if (rv) {
        return SKIP_ERR_FILEIO;
    }

    /* only accept SiLK-2 files */
    rv = skStreamCheckSilkHeader(
        stream, FT_IPSET, 0, IPSET_REC_VERSION_CLASSC, NULL);
    if (rv) {
        if (SKSTREAM_ERR_UNSUPPORT_VERSION == rv) {
            return SKIP_ERR_FILEVERSION;
        }
        return SKIP_ERR_FILETYPE;
    }
    if (skHeaderGetRecordLength(hdr) != 1) {
        return SKIPSET_ERR_FILEVERSION;
    }

    /* Read the stream as a SiLK-3 IPset */
    ipset = NULL;
    rv = ipsetReadClasscIntoIPTree(&ipset, stream, hdr);
    switch (rv) {
      case SKIPSET_OK:
        break;
      case SKIPSET_ERR_ALLOC:
        return SKIP_ERR_ALLOC;
      case SKIPSET_ERR_FILEIO:
        return SKIP_ERR_FILEIO;
      default:
        skAbortBadCase(rv);
    }

    /* Steal the IPTree from the IPset and destroy the IPset */
    *iptree = ipset->s.v2;
    ipset->s.v2 = NULL;
    skIPSetDestroy(&ipset);

    return SKIP_OK;
}


/* Remove all addresses from an IPset */
int
skIPTreeRemoveAll(
    skIPTree_t         *ipset)
{
    if (ipset == NULL) {
        return SKIP_ERR_BADINPUT;
    }
    ipsetRemoveAllIPTree(ipset);
    return SKIP_OK;
}


/* Write 'ipset' to 'filename'--a wrapper around skIPTreeWrite(). */
int
skIPTreeSave(
    const skIPTree_t   *iptree,
    const char         *filename)
{
    if (NULL == iptree || NULL == filename) {
        return SKIP_ERR_BADINPUT;
    }
    return iptreeSaveOrWrite(iptree, filename, NULL);
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
    (void)ipsetSubtractIPTree(result_ipset, ipset);
}


/* Merge 'ipset' into 'result_ipset' */
int
skIPTreeUnion(
    skIPTree_t         *result_ipset,
    const skIPTree_t   *ipset)
{
    return (ipsetUnionIPTree(result_ipset, ipset) ? SKIP_ERR_ALLOC : SKIP_OK);
}


/* Write 'ipset' to 'stream'. */
int
skIPTreeWrite(
    const skIPTree_t   *iptree,
    skstream_t         *stream)
{
    if (NULL == iptree || NULL == stream) {
        return SKIP_ERR_BADINPUT;
    }
    return iptreeSaveOrWrite(iptree, NULL, stream);
}


/* Bind iterator to ipset */
static int
iptreeIteratorBind(
    skipset_iterator_t *iter,
    const skIPTree_t   *iptree,
    int                 cidr)
{
    skipset_t ipset;

    if (iter == NULL || iptree == NULL) {
        return SKIP_ERR_BADINPUT;
    }

    memset(&ipset, 0, sizeof(ipset));
    ipset.s.v2 = (skIPTree_t*)iptree;
    ipset.is_iptree = 1;
    ipset.no_autoconvert = 1;

    ASSERT_OK(skIPSetIteratorBind(iter, &ipset, cidr, SK_IPV6POLICY_IGNORE));
    return SKIP_OK;
}

int
skIPTreeIteratorBind(
    skIPTreeIterator_t *iter,
    const skIPTree_t   *iptree)
{
    return iptreeIteratorBind(iter, iptree, 0);
}

int
skIPTreeCIDRBlockIteratorBind(
    skIPTreeCIDRBlockIterator_t    *block_iter,
    const skIPTree_t               *iptree)
{
    return iptreeIteratorBind(block_iter, iptree, 0);
}


/* Create iterator */
static int
iptreeIteratorCreate(
    skipset_iterator_t    **out_iter,
    const skIPTree_t       *iptree,
    int                     cidr)
{
    assert(out_iter);

    *out_iter = (skipset_iterator_t*)malloc(sizeof(skipset_iterator_t));
    if (*out_iter == NULL) {
        return SKIP_ERR_ALLOC;
    }
    if (iptreeIteratorBind(*out_iter, iptree, cidr)) {
        skIPTreeIteratorDestroy(out_iter);
        return SKIP_ERR_BADINPUT;
    }

    return SKIP_OK;
}

int
skIPTreeIteratorCreate(
    skIPTreeIterator_t    **out_iter,
    const skIPTree_t       *iptree)
{
    return iptreeIteratorCreate(out_iter, iptree, 0);
}

int
skIPTreeCIDRBlockIteratorCreate(
    skIPTreeCIDRBlockIterator_t   **out_block_iter,
    const skIPTree_t               *iptree)
{
    return iptreeIteratorCreate(out_block_iter, iptree, 1);
}


/* Destroy iterator */
void
skIPTreeIteratorDestroy(
    skIPTreeIterator_t    **out_iter)
{
    if (*out_iter) {
        free(*out_iter);
        *out_iter = NULL;
    }
}


/* Get next entry in tree */
skIteratorStatus_t
skIPTreeIteratorNext(
    uint32_t           *out_addr,
    skIPTreeIterator_t *iter)
{
    skipaddr_t ipaddr;
    uint32_t prefix;
    skIteratorStatus_t rv;

    assert(iter);
    assert(iter->is_iptree);
    assert(0 == iter->cidr_blocks);

    rv = (skIteratorStatus_t)skIPSetIteratorNext(iter, &ipaddr, &prefix);
    if (SK_ITERATOR_OK == rv) {
        assert(32 == prefix);
        *out_addr = skipaddrGetV4(&ipaddr);
    }
    return rv;
}

skIteratorStatus_t
skIPTreeCIDRBlockIteratorNext(
    skIPTreeCIDRBlock_t            *out_cidr,
    skIPTreeCIDRBlockIterator_t    *iter)
{
    skipaddr_t ipaddr;
    uint32_t prefix;
    skIteratorStatus_t rv;

    assert(iter);
    assert(iter->is_iptree);
    assert(1 == iter->cidr_blocks);

    rv = (skIteratorStatus_t)skIPSetIteratorNext(iter, &ipaddr, &prefix);
    if (SK_ITERATOR_OK == rv) {
        out_cidr->addr = skipaddrGetV4(&ipaddr);
        out_cidr->mask = prefix;
    }
    return rv;
}


/* Reset iterator */
void
skIPTreeIteratorReset(
    skIPTreeIterator_t *iter)
{
    skIPSetIteratorReset(iter);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
