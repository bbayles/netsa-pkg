/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  sknetstruct.h
**
**    Utilities used by IPsets and Bags to group IPs into arbitrarily
**    sized netblocks for printing.  Each netblock keeps a count of
**    the number of smaller netblocks seen.  In the case of Bags, each
**    netblock sums the counters for the entries in that netblock.
**
*/
#ifndef _SKNETSTRUCT_H
#define _SKNETSTRUCT_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKNETSTRUCT_H, "$SiLK: sknetstruct.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>

/**
 *    The context object for processing IP addresses.
 */
typedef struct sk_netstruct_st sk_netstruct_t;
typedef struct sk_netstruct_st skNetStruct_t    SK_GCC_DEPRECATED;

/**
 *    Add the CIDR block 'ipaddr'/'prefix' to the network structure
 *    context object 'ns'.  It is an error to call this function on a
 *    network structure object configured to process counters.
 */
void
skNetStructureAddCIDR(
    sk_netstruct_t     *ns,
    const skipaddr_t   *ipaddr,
    uint32_t            prefix);

/**
 *    Add the ('ipaddr', 'counter') pair to the network structure
 *    context object 'ns'.  It is an error to call this function on a
 *    network structure object that is not configured to process
 *    counters.
 */
void
skNetStructureAddKeyCounter(
    sk_netstruct_t     *ns,
    const skipaddr_t   *ipaddr,
    const uint64_t     *counter);

/**
 *    Creates a new context object for processing IP addresses and
 *    stores that object in the location specified by 'ns'.
 *
 *    When 'has_count' is non-zero, the context object is configured
 *    to work with Bag files, and the caller must use
 *    skNetStructureAddKeyCounter() to add new (IP,counter) pairs to
 *    the context object for printing.
 *
 *    When 'has_count' is zero, the context object is configured to
 *    work with IPset files and the caller must use
 *    skNetStructureAddCIDR() to add a new CIDR block to the context
 *    object for printing.
 *
 *    Once all IPs have been processed, the caller must invoke
 *    skNetStructurePrintFinalize() to close any netblock that is
 *    still open and to print the total.
 *
 *    Text is printed in pipe-delimited columns by default.
 *
 *    By default, the context object prints to standard output.
 *
 *    Whether the network structure groups the IPs into IPv4 or IPv6
 *    netblocks is determined by the input passed to
 *    skNetStructureParse().  The default is to use the IPv4
 *    netblocks.
 *
 *    When configured to process IPv4 addresses, hosts are grouped by
 *    the /8, /16, /24, and /27 netblocks by default.  This may be
 *    changed by calling skNetStructureParse().
 *
 *    When configured to process IPv6 addresses, hosts are grouped by
 *    the /48 and /64 netblocks.  This may be changed by calling
 *    skNetStructureParse().
 *
 *    The default output prints the number of unique hosts seen and
 *    the number of each of the above netblocks that were seen.
 *
 *
 */
int
skNetStructureCreate(
    sk_netstruct_t    **ns,
    int                 has_count);

/**
 *    Destroy the network structure context object pointed at by 'ns'
 *    and set 'ns' to NULL.  Does nothing if 'ns' or *ns is NULL.
 */
void
skNetStructureDestroy(
    sk_netstruct_t    **ns);

/**
 *    Have the network structure context object 'ns' parse the user's
 *    configuration setting in input.  The input configures whether
 *    the network structure context object groups into IPv4 or IPv6
 *    netblocks and whether the be counted and/or printed.
 */
int
skNetStructureParse(
    sk_netstruct_t     *ns,
    const char         *input);

/**
 *    Tell the network structure context object 'ns' that all IPs have
 *    been added and that it should finalize its output by closing any
 *    open netblocks and printing the results.
 */
void
skNetStructurePrintFinalize(
    sk_netstruct_t     *ns);

/**
 *    Configure the network structure context object 'ns' to use
 *    'width' as the width of the column that contains the counter
 *    sum.  The value is only used when processing Bag files.
 */
void
skNetStructureSetCountWidth(
    sk_netstruct_t     *ns,
    int                 width);

/**
 *    Configure the network structure context object 'ns' to print
 *    'delimiter' between columns and at the end of each row.
 */
void
skNetStructureSetDelimiter(
    sk_netstruct_t     *ns,
    char                delimiter);

/**
 *    Configure the network structure context object 'ns' so it uses
 *    'format' when printing IP addresses, where 'format' will be
 *    passed to the skipaddrString() function.
 */
void
skNetStructureSetIpFormat(
    sk_netstruct_t     *ns,
    uint32_t            format);

/**
 *    Configure the network structure context object 'ns' so it does
 *    not print the data in columns.
 */
void
skNetStructureSetNoColumns(
    sk_netstruct_t     *ns);

/**
 *    Configure the network structure context object 'ns' so it does
 *    not print the final delimiter on each row.
 */
void
skNetStructureSetNoFinalDelimiter(
    sk_netstruct_t     *ns);

/**
 *    Configure the network structure context object 'ns' to send its
 *    output to 'stream'.
 */
void
skNetStructureSetOutputStream(
    sk_netstruct_t     *ns,
    skstream_t         *stream);

#ifdef __cplusplus
}
#endif
#endif /* _SKNETSTRUCT_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
