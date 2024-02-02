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
**  Functions for printing CIDR blocks with indentation noting the
**  level of the block.  Also does summation for smaller CIDR blocks.
**  Used by rwbagcat and rwsetcat.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sknetstruct.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/sknetstruct.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* DEFINES AND TYPEDEFS */

#define  NETSTRUCT_DEFAULT_SUMMARY_V4  "ABCXH"
#define  NETSTRUCT_DEFAULT_INPUT_V4    "TS/" NETSTRUCT_DEFAULT_SUMMARY_V4

#define  NETSTRUCT_DEFAULT_SUMMARY_V6  "48,64"
#define  NETSTRUCT_DEFAULT_INPUT_V6    "TS/" NETSTRUCT_DEFAULT_SUMMARY_V6

#define PLURAL(x) (((x) == 1) ? "" : "s")

#define NET_TOTAL_TITLE "TOTAL"


/*
 *    Structure for representing 128 bit unsigned integers.  ip[0]
 *    contains the most significant bits.
 */
typedef struct ns128_st {
    uint64_t    ip[2];
} ns128_t;

/* Convert from an IPv6 skipaddr_t* 'nfa_addr6' to ns128_t* 'nfa_val' */
#define NS128_FROM_IPADDRV6(nfa_val, nfa_addr6)         \
    {                                                   \
        skipaddrGetAsV6((nfa_addr6), (nfa_val));        \
        (nfa_val)->ip[0] = ntoh64((nfa_val)->ip[0]);    \
        (nfa_val)->ip[1] = ntoh64((nfa_val)->ip[1]);    \
    }

/* Convert from ns128_t 'nta_val' to an IPv6 skipaddr_t 'nta_addr' */
#define NS128_TO_IPADDR(nta_val, nta_addr)              \
    {                                                   \
        ns128_t nta_tmp;                                \
        nta_tmp.ip[0] = hton64((nta_val)->ip[0]);       \
        nta_tmp.ip[1] = hton64((nta_val)->ip[1]);       \
        skipaddrSetV6((nta_addr), &nta_tmp);            \
    }

/* Apply netblock mask 'nac_prefix' to the ns128_t* 'nac_val' */
#define NS128_APPLY_CIDR(nac_val, nac_prefix)                           \
    if ((nac_prefix) > 64) {                                            \
        if ((nac_prefix) < 128) {                                       \
            (nac_val)->ip[1] &= ~(UINT64_MAX >> ((nac_prefix) - 64));   \
        }                                                               \
    } else {                                                            \
        (nac_val)->ip[1] = 0;                                           \
        if ((nac_prefix) < 64) {                                        \
            assert((nac_prefix) > 0);                                   \
            (nac_val)->ip[0] &= ~(UINT64_MAX >> (nac_prefix));          \
        }                                                               \
    }

/* Copy the ns128_t* from 'ncam_src' to 'ncam_dest' and apply the CIDR
 * mask specified in 'nac_prefix' */
#define NS128_COPY_AND_MASK(ncam_dest, ncam_src, ncam_prefix)           \
    if ((ncam_prefix) > 64) {                                           \
        (ncam_dest)->ip[0] = (ncam_src)->ip[0];                         \
        if ((ncam_prefix) < 128) {                                      \
            (ncam_dest)->ip[1] = ((ncam_src)->ip[1]                     \
                                  & ~(UINT64_MAX >> ((ncam_prefix)-64))); \
        } else {                                                        \
            assert((ncam_prefix) == 128);                               \
            (ncam_dest)->ip[1] = (ncam_src)->ip[1];                     \
        }                                                               \
    } else {                                                            \
        (ncam_dest)->ip[1] = 0;                                         \
        if ((ncam_prefix) < 64) {                                       \
            assert((ncam_prefix) > 0);                                  \
            (ncam_dest)->ip[0] = ((ncam_src)->ip[0]                     \
                                  & ~(UINT64_MAX >> (ncam_prefix)));    \
        } else {                                                        \
            assert((ncam_prefix) == 64);                                \
            (ncam_dest)->ip[0] = (ncam_src)->ip[0];                     \
        }                                                               \
    }

/* Set the ns128_t* in 'nstp_val' to 1 shifted to the left 'nstp_pwr2'
 * positions. */
#define NS128_SET_TO_POWER2(nstp_val, nstp_pwr2)                \
    if ((nstp_pwr2) >= 64) {                                    \
        (nstp_val)->ip[0] = UINT64_C(1) << ((nstp_pwr2) - 64);  \
        (nstp_val)->ip[1] = 0;                                  \
    } else {                                                    \
        (nstp_val)->ip[0] = 0;                                  \
        (nstp_val)->ip[1] = UINT64_C(1) << (nstp_pwr2);         \
    }

/* Add the integer value 'nav_int' (a uint64_t) to the ns128_t*
 * 'nav_sum'. */
#define NS128_ADD_UINT64(nav_sum, nav_int)                      \
    if ((nav_sum)->ip[1] < (UINT64_MAX - (nav_int))) {          \
        (nav_sum)->ip[1] += (nav_int);                          \
    } else {                                                    \
        (nav_sum)->ip[1] -= ((UINT64_MAX - (nav_int)) + 1);     \
        ++(nav_sum)->ip[0];                                     \
    }

/* Add the ns128_t* 'nan_val' to the ns128_t* 'nan_sum'. */
#define NS128_ADD_NS128(nan_sum, nan_val)                               \
    if ((nan_sum)->ip[1] < (UINT64_MAX - (nan_val)->ip[1])) {           \
        (nan_sum)->ip[1] += (nan_val)->ip[1];                           \
        (nan_sum)->ip[0] += (nan_val)->ip[0];                           \
    } else {                                                            \
        (nan_sum)->ip[1] -= ((UINT64_MAX - (nan_val)->ip[1]) + 1);      \
        (nan_sum)->ip[0] += 1 + (nan_val)->ip[0];                       \
    }

/* Return "" if the value in the ns128_t* 'np_val' is 1, return "s"
 * otherwise. */
#define NS128_PLURAL(np_val)                                            \
    (((0 == (np_val)->ip[0]) && (1 == (np_val)->ip[1])) ? "" : "s")



/* forward type declarations */

typedef struct netstruct_column_st netstruct_column_t;
typedef struct netstruct_cidr_v4_st netstruct_cidr_v4_t;
typedef struct netstruct_cidr_v6_st netstruct_cidr_v6_t;

/* sk_netstruct_t: The context object that holds the current status
 * and the user's preferences. */
struct sk_netstruct_st {
    /* output stream where data is written */
    skstream_t             *outstrm;

    /* This is an array; each entry is a CIDR block to print and/or
     * summarize.  The array's length is one more that the value in
     * the 'total_level' member.  The array is ordered from the CIDR
     * with the fewest hosts to the one with the most hosts: position
     * 0 represents a host; cblock[total_level] represents all of the
     * possible IP space. */
    union cblock_un {
        netstruct_cidr_v4_t  *v4;
        netstruct_cidr_v6_t  *v6;
    }                       cblock;

    /* This is an array that has the same number of elements as the
     * 'cblock' member.  Each member of this array says whether the
     * cblock is to be printed and, if so, the column width and column
     * indentation to use. */
    netstruct_column_t     *column;

    /* previous IP */
    skipaddr_t              prev_ipaddr;

    /* the position in the 'cblock[]' member array where the totals
     * for all of the IP space are. this value is one less than the
     * total number of entries in cblock[]. */
    uint32_t                total_level;

    /* the width of the 'count' column */
    int                     count_width;

    /* how to print the IP address. Values from "enum skipaddr_flags_t" */
    uint32_t                ip_format;

    /* delimiter to print between columns */
    char                    delimiter;

    /* delimiter or empty string to go between IP and Count */
    char                    ip_count_delim[2];

    /* delimiter or empty string to go between Count and EOL */
    char                    count_eol_delim[2];

    /* whether the blocks to print have been initialized */
    unsigned                parsed_input        :1;

    /* whether this entry is the first entry to be printed */
    unsigned                first_entry         :1;

    /* whether this entry is final entry to be printed */
    unsigned                final_entry         :1;

    /* whether to suppress fixed width columnar output */
    unsigned                no_columns          :1;

    /* whether to suppress the final delimiter */
    unsigned                no_final_delimiter  :1;

    /* whether to print the summary */
    unsigned                print_summary       :1;

    /* whether the caller will be passing a valid 'count' value. */
    unsigned                use_count           :1;

    /* whether to print the number of IPs */
    unsigned                print_ip_count      :1;

    /* whether this structure is for ipv6 */
    unsigned                is_ipv6             :1;
};

/* netstruct_cidr_v4_t: the 'cblock' member of struct sk_netstruct_st
 * contains a variable-length array of this structure. see the
 * description of cblock above for more info. */
struct netstruct_cidr_v4_st {
    /* this is an array. Each entry represents a smaller CIDR block
     * contained within this CIDR block.  When printing data for
     * /8,/16,/24, and this netstruct_cidr_v4_t is for a /8, cb_ips
     * holds the number of /16's and /24's that have been seen.  array
     * length is one less than the position of this netstruct_cidr_v4_t
     * in the 'cblock' array. */
    uint64_t   *cb_ips;

    /* The sum of the counters seen at this level. */
    uint64_t    cb_sum;

    /* mask that passes the most significant 'cb_bits' bits; if
     * cb_bits is /8, this will be 0xFF000000. */
    uint32_t    cb_mask;

    /* the CIDR prefix for this netblock; /8 for example */
    uint32_t    cb_bits;
};

/* netstruct_cidr_v6_t: the 'cblock' member of struct sk_netstruct_st
 * contains a variable-length array of this structure. see the
 * description of cblock above for more info. */
struct netstruct_cidr_v6_st {
    /* this is an array. Each entry represents a smaller CIDR block
     * contained within this CIDR block. */
    ns128_t    *cb_ips;

    /* The sum of the counters. */
    ns128_t     cb_sum;

#if 0
    /* mask that passes the most significant 'cb_bits' bits */
    ns128_t     cb_mask;
#endif

    /* the CIDR prefix for this netblock; /8 for example */
    uint32_t    cb_bits;
};

/* netstruct_column_t: the 'column' member of struct sk_netstruct_st
 * contains a variable-length array of this structure. see the
 * description of column above for more info. */
struct netstruct_column_st {
    /* when printing, the number of spaces by which to indent this
     * netstruct_cidr_v*_t block. */
    int         co_indent;

    /* when printing, the number of characters to allow for printing
     * the IP referenced by the netstruct_cidr_v*_t. */
    int         co_width;

    /* whether to output the data for the netstruct_cidr_v*_t
     * block. If this is 0, the block is only for summing smaller
     * blocks. */
    unsigned    co_print  :1;
};


/* LOCAL VARIABLES */

/* connecting words used when printing summary */
static const char *summary_strings[] = {" in", ",", " and", ", and"};


/* LOCAL FUNCTION PROTOTYPES */

static void
netStructureInitialize(
    sk_netstruct_t     *ns,
    int                 has_count);
#if SK_ENABLE_IPV6
static char *
netStructureNS128ToString(
    const ns128_t      *val,
    char               *buf,
    size_t              buflen);
#endif  /* SK_ENABLE_IPV6 */
static void
netStructurePreparePrint(
    sk_netstruct_t     *ns);
static void
netStructurePrintEmpty(
    sk_netstruct_t     *ns);


/* FUNCTION DEFINITIONS */

/* Add a CIDR block to the network-structure */
static void
netStructureAddCIDRV4(
    sk_netstruct_t     *ns,
    const skipaddr_t   *base_ipaddr,
    uint32_t            prefix)
{
    char ip_buf[SKIPADDR_CIDR_STRLEN];
    /* 'joiner' will point into 'summary_strings' array */
    const char *joiner;
    skipaddr_t ipaddr;
    uint32_t base_ip;
    uint32_t xor_ips;
    uint32_t ip;
    uint32_t prev_ip;
    uint32_t print_id;
    uint32_t summary_id;
    uint32_t print_count;
    uint32_t summary_count;
    uint32_t step;
    uint32_t max_block = 0;
    uint32_t i, j, k;
    int cidr_adjust = 0;

    assert(ns);
    assert(base_ipaddr);
    if (ns->use_count) {
        skAppPrintErr("May only use skNetStructureAddCIDR() when"
                      " sk_netstruct_t was created without 'has_count'");
        skAbort();
    }

    if (skipaddrGetAsV4(base_ipaddr, &base_ip)) {
        return;
    }
    if (skipaddrIsV6(base_ipaddr)) {
        if (prefix > 128 || prefix < 96) {
            skAppPrintErr("Invalid IPv6 prefix %u", prefix);
            skAbort();
        }
        prefix -= 96;
    } else if (prefix > 32) {
        skAppPrintErr("Invalid IPv4 prefix %u", prefix);
        skAbort();
    }
    if (prefix < 32) {
        base_ip &= ~(UINT32_MAX >> prefix);
    }

    if (SKIPADDR_MAP_V4 & ns->ip_format) {
        cidr_adjust = 96;
    }

    /* determine which blocks we need to increment and summarize
     * blocks as required */
    if (ns->first_entry) {
        /* set up for printing */
        netStructurePreparePrint(ns);
        ns->first_entry = 0;

        /* treat this has a change across all blocks */
        max_block = ns->total_level;
    } else {
        /* calculate changes in blocks and close out blocks */
        prev_ip = skipaddrGetV4(&ns->prev_ipaddr);

        if (ns->final_entry) {
            /* for the last entry, we need to close all the blocks and
             * print all summaries. */
            max_block = ns->total_level;
        } else if (base_ip <= prev_ip) {
            skAppPrintErr(("New IP not greater than previous IP:"
                           " new %" PRIx32 ", prev %" PRIx32),
                          base_ip, prev_ip);
            skAbort();
        } else {
            /* compare the current IP to the previous and determine
             * the block holding the most significant changed bit */
            xor_ips = base_ip ^ prev_ip;
            for (max_block = ns->total_level - 1; max_block > 0; --max_block) {
                if (xor_ips & ns->cblock.v4[max_block].cb_mask) {
                    break;
                }
            }
        }

        for (i = 1; i <= max_block; ++i) {
            /* only print if requested and host count is non-zero */
            if ( !ns->column[i].co_print || !ns->cblock.v4[i].cb_ips[0]) {
                continue;
            }
            /* Row label: IP/CIDR or NET_TOTAL_TITLE */
            if (ns->total_level == i) {
                strncpy(ip_buf, NET_TOTAL_TITLE, sizeof(ip_buf));
            } else {
                ip = prev_ip & ns->cblock.v4[i].cb_mask;
                skipaddrSetV4(&ipaddr, &ip);
                skipaddrCidrString(ip_buf, &ipaddr,
                                   cidr_adjust + ns->cblock.v4[i].cb_bits,
                                   ns->ip_format);
            }
            if (ns->print_ip_count) {
                skStreamPrint(ns->outstrm, "%*s%*s%s %" PRIu64 "\n",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, ns->cblock.v4[i].cb_ips[0]);
            } else {
                skStreamPrint(ns->outstrm, ("%*s%*s%s %" PRIu64 " host%s"),
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, ns->cblock.v4[i].cb_ips[0],
                              PLURAL(ns->cblock.v4[i].cb_ips[0]));
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    skStreamPrint(ns->outstrm, ("%s %" PRIu64 " /%d%s"),
                                  joiner,
                                  ns->cblock.v4[i].cb_ips[j],
                                  cidr_adjust + ns->cblock.v4[j].cb_bits,
                                  PLURAL(ns->cblock.v4[i].cb_ips[j]));
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }

        /* Now that we have closed the blocks, return if we are at the
         * end of the data set. */
        if (ns->final_entry) {
            return;
        }

        /* Reset the IP count for all blocks that are smaller than the
         * one where the change was seen */
        for (i = 1; i <= max_block; ++i) {
            memset(ns->cblock.v4[i].cb_ips, 0, (i * sizeof(uint64_t)));
        }
    } /* if !first_entry */

    /* store the end of the CIDR block */
    if (32 == prefix) {
        skipaddrSetV4(&ns->prev_ipaddr, &base_ip);
    } else {
        prev_ip = base_ip | (UINT32_MAX >> prefix);
        skipaddrSetV4(&ns->prev_ipaddr, &prev_ip);
    }

    /* Increment the CIDR count for all blocks that are larger
     * (numerically smaller) than the one where the change was seen */
    for (i = 1; i <= ns->total_level; ++i) {
        if (ns->cblock.v4[i].cb_bits < prefix) {
            for (j = 0; j < i && j <= max_block; ++j) {
                if (ns->cblock.v4[j].cb_bits >= prefix) {
                    ns->cblock.v4[i].cb_ips[j]
                        += 1u << (ns->cblock.v4[j].cb_bits - prefix);
                } else {
                    ++ns->cblock.v4[i].cb_ips[j];
                }
            }
        }
    }

    /* Find the index in the cblock.v4[] array that contains the
     * numerically largest prefix that must be printed. */
    print_id = UINT32_MAX;
    for (i = 0; i < ns->total_level && prefix <= ns->cblock.v4[i].cb_bits; ++i)
    {
        if (ns->column[i].co_print) {
            print_id = i;
            break;
        }
    }
    if (UINT32_MAX == print_id) {
        return;
    }

    /* Find the index in the cblock.v4[] array that contains the prefix
     * numerically smaller than 'print_id' where a summary must be
     * printed. */
    summary_id = UINT32_MAX;
    for (++i; i < ns->total_level && prefix <= ns->cblock.v4[i].cb_bits; ++i) {
        if (ns->column[i].co_print) {
            summary_id = i;
            break;
        }
    }

    /* calculate the number of printing iterations to make before
     * printing a summary, and determine the number of summary
     * iterations to make */
    if (UINT32_MAX == summary_id) {
        print_count = 1u << (ns->cblock.v4[print_id].cb_bits - prefix);
        summary_count = 1;
        summary_id = print_id;
    } else {
        print_count = 1u << (ns->cblock.v4[print_id].cb_bits
                             - ns->cblock.v4[summary_id].cb_bits);
        summary_count = 1u << (ns->cblock.v4[summary_id].cb_bits - prefix);
    }

    /* determine how much to increase the IP on each print
     * iteration */
    step = 1u << (32 - ns->cblock.v4[print_id].cb_bits);

    for (k = 0; k < summary_count; ++k) {
        /* print all the blocks at the 'print_id' level */
        ip = base_ip | (k << (32 - ns->cblock.v4[summary_id].cb_bits));
        if (0 == print_id) {
            /* print each host */
            skipaddrSetV4(&ipaddr, &ip);
            for (i = 0; i < print_count; ++i) {
                skStreamPrint(ns->outstrm, "%*s%*s%s\n",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width,
                              skipaddrString(ip_buf, &ipaddr, ns->ip_format),
                              ns->ip_count_delim);
                skipaddrIncrement(&ipaddr);
            }
        } else if (ns->print_ip_count) {
            /* print IP/netblock and a count of IPs */
            for (i = 0; i < print_count; ++i) {
                skipaddrSetV4(&ipaddr, &ip);
                skipaddrCidrString(ip_buf, &ipaddr,
                                   ns->cblock.v4[print_id].cb_bits,
                                   ns->ip_format);
                skStreamPrint(ns->outstrm, "%*s%*s%s %" PRIu32 "\n",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width, ip_buf,
                              ns->ip_count_delim,
                              1u << (32 - ns->cblock.v4[print_id].cb_bits));
                ip += step;
            }
        } else {
            /* print IP/netblock, IP count, sub-netblock count */
            for (i = 0; i < print_count; ++i) {
                skipaddrSetV4(&ipaddr, &ip);
                skipaddrCidrString(ip_buf, &ipaddr,
                                   ns->cblock.v4[print_id].cb_bits,
                                   ns->ip_format);
                skStreamPrint(ns->outstrm, "%*s%*s%s %" PRIu32 " hosts",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width, ip_buf,
                              ns->ip_count_delim,
                              1u << (32 - ns->cblock.v4[print_id].cb_bits));
                joiner = NULL;
                for (j = print_id - 1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    skStreamPrint(ns->outstrm, ("%s %" PRIu32 " /%ds"),
                                  joiner,
                                  (1u << (ns->cblock.v4[j].cb_bits
                                          - ns->cblock.v4[print_id].cb_bits)),
                                  cidr_adjust + ns->cblock.v4[j].cb_bits);
                }
                skStreamPrint(ns->outstrm, "\n");
                ip += step;
            }
        }

        /* nothing to do if there was only one level to print */
        if (summary_id == print_id) {
            return;
        }

        /* print any summary blocks that the CIDR block spans */
        ip = base_ip | (k << (32 - ns->cblock.v4[summary_id].cb_bits));
        skipaddrSetV4(&ipaddr, &ip);
        for (i = summary_id; i < ns->total_level; ++i) {
            if (!ns->column[i].co_print) {
                continue;
            }
            if (prefix > ns->cblock.v4[i].cb_bits) {
                /* cblock[i] is broader than the prefix */
                break;
            }
            if ((k & ((1u << (ns->cblock.v4[summary_id].cb_bits
                              - ns->cblock.v4[i].cb_bits)) - 1))
                != ((1u << (ns->cblock.v4[summary_id].cb_bits
                            - ns->cblock.v4[i].cb_bits)) - 1))
            {
                /* this netblock is not full yet */
                break;
            }
            /* mask the IP for printing */
            skipaddrApplyCIDR(&ipaddr, ns->cblock.v4[i].cb_bits);
            skipaddrCidrString(ip_buf, &ipaddr, ns->cblock.v4[i].cb_bits,
                               ns->ip_format);
            if (ns->print_ip_count) {
                skStreamPrint(ns->outstrm, "%*s%*s%s %" PRIu32 "\n",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              1u << (32 - ns->cblock.v4[i].cb_bits));
            } else {
                skStreamPrint(ns->outstrm, "%*s%*s%s %" PRIu32 " hosts",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              1u << (32 - ns->cblock.v4[i].cb_bits));
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    skStreamPrint(ns->outstrm, ("%s %" PRIu32 " /%ds"),
                                  joiner,
                                  (1u << (ns->cblock.v4[j].cb_bits
                                          - ns->cblock.v4[i].cb_bits)),
                                  cidr_adjust + ns->cblock.v4[j].cb_bits);
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }
    }
}

#if SK_ENABLE_IPV6
/* Add a CIDR block to the network-structure */
static void
netStructureAddCIDRV6(
    sk_netstruct_t     *ns,
    const skipaddr_t   *base_ipaddr,
    uint32_t            prefix)
{
    char ip_buf[SKIPADDR_CIDR_STRLEN];
    /* buffer for holding 128-bit counters */
    char count_buf[64];
    /* 'joiner' will point into 'summary_strings' array */
    const char *joiner;
    skipaddr_t ipaddr;
    ns128_t base_ip;
    ns128_t ip;
    ns128_t prev_ip;
    ns128_t count;
    uint64_t print_id;
    uint64_t summary_id;
    ns128_t print_count;
    ns128_t summary_count;
    ns128_t print_step;
    ns128_t summary_step;
    ns128_t summary_ip;
    uint32_t max_block = 0;
    uint64_t i, j, k;

    assert(ns);
    assert(base_ipaddr);
    if (ns->use_count) {
        skAppPrintErr("May only use skNetStructureAddCIDR() when"
                      " sk_netstruct_t was created without 'has_count'");
        skAbort();
    }

    NS128_FROM_IPADDRV6(&base_ip, base_ipaddr);
    if (skipaddrIsV6(base_ipaddr)) {
        if (prefix > 128) {
            skAppPrintErr("Invalid IPv6 prefix %u", prefix);
            skAbort();
        }
    } else {
        if (prefix > 32) {
            skAppPrintErr("Invalid IPv4 prefix %u", prefix);
            skAbort();
        }
        prefix += 96;
    }
    NS128_APPLY_CIDR(&base_ip, prefix);

    /* determine which blocks we need to increment and summarize
     * blocks as required */
    if (ns->first_entry) {
        /* set up for printing */
        netStructurePreparePrint(ns);
        ns->first_entry = 0;

        /* treat this has a change across all blocks */
        max_block = ns->total_level;
    } else {
        /* calculate changes in blocks and close out blocks */
        NS128_FROM_IPADDRV6(&prev_ip, &ns->prev_ipaddr);

        if (ns->final_entry) {
            /* for the last entry, we need to close all the blocks and
             * print all summaries. */
            max_block = ns->total_level;
        } else if ((base_ip.ip[0] < prev_ip.ip[0])
                   || ((base_ip.ip[0] == prev_ip.ip[0])
                       && (base_ip.ip[1] < prev_ip.ip[1])))
        {
            skAppPrintErr(("New IP not greater than previous IP:"
                           " new %" PRIx64 "%16" PRIx64
                           ", prev %" PRIx64 "%16" PRIx64),
                          base_ip.ip[0], base_ip.ip[1],
                          prev_ip.ip[0], prev_ip.ip[1]);
            skAbort();
        } else {
            /* compare the current IP to the previous and determine
             * the block holding the most significant changed bit */
            int pos;
            if (base_ip.ip[0] ^ prev_ip.ip[0]) {
                pos = skIntegerLog2(base_ip.ip[0] ^ prev_ip.ip[0]);
                assert(-1 != pos);
                pos = 64 - pos;
            } else {
                pos = skIntegerLog2(base_ip.ip[1] ^ prev_ip.ip[1]);
                assert(-1 != pos);
                pos = 128 - pos;
            }
            for (max_block = ns->total_level - 1; max_block > 0; --max_block) {
                if ((uint32_t)pos <= ns->cblock.v6[max_block].cb_bits) {
                    break;
                }
            }
        }

        for (i = 1; i <= max_block; ++i) {
            /* only print if requested and host count is non-zero */
            if (!ns->column[i].co_print
                || (!ns->cblock.v6[i].cb_ips[0].ip[0]
                    && !ns->cblock.v6[i].cb_ips[0].ip[1]))
            {
                continue;
            }

            /* Row label: IP/CIDR or NET_TOTAL_TITLE */
            if (ns->total_level == i) {
                strncpy(ip_buf, NET_TOTAL_TITLE, sizeof(ip_buf));
            } else {
                NS128_COPY_AND_MASK(&ip, &prev_ip, ns->cblock.v6[i].cb_bits);
                NS128_TO_IPADDR(&ip, &ipaddr);
                skipaddrCidrString(ip_buf, &ipaddr, ns->cblock.v6[i].cb_bits,
                                   ns->ip_format);
            }
            netStructureNS128ToString(&ns->cblock.v6[i].cb_ips[0],
                                      count_buf, sizeof(count_buf));
            if (ns->print_ip_count) {
                skStreamPrint(ns->outstrm, "%*s%*s%s %s\n",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, count_buf);
            } else {
                skStreamPrint(ns->outstrm, ("%*s%*s%s %s host%s"),
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, count_buf,
                              NS128_PLURAL(&ns->cblock.v6[i].cb_ips[0]));
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    netStructureNS128ToString(&ns->cblock.v6[i].cb_ips[j],
                                              count_buf, sizeof(count_buf));
                    skStreamPrint(ns->outstrm, ("%s %s /%d%s"),
                                  joiner, count_buf,
                                  ns->cblock.v6[j].cb_bits,
                                  NS128_PLURAL(&ns->cblock.v6[i].cb_ips[j]));
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }

        /* Now that we have closed the blocks, return if we are at the
         * end of the data set. */
        if (ns->final_entry) {
            return;
        }

        /* Reset the IP count for all blocks that are smaller than the
         * one where the change was seen */
        for (i = 1; i <= max_block; ++i) {
            memset(ns->cblock.v6[i].cb_ips, 0, (i * sizeof(ns128_t)));
        }
    } /* if !first_entry */

    /* store the end of the CIDR block */
    if (prefix > 64) {
        if (128 == prefix) {
            NS128_TO_IPADDR(&base_ip, &ns->prev_ipaddr);
        } else {
            prev_ip.ip[0] = base_ip.ip[0];
            prev_ip.ip[1] = base_ip.ip[1] | (UINT64_MAX >> (prefix - 64));
            NS128_TO_IPADDR(&prev_ip, &ns->prev_ipaddr);
        }
    } else {
        prev_ip.ip[1] = UINT64_MAX;
        if (prefix < 64) {
            prev_ip.ip[0] = base_ip.ip[0] | (UINT64_MAX >> prefix);
        } else {
            prev_ip.ip[0] = base_ip.ip[0];
        }
        NS128_TO_IPADDR(&prev_ip, &ns->prev_ipaddr);
    }

    /* Increment the CIDR count for all blocks that are smaller than
     * the one where the change was seen */
    for (i = 1; i <= ns->total_level; ++i) {
        if (ns->cblock.v6[i].cb_bits < prefix) {
            for (j = 0; j < i && j <= max_block; ++j) {
                if (ns->cblock.v6[j].cb_bits >= prefix) {
                    NS128_SET_TO_POWER2(&count,
                                        (ns->cblock.v6[j].cb_bits - prefix));
                    NS128_ADD_NS128(&ns->cblock.v6[i].cb_ips[j], &count);
                } else {
                    NS128_ADD_UINT64(&ns->cblock.v6[i].cb_ips[j], 1);
                }
            }
        }
    }

    /* Find the index in the cblock.v6[] array that contains the
     * numerically largest prefix that must be printed. */
    print_id = UINT32_MAX;
    for (i = 0; i < ns->total_level && prefix <= ns->cblock.v6[i].cb_bits; ++i)
    {
        if (ns->column[i].co_print) {
            print_id = i;
            break;
        }
    }
    if (UINT32_MAX == print_id) {
        return;
    }

    /* Find the index in the cblock.v6[] array that contains the prefix
     * numerically smaller than 'print_id' where a summary must be
     * printed. */
    summary_id = UINT32_MAX;
    for (++i; i < ns->total_level && prefix <= ns->cblock.v6[i].cb_bits; ++i) {
        if (ns->column[i].co_print) {
            summary_id = i;
            break;
        }
    }

    /* calculate the number of printing iterations to make before
     * printing a summary, and determine the number of summary
     * iterations to make */
    if (UINT32_MAX == summary_id) {
        NS128_SET_TO_POWER2(&print_count,
                            (ns->cblock.v6[print_id].cb_bits - prefix));
        summary_count.ip[0] = 0;
        summary_count.ip[1] = 1;
        summary_id = print_id;
    } else {
        NS128_SET_TO_POWER2(&print_count,
                            (ns->cblock.v6[print_id].cb_bits
                             - ns->cblock.v6[summary_id].cb_bits));
        NS128_SET_TO_POWER2(&summary_count,
                            (ns->cblock.v6[summary_id].cb_bits - prefix));
    }
    if (summary_count.ip[0] || print_count.ip[0]) {
        skAppPrintErr("More than 2^64 output lines requested");
        return;
    }

    /* determine how much to increase the IP on each print
     * iteration */
    NS128_SET_TO_POWER2(&print_step, (128 - ns->cblock.v6[print_id].cb_bits));

    /* set values that initialize the summary IP on each loop */
    NS128_SET_TO_POWER2(&summary_step,
                        (128 - ns->cblock.v6[summary_id].cb_bits));
    summary_ip = base_ip;

    for (k = 0; k < summary_count.ip[1]; ++k) {
        if (k > 0) {
            NS128_ADD_NS128(&summary_ip, &summary_step);
        }
        ip = summary_ip;

        /* print all the blocks at the 'print_id' level */
        if (0 == print_id) {
            /* print each host */
            NS128_TO_IPADDR(&ip, &ipaddr);
            for (i = 0; i < print_count.ip[1]; ++i) {
                skStreamPrint(ns->outstrm, "%*s%*s%s\n",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width,
                              skipaddrString(ip_buf, &ipaddr, ns->ip_format),
                              ns->ip_count_delim);
                skipaddrIncrement(&ipaddr);
            }
        } else if (ns->print_ip_count) {
            /* print IP/netblock and a count of IPs */
            for (i = 0; i < print_count.ip[1]; ++i) {
                NS128_TO_IPADDR(&ip, &ipaddr);
                skipaddrCidrString(ip_buf, &ipaddr,
                                   ns->cblock.v6[print_id].cb_bits,
                                   ns->ip_format);
                NS128_SET_TO_POWER2(&count,
                                    (128 - ns->cblock.v6[print_id].cb_bits));
                netStructureNS128ToString(&count, count_buf, sizeof(count_buf));
                skStreamPrint(ns->outstrm, "%*s%*s%s %s\n",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width, ip_buf,
                              ns->ip_count_delim, count_buf);
                NS128_ADD_NS128(&ip, &print_step);
            }
        } else {
            /* print IP/netblock, IP count, sub-netblock count */
            for (i = 0; i < print_count.ip[1]; ++i) {
                NS128_TO_IPADDR(&ip, &ipaddr);
                skipaddrCidrString(ip_buf, &ipaddr,
                                   ns->cblock.v6[print_id].cb_bits,
                                   ns->ip_format);
                NS128_SET_TO_POWER2(&count,
                                    (128 - ns->cblock.v6[print_id].cb_bits));
                netStructureNS128ToString(&count, count_buf, sizeof(count_buf));
                skStreamPrint(ns->outstrm, "%*s%*s%s %s hosts",
                              ns->column[print_id].co_indent, "",
                              ns->column[print_id].co_width, ip_buf,
                              ns->ip_count_delim, count_buf);
                joiner = NULL;
                for (j = print_id - 1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    NS128_SET_TO_POWER2(&count,
                                        (ns->cblock.v6[j].cb_bits
                                         - ns->cblock.v6[print_id].cb_bits));
                    netStructureNS128ToString(&count,
                                              count_buf, sizeof(count_buf));
                    skStreamPrint(ns->outstrm, ("%s %s /%ds"),
                                  joiner, count_buf, ns->cblock.v6[j].cb_bits);
                }
                skStreamPrint(ns->outstrm, "\n");
                NS128_ADD_NS128(&ip, &print_step);
            }
        }

        /* nothing to do if there was only one level to print */
        if (summary_id == print_id) {
            return;
        }

        /* print any summary blocks that the CIDR block spans */
        ip = summary_ip;
        NS128_TO_IPADDR(&ip, &ipaddr);
        for (i = summary_id; i < ns->total_level; ++i) {
            if (!ns->column[i].co_print) {
                continue;
            }
            if (prefix > ns->cblock.v6[i].cb_bits) {
                /* cblock[i] is broader than the prefix */
                break;
            }
            if ((k & ((1u << (ns->cblock.v6[summary_id].cb_bits
                              - ns->cblock.v6[i].cb_bits)) - 1))
                != ((1u << (ns->cblock.v6[summary_id].cb_bits
                            - ns->cblock.v6[i].cb_bits)) - 1))
            {
                /* this netblock is not full yet */
                break;
            }
            /* mask the IP for printing */
            skipaddrApplyCIDR(&ipaddr, ns->cblock.v6[i].cb_bits);
            skipaddrCidrString(ip_buf, &ipaddr, ns->cblock.v6[i].cb_bits,
                               ns->ip_format);
            if (ns->print_ip_count) {
                NS128_SET_TO_POWER2(&count, (128 - ns->cblock.v6[i].cb_bits));
                netStructureNS128ToString(&count, count_buf, sizeof(count_buf));
                skStreamPrint(ns->outstrm, "%*s%*s%s %s\n",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, count_buf);
            } else {
                NS128_SET_TO_POWER2(&count, (128 - ns->cblock.v6[i].cb_bits));
                netStructureNS128ToString(&count, count_buf, sizeof(count_buf));
                skStreamPrint(ns->outstrm, "%*s%*s%s %s hosts",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim, count_buf);
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    NS128_SET_TO_POWER2(&count,
                                        (ns->cblock.v6[j].cb_bits
                                         - ns->cblock.v6[i].cb_bits));
                    netStructureNS128ToString(&count,
                                              count_buf, sizeof(count_buf));
                    skStreamPrint(ns->outstrm, ("%s %s /%ds"),
                                  joiner, count_buf, ns->cblock.v6[j].cb_bits);
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }
    }
}
#endif  /* SK_ENABLE_IPV6 */

void
skNetStructureAddCIDR(
    sk_netstruct_t     *ns,
    const skipaddr_t   *base_ipaddr,
    uint32_t            prefix)
{
    /* initialize the blocks */
    if (!ns->parsed_input) {
        skNetStructureParse(ns, NULL);
    }
#if SK_ENABLE_IPV6
    if (ns->is_ipv6) {
        netStructureAddCIDRV6(ns, base_ipaddr, prefix);
        return;
    }
#endif  /* SK_ENABLE_IPV6 */
    netStructureAddCIDRV4(ns, base_ipaddr, prefix);
}

/* Add a key/counter to the network-structure */
static void
netStructureAddKeyCounterV4(
    sk_netstruct_t     *ns,
    const skipaddr_t   *ipaddr,
    const uint64_t     *count)
{
    char ip_buf[SKIPADDR_CIDR_STRLEN];
    /* 'joiner' will point into 'summary_strings' array */
    const char *joiner;
    uint32_t ip;
    uint32_t prev_ip;
    uint32_t xor_ips;
    uint32_t max_block = 0;
    uint32_t i, j;

    assert(ns);
    assert(ipaddr);
    assert(count);
    if (!ns->use_count) {
        skAppPrintErr("May only use skNetStructureAddKeyCounter() when"
                      " sk_netstruct_t was created with 'has_count'");
        skAbort();
    }
    assert(0 == ns->print_ip_count);

    if (skipaddrGetAsV4(ipaddr, &ip)) {
        return;
    }

    /* determine which blocks we need to increment and summarize
     * blocks as required */
    if (ns->first_entry) {
        /* set up for printing */
        netStructurePreparePrint(ns);
        ns->first_entry = 0;

        /* treat this has a change across all blocks */
        max_block = ns->total_level;
    } else {
        /* calculate changes in blocks and close out blocks */
        prev_ip = skipaddrGetV4(&ns->prev_ipaddr);

        if (ns->final_entry) {
            /* for the last entry, we need to close all the blocks and
             * print all summaries. */
            max_block = ns->total_level;
        } else if (ip <= prev_ip) {
            skAppPrintErr(("New IP not greater than previous IP:"
                           " new %" PRIx32 ", prev %" PRIx32),
                          ip, prev_ip);
            skAbort();
        } else {
            /* compare the current IP to the previous and determine
             * the block holding the most significant changed bit */
            xor_ips = ip ^ prev_ip;
            for (max_block = ns->total_level - 1; max_block > 0; --max_block) {
                if (xor_ips & ns->cblock.v4[max_block].cb_mask) {
                    break;
                }
            }
        }

        for (i = 1; i <= max_block; ++i) {
            /* only print if requested */
            if ( !ns->column[i].co_print) {
                continue;
            }
            /* Row label: IP/CIDR or NET_TOTAL_TITLE */
            if (ns->total_level == i) {
                strncpy(ip_buf, NET_TOTAL_TITLE, sizeof(ip_buf));
            } else {
                skipaddr_t tmp_ipaddr;
                uint32_t tmp_ip;

                tmp_ip = prev_ip & ns->cblock.v4[i].cb_mask;
                skipaddrSetV4(&tmp_ipaddr, &tmp_ip);
                skipaddrCidrString(ip_buf, &tmp_ipaddr,
                                   ns->cblock.v4[i].cb_bits, ns->ip_format);
            }
            if (!ns->print_summary) {
                skStreamPrint(ns->outstrm, ("%*s%*s%s%*" PRIu64 "%s\n"),
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              ns->count_width, ns->cblock.v4[i].cb_sum,
                              ns->count_eol_delim);
            } else {
                skStreamPrint(ns->outstrm,
                              ("%*s%*s%s%*" PRIu64 "%s %" PRIu64 " host%s"),
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              ns->count_width, ns->cblock.v4[i].cb_sum,
                              ns->count_eol_delim, ns->cblock.v4[i].cb_ips[0],
                              PLURAL(ns->cblock.v4[i].cb_ips[0]));
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }

                    skStreamPrint(ns->outstrm, ("%s %" PRIu64 " /%u%s"),
                                  joiner,
                                  ns->cblock.v4[i].cb_ips[j],
                                  ns->cblock.v4[j].cb_bits,
                                  PLURAL(ns->cblock.v4[i].cb_ips[j]));
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }

        /* Now that we have closed the blocks, return if we are at the
         * end of the data set. */
        if (ns->final_entry) {
            return;
        }

        /* Reset the IP count and counters for all blocks that are
         * smaller than the one where the change was seen */
        for (i = 1; i <= max_block; ++i) {
            memset(ns->cblock.v4[i].cb_ips, 0, (i * sizeof(uint64_t)));
            ns->cblock.v4[i].cb_sum = 0;
        }
    } /* if !first_entry */

    /* store this IP as IPv4 */
    skipaddrSetV4(&ns->prev_ipaddr, &ip);

    /* Increment the CIDR count and sums for all blocks that are
     * larger (numerically smaller) than the one where the change was
     * seen */
    for (i = 1; i <= ns->total_level; ++i) {
        for (j = 0; j < i && j <= max_block; ++j) {
            ++ns->cblock.v4[i].cb_ips[j];
        }
        ns->cblock.v4[i].cb_sum += *count;
    }

    if (ns->column[0].co_print) {
        /* print the current IP and count */
        skStreamPrint(ns->outstrm, ("%*s%*s%s%*" PRIu64 "%s\n"),
                      ns->column[0].co_indent, "",
                      ns->column[0].co_width,
                      skipaddrString(ip_buf, &ns->prev_ipaddr, ns->ip_format),
                      ns->ip_count_delim,
                      ns->count_width, *count, ns->count_eol_delim);
    }
}

#if SK_ENABLE_IPV6
/* Add a key/counter to the network-structure */
static void
netStructureAddKeyCounterV6(
    sk_netstruct_t     *ns,
    const skipaddr_t   *ipaddr,
    const uint64_t     *count)
{
    char ip_buf[SKIPADDR_CIDR_STRLEN];
    /* buffers for holding 128-bit counters */
    char count_buf[64];
    char sum_buf[64];
    /* 'joiner' will point into 'summary_strings' array */
    const char *joiner;
    ns128_t ip;
    ns128_t prev_ip;
    uint32_t max_block = 0;
    uint32_t i, j;

    assert(ns);
    assert(ipaddr);
    assert(count);
    if (!ns->use_count) {
        skAppPrintErr("May only use skNetStructureAddKeyCounter() when"
                      " sk_netstruct_t was created with 'has_count'");
        skAbort();
    }
    assert(0 == ns->print_ip_count);

    NS128_FROM_IPADDRV6(&ip, ipaddr);

    /* determine which blocks we need to increment and summarize
     * blocks as required */
    if (ns->first_entry) {
        /* set up for printing */
        netStructurePreparePrint(ns);
        ns->first_entry = 0;

        /* treat this has a change across all blocks */
        max_block = ns->total_level;
    } else {
        /* calculate changes in blocks and close out blocks */
        NS128_FROM_IPADDRV6(&prev_ip, &ns->prev_ipaddr);

        if (ns->final_entry) {
            /* for the last entry, we need to close all the blocks and
             * print all summaries. */
            max_block = ns->total_level;
        } else if (((ip.ip[0] == prev_ip.ip[0]) && (ip.ip[1] <= prev_ip.ip[1]))
                   || (ip.ip[0] < prev_ip.ip[0]))
        {
            skAppPrintErr(("New IP not greater than previous IP:"
                           " new %" PRIx64 "%16" PRIx64
                           ", prev %" PRIx64 "%16" PRIx64),
                          ip.ip[0], ip.ip[1], prev_ip.ip[0], prev_ip.ip[1]);
            skAbort();
        } else {
            /* compare the current IP to the previous and determine
             * the block holding the most significant changed bit */
            int pos;
            if (ip.ip[0] ^ prev_ip.ip[0]) {
                pos = skIntegerLog2(ip.ip[0] ^ prev_ip.ip[0]);
                assert(-1 != pos);
                pos = 64 - pos;
            } else {
                pos = skIntegerLog2(ip.ip[1] ^ prev_ip.ip[1]);
                assert(-1 != pos);
                pos = 128 - pos;
            }
            for (max_block = ns->total_level - 1; max_block > 0; --max_block) {
                if ((uint32_t)pos <= ns->cblock.v6[max_block].cb_bits) {
                    break;
                }
            }
        }

        for (i = 1; i <= max_block; ++i) {
            /* only print if requested */
            if ( !ns->column[i].co_print) {
                continue;
            }

            /* Row label: IP/CIDR or NET_TOTAL_TITLE */
            if (ns->total_level == i) {
                strncpy(ip_buf, NET_TOTAL_TITLE, sizeof(ip_buf));
            } else {
                skipaddr_t tmp_ipaddr;
                ns128_t tmp_ip;

                NS128_COPY_AND_MASK(&tmp_ip,&prev_ip,ns->cblock.v6[i].cb_bits);
                NS128_TO_IPADDR(&tmp_ip, &tmp_ipaddr);
                skipaddrCidrString(ip_buf, &tmp_ipaddr,
                                   ns->cblock.v6[i].cb_bits, ns->ip_format);
            }
            netStructureNS128ToString(&ns->cblock.v6[i].cb_sum,
                                      sum_buf, sizeof(sum_buf));
            if (!ns->print_summary) {
                skStreamPrint(ns->outstrm, "%*s%*s%s%*s%s\n",
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              ns->count_width, sum_buf,
                              ns->count_eol_delim);
            } else {
                netStructureNS128ToString(&ns->cblock.v6[i].cb_ips[0],
                                          count_buf, sizeof(count_buf));
                skStreamPrint(ns->outstrm,
                              ("%*s%*s%s%*s%s %s host%s"),
                              ns->column[i].co_indent, "",
                              ns->column[i].co_width, ip_buf,
                              ns->ip_count_delim,
                              ns->count_width, sum_buf,
                              ns->count_eol_delim, count_buf,
                              NS128_PLURAL(&ns->cblock.v6[i].cb_ips[0]));
                joiner = NULL;
                for (j = i-1; j > 0; --j) {
                    /* determine what text to use between counts */
                    if (NULL == joiner) {
                        joiner = summary_strings[0];
                    } else if (j > 1) {
                        joiner = summary_strings[1];
                    } else if (summary_strings[0] == joiner) {
                        joiner = summary_strings[2];
                    } else {
                        joiner = summary_strings[3];
                    }
                    netStructureNS128ToString(&ns->cblock.v6[i].cb_ips[j],
                                              count_buf, sizeof(count_buf));
                    skStreamPrint(ns->outstrm, ("%s %s /%u%s"),
                                  joiner, count_buf,
                                  ns->cblock.v6[j].cb_bits,
                                  NS128_PLURAL(&ns->cblock.v6[i].cb_ips[j]));
                }
                skStreamPrint(ns->outstrm, "\n");
            }
        }

        /* Now that we have closed the blocks, return if we are at the
         * end of the data set. */
        if (ns->final_entry) {
            return;
        }

        /* Reset the IP count and counters for all blocks that are
         * smaller than the one where the change was seen */
        for (i = 1; i <= max_block; ++i) {
            memset(ns->cblock.v6[i].cb_ips, 0, (i * sizeof(ns128_t)));
            memset(&ns->cblock.v6[i].cb_sum, 0, sizeof(ns128_t));
        }
    } /* if !first_entry */

    /* store this IP */
    skipaddrCopy(&ns->prev_ipaddr, ipaddr);

    /* Increment the CIDR count and sums for all blocks that are
     * smaller than the one where the change was seen */
    for (i = 1; i <= ns->total_level; ++i) {
        for (j = 0; j < i && j <= max_block; ++j) {
            NS128_ADD_UINT64(&ns->cblock.v6[i].cb_ips[j], 1);
        }
        NS128_ADD_UINT64(&ns->cblock.v6[i].cb_sum, *count);
    }

    if (ns->column[0].co_print) {
        /* print the current IP and count */
        skStreamPrint(ns->outstrm, ("%*s%*s%s%*" PRIu64 "%s\n"),
                      ns->column[0].co_indent, "",
                      ns->column[0].co_width,
                      skipaddrString(ip_buf, ipaddr, ns->ip_format),
                      ns->ip_count_delim,
                      ns->count_width, *count, ns->count_eol_delim);
    }
}
#endif  /* SK_ENABLE_IPV6 */

void
skNetStructureAddKeyCounter(
    sk_netstruct_t     *ns,
    const skipaddr_t   *ipaddr,
    const uint64_t     *counter)
{
    /* initialize the blocks */
    if (!ns->parsed_input) {
        skNetStructureParse(ns, NULL);
    }
#if SK_ENABLE_IPV6
    if (ns->is_ipv6) {
        netStructureAddKeyCounterV6(ns, ipaddr, counter);
        return;
    }
#endif  /* SK_ENABLE_IPV6 */
    netStructureAddKeyCounterV4(ns, ipaddr, counter);
}

/* Create the structure */
int
skNetStructureCreate(
    sk_netstruct_t    **ns_ptr,
    int                 has_count)
{
    sk_netstruct_t *ns;

    ns = (sk_netstruct_t *)calloc(1, sizeof(sk_netstruct_t));
    if (NULL == ns) {
        return -1;
    }

    netStructureInitialize(ns, has_count);
    *ns_ptr = ns;
    return 0;
}

/* Destroy the structure */
void
skNetStructureDestroy(
    sk_netstruct_t    **ns_ptr)
{
    sk_netstruct_t *ns;
    uint32_t i;

    if (!ns_ptr || !*ns_ptr) {
        return;
    }

    ns = *ns_ptr;
    *ns_ptr = NULL;

    if (ns->is_ipv6) {
        if (ns->cblock.v6) {
            for (i = 0; i <= ns->total_level; ++i) {
                if (ns->cblock.v6[i].cb_ips) {
                    free(ns->cblock.v6[i].cb_ips);
                    ns->cblock.v6[i].cb_ips = NULL;
                }
            }
            free(ns->cblock.v4);
            ns->cblock.v4 = NULL;
        }
    } else {
        if (ns->cblock.v4) {
            for (i = 0; i <= ns->total_level; ++i) {
                if (ns->cblock.v4[i].cb_ips) {
                    free(ns->cblock.v4[i].cb_ips);
                    ns->cblock.v4[i].cb_ips = NULL;
                }
            }
            free(ns->cblock.v4);
            ns->cblock.v4 = NULL;
        }
    }
    if (ns->column) {
        free(ns->column);
    }
    free(ns);
}


/*
 *  netStructureInitialize(ns, has_count);
 *
 *    Initialize the newly created network structure context object
 *    'ns'.
 */
static void
netStructureInitialize(
    sk_netstruct_t     *ns,
    int                 has_count)
{
    assert(ns);
    memset(ns, 0, sizeof(sk_netstruct_t));
    ns->first_entry = 1;
    ns->use_count = (has_count ? 1 : 0);
    ns->ip_format = SKIPADDR_CANONICAL;
    ns->delimiter = '|';
    ns->count_width = 15;
}


#if SK_ENABLE_IPV6
/*
 *  buf = netStructureNS128ToString(val, buf, buflen);
 *
 *    Fill 'buf', whose length is 'buflen' with a string
 *    representation of the value in 'val'.  Return 'buf', or return
 *    NULL if the buffer is too small to hold the value.
 */
static char *
netStructureNS128ToString(
    const ns128_t      *val,
    char               *buf,
    size_t              buflen)
{
    static const uint64_t lim = UINT64_C(10000000000);
    static const uint64_t map_ipv6_to_dec[][4] =
        {{                   1,                    0,  0, 0}, /* 1 <<  0 */
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

    if (0 == val->ip[0]) {
        sz = snprintf(buf, buflen, ("%" PRIu64), val->ip[1]);
        if ((size_t)sz >= buflen) {
            return NULL;
        }
        return buf;
    }
    for (i = 0; i < 4; ++i) {
        switch (i) {
          case 0: tmp2 = (val->ip[1] & UINT32_MAX);         break;
          case 1: tmp2 = ((val->ip[1] >> 32) & UINT32_MAX); break;
          case 2: tmp2 = (val->ip[0] & UINT32_MAX);         break;
          case 3: tmp2 = ((val->ip[0] >> 32) & UINT32_MAX); break;
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
    /* Final check for overflow and determine number of
     * 'decimal' elements that have a value */
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
    if ((size_t)sz >= buflen) {
        return NULL;
    }
    return buf;
}
#endif  /* SK_ENABLE_IPV6 */


/* Parse a string to specify the netblocks to print and the netblocks
 * to count. */
static int
netStructureParseV4(
    sk_netstruct_t     *ns,
    const char         *input)
{
#define MAX_PREFIX_V4 32
    uint32_t block[MAX_PREFIX_V4 + 1];
    const char *cp;
    uint32_t val;
    uint32_t num_levels = 0;
    uint32_t print_levels = 0;
    int rv;
    uint32_t i, j;

    assert(ns);
    assert(!ns->is_ipv6);

    /* Clear printing */
    memset(block, 0, sizeof(block));

    /* If input is NULL, use the default. */
    if (NULL == input) {
        cp = NETSTRUCT_DEFAULT_INPUT_V4;
    } else {
        cp = input;
    }

    /* must have a total level block and a host level block */
    block[0] = 2;
    block[MAX_PREFIX_V4] = 2;

    /* loop twice, once to parse the values before the '/' and the
     * second time to parse those after */
    for (i = 1; i <= 2; ++i) {
        while (*cp && *cp != '/') {
            switch (*cp) {
              case ',':
                break;
              case 'S':
                ns->print_summary = 1;
                break;
              case 'T':
                block[0] |= i;
                break;
              case 'A':
                block[8] |= i;
                break;
              case 'B':
                block[16] |= i;
                break;
              case 'C':
                block[24] |= i;
                break;
              case 'X':
                block[27] |= i;
                break;
              case 'H':
                block[MAX_PREFIX_V4] |= i;
                break;
              default:
                if (isspace((int)*cp)) {
                    break;
                }
                if (!isdigit((int)*cp)) {
                    skAppPrintErr("Invalid network-structure character '%c'",
                                  *cp);
                    return 1;
                }
                rv = skStringParseUint32(&val, cp, 0, MAX_PREFIX_V4);
                if (rv == 0) {
                    /* parsed to end of string; move to final char */
                    cp += strlen(cp) - 1;
                } else if (rv > 0) {
                    /* parsed a value, move to last char of the value */
                    cp += rv - 1;
                } else {
                    const char *err2 = "";
#if SK_ENABLE_IPV6
                    if (rv == SKUTILS_ERR_MAXIMUM) {
                        err2 = ("; prepend \"v6:\" to argument to"
                                " allow IPv6 prefixes");
                    }
#endif  /* SK_ENABLE_IPV6 */
                    skAppPrintErr("Invalid network-structure '%s': %s%s",
                                  input, skStringParseStrerror(rv), err2);
                    return 1;
                }
                block[val] |= i;
                break;
            }

            ++cp;
        }

        if ('/' == *cp) {
            if (2 == i) {
                /* The '/' character appears twice */
                skAppPrintErr(("Invalid network-structure '%s':"
                               " Only one '/' is allowed"),
                              input);
                return 1;
            }
            ns->print_summary = 1;
            ++cp;
        } else if (1 == i) {
            /* No summary definition provided. use default if summary
             * requested */
            if (ns->print_summary) {
                cp = NETSTRUCT_DEFAULT_SUMMARY_V4;
            }
        }
    }

    for (i = 0; i <= MAX_PREFIX_V4; ++i) {
        if (block[i]) {
            ++num_levels;
            if (block[i] & 1) {
                ++print_levels;
            }
        }
    }
    /* Make certain we have something other than just 'S' */
    if (print_levels == 0) {
        skAppPrintErr(("Invalid IPv4 network-structure '%s': A numeric"
                       " prefix and/or a subset of THABCX %s"),
                      input, (strchr(input, '/')
                              ? "must precede '/'" : "must be specified"));
        return 1;
    }

    /* Create the dynamically sized arrays */
    ns->column = ((netstruct_column_t*)
                  calloc(num_levels, sizeof(netstruct_column_t)));
    ns->cblock.v4 = ((netstruct_cidr_v4_t*)
                     calloc(num_levels, sizeof(netstruct_cidr_v4_t)));
    if (NULL == ns->cblock.v4 || NULL == ns->column) {
        return 1;
    }
    for (i = 1; i < num_levels; ++i) {
        ns->cblock.v4[i].cb_ips = (uint64_t*)calloc(i, sizeof(uint64_t));
        if (NULL == ns->cblock.v4[i].cb_ips) {
            return 1;
        }
    }

    ns->total_level = num_levels - 1;

    j = 0;
    i = MAX_PREFIX_V4;
    do {
        if (block[i]) {
            if (block[i] & 1) {
                ns->column[j].co_print = 1;
            }
            ns->cblock.v4[j].cb_bits = i;
            ns->cblock.v4[j].cb_mask
                = ((32 == i) ? UINT32_MAX : ~(UINT32_MAX >> i));
            ++j;
        }
    } while (i-- > 0);

    if (!ns->print_summary && !ns->use_count) {
        /* Without summary nor counts, print the number of IPs seen in
         * the block (otherwise, net structure serves little
         * purpose. */
        ns->print_ip_count = 1;
    }

    return 0;
}

#if SK_ENABLE_IPV6
static int
netStructureParseV6(
    sk_netstruct_t     *ns,
    const char         *input)
{
#define MAX_PREFIX_V6 128
    uint32_t block[MAX_PREFIX_V6 + 1];
    const char *cp;
    uint32_t val;
    uint32_t num_levels = 0;
    uint32_t print_levels = 0;
    int rv;
    uint32_t i, j;

    assert(ns);
    assert(ns->is_ipv6);

    /* Clear printing */
    memset(block, 0, sizeof(block));

    /* If input is NULL, use the default. */
    if (NULL == input) {
        cp = NETSTRUCT_DEFAULT_INPUT_V6;
    } else {
        cp = input;
    }

    /* must have a total level block and a host level block */
    block[0] = 2;
    block[MAX_PREFIX_V6] = 2;

    /* loop twice, once to parse the values before the '/' and the
     * second time to parse those after */
    for (i = 1; i <= 2; ++i) {
        while (*cp && *cp != '/') {
            switch (*cp) {
              case ',':
                break;
              case 'S':
                ns->print_summary = 1;
                break;
              case 'T':
                block[0] |= i;
                break;
              case 'H':
                block[MAX_PREFIX_V6] |= i;
                break;
              default:
                if (isspace((int)*cp)) {
                    break;
                }
                if (!isdigit((int)*cp)) {
                    skAppPrintErr("Invalid network-structure character '%c'",
                                  *cp);
                    return 1;
                }
                rv = skStringParseUint32(&val, cp, 0, MAX_PREFIX_V6);
                if (rv == 0) {
                    /* parsed to end of string; move to final char */
                    cp += strlen(cp) - 1;
                } else if (rv > 0) {
                    /* parsed a value, move to last char of the value */
                    cp += rv - 1;
                } else {
                    skAppPrintErr("Invalid network-structure '%s': %s",
                                  input, skStringParseStrerror(rv));
                    return 1;
                }
                block[val] |= i;
                break;
            }

            ++cp;
        }

        if ('/' == *cp) {
            if (2 == i) {
                /* The '/' character appears twice */
                skAppPrintErr(("Invalid network-structure '%s':"
                               " Only one '/' is allowed"),
                              input);
                return 1;
            }
            ns->print_summary = 1;
            ++cp;
        } else if (1 == i) {
            /* No summary definition provided. use default if summary
             * requested */
            if (ns->print_summary) {
                cp = NETSTRUCT_DEFAULT_SUMMARY_V6;
            }
        }
    }

    for (i = 0; i <= MAX_PREFIX_V6; ++i) {
        if (block[i]) {
            ++num_levels;
            if (block[i] & 1) {
                ++print_levels;
            }
        }
    }
    /* Make certain we have something other than just 'S' */
    if (print_levels == 0) {
        skAppPrintErr(("Invalid IPv6 network-structure '%s': A numeric"
                       " prefix and/or a subset of TH %s"),
                      input, (strchr(input, '/')
                              ? "must precede '/'" : "must be specified"));
        return 1;
    }

    /* Create the dynamically sized arrays */
    ns->column = ((netstruct_column_t*)
                  calloc(num_levels, sizeof(netstruct_column_t)));
    ns->cblock.v6 = ((netstruct_cidr_v6_t*)
                     calloc(num_levels, sizeof(netstruct_cidr_v6_t)));
    if (NULL == ns->cblock.v6 || NULL == ns->column) {
        return 1;
    }
    for (i = 1; i < num_levels; ++i) {
        ns->cblock.v6[i].cb_ips = (ns128_t*)calloc(i, sizeof(ns128_t));
        if (NULL == ns->cblock.v6[i].cb_ips) {
            return 1;
        }
    }

    ns->total_level = num_levels - 1;

    j = 0;
    i = MAX_PREFIX_V6;
    do {
        if (block[i]) {
            if (block[i] & 1) {
                ns->column[j].co_print = 1;
            }
            ns->cblock.v6[j].cb_bits = i;
#if 0
            if (i == 128) {
                ns->cblock.v6[j].cb_mask.ip[1] = UINT64_MAX;
                ns->cblock.v6[j].cb_mask.ip[0] = UINT64_MAX;
            } else if (i > 64) {
                ns->cblock.v6[j].cb_mask.ip[1] = ~(UINT64_MAX >> (i - 64));
                ns->cblock.v6[j].cb_mask.ip[0] = UINT64_MAX;
            } else if (i == 64) {
                ns->cblock.v6[j].cb_mask.ip[1] = 0;
                ns->cblock.v6[j].cb_mask.ip[0] = UINT64_MAX;
            } else {
                ns->cblock.v6[j].cb_mask.ip[1] = 0;
                ns->cblock.v6[j].cb_mask.ip[0] = ~(UINT64_MAX >> i);
            }
#endif  /* 0 */
            ++j;
        }
    } while (i-- > 0);

    if (!ns->print_summary && !ns->use_count) {
        /* Without summary nor counts, print the number of IPs seen in
         * the block (otherwise, net structure serves little
         * purpose. */
        ns->print_ip_count = 1;
    }

    return 0;
}
#endif  /* SK_ENABLE_IPV6 */

int
skNetStructureParse(
    sk_netstruct_t     *ns,
    const char         *input)
{
    const char ipv6_prefix[] = "v6";
    const char ipv4_prefix[] = "v4";
    const char *cp;

    if (ns->parsed_input) {
        skAppPrintErr("Invalid network-structure:"
                      " Switch used multiple times");
        return -1;
    }
    ns->parsed_input = 1;

    if (NULL == input || NULL == (cp = strchr(input, ':'))) {
        ns->is_ipv6 = 0;
        return netStructureParseV4(ns, input);
    }
    ++cp;
    if ((cp - input) == sizeof(ipv6_prefix)
        && 0 == strncmp(ipv6_prefix, input, sizeof(ipv6_prefix)-1))
    {
#if !SK_ENABLE_IPV6
        skAppPrintErr(("Invalid network-structure '%s':"
                       " SiLK was built without IPv6 support"),
                      input);
#else
        /* if input is only 'v6:', use the default netblocks */
        ns->is_ipv6 = 1;
        return netStructureParseV6(ns, (*cp ? cp : NULL));
#endif
    }
    if ((cp - input) == sizeof(ipv4_prefix)
        && 0 == strncmp(ipv4_prefix, input, sizeof(ipv4_prefix)-1))
    {
        /* if input is only 'v6:', use the default netblocks */
        ns->is_ipv6 = 0;
        return netStructureParseV4(ns, (*cp ? cp : NULL));
    }
    skAppPrintErr(("Invalid network-structure '%s':"
                   " Only '%s' or '%s' may precede ':'"),
                  input, ipv6_prefix, ipv4_prefix);
    return -1;
}


/*
 *  netStructurePreparePrint(ns);
 *
 *    Do any initialization required immediately before printing the
 *    first entry and open the output stream if a stream was not
 *    provided.
 *
 *    If skNetStructureParse() has not been called, the default
 *    network structure is used.
 *
 *    Set the indentation and width of each column.
 */
static void
netStructurePreparePrint(
    sk_netstruct_t     *ns)
{
#define INDENT_LEVEL 2
    uint32_t first_level = UINT32_MAX;
    uint32_t last_level = 256;
    int indent = 0;
    int width;
    int justify = -1; /* -1 for left-justified IPs; 1 for right */
    uint32_t i;

    assert(ns);
    assert(ns->parsed_input);

    /* open output stream */
    if (ns->outstrm == NULL) {
        int rv;
        if ((rv = skStreamCreate(&ns->outstrm, SK_IO_WRITE, SK_CONTENT_TEXT))
            || (rv = skStreamBind(ns->outstrm, "stdout"))
            || (rv = skStreamOpen(ns->outstrm)))
        {
            skStreamPrintLastErr(ns->outstrm, rv, &skAppPrintErr);
            skStreamDestroy(&ns->outstrm);
            return;
        }
    }

    /* the delimiter between the IP and count, or between IP and
     * summary when handling sets */
    ns->ip_count_delim[0] = ns->delimiter;
    ns->ip_count_delim[1] = '\0';

    /* the delimiter between the count and summary or count and
     * end-of-line when no summary */
    ns->count_eol_delim[0] = ns->delimiter;
    ns->count_eol_delim[1] = '\0';

    /* Compute indentation for each level. */
    i = ns->total_level + 1;
    while (i > 0) {
        --i;
        ns->column[i].co_indent = indent;
        if (ns->column[i].co_print) {
            last_level = i;
            if (UINT32_MAX == first_level) {
                first_level = i;
                indent += INDENT_LEVEL;
                continue;
            }
        }
        if (last_level < ns->total_level) {
            /* Once we have one thing indented, indent the remaining
             * levels by the offset, even if they are not printed. */
            indent += INDENT_LEVEL;
        }
    }

    if ((first_level == last_level) && !ns->use_count
        && !ns->print_ip_count && !ns->print_summary)
    {
        /* If there is no 'count' column and we are not printing
         * the summary---i.e., print IPs only---do no
         * formatting and disable the ip_count_delim. */
        ns->column[0].co_width = 0;
        ns->ip_count_delim[0] = '\0';
        return;
    }

    /* if no summary is requested and if no_final_delimiter is set,
     * modify the delimiter between the count and the end-of-line */
    if (ns->no_final_delimiter && !ns->print_summary) {
        ns->count_eol_delim[0] = '\0';
    }

    if (ns->no_columns) {
        /* If fixed-width output is not requested, set all widths and
         * indents to 0 and return. */
        for (i = 0; i <= ns->total_level; ++i) {
            ns->column[i].co_indent = 0;
            ns->column[i].co_width = 0;
        }
        ns->count_width = 0;
        return;
    }

    if (ns->total_level == last_level) {
        /* We are printing the total only.  Set that width and
         * return. */
        ns->column[ns->total_level].co_width = strlen(NET_TOTAL_TITLE);
        return;
    }

    /* Width will be at least the size of the indenation, but don't
     * include trailing levels that aren't printed. */
    width = indent - (INDENT_LEVEL * (1 + last_level));

    /* Allow space for the IP address. */
    width += skipaddrStringMaxlen(ns->is_ipv6, ns->ip_format);

    /* Allow space for the CIDR block */
    if (last_level == 0) {
        /* Since the host IP does not include the CIDR block, it may
         * be more narrow that the next larger block.  Account for
         * that. */
        if (ns->column[1].co_print) {
            if (ns->is_ipv6 || (SKIPADDR_MAP_V4 & ns->ip_format)) {
                if (INDENT_LEVEL < 4) {
                    width += (4 - INDENT_LEVEL);
                }
            } else if (INDENT_LEVEL < 3) {
                width += (3 - INDENT_LEVEL);
            }
        }
    } else if (ns->is_ipv6) {
        if (SKIPADDR_ZEROPAD & ns->ip_format) {
            width += 4;
        } else if (ns->cblock.v6[last_level].cb_bits < 10) {
            /* Allow for something like "/8" */
            width += 2;
        } else if (ns->cblock.v6[last_level].cb_bits < 100) {
            /* Allow for something like "/24" */
            width += 3;
        } else {
            /* Allow for something like "/120" */
            width += 4;
        }
    } else if (SKIPADDR_MAP_V4 & ns->ip_format) {
        if (SKIPADDR_ZEROPAD & ns->ip_format) {
            width += 4;
        } else if (ns->cblock.v4[last_level].cb_bits < (100 - 96)) {
            /* Allow for something like "/96" */
            width += 3;
        } else {
            /* Allow for something like "/120" */
            width += 4;
        }
    } else {
        if (SKIPADDR_ZEROPAD & ns->ip_format) {
            width += 3;
        } else if (ns->cblock.v4[last_level].cb_bits < 10) {
            /* Allow for something like "/8" */
            width += 2;
        } else {
            /* Allow for something like "/24" */
            width += 3;
        }
    }

    /* When doing only one level, right justify the keys */
    if (first_level == last_level) {
        justify = 1;
    }
    /* Set the widths for every level */
    for (i = 0; i <= ns->total_level; ++i) {
        ns->column[i].co_width
            = justify * (width - ns->column[i].co_indent);
    }
}


/*
 *  netStructurePrintEmpty(ns);
 *
 *    Check whether the TOTAL row was requested; if so, Print it using
 *    0 for all counts.
 */
static void
netStructurePrintEmpty(
    sk_netstruct_t     *ns)
{
    const char *joiner;
    uint32_t j;

    if (!ns->parsed_input) {
        skNetStructureParse(ns, NULL);
    }
    if (!ns->column[ns->total_level].co_print) {
        return;
    }

    netStructurePreparePrint(ns);
    if (ns->print_ip_count) {
        skStreamPrint(ns->outstrm, (NET_TOTAL_TITLE "%s 0\n"),
                      ns->ip_count_delim);
    } else if (!ns->print_summary) {
        assert(1 == ns->use_count);
        skStreamPrint(ns->outstrm, (NET_TOTAL_TITLE "%s%*d%s\n"),
                      ns->ip_count_delim,
                      ns->count_width, 0, ns->count_eol_delim);
    } else {
        if (ns->use_count) {
            skStreamPrint(ns->outstrm, (NET_TOTAL_TITLE "%s%*d%s 0 hosts"),
                          ns->ip_count_delim,
                          ns->count_width, 0, ns->count_eol_delim);
        } else {
            skStreamPrint(ns->outstrm, (NET_TOTAL_TITLE "%s 0 hosts"),
                          ns->ip_count_delim);
        }
        joiner = NULL;
        for (j = ns->total_level-1; j > 0; --j) {
            /* determine what text to use between counts */
            if (NULL == joiner) {
                joiner = summary_strings[0];
            } else if (j > 1) {
                joiner = summary_strings[1];
            } else if (summary_strings[0] == joiner) {
                joiner = summary_strings[2];
            } else {
                joiner = summary_strings[3];
            }
            if (ns->is_ipv6) {
                skStreamPrint(ns->outstrm, ("%s 0 /%us"),
                              joiner, ns->cblock.v6[j].cb_bits);
            } else {
                skStreamPrint(ns->outstrm, ("%s 0 /%us"),
                              joiner, ns->cblock.v4[j].cb_bits);
            }
        }
        skStreamPrint(ns->outstrm, "\n");
    }
}


/* Close any open blocks and print the total.  Also handle the case
 * where no IPs were processed. */
void
skNetStructurePrintFinalize(
    sk_netstruct_t     *ns)
{
    skipaddr_t ipaddr;
    uint64_t counter;

    ns->final_entry = 1;
    if (ns->first_entry) {
        /* no data was processed; print empty results */
        netStructurePrintEmpty(ns);
        return;
    }
    skipaddrClear(&ipaddr);
    if (ns->use_count) {
        counter = 0;
        skNetStructureAddKeyCounter(ns, &ipaddr, &counter);
    } else {
        skNetStructureAddCIDR(ns, &ipaddr, 0);
    }
}


/* Set width of sum-of-counter column. */
void
skNetStructureSetCountWidth(
    sk_netstruct_t     *ns,
    int                 width)
{
    assert(ns);
    ns->count_width = width;
}


/* Set the delimiter to use between columns */
void
skNetStructureSetDelimiter(
    sk_netstruct_t     *ns,
    char                delimiter)
{
    assert(ns);
    ns->delimiter = delimiter;
}


/* Set the format used for printing IP addresses */
void
skNetStructureSetIpFormat(
    sk_netstruct_t     *ns,
    uint32_t            format)
{
    assert(ns);
    ns->ip_format = format;
}


/* Disable columnar output */
void
skNetStructureSetNoColumns(
    sk_netstruct_t     *ns)
{
    assert(ns);
    ns->no_columns = 1;
}


/* Disable printing of the final delimiter */
void
skNetStructureSetNoFinalDelimiter(
    sk_netstruct_t     *ns)
{
    assert(ns);
    ns->no_final_delimiter = 1;
}


/* Set the stream used for printed */
void
skNetStructureSetOutputStream(
    sk_netstruct_t     *ns,
    skstream_t         *stream)
{
    assert(ns);
    assert(stream);
    ns->outstrm = stream;
}




/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
