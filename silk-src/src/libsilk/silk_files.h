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
#ifndef _SILK_FILES_H
#define _SILK_FILES_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SILK_FILES_H, "$SiLK: silk_files.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>


/*** Compression Methods ***********************************************/

/*
 *    The compression method (compmethod) is used to compress the data
 *    section of a SiLK binary file.
 *
 *    SiLK is able to support the following compmethods.  In order for
 *    a compression method to be supported, the library and header
 *    file must have been available at the time SiLK was compiled.
 *
 *    SiLK cannot read a file if the file uses a compression method
 *    that is not available in this build of SiLK.
 *
 *    The --version switch on most SiLK applications shows what set of
 *    compression methods are available in this SiLK installation.
 *
 *    Keep the following set of constants in sync with the
 *    sk_compmethod_names[] array defined below.
 */

/**
 *    Do not use any compression.
 */
#define SK_COMPMETHOD_NONE      0

/**
 *    Use zlib compression (like that used by gzip).
 */
#define SK_COMPMETHOD_ZLIB      1

/**
 *    Use the lzo1x algorithm from LZO real-time compression library.
 */
#define SK_COMPMETHOD_LZO1X     2

/**
 *    Use Snappy compression.  Since SiLK 3.13.0..
 */
#define SK_COMPMETHOD_SNAPPY    3

#ifdef SKCOMPMETHOD_SOURCE
static const char *sk_compmethod_names[] = {
    "none",
    "zlib",
    "lzo1x",
    "snappy",
    ""
};
#endif /* SKCOMPMETHOD_SOURCE */

/*
 *    Special compression method values also exit.
 */

/**
 *    Use the default compression method that was specified when SiLK
 *    was compiled.
 */
#define SK_COMPMETHOD_DEFAULT 255

/**
 *    Use the "best" compression method.  This is lzo1x if available,
 *    else snappy if available, else zlib if available, else none.
 */
#define SK_COMPMETHOD_BEST    254


/*
 *    Values returned by skCompMethodCheck()
 */

/**
 *    skCompMethodCheck() returns this value when the compression
 *    method is a known value and the method's library is available.
 */
#define SK_COMPMETHOD_IS_AVAIL  6

/**
 *    skCompMethodCheck() returns this value when the compression
 *    method is a known value but the method relies on an external
 *    library that is not part of this build of SiLK.
 */
#define SK_COMPMETHOD_IS_VALID  2

/**
 *    skCompMethodCheck() returns this value when the compression
 *    method is either SK_COMPMETHOD_DEFAULT or SK_COMPMETHOD_BEST.
 */
#define SK_COMPMETHOD_IS_KNOWN  1

/**
 *    Check whether a compression method is valid and/or available.
 *
 *    If the compression method 'comp_method' is completely
 *    unrecognized, return 0.
 *
 *    Return SK_COMPMETHOD_IS_KNOWN when 'comp_method' is an
 *    "undecided" value (i.e., SK_COMPMETHOD_DEFAULT or
 *    SK_COMPMETHOD_BEST).  These compression methods should be
 *    considered valid for writing, as they will be converted to an
 *    appropriate type once the stream they are connected to is
 *    opened.
 *
 *    Return SK_COMPMETHOD_IS_VALID when 'comp_method' contains a
 *    known value other than an "undecided" value, but the compression
 *    method relies on an external library that is not part of this
 *    build of SiLK.
 *
 *    Return SK_COMPMETHOD_IS_AVAIL when 'comp_method' is a known
 *    value whose library is available.  These compression methods are
 *    valid for reading or for writing.
 *
 *    To determine whether 'comp_method' is valid for read, mask the
 *    output by 4.  To determine whether 'comp_method' is valid for
 *    write, mask the output of this function by 5. To determine
 *    whether 'comp_method' is an actual compression method (that is,
 *    not an "undecided" value), mask the output by 2.
 *
 *    Replaces sksiteCompmethodCheck().  Since SiLK 3.13.0.
 */
int
skCompMethodCheck(
    sk_compmethod_t     comp_method);

/**
 *    Return the generically "best" compression method from all those
 *    that are available.
 *
 *    Replaces sksiteCompmethodGetBest().  Since SiLK 3.13.0.
 */
sk_compmethod_t
skCompMethodGetBest(
    void);

/**
 *    Return the default compression method.
 *
 *    Replaces sksiteCompmethodGetDefault().  Since SiLK 3.13.0.
 */
sk_compmethod_t
skCompMethodGetDefault(
    void);

/**
 *    Given the compress method 'comp_method', write the name of that
 *    method into 'out_buffer' whose length is 'bufsize'.  The
 *    function returns a pointer to 'out_buffer', or NULL for an
 *    invalid compression method.
 *
 *    Replaces sksiteCompmethodGetName().  Since SiLK 3.13.0.
 */
int
skCompMethodGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_compmethod_t     comp_method);

/**
 *    Set the default compression method to 'comp_method', overriding
 *    the default value specified when SiLK was compiled.  Return 0 on
 *    success, -1 if the method is not available.
 *
 *    To change the default returned by the --compression-method
 *    switch, call this function prior to calling
 *    skCompMethodOptionsRegister().
 *
 *    Replaces sksiteCompmethodSetDefault().  Since SiLK 3.13.0.
 */
int
skCompMethodSetDefault(
    sk_compmethod_t     comp_method);

/**
 *    Do not check the SILK_COMPRESSION_METHOD environment variable
 *    when initializing the compression method variable passed into
 *    skCompMethodOptionsRegister().
 *
 *    Since SiLK 3.13.0.
 */
void
skCompMethodOptionsNoEnviron(
    void);

/**
 *    Add a command-line switch that allows the user to set the
 *    compression method of binary output files.  After
 *    skOptionsParse() sucessfully returns, the referent of
 *    'compression_method' contains the compression method to use.
 *
 *    When this function is called, the SILK_COMPRESSION_METHOD
 *    environment variable is normally checked for a compression
 *    method, and if the variable specifies an available method, the
 *    referent of 'compression_method' is set to that value.  To
 *    suppress this check of the environment, call
 *    skCompMethodOptionsNoEnviron() prior to calling this function.
 *
 *    This function initializes the referent of 'compression_method'
 *    to the compression method in SILK_COMPRESSION_METHOD envar or
 *    the default compression method specified when SiLK was compiled.
 *    To modify the default value used by an application, call
 *    skCompMethodSetDefault() prior to calling this function.
 *
 *    Replaces sksiteCompmethodOptionsRegister().  Since SiLK 3.13.0.
 */
int
skCompMethodOptionsRegister(
    sk_compmethod_t    *compression_method);

/**
 *    Print the usage for the compression-method option to the file
 *    handle 'fh'.
 *
 *    Replaces sksiteCompmethodOptionsUsage().  Since SiLK 3.13.0.
 */
void
skCompMethodOptionsUsage(
    FILE               *fh);



/** File Formats ******************************************************/

/**
 *    Copy the name of the file format with the ID 'format_id' into
 *    'buffer' whose size is 'buffer_size'.
 *
 *    If the name is longer than buffer_size, the value returned is
 *    truncated with a '\0' in the final position.
 *
 *    Return the number of characters that would have been written if
 *    the buffer had been long enough.  This length does not include
 *    the trailing '\0'.
 *
 *    Replaces sksiteFileformatGetName().  Since SiLK 3.13.0.
 */
int
skFileFormatGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_file_format_t    format_id);

/**
 *    Return 1 if 'format_id' is a valid file output format or 0 if
 *    it is not.
 *
 *    Replaces sksiteFileformatIsValid().  Since SiLK 3.13.0.
 */
int
skFileFormatIsValid(
    sk_file_format_t    format_id);

/**
 *    Return the file output format associated with the name.  If the
 *    name is unknown, return SK_INVALID_FILE_FORMAT (whose value is
 *    defined in silk_types.h).
 *
 *    Replaces sksiteFileformatFromName().  Since SiLK 3.13.0.
 */
sk_file_format_t
skFileFormatFromName(
    const char         *name);


/* define various output file formats here that we write to disk */

#define FT_TCPDUMP          0x00
#define FT_GRAPH            0x01
#define FT_ADDRESSES        0x02        /* old address array used by addrtype */
#define FT_PORTMAP          0x03
#define FT_SERVICEMAP       0x04
#define FT_NIDSMAP          0x05
#define FT_EXPERIMENT1      0x06        /* free for all ID */
#define FT_EXPERIMENT2      0x07        /* free for all ID */
#define FT_TEMPFILE         0x08
#define FT_AGGREGATEBAG     0x09
#define FT_IPFIX            0x0A
#define FT_RWIPV6           0x0B
#define FT_RWIPV6ROUTING    0x0C
#define FT_RWAUGSNMPOUT     0x0D
#define FT_RWAUGROUTING     0x0E
#define FT_RESERVED_0F      0x0F
#define FT_RWROUTED         0X10
#define FT_RWNOTROUTED      0X11
#define FT_RWSPLIT          0X12
#define FT_RWFILTER         0X13
#define FT_RWAUGMENTED      0X14
#define FT_RWAUGWEB         0X15
#define FT_RWGENERIC        0x16
#define FT_RESERVED_17      0x17
#define FT_RWDAILY          0x18
#define FT_RWSCAN           0x19
#define FT_RWACL            0x1A
#define FT_RWCOUNT          0x1B
#define FT_FLOWCAP          0x1C
#define FT_IPSET            0x1D
#define FT_TAGTREE          0x1E
#define FT_RWWWW            0x1F
#define FT_SHUFFLE          0x20
#define FT_RWBAG            0x21
#define FT_BLOOM            0x22
#define FT_RWPRINTSTATS     0x23
#define FT_PDUFLOWCAP       0x24
#define FT_PREFIXMAP        0x25
/* When you add new types here; add the name to the array below. */

/* old identifier names */
#define FT_IPTREE           FT_IPSET
#define FT_MACROBAGTREE     FT_RWBAG


/*
 *   This header is included by skfileformat.c after declaring
 *   SKFILEFORMAT_SOURCE.  Users should use the functions defined
 *   above to access these strings values.
 */

#ifdef SKFILEFORMAT_SOURCE
static const char *sk_file_format_names[] = {
    /* 0x00 */  "FT_TCPDUMP",
    /* 0x01 */  "FT_GRAPH",
    /* 0x02 */  "FT_ADDRESSES",
    /* 0x03 */  "FT_PORTMAP",
    /* 0x04 */  "FT_SERVICEMAP",
    /* 0x05 */  "FT_NIDSMAP",
    /* 0x06 */  "FT_EXPERIMENT1",
    /* 0x07 */  "FT_EXPERIMENT2",
    /* 0x08 */  "FT_TEMPFILE",
    /* 0x09 */  "FT_AGGREGATEBAG",
    /* 0x0A */  "FT_IPFIX",
    /* 0x0B */  "FT_RWIPV6",
    /* 0x0C */  "FT_RWIPV6ROUTING",
    /* 0x0D */  "FT_RWAUGSNMPOUT",
    /* 0x0E */  "FT_RWAUGROUTING",
    /* 0x0F */  "FT_RESERVED_0F",
    /* 0X10 */  "FT_RWROUTED",
    /* 0X11 */  "FT_RWNOTROUTED",
    /* 0X12 */  "FT_RWSPLIT",
    /* 0X13 */  "FT_RWFILTER",
    /* 0X14 */  "FT_RWAUGMENTED",
    /* 0X15 */  "FT_RWAUGWEB",
    /* 0x16 */  "FT_RWGENERIC",
    /* 0x17 */  "FT_RESERVED_17",
    /* 0x18 */  "FT_RWDAILY",
    /* 0x19 */  "FT_RWSCAN",
    /* 0x1A */  "FT_RWACL",
    /* 0x1B */  "FT_RWCOUNT",
    /* 0x1C */  "FT_FLOWCAP",
    /* 0x1D */  "FT_IPSET",
    /* 0x1E */  "FT_TAGTREE",
    /* 0x1F */  "FT_RWWWW",
    /* 0x20 */  "FT_SHUFFLE",
    /* 0x21 */  "FT_RWBAG",
    /* 0x22 */  "FT_BLOOM",
    /* 0x23 */  "FT_RWPRINTSTATS",
    /* 0x24 */  "FT_PDUFLOWCAP",
    /* 0x25 */  "FT_PREFIXMAP",
    ""
};
#endif /* SKFILEFORMAT_SOURCE */

#ifdef __cplusplus
}
#endif
#endif  /* _SILK_FILES_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
