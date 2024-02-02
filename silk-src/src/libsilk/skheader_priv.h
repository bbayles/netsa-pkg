/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
 *  skheader_priv.h
 *
 *    API to read, write, and manipulate the header of a SiLK file.
 *
 *    Mark Thomas
 *    November 2006
 *
 */
#ifndef _SKHEADER_PRIV_H
#define _SKHEADER_PRIV_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKHEADER_PRIV_H, "$SiLK: skheader_priv.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skheader.h>

/**
 *  @file
 *
 *    The API to read, write, and manipulate the header of a binary
 *    SiLK file.
 *
 *    This file declares functions meant for use only in libsilk.
 *
 *    This file is part of libsilk.
 */

/**
 *    Initial file version that had expanded headers
 */
#define SKHDR_EXPANDED_INIT_VERS 16


/**
 *    The structure that holds the function pointers for a specific
 *    header entry type.
 */
typedef struct sk_hentry_type_st sk_hentry_type_t;


/**
 *    sk_header_start_t: The first 16 bytes in any SiLK file whose
 *    version is not less then SKHDR_EXPANDED_INIT_VERS.
 */
struct sk_header_start_st {
    /** fixed byte order 4byte magic number: 0xdeadbeef */
    uint8_t             magic1;
    uint8_t             magic2;
    uint8_t             magic3;
    uint8_t             magic4;
    /** binary flags for the file.  currently a single flag in least
     * significant bit: 1==big endian, 0==little endian */
    uint8_t             file_flags;
    /** output file format; values defined in silk_files.h */
    sk_file_format_t    file_format;
    /** version of the file */
    sk_file_version_t   file_version;
    /** compression method */
    sk_compmethod_t     comp_method;
    /** the version of SiLK that wrote this file */
    uint32_t            silk_version;
    /** the size of each record in this file */
    uint16_t            rec_size;
    /** the version of the records in this file */
    uint16_t            rec_version;
};

/**
 *    sk_file_header_t: The file header contains the header-start and
 *    a list of header-entry-nodes.
 */
struct sk_file_header_st {
    sk_header_start_t       fh_start;
    sk_hentry_node_t       *fh_rootnode;
    /** the following values are not stored in the file */
    uint32_t                padding_modulus;
    uint32_t                header_length;
    sk_header_lock_t        header_lock;
};

/**
 *    sk_hentry_node_t: The nodes make a circular doubly-linked-list
 *    of header-entries.
 */
struct sk_hentry_node_st {
    sk_hentry_node_t       *hen_next;
    sk_hentry_node_t       *hen_prev;
    sk_hentry_type_t       *hen_type;
    sk_header_entry_t      *hen_entry;
};


/**
 *    Every header-entry has a hentry-type associated with it
 */
struct sk_hentry_type_st {
    sk_hentry_pack_fn_t     het_packer;
    sk_hentry_unpack_fn_t   het_unpacker;
    sk_hentry_copy_fn_t     het_copy;
    sk_hentry_callback_fn_t het_free;
    sk_hentry_print_fn_t    het_print;
    sk_hentry_type_t       *het_next;
    sk_hentry_type_id_t     het_id;
};


/*
 *    **********************************************************************
 *
 *    Functions for handling the header and header entries.
 *
 *    **********************************************************************
 */


/**
 *    Create a new File Header at the location specified by '*hdr'.
 *    The header will be suitable for writing an FT_RWGENERIC file
 *    using the machine's native byte order.
 *
 *    Return 0 on success, or -1 on an allocation error.
 */
int
skHeaderCreate(
    sk_file_header_t  **hdr);


/**
 *    Destroy a File Header created by skHeaderCreate().  The value of
 *    'hdr' or '*hdr' may be null; the pointer '*hdr' will be set to
 *    NULL.
 */
int
skHeaderDestroy(
    sk_file_header_t  **hdr);


/**
 *    Return the header's current lock status.
 */
sk_header_lock_t
skHeaderGetLockStatus(
    const sk_file_header_t *hdr);


/**
 *    Initialize the skheader library.  This will register the known
 *    Header Types.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppRegister().
 */
int
skHeaderInitialize(
    void);


/**
 *    Read, from the file descriptor 'stream', all the Header Entries that
 *    belong to the File Header 'hdr'.  This function assumes
 *    'skHeaderReadStart()' has been called.  Return 0 on success, or
 *    non-zero on read or memory allocation error.
 */
int
skHeaderReadEntries(
    skstream_t         *stream,
    sk_file_header_t   *hdr);


/**
 *    Initialize the first section of 'hdr' and verify that the header
 *    contains the SiLK magic number.
 *
 *    This function reads into 'hdr' from the file descriptor 'stream'
 *    the first bytes (the sk_file_header_t section) of a SiLK stream.
 *
 *    Return SKHEADER_OK on success.  Return SKSTREAM_ERR_BAD_MAGIC if
 *    the file is not a SiLK stream.  Return SKSTREAM_ERR_READ or
 *    SKSTREAM_ERR_READ_SHORT when a stream error occurs or if the
 *    header is truncated.  Return SKHEADER_ERR_IS_LOCKED if the
 *    header is locked.
 */
int
skHeaderReadStart(
    skstream_t         *stream,
    sk_file_header_t   *hdr);


/**
 *    Set the file version.
 *
 *    Return SKHEADER_OK on success.  Return
 *    SKHEADER_ERR_NULL_ARGUMENT if 'hdr' is NULL.  Return
 *    SKHEADER_ERR_IS_LOCKED if the header is locked.  Return
 *    SKHEADER_ERR_BAD_VERSION if 'file_version' is not legal.
 */
int
skHeaderSetFileVersion(
    sk_file_header_t   *hdr,
    sk_file_version_t   file_version);


/**
 *    Set the header's lock status to 'lock'.
 */
int
skHeaderSetLock(
    sk_file_header_t   *hdr,
    sk_header_lock_t    lock);


/**
 *    Set the padding modulus of the File Header 'hdr' to 'mod'.  This
 *    will ensure that the header's length is always an even multiple
 *    of 'mod'.  If 'mod' is zero, the header is padded to a multiple
 *    of the reord length.
 */
int
skHeaderSetPaddingModulus(
    sk_file_header_t   *hdr,
    uint32_t            mod);


/**
 *    Free all memory used internally by skheader.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppUnregister().
 */
void
skHeaderTeardown(
    void);


/**
 *    Write the complete File Header 'hdr' to the file descriptor
 *    'stream'.  Returns 0 on success, or -1 on write error.
 */
int
skHeaderWrite(
    skstream_t         *stream,
    sk_file_header_t   *hdr);


/*
 *    **********************************************************************
 *
 *    Functions for handling the header entry types.
 *
 *    **********************************************************************
 */

/**
 *    Lookup a Header Type given its ID.
 */
sk_hentry_type_t *
skHentryTypeLookup(
    sk_hentry_type_id_t entry_id);



/**
 *    Function in skaggbag.c that registers the callback functions
 *    used by header entry whose ID is SK_HENTRY_AGGBAG_ID.
 */
int
skAggBagRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id);

/**
 *    Function in skbag.c that registers the callback functions used
 *    by header entry whose ID is SK_HENTRY_BAG_ID.
 */
int
skBagRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id);

/**
 *    Function in skipset.c that registers the callback functions used
 *    by header entry whose ID is SK_HENTRY_IPSET_ID.
 */
int
skIPSetRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id);

/**
 *    Function in skprefixmap.c that registers the callback functions
 *    used by header entry whose ID is SK_HENTRY_PREFIXMAP_ID.
 */
int
skPrefixMapRegisterHeaderEntry(
    sk_hentry_type_id_t     entry_id);



/*
 *    **********************************************************************
 *
 *    Legacy header support
 *
 *    **********************************************************************
 */


typedef int
(*sk_headlegacy_read_fn_t)(
    skstream_t       *stream,
    sk_file_header_t *hdr,
    size_t           *byte_read);

typedef uint16_t
(*sk_headlegacy_recsize_fn_t)(
    sk_file_version_t   vers);


int
skHeaderLegacyInitialize(
    void);

int
skHeaderLegacyRegister(
    sk_file_format_t            file_format,
    sk_headlegacy_read_fn_t     read_fn,
    sk_headlegacy_recsize_fn_t  reclen_fn,
    uint8_t                     vers_padding,
    uint8_t                     vers_compress);

int
skHeaderLegacyDispatch(
    skstream_t         *stream,
    sk_file_header_t   *hdr);


void
skHeaderLegacyTeardown(
    void);


#ifdef __cplusplus
}
#endif
#endif /* _SKHEADER_PRIV_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
