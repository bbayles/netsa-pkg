/*
** Copyright (C) 2006-2016 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
** See license information in ../../LICENSE.txt
** @OPENSOURCE_LICENSE_END@
*/

/*
**  skheader.h
**
**    API to read, write, and manipulate the header of a SiLK file
**
**    Mark Thomas
**    November 2006
**
*/
#ifndef _SKHEADER_H
#define _SKHEADER_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKHEADER_H, "$SiLK: skheader.h 4c36563f30bb 2016-09-28 22:00:57Z mthomas $");

#include <silk/silk_types.h>

/**
 *  @file
 *
 *    The API to read, write, and manipulate the header of a binary
 *    SiLK file.
 *
 *    This file is part of libsilk.
 */


/**
 *    A SiLK file has a header-section and a data-section.  The header
 *    section is called an 'sk_file_header_t'.
 *
 *    The sk_file_header_t is split into two sections, a fixed size
 *    'sk_header_start_t' and a variable number of variable-sized
 *    'sk_header_entry_t'.
 */
typedef struct sk_file_header_st sk_file_header_t;

/**
 *    The first section of an sk_file_header_t is called the
 *    sk_header_start_t, and it has a fixed size of 16 bytes.
 *
 *    The first four bytes of an sk_header_start_t is the SiLK magic
 *    number, 0xDEADBEEF.
 *
 *    The next four bytes of the sk_header_start_t denote the file's
 *    byte order, the file's format (that is, the type of data it
 *    contains, the file version, and the type of compression unsed
 *    for the data section.
 *
 *    The final eight bytes contain the version of SiLK that wrote
 *    the file, the bytes per record, and the version of the record.
 */
typedef struct sk_header_start_st sk_header_start_t;

/**
 *    The second part of the sk_file_header_t contains a variable
 *    number of sk_header_entry_t's.
 */
typedef struct sk_header_entry_st sk_header_entry_t;

/**
 *    In core, the sk_header_entry_t's are stored in a circular
 *    doubly-linked-linked list of sk_hentry_node_t's.
 */
typedef struct sk_hentry_node_st sk_hentry_node_t;

/**
 *    An sk_hentry_iterator_t is used to visit each of the
 *    header-entries in the header.
 */
typedef struct sk_hentry_iterator_st sk_hentry_iterator_t;

/**
 *    Each sk_header_entry_t is made up of an sk_header_entry_spec_t
 *    and a variable size data section---which may contain 0 bytes.
 */
typedef struct sk_header_entry_spec_st sk_header_entry_spec_t;

/**
 *    The current sk_header_entry_spec_t has four-bytes that specify
 *    its hentry-type-ID, and four-bytes giving the
 *    sk_header_entry_t's complete length---including the length of
 *    the sk_header_entry_spec_t.
 */
typedef uint32_t sk_hentry_type_id_t;

/**
 *    The hentry-type-ID "\0\0\0\0" is used to mark the end of the
 *    header entries.  The length of this header-entry should still be
 *    valid.  In particular, any header padding must be accounted for
 *    in this entry.
 *
 *    The minimum sized header is 24 bytes.  The data section, if
 *    present, begins immediately after the header-entry whose ID is
 *    "\0\0\0\0".
 *
 *    Note that in the new headers, all values are in network (big)
 *    byte order, so use ntohs() and ntohl() to read them.
 *
 *    To avoid clashes with existing files, the file_version value for
 *    all files with this new header will be >= 16.
 */

/**
 *    The minimum file version that may be specified to
 *    skHeaderSetFileVersion().  A SiLK tool may accept a lower
 *    version number when reading data, but the version number may not
 *    be lower than this when creating a file.
 */
#define SK_FILE_VERSION_MINIMUM 16

/**
 *    The maximum file version that may be specified to
 *    skHeaderSetFileVersion().
 */
#define SK_FILE_VERSION_MAXIMUM SK_FILE_VERSION_MINIMUM

/**
 *    The file version to use as the default.
 */
#define SK_FILE_VERSION_DEFAULT SK_FILE_VERSION_MINIMUM

/**
 *    Values returned by the skHeader*() functions.
 */
typedef enum skHeaderErrorCodes_en {
    /** Command succeeded. */
    SKHEADER_OK = 0,

    /** Memory allocation failed */
    SKHEADER_ERR_ALLOC,

    /** Programmer or allocation error: NULL passed as argument to
     * function */
    SKHEADER_ERR_NULL_ARGUMENT,

    /** The file format is not supported */
    SKHEADER_ERR_BAD_FORMAT,

    /** The file version is not supported */
    SKHEADER_ERR_BAD_VERSION,

    /** Attempt to replace an entry that does not exist */
    SKHEADER_ERR_ENTRY_NOTFOUND,

    /** Error in packing an entry */
    SKHEADER_ERR_ENTRY_PACK,

    /** Error in reading an entry from disk */
    SKHEADER_ERR_ENTRY_READ,

    /** Error in unpacking an entry */
    SKHEADER_ERR_ENTRY_UNPACK,

    /** The entry ID is invalid */
    SKHEADER_ERR_INVALID_ID,

    /** Attempt to modify a locked header */
    SKHEADER_ERR_IS_LOCKED,

    /** Error handling a legacy header */
    SKHEADER_ERR_LEGACY,

    /** Header compression value is invalid */
    SKHEADER_ERR_BAD_COMPRESSION,

    /** Read fewer bytes than that required to read the header */
    SKHEADER_ERR_SHORTREAD,

    /** Header length is longer than expected */
    SKHEADER_ERR_TOOLONG
} skHeaderErrorCodes_t;


/**
 *    Settings for the header locks
 */
typedef enum sk_header_lock_en {
    /** Header is completely modifable */
    SKHDR_LOCK_MODIFIABLE,
    /** Header is completely locked: nothing can be changed nor new
     * entries added */
    SKHDR_LOCK_FIXED,
    /** Header cannot be changed, but new header entries may be
     * added. */
    SKHDR_LOCK_ENTRY_OK
} sk_header_lock_t;


/**
 *    sk_header_entry_spec_t: The header-entries have a
 *    header-entry-spec and a data section.
 */
struct sk_header_entry_spec_st {
    /** The ID for this header-entry.  0 marks the final entry */
    sk_hentry_type_id_t     hes_id;
    /** Total length of this header entry, including the
     * header-entry-spec */
    uint32_t                hes_len;
};

/**
 *    sk_header_entry_t
 */
struct sk_header_entry_st {
    sk_header_entry_spec_t  he_spec;
    void                   *he_data;
};

/**
 *    sk_hentry_iterator_t: The hentry-iterator is used to visit the
 *    header-entries.
 */
struct sk_hentry_iterator_st {
    const sk_file_header_t     *hdr;
    sk_hentry_node_t           *node;
    sk_hentry_type_id_t         htype_filter;
};


/**
 *    The 'sk_hentry_pack_fn_t' is used to write an in-core
 *    header-entry to a binary data file.
 *
 *    It take pointers to a header entry data structure, 'hentry_in'
 *    and to a byte-array, 'packed_entry_out' of 'packed_avail_size'
 *    bytes, and it fills 'packed_entry_out' with the data in the
 *    'hentry_in' suitable for writing to a binary stream.  The
 *    function returns the number of bytes in 'packed_entry_out' that
 *    were used, i.e., the number of bytes to be written.  If
 *    'packed_entry_out' is too small, the function should return the
 *    number of bytes that would be required to hold all of
 *    'hentry_in'.  The caller will likely grow 'packed_entry_out' and
 *    invoke this function again.
 *
 *    This function should make certain that the values in the
 *    sk_header_entry_spec_t section of 'packed_entry_out' are in
 *    network (big-endian) byte order.  The other values may have any
 *    meaning, as long as the 'sk_hentry_unpack_fn_t' knows how to
 *    decode them.
 */
typedef ssize_t
(*sk_hentry_pack_fn_t)(
    sk_header_entry_t      *hentry_in,
    uint8_t                *packed_entry_out,
    size_t                  packed_avail_size);

/**
 *    When a binary SiLK file is read, the 'sk_hentry_unpack_fn_t' is
 *    called to convert the bytes to an in-core data structure.
 *
 *    It takes a pointer to a sk_header_entry_t, 'packed_in'---as read
 *    from a binary stream and packed by the
 *    'sk_hentry_pack_fn_t'---and allocates and returns a pointer to
 *    the expanded version of the data.
 */
typedef sk_header_entry_t *
(*sk_hentry_unpack_fn_t)(
    uint8_t                *packed_in);

/**
 *    The 'sk_hentry_copy_fn_t' is used to do a complete (deep) copy
 *    of a header-entry.
 *
 */
typedef sk_header_entry_t *
(*sk_hentry_copy_fn_t)(
    const sk_header_entry_t    *hentry_in);

/**
 *    To produce a human-readable form of the header,
 *    'sk_hentry_print_fn_t' is used.
 *
 *    It prints the header, 'hentry', to the specified stream, 'fh',
 *    as text.
 */
typedef void
(*sk_hentry_print_fn_t)(
    sk_header_entry_t      *hentry,
    FILE                   *fh);

/**
 *    A generic callback function for the header entry 'hentry'.  One
 *    such use is as function to free() the memory allocated by the
 *    'sk_hentry_unpack_fn_t'.
 */
typedef void
(*sk_hentry_callback_fn_t)(
    sk_header_entry_t      *hentry);

/**
 *    When defined and set to a non-empty string, use 0 as the SiLK
 *    version number in the header of files we create.
 */
#define SILK_HEADER_NOVERSION_ENV  "SILK_HEADER_NOVERSION"


/*
 *    **********************************************************************
 *
 *    Functions for handling the header and header entries.
 *
 *    **********************************************************************
 */


/**
 *    Add the Header Entry 'hentry' to the File Header 'hdr'.  Return
 *    0 on sucess, or -1 for the following error conditions: if the
 *    'hentry' is NULL or if it has a reserved ID, or on memory
 *    allocation error.
 */
int
skHeaderAddEntry(
    sk_file_header_t   *hdr,
    sk_header_entry_t  *hentry);


/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the entire header should be copied.
 */
#define SKHDR_CP_ALL           0xFFFFFFFFu

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the byte order value should be copied.
 */
#define SKHDR_CP_ENDIAN        (1u <<  7)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the file format value should be copied.
 */
#define SKHDR_CP_FORMAT        (1u <<  8)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the file version value should be copied.
 */
#define SKHDR_CP_FILE_VERS     (1u <<  9)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the compression method value should be copied.
 */
#define SKHDR_CP_COMPMETHOD    (1u << 10)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the record length value should be copied.
 */
#define SKHDR_CP_REC_LEN       (1u << 11)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the record version value should be copied.
 */
#define SKHDR_CP_REC_VERS      (1u << 12)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that all header entries should be copied.
 */
#define SKHDR_CP_ENTRIES       (1u << 31)

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the file parameter values should be copied.
 */
#define SKHDR_CP_FILE_FLAGS    0x000000FFu

/**
 *    Possible value for 'copy_flags' parameter of skHeaderCopy()
 *    indicating that the entire header except the header entries
 *    should be copied.
 */
#define SKHDR_CP_START         0x00FFFFFFu

/**
 *    Copy the header 'src_hdr' to 'dst_hdr'.  The parts of the header
 *    to copy are specified by the 'copy_flags' value.
 */
int
skHeaderCopy(
    sk_file_header_t       *dst_hdr,
    const sk_file_header_t *src_hdr,
    uint32_t                copy_flags);


/**
 *    Copy all the header entries whose ID is 'entry_id' from
 *    'src_hdr' to 'dst_hdr'.
 */
int
skHeaderCopyEntries(
    sk_file_header_t       *dst_hdr,
    const sk_file_header_t *src_hdr,
    sk_hentry_type_id_t     entry_id);


/**
 *    Create and return a new entry that is a (deep) copy of the
 *    header entry 'src_hentry'.  Return NULL on failure or if the
 *    'src_header' refers to the root node.
 */
sk_header_entry_t *
skHeaderEntryCopy(
    const sk_header_entry_t    *src_hentry);


/**
 *    Return the type ID for a header entry.
 */
#if 0
sk_hentry_type_id_t
skHeaderEntryGetTypeId(
    const sk_header_entry_t    *hentry);
#else
#  define skHeaderEntryGetTypeId(hentry)  ((hentry)->he_spec.hes_id)
#endif


/**
 *   Print a textual representation of the Header Entry 'hentry' to
 *   the stream 'fp'.
 */
void
skHeaderEntryPrint(
    sk_header_entry_t  *hentry,
    FILE               *fp);


/**
 *    Get the byte order of the records in the file for which 'hdr' is
 *    the header.
 */
silk_endian_t
skHeaderGetByteOrder(
    const sk_file_header_t *hdr);


/**
 *    Return the compression method used on 'stream'.
 */
sk_compmethod_t
skHeaderGetCompressionMethod(
    const sk_file_header_t *hdr);


/**
 *    Given the File Header 'hdr', return a pointer to the first
 *    Header Entry that has the given ID, 'entry_id'.
 */
sk_header_entry_t *
skHeaderGetFirstMatch(
    const sk_file_header_t *hdr,
    sk_hentry_type_id_t     entry_id);


/**
 *    Return the SiLK file output format for the header.  Return
 *    SK_INVALID_FILE_FORMAT when header is NULL.
 */
sk_file_format_t
skHeaderGetFileFormat(
    const sk_file_header_t *header);


/**
 *    Return the version of the file.  As of SK_EXPAND_HDR_INIT_VERS,
 *    this is different than the record version.
 */
sk_file_version_t
skHeaderGetFileVersion(
    const sk_file_header_t *hdr);


/**
 *    Return the complete length of the header, in bytes.
 */
size_t
skHeaderGetLength(
    const sk_file_header_t *header);


/**
 *    Return the length of the records as defined in the header.
 */
size_t
skHeaderGetRecordLength(
    const sk_file_header_t *header);


/**
 *    Return the version number of the SiLK file associated with the
 *    header.
 */
sk_file_version_t
skHeaderGetRecordVersion(
    const sk_file_header_t *header);


/**
 *    Return a value representing the version of silk that wrote this file.
 */
uint32_t
skHeaderGetSilkVersion(
    const sk_file_header_t *hdr);


/**
 *    Return 1 if the stream associated with 'header' is in native
 *    byte order, or 0 if it is not.
 */
int
skHeaderIsNativeByteOrder(
    const sk_file_header_t *header);


/**
 *    Bind the Header Entry Iterator 'iter' to the Header Entries in
 *    the File Header 'hdr'.
 */
void
skHeaderIteratorBind(
    sk_hentry_iterator_t   *iter,
    const sk_file_header_t *hdr);


/**
 *    Bind the Header Entry Iterator 'iter' to the Header Entries
 *    whose type is 'htype' in the File Header 'hdr'.
 */
void
skHeaderIteratorBindType(
    sk_hentry_iterator_t   *iter,
    const sk_file_header_t *hdr,
    sk_hentry_type_id_t     htype);


/**
 *    For a Header Entry Iterator 'iter' that has been bound to a file
 *    header, return a pointer to the next Header Entry.  Returns NULL
 *    if all Header Entries have been processed.
 */
sk_header_entry_t *
skHeaderIteratorNext(
    sk_hentry_iterator_t   *iter);


/**
 *    On the File Header 'hdr', remove every Header Entry whose Header
 *    Entry Type is 'entry_id'.
 *
 *    Each Header Entry of the specified Type will be passed to the
 *    free function for that Type.
 *
 *    Return SKHEADER_OK on success.  Return SKHEADER_ERR_INVALID_ID
 *    if 'entry_id' is a restricted ID.  Return SKHEADER_ERR_IS_LOCKED
 *    if the 'hdr' is locked.
 */
int
skHeaderRemoveAllMatching(
    sk_file_header_t       *hdr,
    sk_hentry_type_id_t     entry_id);


/**
 *    Set the byte order of the records in the file for which 'hdr' is
 *    the header to 'byte_order'.
 */
int
skHeaderSetByteOrder(
    sk_file_header_t   *hdr,
    silk_endian_t       byte_order);


/**
 *    Set the compression method of the records in the file for which
 *    'hdr' is the header to 'comp_method'.
 */
int
skHeaderSetCompressionMethod(
    sk_file_header_t   *hdr,
    uint8_t             comp_method);


/**
 *    Set the format of the file this header references to
 *    'file_format'.
 */
int
skHeaderSetFileFormat(
    sk_file_header_t   *hdr,
    sk_file_format_t    file_format);


/**
 *    Set the file version.  The value must be between
 *    SK_FILE_VERSION_MINIMUM and SK_FILE_VERSION_MAXIMUM inclusive.
 *    When this function is not called, the file version is that
 *    specified by SK_FILE_VERSION_DEFAULT.
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
 *    Set the length of the records in the file for which 'hdr' is the
 *    header to 'rec_len' octets.
 */
int
skHeaderSetRecordLength(
    sk_file_header_t   *hdr,
    size_t              rec_len);


/**
 *    Set the version of the records in the file for which 'hdr' is
 *    the header to 'version'.
 */
int
skHeaderSetRecordVersion(
    sk_file_header_t   *hdr,
    sk_file_version_t   record_version);

/**
 *    Return a string explaining the error code 'err_code'.
 */
const char *
skHeaderStrerror(
    ssize_t             err_code);


/*
 *    **********************************************************************
 *
 *    Functions for handling the header entry types.
 *
 *    **********************************************************************
 */


/**
 *    Register a Header Type.
 */
int
skHentryTypeRegister(
    sk_hentry_type_id_t     entry_id,
    sk_hentry_pack_fn_t     pack_fn,
    sk_hentry_unpack_fn_t   unpack_fn,
    sk_hentry_copy_fn_t     copy_fn,
    sk_hentry_callback_fn_t free_fn,
    sk_hentry_print_fn_t    print_fn);


/*
 *    **********************************************************************
 *
 *    The 'packedfile' header entry type is used on data files
 *    generated by rwflowpack.  It specifies the start-time,
 *    flow-type, and sensor for a packed data * file, e.g. FT_RWSPLIT,
 *    FT_RWWWW.
 *
 *    **********************************************************************
 */

#define SK_HENTRY_PACKEDFILE_ID 1

typedef struct sk_hentry_packedfile_st {
    sk_header_entry_spec_t  he_spec;
    int64_t                 start_time;
    uint32_t                flowtype_id;
    uint32_t                sensor_id;
} sk_hentry_packedfile_t;

int
skHeaderAddPackedfile(
    sk_file_header_t   *hdr,
    sktime_t            start_time,
    sk_flowtype_id_t    flowtype_id,
    sk_sensor_id_t      sensor_id);

sk_header_entry_t *
skHentryPackedfileCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryPackedfileCreate(
    sktime_t            start_time,
    sk_flowtype_id_t    flowtype_id,
    sk_sensor_id_t      sensor_id);

void
skHentryPackedfileFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryPackedfilePacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryPackedfilePrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryPackedfileUnpacker(
    uint8_t            *in_packed);

#define skHentryPackedfileGetStartTime(hentry)  \
    ((sktime_t)((hentry)->start_time))

#define skHentryPackedfileSetStartTime(hentry, s_time)  \
    { (hentry)->start_time = (sktime_t)(s_time); }

#define skHentryPackedfileGetSensorID(hentry)   \
    ((sk_sensor_id_t)((hentry)->sensor_id))

#define skHentryPackedfileSetSensorID(hentry, sensor_id)        \
    { (hentry)->sensor_id = (sensor_id); }

#define skHentryPackedfileGetFlowtypeID(hentry) \
    ((sk_flowtype_id_t)((hentry)->flowtype_id))

#define skHentryPackedfileSetFlowtypeID(hentry, flowtype_id)    \
    { (hentry)->flowtype_id = (flowtype_id); }




/*
 *    **********************************************************************
 *
 *    The 'invocation' header entry type is used to store the command
 *    line history, with one 'invocation' structure per command
 *    invocation.
 *
 *    The current plan is to have one of these per invocation.  I
 *    suppose we could think about joining them into a single
 *    header.
 *
 *    **********************************************************************
 */

#define SK_HENTRY_INVOCATION_ID 2

typedef struct sk_hentry_invocation_st {
    sk_header_entry_spec_t  he_spec;
    char                   *command_line;
} sk_hentry_invocation_t;

int
skHeaderAddInvocation(
    sk_file_header_t   *hdr,
    int                 strip_path,
    int                 argc,
    char              **argv);

sk_header_entry_t *
skHentryInvocationCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryInvocationCreate(
    int                 strip_path,
    int                 argc,
    char              **argv);

void
skHentryInvocationFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryInvocationPacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryInvocationPrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryInvocationUnpacker(
    uint8_t            *in_packed);



/*
 *    **********************************************************************
 *
 *    The 'annotation' header entry type is used to store a generic
 *    comment or annotation about the file.
 *
 *    We should think about making the size of these larger, or have
 *    them allocated in 256 or 512 chunks, so that minor modification
 *    to the annotation can be done on a file without completely
 *    rewriting it.
 *
 *    **********************************************************************
 */

#define SK_HENTRY_ANNOTATION_ID 3

typedef struct sk_hentry_annotation_st {
    sk_header_entry_spec_t  he_spec;
    char                   *annotation;
} sk_hentry_annotation_t;

int
skHeaderAddAnnotation(
    sk_file_header_t   *hdr,
    const char         *annotation);

int
skHeaderAddAnnotationFromFile(
    sk_file_header_t   *hdr,
    const char         *pathname);

sk_header_entry_t *
skHentryAnnotationCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryAnnotationCreate(
    const char         *annotation);

sk_header_entry_t *
skHentryAnnotationCreateFromFile(
    const char         *pathname);

void
skHentryAnnotationFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryAnnotationPacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryAnnotationPrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryAnnotationUnpacker(
    uint8_t            *in_packed);


/*
 *    **********************************************************************
 *
 *    The 'probename' header entry type is used to store the name of
 *    the probe where flow data was collected.
 *
 *    **********************************************************************
 */

#define SK_HENTRY_PROBENAME_ID  4

typedef struct sk_hentry_probename_st {
    sk_header_entry_spec_t  he_spec;
    char                   *probe_name;
} sk_hentry_probename_t;

int
skHeaderAddProbename(
    sk_file_header_t   *hdr,
    const char         *probe_name);

sk_header_entry_t *
skHentryProbenameCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryProbenameCreate(
    const char         *probe_name);

void
skHentryProbenameFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryProbenamePacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryProbenamePrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryProbenameUnpacker(
    uint8_t            *in_packed);


#define skHentryProbenameGetProbeName(hentry)   \
    ((hentry)->probe_name)


/*
 *    **********************************************************************
 *
 *    The 'prefixmap' header entry type is used to store information
 *    particular to prefix maps (pmaps).
 *
 *    **********************************************************************
 */

#define SK_HENTRY_PREFIXMAP_ID  5

typedef struct sk_hentry_prefixmap_st {
    sk_header_entry_spec_t  he_spec;
    uint32_t                version;
    char                   *mapname;
} sk_hentry_prefixmap_t;

int
skHeaderAddPrefixmap(
    sk_file_header_t   *hdr,
    const char         *mapname);

sk_header_entry_t *
skHentryPrefixmapCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryPrefixmapCreate(
    const char         *mapname);

void
skHentryPrefixmapFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryPrefixmapPacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryPrefixmapPrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryPrefixmapUnpacker(
    uint8_t            *in_packed);


#define skHentryPrefixmapGetMapmame(hentry)   \
    ((hentry)->mapname)

#define skHentryPrefixmapGetVersion(hentry)   \
    ((hentry)->version)


/*
 *    **********************************************************************
 *
 *    The 'bag' header entry type is used to store information
 *    particular to binary Bag files.
 *
 *    **********************************************************************
 */

#define SK_HENTRY_BAG_ID        6

typedef struct sk_hentry_bag_st {
    sk_header_entry_spec_t  he_spec;
    uint16_t                key_type;
    uint16_t                key_length;
    uint16_t                counter_type;
    uint16_t                counter_length;
} sk_hentry_bag_t;

int
skHeaderAddBag(
    sk_file_header_t   *hdr,
    uint16_t            key_type,
    uint16_t            key_length,
    uint16_t            counter_type,
    uint16_t            counter_length);

sk_header_entry_t *
skHentryBagCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryBagCreate(
    uint16_t            key_type,
    uint16_t            key_length,
    uint16_t            counter_type,
    uint16_t            counter_length);

void
skHentryBagFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryBagPacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryBagPrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryBagUnpacker(
    uint8_t            *in_packed);

#define skHentryBagGetKeyType(hentry)           \
    (((sk_hentry_bag_t*)(hentry))->key_type)

#define skHentryBagGetKeyLength(hentry)         \
    (((sk_hentry_bag_t*)(hentry))->key_length)

#define skHentryBagGetCounterType(hentry)               \
    (((sk_hentry_bag_t*)(hentry))->counter_type)

#define skHentryBagGetCounterLength(hentry)             \
    (((sk_hentry_bag_t*)(hentry))->counter_length)


/*
 *    **********************************************************************
 *
 *    The 'ipset' header entry type is used to store information
 *    particular to IPSets
 *
 *    **********************************************************************
 */

#define SK_HENTRY_IPSET_ID      7

typedef struct sk_hentry_ipset_st {
    sk_header_entry_spec_t  he_spec;
    uint32_t                child_node;
    uint32_t                leaf_count;
    uint32_t                leaf_size;
    uint32_t                node_count;
    uint32_t                node_size;
    uint32_t                root_idx;
} sk_hentry_ipset_t;

int
skHeaderAddIPSet(
    sk_file_header_t   *hdr,
    uint32_t            child_node,
    uint32_t            leaf_count,
    uint32_t            leaf_size,
    uint32_t            node_count,
    uint32_t            node_size,
    uint32_t            root_idx);

sk_header_entry_t *
skHentryIPSetCopy(
    const sk_header_entry_t    *hentry);

sk_header_entry_t *
skHentryIPSetCreate(
    uint32_t            child_node,
    uint32_t            leaf_count,
    uint32_t            leaf_size,
    uint32_t            node_count,
    uint32_t            node_size,
    uint32_t            root_idx);

void
skHentryIPSetFree(
    sk_header_entry_t  *hentry);

ssize_t
skHentryIPSetPacker(
    sk_header_entry_t  *in_hentry,
    uint8_t            *out_packed,
    size_t              bufsize);

void
skHentryIPSetPrint(
    sk_header_entry_t  *hentry,
    FILE               *fh);

sk_header_entry_t *
skHentryIPSetUnpacker(
    uint8_t            *in_packed);

#define skHentryIPSetGetChildPerNode(hentry)    \
    (((sk_hentry_ipset_t*)(hentry))->child_node)

#define skHentryIPSetGetLeafCount(hentry)       \
    (((sk_hentry_ipset_t*)(hentry))->leaf_count)

#define skHentryIPSetGetLeafSize(hentry)        \
    (((sk_hentry_ipset_t*)(hentry))->leaf_size)

#define skHentryIPSetGetNodeCount(hentry)       \
    (((sk_hentry_ipset_t*)(hentry))->node_count)

#define skHentryIPSetGetNodeSize(hentry)        \
    (((sk_hentry_ipset_t*)(hentry))->node_size)

#define skHentryIPSetGetRootIndex(hentry)       \
    (((sk_hentry_ipset_t*)(hentry))->root_idx)

#ifdef __cplusplus
}
#endif
#endif /* _SKHEADER_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
