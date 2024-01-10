/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
#ifndef _SKPREFIXMAP_H
#define _SKPREFIXMAP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKPREFIXMAP_H, "$SiLK: skprefixmap.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>
#include <silk/skplugin.h>

/*
**  skprefixmap.h
**
**  Katherine Prevost
**  December 1st, 2004
*/

/**
 *  @file
 *
 *    Implementation of a tree data structure for mapping CIDR blocks
 *    (or protocol/port pairs) to 31-bit unsigned values.  Usually
 *    those values map into a dictionary of labels.
 *
 *    This file is part of libsilk.
 */


/**
 *    The prefix map type is opaque.
 */
typedef struct skPrefixMap_st skPrefixMap_t;

/**
 *    Return values for the functions in this file.
 */
typedef enum skPrefixMapErr_en {
    /** Successful */
    SKPREFIXMAP_OK = 0,
    /** Invalid argument to function (low > high, value out of range) */
    SKPREFIXMAP_ERR_ARGS = 1,
    /** Memory allocation failure */
    SKPREFIXMAP_ERR_MEMORY = 2,
    /** Stream read/write error */
    SKPREFIXMAP_ERR_IO = 3,
    /** Attempt to add duplicate value to dictionary */
    SKPREFIXMAP_ERR_DUPLICATE = 4,
    /** Operation failed since it requires an empty prefix map  */
    SKPREFIXMAP_ERR_NOTEMPTY = 5,
    /** Unexpected values found in file header */
    SKPREFIXMAP_ERR_HEADER = 6,
    /** Prefix map does not support IPv6 addresses */
    SKPREFIXMAP_ERR_NO_IPV6 = 7
} skPrefixMapErr_t;

/**
 *    The type of keys in the prefix map.
 */
typedef enum skPrefixMapContent_en {
    /** Key is an IPv4 address */
    SKPREFIXMAP_CONT_ADDR_V4 = 0,
    /** Key is as IPv6 address */
    SKPREFIXMAP_CONT_ADDR_V6 = 2,
    /** Key is a protocol/port pair */
    SKPREFIXMAP_CONT_PROTO_PORT = 1
} skPrefixMapContent_t;

/**
 *    If the prefix map's content is SKPREFIXMAP_CONT_PROTO_PORT, the
 *    caller should use a pointer to this structure in the
 *    skPrefixMapFindValue(), skPrefixMapFindRange(),
 *    skPrefixMapFindString(), skPrefixMapAddRange(), and
 *    skPrefixMapIteratorNext() functions.  For prefix maps that
 *    contain IP addresses, the caller should pass a pointer to an
 *    skipaddr_t.
 */
typedef struct skPrefixMapProtoPort_st {
    uint8_t     proto;
    uint16_t    port;
} skPrefixMapProtoPort_t;

/**
 *    Structure to support iterating over the entries in the prefix
 *    map.  The internals of this structure should be considered
 *    opaque; the structure is defined publically to allow it to be
 *    created on the stack.
 */
typedef struct skPrefixMapIterator_st {
    const skPrefixMap_t    *map;
    union start_un {
        uint32_t    u32;
        skipaddr_t  addr;
    }                       start;
    union end_un {
        uint32_t    u32;
        skipaddr_t  addr;
    }                       end;
} skPrefixMapIterator_t;


/**
 *    The lookup functions return this value when a value is not found.
 */
#define SKPREFIXMAP_NOT_FOUND       UINT32_C(0xFFFFFFFF)

/**
 *    This is the maximum legal value that may be put into a prefix map.
 */
#define SKPREFIXMAP_MAX_VALUE       UINT32_C(0x7FFFFFFF)



/**
 *    Add a new key->value mapping to the prefix map 'map', specifying
 *    that all keys from 'low_key' to 'high_key' should be mapped to
 *    'dict_val'.  'dict_val' should not be greater than
 *    SKPREFIXMAP_MAX_VALUE.
 *
 *    'low_val' and 'high_val' must be pointers to skipaddr_t's or
 *    skPrefixMapProtoPort_t's.
 */
skPrefixMapErr_t
skPrefixMapAddRange(
    skPrefixMap_t      *map,
    const void         *low_val,
    const void         *high_val,
    uint32_t            dict_val);


/**
 *    Create a new prefix map at the memory pointed at by 'map'.
 */
skPrefixMapErr_t
skPrefixMapCreate(
    skPrefixMap_t     **map);


/**
 *    Frees the resources used by the prefixmap pointed to by map, then
 *    frees map itself.  After calling, map is an invalid pointer.
 *    Does nothing if 'map' is NULL.
 */
void
skPrefixMapDelete(
    skPrefixMap_t      *map);


/**
 *    Fills the character array 'out_buf' with the dictionary entry
 *    (label) for the given integer 'dict_val' and returns the string
 *    length of the label.  If the label's length is larger than
 *    'bufsize', the buffer was too small to hold the label and only
 *    the first bufsize-1 characters were written to 'out_buf'.  A
 *    prefixmap will give a result for any input value; if 'dict_val'
 *    is not in the dictionary, 'out_buf' is filled with a string
 *    representation of the value.
 */
int
skPrefixMapDictionaryGetEntry(
    const skPrefixMap_t    *map,
    uint32_t                dict_val,
    char                   *out_buf,
    size_t                  bufsize);


/**
 *    Returns the length in characters of the longest word in the
 *    dictionary.
 */
uint32_t
skPrefixMapDictionaryGetMaxWordSize(
    const skPrefixMap_t    *map);


/**
 *    Returns the number of words in the dictionary.  Returns 0 if the
 *    prefix map does not contain a dictionary.
 */
uint32_t
skPrefixMapDictionaryGetWordCount(
    const skPrefixMap_t    *map);


/**
 *    Add a new 'word' to the dictionary on the prefix map 'map' at
 *    the location specified by 'dict_val'.  There must not be an
 *    entry at 'dict_val'; that is, 'dict_val' must be greater than
 *    the current maximum dictionary ID or that entry must be empty.
 *    If either of these conditions is not met, return
 *    SKPREFIXMAP_ERR_DUPLICATE.
 *
 *    To insert a word into the dictionary at the next available ID,
 *    use skPrefixMapDictionarySearch().
 */
skPrefixMapErr_t
skPrefixMapDictionaryInsert(
    skPrefixMap_t      *map,
    uint32_t            dict_val,
    const char         *word);


/**
 *    Return the value for a given 'word' in the dictionary associated
 *    with 'map'.  Return SKPREFIXMAP_NOT_FOUND if 'word' is not in
 *    the dictionary.
 *
 *    This function treats 'word' as text to find.  It does not treat
 *    'word' as an index into the dictionary.
 *
 *    See also skPrefixMapDictionarySearch().
 */
uint32_t
skPrefixMapDictionaryLookup(
    const skPrefixMap_t    *map,
    const char             *word);


/**
 *    See if 'word' exists in the dictionary on the prefix map 'map'.
 *    If so, place the ID of its entry in the memory pointed at by
 *    'out_dict_val' and return SKPREFIXMAP_OK.
 *
 *    If 'word' does not exist, append it to the dictionary, fill
 *    'out_dict_val' with the newly created ID, and return
 *    SKPREFIXMAP_OK.
 *
 *    This function treats 'word' as text to find.  It does not treat
 *    'word' as an index into the dictionary.
 *
 *    The function may return SKPREFIXMAP_ERR_MEMORY if it is unable
 *    to grow the dictionary.
 *
 *    See also skPrefixMapDictionaryLookup(), which will not modify
 *    the prefix map 'map'.  To insert a word into the dictionary at a
 *    particular numeric ID, use skPrefixMapDictionaryInsert().
 */
skPrefixMapErr_t
skPrefixMapDictionarySearch(
    skPrefixMap_t      *map,
    const char         *word,
    uint32_t           *out_dict_val);


/**
 *    Find and return the mapped value for 'key' in the prefix map
 *    'map'.  In addition, set the values pointed at by 'start_range'
 *    and 'end_range' to the starting and ending protocol-port pairs
 *    or IP addresses of the range in 'map' that contains 'key'.
 *
 *    Each of 'key', 'start_range', and 'end_range' should be a
 *    pointer to skPrefixMapProtoPort_t if the map's content is
 *    SKPREFIXMAP_CONT_PROTO_PORT or a pointer to skipaddr_t if the
 *    map contains IP addresses.
 *
 *    A valid result is never greater than SKPREFIXMAP_MAX_VALUE.
 *    Returns SKPREFIXMAP_NOT_FOUND if the key is not found in the
 *    tree.
 *
 *    See also skPrefixMapFindString(), skPrefixMapFindValue().
 */
uint32_t
skPrefixMapFindRange(
    const skPrefixMap_t    *map,
    const void             *key,
    void                   *start_range,
    void                   *end_range);


/**
 *    Fill the character array 'out_buf' with the mapped value (label)
 *    for the given 'key' and returns the string length of the label.
 *    'key' should be an skPrefixMapProtoPort_t if the map's content
 *    is SKPREFIXMAP_CONT_PROTO_PORT or an skipaddr_t if the map
 *    contains IP addresses.
 *
 *    If the label's length is larger than 'bufsize', the buffer was
 *    too small to hold the label and only the first bufsize-1
 *    characters were written to 'out_buf'.  A prefixmap will give a
 *    result for any input value.
 *
 *    See also skPrefixMapFindValue(), skPrefixMapFindRange().
 *
 *    skPrefixMapFindString() was added in SiLK-3.8.0 and replaces
 *    skPrefixMapGetString(), which is deprecated.
 */
int
skPrefixMapFindString(
    const skPrefixMap_t    *map,
    const void             *key,
    char                   *out_buf,
    size_t                  bufsize);


/**
 *    Return the mapped value for 'key' in the prefix map 'map'.
 *    'key' should be an skPrefixMapProtoPort_t if the map's content
 *    is SKPREFIXMAP_CONT_PROTO_PORT or an skipaddr_t if the map
 *    contains IP addresses.
 *
 *    A valid result is never greater than SKPREFIXMAP_MAX_VALUE.
 *    Returns SKPREFIXMAP_NOT_FOUND if the key is not found in the
 *    tree.
 *
 *    See also skPrefixMapFindString(), skPrefixMapFindRange().
 *
 *    skPrefixMapFindValue() was added in SiLK-3.8.0 and replaces
 *    skPrefixMapGet(), which is deprecated.
 */
uint32_t
skPrefixMapFindValue(
    const skPrefixMap_t    *map,
    const void             *key);


/**
 *    Alias the skPrefixMapFindValue() function.
 *
 *    skPrefixMapGet() is deprecated as of SiLK 3.8.0.
 */
#define skPrefixMapGet(pmg_a, pmg_b) skPrefixMapFindValue(pmg_a, pmg_b)


/**
 *    Given the content type 'content_id'---which should be a value
 *    from skPrefixMapContent_t---return a textual representation of
 *    it.
 */
const char *
skPrefixMapGetContentName(
    int                 content_id);


/**
 *    Return the content type of the prefix map.  One of:
 *
 *    SKPREFIXMAP_CONTENTS_ADDR_V4 - IPv4 Addresses
 *    SKPREFIXMAP_CONTENTS_ADDR_V6 - IPv6 Addresses
 *    SKPREFIXMAP_CONTENTS_PROTO_PORT - Protocol and Port
 */
skPrefixMapContent_t
skPrefixMapGetContentType(
    const skPrefixMap_t    *map);


/**
 *    Return the map-name of the prefix map, or NULL if no map-name is
 *    defined.
 */
const char *
skPrefixMapGetMapName(
    const skPrefixMap_t    *map);


/**
 *    Alias the skPrefixMapFindString() function.
 *
 *    skPrefixMapGetString() is deprecated as of SiLK 3.8.0.
 */
#define skPrefixMapGetString(pmgs_a, pmgs_b, pmgs_c, pmgs_d)    \
    skPrefixMapFindString(pmgs_a, pmgs_b, pmgs_c, pmgs_d)


/**
 *    Binds the prefix map iterator 'iter' to iterate over all the
 *    entries in the prefix map 'map'.  Returns 0 on success, non-zero
 *    otherwise.
 */
int
skPrefixMapIteratorBind(
    skPrefixMapIterator_t  *iter,
    const skPrefixMap_t    *map);


/**
 *    Creates a new iterator at the address pointed to by 'out_iter'
 *    and binds it to iterate over all the entries in the prefix map
 *    'map'.  Returns 0 on success, non-zero otherwise.
 *
 *    The caller should use skPrefixMapIteratorDestroy() to free the
 *    iterator once iteration is complete.
 */
int
skPrefixMapIteratorCreate(
    skPrefixMapIterator_t **out_iter,
    const skPrefixMap_t    *map);


/**
 *    Destroys the iterator pointed to by 'out_iter'.  Does nothing if
 *    'out_iter' or the location it points to is NULL.
 */
void
skPrefixMapIteratorDestroy(
    skPrefixMapIterator_t **out_iter);


/**
 *    If there are more entries in the prefix map, this function fills
 *    the locations pointed to by 'out_key_start', 'out_key_end', and
 *    'out_dict_val' with the value of the starting and ending values
 *    of the range and the value, respectively, and returns
 *    SK_ITERATOR_OK.  Otherwise, the output values are not touched
 *    and SK_ITERATOR_NO_MORE_ENTRIES is returned.
 *
 *    'out_key_start' and 'out_key_end' should be
 *    skPrefixMapProtoPort_t's if the map's content is
 *    SKPREFIXMAP_CONT_PROTO_PORT or an skipaddr_t's if the map
 *    contains IP addresses.
 */
skIteratorStatus_t
skPrefixMapIteratorNext(
    skPrefixMapIterator_t  *iter,
    void                   *out_key_start,
    void                   *out_key_end,
    uint32_t               *out_dict_val);


/**
 *    Resets the iterator 'iter' to begin looping through the entries
 *    in the prefix map again.
 */
void
skPrefixMapIteratorReset(
    skPrefixMapIterator_t  *iter);


/**
 *    Opens a stream to the file at 'path' and calls skPrefixMapRead()
 *    to read the prefixmap from the stream.
 */
skPrefixMapErr_t
skPrefixMapLoad(
    skPrefixMap_t     **map,
    const char         *path);


/**
 *    Allocates a new prefixmap and assigns a pointer to it into the
 *    provided space, 'map'.  Then reads a prefixmap from the stream
 *    'in'.  Before calling, map should not be NULL, *map may have any
 *    value, and 'in' should open to a valid stream.
 *    skPrefixMapRead() returns successfully memory has been
 *    allocated, and *map will contain a new valid skPrefixMap_t
 *    pointer.  If skPrefixMapRead() returns an error, *map will not
 *    contain a valid pointer, and any allocated memory will have been
 *    freed.
 */
skPrefixMapErr_t
skPrefixMapRead(
    skPrefixMap_t     **map,
    skstream_t         *in);


/**
 *    Open a file at the location specified by 'pathname', and then
 *    call skPrefixMapWrite() to write the prefix map 'map' to that
 *    location.  Finally, close the stream.
 */
skPrefixMapErr_t
skPrefixMapSave(
    skPrefixMap_t      *map,
    const char         *pathname);


/**
 *    Set the content type of the prefix map 'map' to 'content_type'.
 *    Return SKPREFIXMAP_ERR_NO_IPV6 if SiLK is built without IPv6
 *    support.
 */
skPrefixMapErr_t
skPrefixMapSetContentType(
    skPrefixMap_t          *map,
    skPrefixMapContent_t    content_type);


/**
 *    Set the default value to use for the prefix map 'map' to
 *    'dict_val'.  The map must be empty and must have had no default
 *    set previously; if either of these conditions is not met,
 *    SKPREFIXMAP_ERR_NOTEMPTY is returned.
 */
skPrefixMapErr_t
skPrefixMapSetDefaultVal(
    skPrefixMap_t      *map,
    uint32_t            dict_val);


/**
 *    Set the mapname of the prefix map 'map' to 'name'.  Overwrites
 *    the current name.  If 'name' is NULL, the current name is
 *    cleared.  Makes a copy of 'name'.  Returns SKPREFIXMAP_OK on
 *    success.  If there is an allocation error the original mapname
 *    is unchanged and SKPREFIXMAP_ERR_MEMORY is returned.
 */
skPrefixMapErr_t
skPrefixMapSetMapName(
    skPrefixMap_t      *map,
    const char         *name);


/**
 *    Given the 'error_code'---a skPrefixMapErr_t---return a textual
 *    representation of it.
 */
const char *
skPrefixMapStrerror(
    int                 error_code);


/**
 *    Write the binary prefix map 'map' to the stream 'stream'.
 */
skPrefixMapErr_t
skPrefixMapWrite(
    skPrefixMap_t      *map,
    skstream_t         *stream);



/*
 * *********************************************************************
 * Additional functions not strictly part of Prefix Maps
 * *********************************************************************
 */

/**
 *    Provide support in the calling SiLK application for loading a
 *    prefix map and using the switches and fields that are created as
 *    a result of loading the prefix map.
 */
skplugin_err_t
skPrefixMapAddFields(
    uint16_t            major_version,
    uint16_t            minor_version,
    void               *pi_data);


/**
 *    Name of the environment variable naming the path to the
 *    AddressTypes mapping file.
 */
#define SK_ADDRTYPE_MAP_ENVAR "SILK_ADDRESS_TYPES"

/**
 *    Name to use for the AddressTypes mapping file if the above
 *    environment variable is not set.
 */
#define SK_ADDRTYPE_DEFAULT_MAP "address_types.pmap"


/**
 *    Loads the AddressTypes (addrtype) prefix map.
 *
 *    Uses the AddressTypes map name in 'map_name' if that value is
 *    provided.  If not, the environment variable named by
 *    SK_ADDRTYPE_MAP_ENVAR is used.  If that is empty, the
 *    SK_ADDRTYPE_DEFAULT_MAP is used.
 *
 *    Returns 0 on success, or non-zero if the map cannot be found or
 *    there is a problem reading the file.  On error, a messages will
 *    be printed using 'errfn' if non-NULL.
 *
 *    If the AddressTypes map was previously initialized, this
 *    function returns 0.  To load a different map, first destroy the
 *    current mapping by calling skAddressTypesTeardown().
 */
int
skAddressTypesSetup(
    const char         *map_name,
    sk_msg_fn_t         errfn);


/**
 *    Removes the AddressTypes mapping file from memory.
 */
void
skAddressTypesTeardown(
    void);


/**
 *    Return the prefix map file loaded by skAddressTypesSetup().
 *    Return NULL if the AddressTypes prefix map has not been loaded
 *    or failed to load.
 */
skPrefixMap_t *
skAddressTypesGetPmap(
    void);


/**
 *    Add support for the --stype, --dtype switches in rwfilter, and
 *    the stype and dtype fields in rwcut, rwgroup, rwsort, rwuniq,
 *    and rwstats.
 */
skplugin_err_t
skAddressTypesAddFields(
    uint16_t            major_version,
    uint16_t            minor_version,
    void               *pi_data);

#ifdef __cplusplus
}
#endif
#endif /* _SKPREFIXMAP_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
