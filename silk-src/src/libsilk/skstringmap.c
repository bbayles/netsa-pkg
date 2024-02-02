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

#include <silk/silk.h>

RCSIDENT("$SiLK: skstringmap.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skdllist.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include <silk/utils.h>


/* typedef struct sk_stringmap_iter_st sk_stringmap_iter_t; */
struct sk_stringmap_iter_st {
    sk_vector_t    *vec;
    size_t          pos;
    unsigned        has_attr :1;
};

/* objects to put inside the iterator */
typedef struct stringmap_iter_node_st {
    sk_stringmap_entry_t   *entry;
    const char             *attr;
} stringmap_iter_node_t;


/* LOCAL VARIABLES */

/* value to use for no attributes */
static const char *stringmap_no_attr = "";

/* for returning an error to the caller */
static char errbuf[2 * PATH_MAX];


/* LOCAL FUNCTION DECLARATIONS */

static sk_stringmap_status_t
stringMapCheckValidName(
    sk_stringmap_t     *str_map,
    const char         *name);

static void
stringMapFreeEntry(
    sk_stringmap_entry_t   *map_entry);


/* FUNCTION DEFINITIONS */

/* Create a new string map */
sk_stringmap_status_t
skStringMapCreate(
    sk_stringmap_t    **out_str_map)
{
    *out_str_map = skDLListCreate((sk_dll_free_fn_t)&stringMapFreeEntry);
    if (*out_str_map == NULL) {
        return SKSTRINGMAP_ERR_MEM;
    }

    return SKSTRINGMAP_OK;
}


/* Destroy a string map */
sk_stringmap_status_t
skStringMapDestroy(
    sk_stringmap_t     *str_map)
{
    skDLListDestroy(str_map);
    return SKSTRINGMAP_OK;
}


/* add multiple keys to a StringMap */
sk_stringmap_status_t
skStringMapAddEntries(
    sk_stringmap_t             *str_map,
    int                         entryc,
    const sk_stringmap_entry_t *entryv)
{
    sk_stringmap_entry_t *map_entry = NULL;
    sk_stringmap_entry_t *node = NULL;
    sk_dll_iter_t map_node;
    const sk_stringmap_entry_t *e;
    sk_stringmap_status_t rv;
    int i;
    int rv_list;

    /* check inputs */
    if (str_map == NULL || entryv == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    /* use "i != entryc" to handle entryc < 0 */
    for (i = 0, e = entryv; i != entryc && e->name != NULL; ++i, ++e) {
        /* check to see if the name is valid */
        rv = stringMapCheckValidName(str_map, e->name);
        if (SKSTRINGMAP_OK != rv) {
            return rv;
        }
    }
    if (entryc < 0) {
        entryc = i;
    } else if (i < entryc) {
        /* NULL name given within the first entryc entries */
        return SKSTRINGMAP_ERR_INPUT;
    }

#if 0
    for (i = 0, e = entryv; i < entryc; ++i, ++e) {
        if (e->description) {
            fprintf(stderr, "skStringMapAddEntry('%s', %u, '%s', %p)\n",
                    e->name, e->id, (char*)e->description, e->userdata);
        } else {
            fprintf(stderr, "skStringMapAddEntry('%s', %u, NULL, %p)\n",
                    e->name, e->id, e->userdata);
        }
    }
#endif  /* 0 */

    for (i = 0, e = entryv; i < entryc; ++i, ++e) {
        assert(e->name);
        /* allocate entry */
        map_entry = (sk_stringmap_entry_t*)malloc(sizeof(sk_stringmap_entry_t));
        if (NULL == map_entry) {
            return SKSTRINGMAP_ERR_MEM;
        }

        /* copy the entry from the caller */
        map_entry->id = e->id;
        map_entry->userdata = e->userdata;
        map_entry->description = NULL;

        /* duplicate strings for our own use */
        map_entry->name = strdup(e->name);
        if (NULL == map_entry->name) {
            rv = SKSTRINGMAP_ERR_MEM;
            goto ERROR;
        }
        if (e->description) {
            map_entry->description = strdup((const char*)e->description);
            if (NULL == map_entry->description) {
                rv = SKSTRINGMAP_ERR_MEM;
                goto ERROR;
            }
        }

        /* if this entry has the same ID as an existing entry, add the
         * new entry after the existing entry */
        skDLLAssignIter(&map_node, str_map);
        while (skDLLIterBackward(&map_node, (void **)&node) == 0) {
            if (node->id == map_entry->id) {
                if (skDLLIterAddAfter(&map_node, (void*)map_entry)) {
                    rv = SKSTRINGMAP_ERR_MEM;
                    goto ERROR;
                }
                map_entry = NULL;
                break;
            }
        }

        if (map_entry) {
            /* add entry to end of list */
            rv_list = skDLListPushTail(str_map, (void *)map_entry);
            if (rv_list != 0) {
                rv = SKSTRINGMAP_ERR_MEM;
                goto ERROR;
            }
        }
    }

    return SKSTRINGMAP_OK;

  ERROR:
    stringMapFreeEntry(map_entry);
    return rv;
}


/* remove a key from a StringMap */
sk_stringmap_status_t
skStringMapRemoveByName(
    sk_stringmap_t     *str_map,
    const char         *name)
{
    int rv_list;
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;

    /* check inputs */
    if (str_map == NULL || name == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    skDLLAssignIter(&map_node, str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        if (strcasecmp(map_entry->name, name) == 0) {
            rv_list = skDLLIterDel(&map_node);
            if (rv_list != 0) {
                assert(0);
                return SKSTRINGMAP_ERR_LIST;
            }
            stringMapFreeEntry(map_entry);
        }
    }

    return SKSTRINGMAP_OK;
}


/* remove all entries have given ID from a StringMap */
sk_stringmap_status_t
skStringMapRemoveByID(
    sk_stringmap_t     *str_map,
    sk_stringmap_id_t   id)
{
    int rv_list;
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;

    /* check inputs */
    if (str_map == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    skDLLAssignIter(&map_node, str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        if (id == map_entry->id) {
            rv_list = skDLLIterDel(&map_node);
            if (rv_list != 0) {
                assert(0);
                return SKSTRINGMAP_ERR_LIST;
            }
            stringMapFreeEntry(map_entry);
        }
    }

    return SKSTRINGMAP_OK;
}


/* remove multiple keys from a StringMap */
sk_stringmap_status_t
skStringMapRemoveEntries(
    sk_stringmap_t             *str_map,
    int                         entryc,
    const sk_stringmap_entry_t *entryv)
{
    const sk_stringmap_entry_t *e;
    sk_stringmap_status_t rv;
    int i;

    /* check inputs */
    if (str_map == NULL || entryv == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    /* use "i != entryc" to handle entryc < 0 */
    for (i = 0, e = entryv; i != entryc && e->name != NULL; ++i, ++e)
        ;  /* empty */
    if (entryc < 0) {
        entryc = i;
    } else if (i < entryc) {
        /* NULL name given within the first entryc entries */
        return SKSTRINGMAP_ERR_INPUT;
    }

    for (i = 0, e = entryv; i < entryc; ++i, ++e) {
        assert(e->name);
        rv = skStringMapRemoveByName(str_map, e->name);
        if (rv != SKSTRINGMAP_OK) {
            return rv;
        }
    }

    return SKSTRINGMAP_OK;
}


static sk_stringmap_status_t
stringMapIterCreate(
    sk_stringmap_iter_t   **iter,
    const int               with_attr)
{
    sk_stringmap_iter_t *map_iter;

    assert(iter);

    map_iter = (sk_stringmap_iter_t*)calloc(1, sizeof(sk_stringmap_iter_t));
    if (NULL == map_iter) {
        return SKSTRINGMAP_ERR_MEM;
    }
    if (with_attr) {
        map_iter->vec = skVectorNew(sizeof(stringmap_iter_node_t));
        map_iter->has_attr = 1;
    } else {
        map_iter->vec = skVectorNew(sizeof(sk_stringmap_entry_t*));
    }
    if (NULL == map_iter->vec) {
        free(map_iter);
        return SKSTRINGMAP_ERR_MEM;
    }
    *iter = map_iter;
    return SKSTRINGMAP_OK;
}


size_t
skStringMapIterCountMatches(
    sk_stringmap_iter_t    *iter)
{
    if (NULL == iter) {
        return 0;
    }
    return skVectorGetCount(iter->vec);
}


void
skStringMapIterDestroy(
    sk_stringmap_iter_t    *iter)
{
    stringmap_iter_node_t *node;
    size_t count;
    size_t i;

    if (iter) {
        if (iter->vec) {
            if (iter->has_attr) {
                count = skVectorGetCount(iter->vec);
                for (i = 0; i < count; ++i) {
                    node = ((stringmap_iter_node_t*)
                            skVectorGetValuePointer(iter->vec, i));
                    if (node->attr != stringmap_no_attr) {
                        free((char*)node->attr);
                    }
                }
            }
            skVectorDestroy(iter->vec);
        }
        memset(iter, 0, sizeof(sk_stringmap_iter_t));
        free(iter);
    }
}


int
skStringMapIterNext(
    sk_stringmap_iter_t    *iter,
    sk_stringmap_entry_t  **entry,
    const char            **attr)
{
    stringmap_iter_node_t *iter_node;

    assert(entry);

    if (NULL == iter) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    if (iter->pos >= skVectorGetCount(iter->vec)) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    if (!iter->has_attr) {
        skVectorGetValue(entry, iter->vec, iter->pos);
    } else {
        iter_node = ((stringmap_iter_node_t*)
                     skVectorGetValuePointer(iter->vec, iter->pos));
        *entry = iter_node->entry;
        if (attr) {
            *attr = iter_node->attr;
        }
    }
    ++iter->pos;
    return SK_ITERATOR_OK;
}


void
skStringMapIterReset(
    sk_stringmap_iter_t    *iter)
{
    if (iter) {
        iter->pos = 0;
    }
}


/*
 *  stringMapFind(str_map, token, token_len, &found_entry);
 *
 *    Search in 'str_map' for an entry that matches 'token', whose
 *    length is 'token_len'.  'token' does not need to be NUL
 *    terminated.
 *
 *    When 'token' is an exact match for an entry or is a prefix for
 *    one and only one entry, set 'found_entry' to that entry and
 *    return SKSTRINGMAP_OK.  If 'token' is a prefix for multiple
 *    entries and does not match a complete entry exactly, set
 *    'found_entry' to one of the entries and return
 *    SKSTRINGMAP_PARSE_AMBIGUOUS.  If no match for 'token' is found,
 *    set 'found_entry' to NULL and return SKSTRINGMAP_PARSE_NO_MATCH.
 */
static sk_stringmap_status_t
stringMapFind(
    const sk_stringmap_t   *str_map,
    const char             *token,
    const size_t            token_len,
    sk_stringmap_entry_t  **found_entry)
{
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;
    int unique = 1;

    assert(found_entry);
    assert(str_map);
    assert(token);
    assert(token_len > 0);

    *found_entry = NULL;

    /* Typecast away const.  We are still treating it as const
     * though. */
    skDLLAssignIter(&map_node, (sk_stringmap_t *)str_map);
    /* check the token against each entry in the map */
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {

        if (0 != strncasecmp(map_entry->name, token, token_len)) {
            /* no match, try next entry in the map */
            continue;
        }

        /* first 'token_len' chars match.  check whether exact match */
        if (map_entry->name[token_len] == '\0') {
            /* exact match; set found_entry here and return */
            *found_entry = map_entry;
            return SKSTRINGMAP_OK;
        }
        /* else not an exact match. */

        if (isdigit((int)*token)) {
            /* partial number match doesn't make sense; try again */
            continue;
        }
        /* else partial match. */

        /* If '*found_entry' has not been set, set it to this location
         * as a potential match.  Else if '*found_entry' is set,
         * compare the IDs on the current entry and *found_entry and
         * if they are different, return 'ambiguous'. */
        if (*found_entry == NULL) {
            *found_entry = map_entry;
        } else if ((*found_entry)->id != map_entry->id) {
            /* The 'token' matches two entries with different IDs;
             * mark as possibly ambiguous.  Continue in case there is
             * an exact match. */
            unique = 0;
        }
        /* else token matches two entries that map to same ID, so
         * allow it and don't complain. */
    }

    if (!unique) {
        /* Multiple matches were found, mark as ambiguous */
        return SKSTRINGMAP_PARSE_AMBIGUOUS;
    }

    /* did we find a match? */
    if (*found_entry == NULL) {
        return SKSTRINGMAP_PARSE_NO_MATCH;
    }

    return SKSTRINGMAP_OK;
}


/*
 *  stringMapFindCheckDupes(str_map, token, token_len, &found_entry, iter, handle_dupes);
 *
 *    Search in 'str_map' for an entry that matches 'token', whose
 *    length is 'token_len'.  'token' does not need to be NUL
 *    terminated.
 *
 *    When 'token' is an exact match for an entry or is a prefix for
 *    one and only one entry, the result depends on the setting of
 *    'handle_dupes'.  If 'handle_dupes' is SKSTRINGMAP_DUPES_KEEP,
 *    'found_entry' is set to that entry and the function returns
 *    SKSTRINGMAP_OK.  When 'handle_dupes' is SKSTRINGMAP_DUPES_KEEP,
 *    'iter' may be NULL.  Any other value of 'handle_dupes' requires
 *    the 'iter' parameter.  If 'handle_dups' is
 *    SKSTRINGMAP_DUPES_ERROR, set 'found_entry' to the duplicate, put
 *    an appropriate error message into 'errbuf', and return
 *    SKSTRINGMAP_ERR_DUPLICATE_ENTRY.  If 'handle_dups' is
 *    SKSTRINGMAP_DUPES_REMOVE_SILENT, set 'found_entry' to NULL and
 *    return SKSTRINGMAP_OK.  If 'handle_dups' is
 *    SKSTRINGMAP_DUPES_REMOVE_WARN, set 'found_entry' to NULL, put a
 *    warning message into 'errbuf', and return
 *    SKSTRINGMAP_OK_DUPLICATE.
 *
 *    If 'token' is a prefix for multiple entries and does not match a
 *    complete entry exactly, set 'found_entry' to one of the entries,
 *    put an appropriate error message into 'errbuf', and return
 *    SKSTRINGMAP_PARSE_AMBIGUOUS.
 *
 *    If no match for 'token' is found, set 'found_entry' to NULL, put
 *    an appropriate error message into 'errbuf', and return
 *    SKSTRINGMAP_PARSE_NO_MATCH.
 */
static sk_stringmap_status_t
stringMapFindCheckDupes(
    const sk_stringmap_t       *str_map,
    const char                 *token,
    const size_t                token_len,
    sk_stringmap_entry_t      **found_entry,
    const sk_stringmap_iter_t  *iter,
    sk_stringmap_dupes_t        handle_dupes)
{
#define COPY_TOKEN                              \
    if (token_len > sizeof(buf)) {              \
        strncpy(buf, token, sizeof(buf));       \
        buf[sizeof(buf)-1] = '\0';              \
    } else {                                    \
        strncpy(buf, token, token_len);         \
        buf[token_len] = '\0';                  \
    }

    char buf[PATH_MAX];
    sk_stringmap_status_t rv;
    sk_stringmap_entry_t *entry;
    void *ptr;
    size_t j;

    assert(found_entry);
    assert(str_map);
    assert(token);
    assert(token_len > 0);
    assert(SKSTRINGMAP_DUPES_KEEP == handle_dupes || iter);

    rv = stringMapFind(str_map, token, token_len, found_entry);
    switch (rv) {
      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        COPY_TOKEN;
        snprintf(errbuf, sizeof(errbuf),
                 "The field '%s' matches multiple keys", buf);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        COPY_TOKEN;
        snprintf(errbuf, sizeof(errbuf),
                 "No match was found for the field '%s'", buf);
        break;

      case SKSTRINGMAP_OK:
        /* found a single match. it may be a duplicate */
        if (SKSTRINGMAP_DUPES_KEEP == handle_dupes) {
            /* dupes are ok. */
            break;
        }
        /* else search for a duplicate */
        for (j = 0;
             NULL != (ptr = skVectorGetValuePointer(iter->vec, j));
             ++j)
        {
            if (iter->has_attr) {
                entry = ((stringmap_iter_node_t*)ptr)->entry;
            } else {
                entry = *((sk_stringmap_entry_t**)ptr);
            }
            if (entry->id != (*found_entry)->id) {
                continue;
            }
            /* found a dupe */
            switch (handle_dupes) {
              case SKSTRINGMAP_DUPES_ERROR:
                rv = SKSTRINGMAP_ERR_DUPLICATE_ENTRY;
                COPY_TOKEN;
                snprintf(errbuf, sizeof(errbuf),
                         "Duplicate name '%s'", buf);
                break;
              case SKSTRINGMAP_DUPES_REMOVE_WARN:
                rv = SKSTRINGMAP_OK_DUPLICATE;
                COPY_TOKEN;
                snprintf(errbuf, sizeof(errbuf),
                         "Ignoring duplicate value '%s'", buf);
                /* FALLTHROUGH */
              case SKSTRINGMAP_DUPES_REMOVE_SILENT:
                *found_entry = NULL;
                break;
              case SKSTRINGMAP_DUPES_KEEP:
                /* shouldn't be in this loop at all */
                skAbortBadCase(handle_dupes);
            }
            break;
        }
        break;

      default:
        snprintf(errbuf, sizeof(errbuf),
                 "Unexpected return value from field parser (%d)", rv);
        break;
    }
    return rv;
}


/* match a single key against a StringMap, filling out_entry with a
 * pointer to the entry. */
sk_stringmap_status_t
skStringMapGetByName(
    const sk_stringmap_t   *str_map,
    const char             *user_string,
    sk_stringmap_entry_t  **out_entry)
{
    sk_stringmap_status_t rv;
    sk_stringmap_entry_t *found_entry;

    /* check inputs */
    if (out_entry == NULL || str_map == NULL
        || user_string == NULL || user_string[0] == '\0')
    {
        return SKSTRINGMAP_ERR_INPUT;
    }

    rv = stringMapFind(str_map, user_string, strlen(user_string),&found_entry);
    if (rv == SKSTRINGMAP_OK) {
        *out_entry = found_entry;
    }

    return rv;
}


/* match a single key against a StringMap, filling out_entry with a
 * pointer to the entry. */
sk_stringmap_status_t
skStringMapGetByNameWithAttributes(
    const sk_stringmap_t   *str_map,
    const char             *user_string,
    sk_stringmap_entry_t  **out_entry,
    char                   *attributes,
    size_t                  attributes_len)
{
    sk_stringmap_status_t rv;
    sk_stringmap_entry_t *found_entry;
    const char *cp;
    const char *ep;
    size_t len;

    /* check inputs */
    if (out_entry == NULL || str_map == NULL
        || user_string == NULL || user_string[0] == '\0'
        || attributes == NULL || attributes_len == 0)
    {
        return SKSTRINGMAP_ERR_INPUT;
    }

    /* find the start of attributes, and check for invalid
     * characters. set 'len' to length of field */
    cp = strpbrk(user_string, ":[]");
    if (NULL == cp) {
        attributes[0] = '\0';
        len = strlen(user_string);
    } else if ('[' == *cp || ']' == *cp) {
        return SKSTRINGMAP_PARSE_UNPARSABLE;
    } else {
        len = cp - user_string;
    }

    /* find the field; set 'out_entry' if successful */
    rv = stringMapFind(str_map, user_string, len, &found_entry);
    if (rv != SKSTRINGMAP_OK) {
        return rv;
    }
    *out_entry = found_entry;

    /* if no attributes, return */
    if (NULL == cp) {
        return rv;
    }

    /* move 'cp' onto first char in the attributes */
    ++cp;
    if ('\0' == *cp) {
        return SKSTRINGMAP_PARSE_UNPARSABLE;
    } else if ('[' != *cp) {
        /* ensure a single attribute */
        if (strpbrk(cp, ",:[]")) {
            return SKSTRINGMAP_PARSE_UNPARSABLE;
        }
        len = strlen(cp);
    } else {
        /* find end of attributes and check for invalid chars */
        ++cp;
        ep = strpbrk(cp, ":[]");
        if ((NULL == ep) || (cp == ep) || (':' == *ep) || ('[' == *ep)
            || ('\0' != *(ep + 1)))
        {
            return SKSTRINGMAP_PARSE_UNPARSABLE;
        }
        len = ep - cp;
    }

    /* copy attributes and return */
    if (len >= attributes_len) {
        return SKSTRINGMAP_PARSE_UNPARSABLE;
    }
    strncpy(attributes, cp, attributes_len);
    attributes[len] = '\0';
    return rv;
}


/*
 *  stringMapGetToken(dest, src, dest_len);
 *
 *    Find the end of the current token in 'src' and copy that value
 *    into 'dest', a buffer of size 'dest_len'.  The end of a token
 *    normally occurs at the next ','; however, if a '[' is found
 *    before the next comma, the token extends to the next ']'
 *    character.  No attempt is made to handled nested '[' and ']'
 *    characters.
 *
 *    If the current token is larger than 'dest_len', copy as much of
 *    the token as possible into 'dest'.
 */
static void
stringMapGetToken(
    char               *dest,
    const char         *src,
    size_t              dest_len)
{
    const char *ep;

    ep = strpbrk(src, ",[");
    if (NULL == ep) {
        strncpy(dest, src, dest_len);
        dest[dest_len-1] = '\0';
        return;
    }
    if (*ep == '[') {
        ep = strchr(ep, ']');
        if (NULL == ep) {
            strncpy(dest, src, dest_len);
            dest[dest_len-1] = '\0';
            return;
        }
    }
    if (ep - src < (ssize_t)dest_len) {
        dest_len = 1 + ep - src;
    }
    strncpy(dest, src, dest_len);
    dest[dest_len - 1] = '\0';
}


/*
 *  status = stringMapSetAttribute(iter, attr_str, attr_str_len);
 *
 *    Copy 'attr_str_len' characters from the string 'attr_str' into
 *    newly allocated memory and then set the 'attr' field for the
 *    final value in the stringmap iterator 'iter'.  Return
 *    SKSTRINGMAP_ERR_MEM if the allocation operation fails; otherwise
 *    return SKSTRINGMAP_OK.
 */
static sk_stringmap_status_t
stringMapSetAttribute(
    sk_stringmap_iter_t    *iter,
    const char             *attribute,
    size_t                  len)
{
    stringmap_iter_node_t *iter_node;
    char *cp;

    assert(iter);
    assert(iter->vec);
    assert(sizeof(stringmap_iter_node_t) == skVectorGetElementSize(iter->vec));
    assert(skVectorGetCount(iter->vec) > 0);
    assert(attribute);
    assert(len);

    cp = (char*)malloc(1 + len);
    if (NULL == cp) {
        return SKSTRINGMAP_ERR_MEM;
    }
    strncpy(cp, attribute, len);
    cp[len] = '\0';

    iter_node = ((stringmap_iter_node_t*)
                 skVectorGetValuePointer(iter->vec,
                                         skVectorGetCount(iter->vec) - 1));
    assert(iter_node);
    assert(stringmap_no_attr == iter_node->attr);

    iter_node->attr = cp;
    return SKSTRINGMAP_OK;
}


/*
 *    A helper function for skStringMapMatch(), skStringMapParse(),
 *    and skStringMapParseWithAttributes().
 */
static sk_stringmap_status_t
stringMapParseHelper(
    const sk_stringmap_t           *str_map,
    const char                     *user_string,
    const sk_stringmap_dupes_t      handle_dupes,
    const int                       wants_attr,
    sk_stringmap_iter_t           **out_iter,
    char                          **bad_token,
    char                          **errmsg)
{
    char buf[PATH_MAX];

    const char *delim;
    const char *cp;
    const char *ep;
    const char *attr_start;

    int saw_dupes = 0;

    sk_stringmap_status_t rv;
    sk_stringmap_entry_t *entry;

    sk_stringmap_iter_t *iter = NULL;
    stringmap_iter_node_t iter_node;

    uint32_t range_beg;
    uint32_t range_end;
    uint32_t i;
    int parse_rv;
    int vec_rv;

    int len;

    enum parse_state_en {
        SM_START, SM_PARTIAL, SM_ATTR_LIST, SM_ATTR
    } state;

    /* check inputs */
    if (str_map == NULL || out_iter == NULL || user_string == NULL) {
        snprintf(errbuf, sizeof(errbuf),
                 "Programmer error: NULL passed to function");
        rv = SKSTRINGMAP_ERR_INPUT;
        goto END;
    }

    cp = user_string;
    while (isspace((int)*cp)) {
        ++cp;
    }
    if (*cp == '\0') {
        snprintf(errbuf, sizeof(errbuf), "Field list is empty");
        rv = SKSTRINGMAP_ERR_INPUT;
        goto END;
    }

    /* initialize values */
    rv = stringMapIterCreate(&iter, wants_attr);
    if (rv) {
        goto END;
    }
    if (wants_attr) {
        delim = ":,-[]";
    } else {
        delim = ",-";
    }
    state = SM_START;
    ep = cp;
    attr_start = cp;
    saw_dupes = 0;

    while (*cp) {
        ep = strpbrk(ep, delim);
        if (ep == NULL) {
            /* at end of string; put 'ep' on the final \0. */
            for (ep = cp + 1; *ep; ++ep)
                ; /* empty */
        }
        switch (state) {
          case SM_START:
            if (ep == cp) {
                if (',' == *cp) {
                    /* double delimiter */
                    ++cp;
                    ep = cp;
                    continue;
                }
                /* else error; report bad token */
                stringMapGetToken(buf, cp, sizeof(buf));
                if (bad_token) {
                    *bad_token = strdup(buf);
                }
                snprintf(errbuf, sizeof(errbuf),
                         "Invalid character at start of name '%s'", buf);
                rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                goto END;
            }
            if (isdigit(*cp) && *ep == '-') {
                /* looks like a numeric range */
                parse_rv = skStringParseUint32(&range_beg, cp, 0, 0);
                if (parse_rv < 0 || parse_rv != ep - cp) {
                    /* error; report bad token */
                    stringMapGetToken(buf, cp, sizeof(buf));
                    if (bad_token) {
                        *bad_token = strdup(buf);
                    }
                    snprintf(errbuf, sizeof(errbuf),
                             "Cannot parse start of numeric range '%s'", buf);
                    rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                    goto END;
                }
                ++ep;
                parse_rv = skStringParseUint32(&range_end, ep, 0, 0);
                if (parse_rv < 0 || (parse_rv > 0 && *(ep + parse_rv) != ',')){
                    stringMapGetToken(buf, cp, sizeof(buf));
                    if (bad_token) {
                        *bad_token = strdup(buf);
                    }
                    snprintf(errbuf, sizeof(errbuf),
                             "Cannot parse end of numeric range '%s'", buf);
                    rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                    goto END;
                }
                /* parse is good; move 'ep' to end of token */
                if (parse_rv) {
                    ep += parse_rv;
                } else {
                    for (++ep; *ep; ++ep)
                        ; /* empty */
                }
                if (range_end < range_beg) {
                    stringMapGetToken(buf, cp, sizeof(buf));
                    if (bad_token) {
                        *bad_token = strdup(buf);
                    }
                    snprintf(errbuf, sizeof(errbuf),
                             "Invalid numeric range '%s'", buf);
                    rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                    goto END;
                }
                for (i = range_beg; i <= range_end; ++i) {
                    len = snprintf(buf, sizeof(buf), ("%" PRIu32), i);
                    rv = stringMapFindCheckDupes(str_map, buf, len, &entry,
                                                 iter, handle_dupes);
                    if (SKSTRINGMAP_OK_DUPLICATE == rv) {
                        saw_dupes = 1;
                        rv = SKSTRINGMAP_OK;
                    } else if (rv) {
                        if (bad_token) {
                            *bad_token = strdup(buf);
                        }
                        snprintf(errbuf, sizeof(errbuf),
                                 "No match was found for the value '%s'", buf);
                        goto END;
                    } else if (NULL != entry) {
                        if (wants_attr) {
                            iter_node.entry = entry;
                            iter_node.attr = stringmap_no_attr;
                            vec_rv = skVectorAppendValue(iter->vec, &iter_node);
                        } else {
                            vec_rv = skVectorAppendValue(iter->vec, &entry);
                        }
                        if (vec_rv) {
                            snprintf(errbuf, sizeof(errbuf), "Out of memory");
                            rv = SKSTRINGMAP_ERR_MEM;
                            goto END;
                        }
                    }
                }
                cp = ep;
                break;
            }
            /* FALLTHROUGH */

          case SM_PARTIAL:
            if (*ep == '-') {
                /* handle a token such as "foo-bar" */
                ++ep;
                state = SM_PARTIAL;
                continue;
            }
            if (*ep == '[' || *ep == ']') {
                stringMapGetToken(buf, cp, sizeof(buf));
                if (bad_token) {
                    *bad_token = strdup(buf);
                }
                snprintf(errbuf, sizeof(errbuf),
                         "Invalid character '%c' in name '%s'",
                         *ep, buf);
                rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                goto END;
            }
            rv = stringMapFindCheckDupes(str_map, cp, ep-cp, &entry,
                                         iter, handle_dupes);
            if (SKSTRINGMAP_OK_DUPLICATE == rv) {
                saw_dupes = 1;
                rv = SKSTRINGMAP_OK;
            } else if (rv) {
                if (bad_token) {
                    stringMapGetToken(buf, cp, sizeof(buf));
                    *bad_token = strdup(buf);
                }
                goto END;
            } else if (NULL != entry) {
                if (wants_attr) {
                    /* will set the attribute later if we find one */
                    iter_node.entry = entry;
                    iter_node.attr = stringmap_no_attr;
                    vec_rv = skVectorAppendValue(iter->vec, &iter_node);
                } else {
                    vec_rv = skVectorAppendValue(iter->vec, &entry);
                }
                if (vec_rv) {
                    snprintf(errbuf, sizeof(errbuf), "Out of memory");
                    rv = SKSTRINGMAP_ERR_MEM;
                    goto END;
                }
            }
            if (*ep == ',' || *ep == '\0') {
                /* attribute is empty */
                if (*ep) {
                    ++ep;
                }
                cp = ep;
                state = SM_START;
            } else if (*ep == ':') {
                ++ep;
                if (*ep == '[') {
                    ++ep;
                    state = SM_ATTR_LIST;
                } else {
                    state = SM_ATTR;
                }
                attr_start = ep;
            } else {
                skAbort();
            }
            break;

          case SM_ATTR:
            if (*ep == '-') {
                ++ep;
                continue;
            }
            if (*ep == ',' || *ep == '\0') {
                rv = stringMapSetAttribute(iter, attr_start, ep - attr_start);
                if (rv) {
                    snprintf(errbuf, sizeof(errbuf), "Out of memory");
                    goto END;
                }
                if (*ep) {
                    ++ep;
                }
                cp = ep;
                state = SM_START;
            } else {
                /* bad character */
                stringMapGetToken(buf, cp, sizeof(buf));
                if (bad_token) {
                    *bad_token = strdup(buf);
                }
                snprintf(errbuf, sizeof(errbuf),
                         "Invalid character '%c' in attribute for field '%s'",
                         *ep, buf);
                rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                goto END;
                /* else error */
            }
            break;

          case SM_ATTR_LIST:
            if (*ep == '-' || *ep == ',') {
                ++ep;
                continue;
            }
            if (*ep == ']') {
                rv = stringMapSetAttribute(iter, attr_start, ep - attr_start);
                if (rv) {
                    snprintf(errbuf, sizeof(errbuf), "Out of memory");
                    goto END;
                }
                ++ep;
                cp = ep;
                state = SM_START;
            } else if (*ep == '\0') {
                /* error: not closed */
                if (bad_token) {
                    *bad_token = strdup(cp);
                }
                snprintf(errbuf, sizeof(errbuf),
                         "Did not find closing ']' in attribute for field '%s'",
                         cp);
                rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                goto END;
            } else {
                /* error: bad character */
                stringMapGetToken(buf, cp, sizeof(buf));
                if (bad_token) {
                    *bad_token = strdup(buf);
                }
                snprintf(errbuf, sizeof(errbuf),
                         "Invalid character '%c' in attribute for field '%s'",
                         *ep, buf);
                rv = SKSTRINGMAP_PARSE_UNPARSABLE;
                goto END;
            }
            break;
        }
    }

    /* success */
    *out_iter = iter;

    if (saw_dupes) {
        rv = SKSTRINGMAP_OK_DUPLICATE;
        if (errmsg) {
            *errmsg = errbuf;
        }
    } else {
        rv = SKSTRINGMAP_OK;
    }

  END:
    if (rv != SKSTRINGMAP_OK && rv != SKSTRINGMAP_OK_DUPLICATE) {
        if (errmsg) {
            *errmsg = errbuf;
        }
        if (iter) {
            skStringMapIterDestroy(iter);
        }
    }
    return rv;
}


/* parse a user string for a list of keys, and match those keys
 * againts a StringMap */
sk_stringmap_status_t
skStringMapMatch(
    const sk_stringmap_t   *str_map,
    const char             *user_string,
    sk_stringmap_iter_t   **iter,
    char                  **bad_token)
{
    return stringMapParseHelper(str_map, user_string, SKSTRINGMAP_DUPES_KEEP,
                                0, iter, bad_token, NULL);
}


/* parse a user string for a list of keys, and match those keys
 * againts a StringMap.  Handle duplicate entries as directed.  If an
 * error occurs, set 'errmsg' to a static buffer containing the
 * error.  */
sk_stringmap_status_t
skStringMapParse(
    const sk_stringmap_t   *str_map,
    const char             *user_string,
    sk_stringmap_dupes_t    handle_dupes,
    sk_stringmap_iter_t   **iter,
    char                  **errmsg)
{
    return stringMapParseHelper(str_map, user_string, handle_dupes, 0,
                                iter, NULL, errmsg);
}


sk_stringmap_status_t
skStringMapParseWithAttributes(
    const sk_stringmap_t   *str_map,
    const char             *user_string,
    sk_stringmap_dupes_t    handle_dupes,
    sk_stringmap_iter_t   **iter,
    char                  **errmsg)
{
    return stringMapParseHelper(str_map, user_string, handle_dupes, 1,
                                iter, NULL, errmsg);
}


/* add to a list the string names which map to a particular value */
sk_stringmap_status_t
skStringMapGetByID(
    const sk_stringmap_t   *str_map,
    sk_stringmap_id_t       id,
    sk_stringmap_iter_t   **iter)
{
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;

    /* check inputs */
    if (iter == NULL || str_map == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    if (stringMapIterCreate(iter, 0)) {
        return SKSTRINGMAP_ERR_MEM;
    }

    /* Typecast away const.  We are still treating it as const
     * though. */
    skDLLAssignIter(&map_node, (sk_stringmap_t *)str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        /* add name if the id matches */
        if (map_entry->id == id) {
            if (0 != skVectorAppendValue((*iter)->vec, &map_entry)) {
                skStringMapIterDestroy(*iter);
                *iter = NULL;
                return SKSTRINGMAP_ERR_MEM;
            }
        }
    }

    return SKSTRINGMAP_OK;
}


/* return the name of the first entry in 'str_map' whose ID matches
 * 'id' */
const char *
skStringMapGetFirstName(
    const sk_stringmap_t   *str_map,
    sk_stringmap_id_t       id)
{
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;

    /* Typecast away const.  We are still treating it as const
     * though. */
    skDLLAssignIter(&map_node, (sk_stringmap_t *)str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        /* add name if the id matches */
        if (map_entry->id == id) {
            return (const char *)(map_entry->name);
        }
    }

    return NULL;
}


/*
 * Helper functions
 */

/* print the StringMap to an output stream in human-readable form */
sk_stringmap_status_t
skStringMapPrintMap(
    const sk_stringmap_t   *str_map,
    FILE                   *outstream)
{
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;
    int first_entry_skip_comma = 1;

    if (str_map == NULL || outstream == NULL) {
        return SKSTRINGMAP_ERR_INPUT;
    }

    fprintf(outstream, "{");
    /* Typecast away const.  We are still treating it as const
     * though. */
    skDLLAssignIter(&map_node, (sk_stringmap_t *)str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        if (!first_entry_skip_comma) {
            fprintf(outstream, ", ");
        } else {
            first_entry_skip_comma = 0;
        }

        fprintf(outstream, (" \"%s\" : %" PRIu32),
                map_entry->name, (uint32_t)map_entry->id);
    }
    fprintf(outstream, " }");

    return SKSTRINGMAP_OK;
}


void
skStringMapPrintUsage(
    const sk_stringmap_t   *str_map,
    FILE                   *fh,
    const int               indent_len)
{
    const char column_sep = ';';
    const char alias_sep = ',';
    char line_buf[81];
    sk_stringmap_entry_t *entry;
    sk_stringmap_entry_t *old_entry;
    sk_dll_iter_t node;
    int len;
    int avail_len;
    int entry_len;
    int total_len;
    int last_field_end;

    assert(indent_len < (int)sizeof(line_buf));

    if (NULL == str_map) {
        fprintf(fh, "\t[Fields not available]\n");
        return;
    }

    fprintf(fh,
            "\t(Semicolon separates unique items."
            " Comma separates item aliases.\n"
            "\t Names are case-insensitive and"
            " may be abbreviated to the shortest\n"
            "\t unique prefix.)\n");

    /* previous value from map */
    old_entry = NULL;

    /* set indentation */
    memset(line_buf, ' ', sizeof(line_buf));
    total_len = indent_len;
    avail_len = sizeof(line_buf) - indent_len - 1;
    last_field_end = 0;

    /* loop through all entries in the map */
    skDLLAssignIter(&node, (sk_stringmap_t*)str_map);
    while (skDLLIterForward(&node, (void **)&entry) == 0) {
        entry_len = strlen(entry->name);

        if (last_field_end == 0) {
            /* very first field */
            last_field_end = total_len - 1;
        } else if ((old_entry != NULL) && (old_entry->id == entry->id)) {
            /* 'entry' is an alias for 'old_entry' */
            len = snprintf(&(line_buf[total_len]), avail_len, "%c",
                           alias_sep);
            assert(len <= avail_len);
            total_len += len;
            avail_len -= len;
            entry_len += len;
        } else {
            /* start of a new field */
            len = snprintf(&(line_buf[total_len]), avail_len, "%c ",
                           column_sep);
            assert(len <= avail_len);
            total_len += len;
            avail_len -= len;
            entry_len += len;
            last_field_end = total_len - 1;
        }

        if (entry_len >= avail_len) {
            /* need to start a new line */
            int to_move;
            if (last_field_end <= indent_len) {
                skAppPrintErr("Too many aliases or switch names too long");
                skAbort();
            }
            line_buf[last_field_end] = '\0';
            fprintf(fh, "%s\n", line_buf);
            ++last_field_end;
            to_move = total_len - last_field_end;
            if (to_move > 0) {
                memmove(&(line_buf[indent_len]), &(line_buf[last_field_end]),
                        to_move);
            }
            avail_len = sizeof(line_buf) - indent_len - to_move - 1;
            total_len = indent_len + to_move;
            last_field_end = indent_len - 1;
        }

        old_entry = entry;
        len = snprintf(&(line_buf[total_len]), avail_len, "%s", entry->name);
        assert(len <= avail_len);
        total_len += len;
        avail_len -= len;
    }

    /* close out last line */
    if (last_field_end > 0) {
        fprintf(fh, "%s%c\n", line_buf, column_sep);
    }
}


void
skStringMapPrintDetailedUsage(
    const sk_stringmap_t   *str_map,
    FILE                   *fh)
{
    const int MIN_DESCRIPTION_WDITH = 20;
    const char *alias_sep[2] = {"Alias: ", ","};
    const char post_name[] = " - ";
    const char *cp;
    const char *sp;
    char line_buf[72];
    char alias_buf[512];
    sk_stringmap_entry_t *entry;
    sk_stringmap_entry_t *next_entry;
    sk_dll_iter_t node;
    int newline_description = 0;
    int len;
    int continue_len;
    int avail_len;
    int name_len;
    int alias_len;
    int descript_len;
    int done;

    if (NULL == str_map) {
        fprintf(fh, "\t[Fields not available]\n");
        return;
    }

    /* loop through all entries in the map to get the length of the
     * longest primary field name */
    skDLLAssignIter(&node, (sk_stringmap_t*)str_map);
    if (skDLLIterForward(&node, (void **)&entry)) {
        fprintf(fh, "\t[No fields defined]\n");
        return;
    }
    name_len = strlen(entry->name);
    while (skDLLIterForward(&node, (void **)&next_entry) == 0) {
        if (next_entry->id != entry->id) {
            len = strlen(next_entry->name);
            if (len > name_len) {
                name_len = len;
            }
        }
        entry = next_entry;
    }

    /* continuation lines are indented by name_len plus the length of
     * the post_name string */
    continue_len = name_len + strlen(post_name);

    /* determine width for the descriptions */
    descript_len = sizeof(line_buf) - continue_len;
    if (descript_len < MIN_DESCRIPTION_WDITH) {
        newline_description = 1;
        continue_len = 8 + strlen(post_name);
        descript_len = sizeof(line_buf) - continue_len;
    }
    assert(descript_len > 0);

    /* print all entries in the map */
    skDLLAssignIter(&node, (sk_stringmap_t*)str_map);
    done = skDLLIterForward(&node, (void **)&next_entry);
    while (!done) {
        entry = next_entry;
        /* determine the list of aliases for this entry */
        alias_buf[0] = '\0';
        alias_len = 0;
        avail_len = sizeof(alias_buf) - 1;
        while (((done = skDLLIterForward(&node, (void **)&next_entry)) == 0)
               && (entry->id == next_entry->id))
        {
            /* 'next_entry' is an alias for 'entry' */
            len = snprintf(&(alias_buf[alias_len]), avail_len, "%s%s",
                           alias_sep[alias_len ? 1 : 0], next_entry->name);
            if (len > avail_len) {
                skAbort();
            }
            alias_len += len;
            avail_len -= len;
        }

        /* print the entry's name */
        if (newline_description) {
            fprintf(fh, "\t%s\n\t%*s",
                    entry->name, continue_len, post_name);
        } else {
            fprintf(fh, "\t%*s%s",
                    -name_len, entry->name, post_name);
        }
        /* handle the description, line wrapping as needed */
        sp = (const char*)entry->description;
        if (NULL == sp) {
            if (0 == alias_len) {
                fprintf(fh, "[No description available]\n");
            } else {
                fprintf(fh, "%s\n", alias_buf);
            }
            continue;
        }
        for (;;) {
            len = strlen(sp);
            if (len < descript_len) {
                /* (remainder of) description fits on this line */
                if (0 == alias_len) {
                    /* no aliases to print */
                    fprintf(fh, "%s\n", sp);
                } else if (len + 2 + alias_len < descript_len) {
                    /* print description and alias on one line */
                    fprintf(fh, "%s. %s\n", sp, alias_buf);
                } else {
                    /* print description and alias on two lines */
                    fprintf(fh, "%s\n\t%*s%s\n",
                            sp, continue_len, "", alias_buf);
                }
                break;
            }
            /* find a place to break the description */
            cp = sp + descript_len;
            while (cp > sp && !isspace((int)*cp)) {
                --cp;
            }
            if (cp == sp) {
                /* no break point found; try going forward instead */
                cp = sp + descript_len + 1;
                while (*cp && !isspace((int)*cp)) {
                    ++cp;
                }
                if (!*cp) {
                    if (0 == alias_len) {
                        fprintf(fh, "%s\n", sp);
                    } else {
                        fprintf(fh, "%s\n\t%*s%s\n",
                                sp, continue_len, "", alias_buf);
                    }
                    break;
                }
                while ((size_t)(cp - sp) >= sizeof(line_buf)) {
                    strncpy(line_buf, sp, sizeof(line_buf)-1);
                    line_buf[sizeof(line_buf)-1] = '\0';
                    fprintf(fh, "%s", line_buf);
                    sp += sizeof(line_buf)-1;
                }
            }
            strncpy(line_buf, sp, (cp - sp));
            line_buf[(cp - sp)] = '\0';
            fprintf(fh, "%s\n", line_buf);
            fprintf(fh, "\t%*s", continue_len, "");
            sp = cp + 1;
        }
    }
}


/* Return a textual representation of the specified error code. */
const char *
skStringMapStrerror(
    int                 error_code)
{
    static char buf[256];

    switch ((sk_stringmap_status_t)error_code) {
      case SKSTRINGMAP_OK:
        return "Command was successful";

      case SKSTRINGMAP_ERR_INPUT:
        return "Bad input to function";

      case SKSTRINGMAP_ERR_MEM:
        return "Memory allocation failed";

      case SKSTRINGMAP_ERR_LIST:
        return "Unexpected error occured in the linked list";

      case SKSTRINGMAP_ERR_DUPLICATE_ENTRY:
        return "Name is already in use";

      case SKSTRINGMAP_ERR_ZERO_LENGTH_ENTRY:
        return "Name is the empty string";

      case SKSTRINGMAP_ERR_NUMERIC_START_ENTRY:
        return "Name cannot begin with digit";

      case SKSTRINGMAP_ERR_ALPHANUM_START_ENTRY:
        return "Name cannot begin with a non-alphanumeric";

      case SKSTRINGMAP_ERR_PARSER:
        return "Unexpected error during parsing";

      case SKSTRINGMAP_PARSE_NO_MATCH:
        return "Input does not match any names";

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        return "Input matches multiple names";

      case SKSTRINGMAP_PARSE_UNPARSABLE:
        return "Input not parsable";

      case SKSTRINGMAP_OK_DUPLICATE:
        return "Removed duplicates during parsing";
    }

    snprintf(buf, sizeof(buf), "Unrecognized string map error code %d",
             error_code);
    return buf;
}



/*
 *  stringMapCheckValidName(name, map);
 *
 *    Parse a key to be inserted into a StringMap to determine if it is
 *    legal or not.  Assumes arguments are non-NULL.
 *
 *  Arguments
 *
 *    const char *name - the key to check
 *
 *    sk_stringmap_t *str_map - the StringMap against whose contents the
 *    string key should be validated
 *
 *  Return Values
 *
 *    if name is the empty string, returns
 *    SKSTRINGMAP_ZERO_LENGTH_ENTRY
 *
 *    if name starts with a number, but does not contain all numeric
 *    characters (e.g., "34yh"), returns
 *    SKSTRINGMAP_ERR_NUMERIC_START_ENTRY
 *
 *    if name does not start with a alpha-numeric, return
 *    SKSTRINGMAP_ERR_ALPHANUM_START_ENTRY
 *
 *    if name already exists in the StringMap, returns
 *    SKSTRINGMAP_DUPLICATE_ENTRY
 *
 */
static sk_stringmap_status_t
stringMapCheckValidName(
    sk_stringmap_t     *str_map,
    const char         *name)
{
    sk_dll_iter_t map_node;
    sk_stringmap_entry_t *map_entry;
    size_t i;

    assert(name != NULL);
    assert(str_map != NULL);

    if (name[0] == '\0') {
        return SKSTRINGMAP_ERR_ZERO_LENGTH_ENTRY;
    }

    if (isdigit((int)name[0])) {
        /* if the first character is a digit, they ALL have to be digits */
        for (i = strlen(name) - 1; i > 0; --i) {
            if ( !isdigit((int)name[i])) {
                return SKSTRINGMAP_ERR_NUMERIC_START_ENTRY;
            }
        }
    } else if (!isalpha((int)name[0])) {
        return SKSTRINGMAP_ERR_ALPHANUM_START_ENTRY;
    }

    skDLLAssignIter(&map_node, str_map);
    while (skDLLIterForward(&map_node, (void **)&map_entry) == 0) {
        if (0 == strcasecmp(map_entry->name, name)) {
            return SKSTRINGMAP_ERR_DUPLICATE_ENTRY;
        }
    }

    return SKSTRINGMAP_OK;
}


/*
 *  stringMapFreeEntry(map_entry);
 *
 *    Internal helper function to free a single entry 'map_entry' from
 *    a StringMap.
 */
static void
stringMapFreeEntry(
    sk_stringmap_entry_t   *map_entry)
{
    if (map_entry) {
        /* free char string in entry */
        if (NULL != map_entry->name) {
            /* we know we allocated this ourselves, so the cast to (char*)
             * is safe */
            free((char*)map_entry->name);
        }
        if (NULL != map_entry->description) {
            free((char*)map_entry->description);
        }
        /* free entry itself */
        free(map_entry);
    }
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
