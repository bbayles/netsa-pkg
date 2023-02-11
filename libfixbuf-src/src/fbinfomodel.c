/*
 ** fbinfomodel.c
 ** IPFIX Information Model and IE storage management
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2023 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_LICENSE_START@
 ** libfixbuf 2.0
 **
 ** Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
 **
 ** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 ** ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 ** BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 ** EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 ** EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 ** MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 ** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 ** COPYRIGHT INFRINGEMENT.
 **
 ** Released under a GNU-Lesser GPL 3.0-style license, please see
 ** LICENSE.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
 ** and Trademark Office by Carnegie Mellon University.
 **
 ** DM18-0325
 ** @OPENSOURCE_LICENSE_END@
 ** ------------------------------------------------------------------------
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

/*
 *  This determines the behavior of fbInfoElementCheckTypesSize().  If the
 *  value is true, failing the template check causes the template to be
 *  rejected.  If the value is false, failing the check produces a non-fatal
 *  g_message() but accepts the template.
 */
#ifndef FIXBUF_FATAL_TYPE_LEN_MISMATCH
#define FIXBUF_FATAL_TYPE_LEN_MISMATCH  0
#endif

struct fbInfoModel_st {
    GHashTable          *ie_table;
    GHashTable          *ie_byname;
    GStringChunk        *ie_names;
    GStringChunk        *ie_desc;
};


#include "infomodel.h"


static fbInfoElementSpec_t ie_type_spec[] = {
    {"privateEnterpriseNumber",         4, 0 },
    {"informationElementId",            2, 0 },
    {"informationElementDataType",      1, 0 },
    {"informationElementSemantics",     1, 0 },
    {"informationElementUnits",         2, 0 },
    {"paddingOctets",                   6, 1 },
    {"informationElementRangeBegin",    8, 0 },
    {"informationElementRangeEnd",      8, 0 },
    {"informationElementName",          FB_IE_VARLEN, 0 },
    {"informationElementDescription",   FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};


uint32_t            fbInfoElementHash(
    fbInfoElement_t     *ie)
{
    return ((ie->ent & 0x0000ffff) << 16) | (ie->num << 2) | (ie->midx << 4);
}

gboolean            fbInfoElementEqual(
    const fbInfoElement_t   *a,
    const fbInfoElement_t   *b)
{
    return ((a->ent == b->ent) && (a->num == b->num) && (a->midx == b->midx));
}

void                fbInfoElementDebug(
    gboolean            tmpl,
    fbInfoElement_t     *ie)
{
    if (ie->len == FB_IE_VARLEN) {
        fprintf(stderr, "VL %02x %08x:%04x %2u (%s)\n",
                    ie->flags, ie->ent, ie->num, ie->midx,
                    tmpl ? ie->ref.canon->ref.name : ie->ref.name);
    } else {
        fprintf(stderr, "%2u %02x %08x:%04x %2u (%s)\n",
                    ie->len, ie->flags, ie->ent, ie->num, ie->midx,
                    tmpl ? ie->ref.canon->ref.name : ie->ref.name);
    }
}

static void         fbInfoElementFree(
    fbInfoElement_t     *ie)
{
    g_slice_free(fbInfoElement_t, ie);
}

fbInfoModel_t       *fbInfoModelAlloc(
    void)
{
    fbInfoModel_t       *model = NULL;

    /* Create an information model */
    model = g_slice_new0(fbInfoModel_t);

    /* Allocate information element tables */
    model->ie_table = g_hash_table_new_full(
            (GHashFunc)fbInfoElementHash, (GEqualFunc)fbInfoElementEqual,
            NULL, (GDestroyNotify)fbInfoElementFree);

    model->ie_byname = g_hash_table_new(g_str_hash, g_str_equal);

    /* Allocate information element name chunk */
    model->ie_names = g_string_chunk_new(64);
    model->ie_desc = g_string_chunk_new(128);

    /* Add elements to the information model */
    infomodelAddGlobalElements(model);

    /* Return the new information model */
    return model;
}

void                fbInfoModelFree(
    fbInfoModel_t       *model)
{
    if (NULL == model) {
        return;
    }
    g_hash_table_destroy(model->ie_byname);
    g_string_chunk_free(model->ie_names);
    g_string_chunk_free(model->ie_desc);
    g_hash_table_destroy(model->ie_table);
    g_slice_free(fbInfoModel_t, model);
}

static void         fbInfoModelReversifyName(
    const char          *fwdname,
    char                *revname,
    size_t              revname_sz)
 {
    /* paranoid string copy */
    strncpy(revname + FB_IE_REVERSE_STRLEN, fwdname, revname_sz - FB_IE_REVERSE_STRLEN - 1);
    revname[revname_sz - 1] = (char)0;

    /* uppercase first char */
    revname[FB_IE_REVERSE_STRLEN] = toupper(revname[FB_IE_REVERSE_STRLEN]);

    /* prepend reverse */
    memcpy(revname, FB_IE_REVERSE_STR, FB_IE_REVERSE_STRLEN);
}

#define FB_IE_REVERSE_BUFSZ 256

/**
 *  Updates the two hash tables of 'model' with the data in 'model_ie'.  A
 *  helper function for fbInfoModelAddElement().
 */
static void         fbInfoModelInsertElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *model_ie)
{
    fbInfoElement_t     *found;

    /* Check for an existing element with same ID.  If it is not known, add it
     * to both tables. */
    found = g_hash_table_lookup(model->ie_table, model_ie);
    if (found == NULL) {
        g_hash_table_insert(model->ie_table, model_ie, model_ie);
        g_hash_table_insert(model->ie_byname,
                            (char *)model_ie->ref.name, model_ie);
        return;
    }

    /* If 'found' has a different name than 'model_ie', remove found from the
     * model->ie_byname table if it is present.  We can compare name pointers
     * since we use g_string_chunk_insert_const(). */
    if (found->ref.name != model_ie->ref.name) {
        if (g_hash_table_lookup(model->ie_byname, found->ref.name) == found) {
            g_hash_table_remove(model->ie_byname, found->ref.name);
        }
    }

    /* Update the existing element in place */
    memcpy(found, model_ie, sizeof(*found));

    /* (Re)add found to the ie_byname table */
    g_hash_table_insert(model->ie_byname, (char *)found->ref.name, found);

    /* Free unused model_ie */
    g_slice_free(fbInfoElement_t, model_ie);
}

void                fbInfoModelAddElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    fbInfoElement_t     *model_ie = NULL;
    char                revname[FB_IE_REVERSE_BUFSZ];

    g_assert(ie);

    /* Allocate a new information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Copy external IE to model IE */
    model_ie->ref.name = g_string_chunk_insert_const(model->ie_names,
                                                     ie->ref.name);
    model_ie->midx = 0;
    model_ie->ent = ie->ent;
    model_ie->num = ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;
    model_ie->min = ie->min;
    model_ie->max = ie->max;
    model_ie->type = ie->type;
    if (ie->description) {
        model_ie->description = (g_string_chunk_insert_const(
                                     model->ie_desc, ie->description));
    }

    fbInfoModelInsertElement(model, model_ie);

    /* Short circuit if not reversible */
    if (!(ie->flags & FB_IE_F_REVERSIBLE)) {
        return;
    }

    /* Allocate a new reverse information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Generate reverse name */
    fbInfoModelReversifyName(ie->ref.name, revname, sizeof(revname));

    /* Copy external IE to reverse model IE */
    model_ie->ref.name = g_string_chunk_insert_const(model->ie_names, revname);
    model_ie->midx = 0;
    model_ie->ent = ie->ent ? ie->ent : FB_IE_PEN_REVERSE;
    model_ie->num = ie->ent ? ie->num | FB_IE_VENDOR_BIT_REVERSE : ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;
    model_ie->min = ie->min;
    model_ie->max = ie->max;
    model_ie->type = ie->type;

    fbInfoModelInsertElement(model, model_ie);
}

void                fbInfoModelAddElementArray(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    g_assert(ie);
    for (; ie->ref.name; ie++) fbInfoModelAddElement(model, ie);
}

const fbInfoElement_t     *fbInfoModelGetElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie)
{
    return g_hash_table_lookup(model->ie_table, ex_ie);
}

/*
 *  Checks if the specified size 'len' of the element 'model_ie' is valid
 *  given the element's type.  Returns TRUE if valid.  Sets 'err' and returns
 *  FALSE if not.  The list of things that are check are:
 *
 *  -- Whether a fixed size element (e.g., IP address, datetime) uses an
 *     different size.
 *  -- Whether a float64 uses a size other than 4 or 8.
 *  -- Whether an integer uses a size larger than the natural size of the
 *     integer (e.g., attempting to use 4 bytes for a unsigned16).
 *  -- Whether VARLEN is used for anything other than strings, octetArrays,
 *     and structed data (lists).
 *  -- Whether a size of 0 is used for anything other than string or
 *     octetArray.
 */
static gboolean     fbInfoElementCheckTypesSize(
    const fbInfoElement_t   *model_ie,
    const uint16_t           len,
    GError                 **err)
{
    switch (model_ie->type) {
      case FB_BOOL:
      case FB_DT_MICROSEC:
      case FB_DT_MILSEC:
      case FB_DT_NANOSEC:
      case FB_DT_SEC:
      case FB_FLOAT_32:
      case FB_INT_8:
      case FB_IP4_ADDR:
      case FB_IP6_ADDR:
      case FB_MAC_ADDR:
      case FB_UINT_8:
        /* fixed size */
        if (len == model_ie->len) {
            return TRUE;
        }
        break;
      case FB_FLOAT_64:
        /* may be either 4 or 8 octets */
        if (len == 4 || len == 8) {
            return TRUE;
        }
        break;
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
        /* these support reduced length encoding */
        if (len <= model_ie->len && len > 0) {
            return TRUE;
        }
        break;
      case FB_BASIC_LIST:
      case FB_SUB_TMPL_LIST:
      case FB_SUB_TMPL_MULTI_LIST:
        if (len > 0) {
            return TRUE;
        }
        break;
      case FB_OCTET_ARRAY:
      case FB_STRING:
      default:
        /* may be any size */
        return TRUE;
    }

    if (len == FB_IE_VARLEN) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Template warning: Information element %s"
                    " may not be variable length",
                    model_ie->ref.name);
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Template warning: Illegal length %d"
                    " for information element %s",
                    len, model_ie->ref.name);
    }
#if FIXBUF_FATAL_TYPE_LEN_MISMATCH
    return FALSE;
#else
    g_message("%s", (*err)->message);
    g_clear_error(err);
    return TRUE;
#endif
}


gboolean            fbInfoElementCopyToTemplate(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie,
    fbInfoElement_t     *tmpl_ie,
    GError             **err)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElement(model, ex_ie);
    if (!model_ie) {
        /* Information element not in model. Note it's alien and add it. */
        model_ie = fbInfoModelAddAlienElement(model, ex_ie);
    }

    if (!fbInfoElementCheckTypesSize(model_ie, ex_ie->len, err)) {
        return FALSE;
    }

    /* Refer to canonical IE in the model */
    tmpl_ie->ref.canon = model_ie;

    /* Copy model IE to template IE */
    tmpl_ie->midx = 0;
    tmpl_ie->ent = model_ie->ent;
    tmpl_ie->num = model_ie->num;
    tmpl_ie->len = ex_ie->len;
    tmpl_ie->flags = model_ie->flags;
    tmpl_ie->type = model_ie->type;
    tmpl_ie->min = model_ie->min;
    tmpl_ie->max = model_ie->max;
    tmpl_ie->description = model_ie->description;

    /* All done */
    return TRUE;
}

gboolean            fbInfoElementCopyToTemplateByName(
    fbInfoModel_t       *model,
    const char          *name,
    uint16_t            len_override,
    fbInfoElement_t     *tmpl_ie,
    GError             **err)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElementByName(model, name);
    if (!model_ie) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "No such information element %s", name);
        return FALSE;
    }
    if (len_override) {
        if (!fbInfoElementCheckTypesSize(model_ie, len_override, err)) {
            return FALSE;
        }
    }

    /* Refer to canonical IE in the model */
    tmpl_ie->ref.canon = model_ie;

    /* Copy model IE to template IE */
    tmpl_ie->midx = 0;
    tmpl_ie->ent = model_ie->ent;
    tmpl_ie->num = model_ie->num;
    tmpl_ie->len = len_override ? len_override : model_ie->len;
    tmpl_ie->flags = model_ie->flags;
    tmpl_ie->type = model_ie->type;
    tmpl_ie->min = model_ie->min;
    tmpl_ie->max = model_ie->max;
    tmpl_ie->description = model_ie->description;

    /* All done */
    return TRUE;
}

const fbInfoElement_t     *fbInfoModelGetElementByName(
    fbInfoModel_t       *model,
    const char          *name)
{
    g_assert(name);
    return g_hash_table_lookup(model->ie_byname, name);
}

const fbInfoElement_t    *fbInfoModelGetElementByID(
    fbInfoModel_t      *model,
    uint16_t           id,
    uint32_t           ent)
{
    fbInfoElement_t tempElement;

    tempElement.midx = 0;
    tempElement.ent = ent;
    tempElement.num = id;

    return fbInfoModelGetElement(model, &tempElement);
}

fbTemplate_t *fbInfoElementAllocTypeTemplate(
    fbInfoModel_t          *model,
    GError                 **err)
{
    return fbInfoElementAllocTypeTemplate2(model, TRUE, err);
}

fbTemplate_t *fbInfoElementAllocTypeTemplate2(
    fbInfoModel_t          *model,
    gboolean                internal,
    GError                 **err)
{
    fbTemplate_t *tmpl;
    uint32_t flags;

    flags = internal ? ~0 : 0;

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, ie_type_spec, flags, err)) {
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    fbTemplateSetOptionsScope(tmpl, 2);
    return tmpl;
}

gboolean fbInfoElementWriteOptionsRecord(
    fBuf_t                  *fbuf,
    const fbInfoElement_t   *model_ie,
    uint16_t                itid,
    uint16_t                etid,
    GError                  **err)
{
    fbInfoElementOptRec_t   rec;

    g_assert(model_ie);
    if (model_ie == NULL) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "Invalid [NULL] Information Element");
        return FALSE;
    }

    rec.ie_range_begin = model_ie->min;
    rec.ie_range_end = model_ie->max;
    rec.ie_pen = model_ie->ent;
    rec.ie_units = FB_IE_UNITS(model_ie->flags);
    rec.ie_semantic = FB_IE_SEMANTIC(model_ie->flags);
    rec.ie_id = model_ie->num;
    rec.ie_type = model_ie->type;
    memset(rec.padding, 0, sizeof(rec.padding));
    rec.ie_name.buf = (uint8_t *)model_ie->ref.name;
    rec.ie_name.len = strlen(model_ie->ref.name);
    rec.ie_desc.buf = (uint8_t *)model_ie->description;
    if (model_ie->description) {
        rec.ie_desc.len = strlen(model_ie->description);
    } else {
        rec.ie_desc.len = 0;
    }

    if (!fBufSetExportTemplate(fbuf, etid, err)) {
        return FALSE;
    }

    if (!fBufSetInternalTemplate(fbuf, itid, err)) {
        return FALSE;
    }

    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    return TRUE;
}

gboolean fbInfoElementAddOptRecElement(
    fbInfoModel_t           *model,
    fbInfoElementOptRec_t   *rec)
{
    fbInfoElement_t     ie;
    char                name[500];
    char                description[4096];
    size_t              len;

    if (rec->ie_pen != 0) {

        ie.min = rec->ie_range_begin;
        ie.max = rec->ie_range_end;
        ie.ent = rec->ie_pen;
        ie.num = rec->ie_id;
        ie.type = rec->ie_type;
        len = ((rec->ie_name.len < sizeof(name))
               ? rec->ie_name.len : (sizeof(name) - 1));
        strncpy(name, (char *)rec->ie_name.buf, len);
        name[len] = '\0';
        ie.ref.name = name;
        len = ((rec->ie_desc.len < sizeof(description))
               ? rec->ie_desc.len : (sizeof(description) - 1));
        strncpy(description, (char *)rec->ie_desc.buf, len);
        description[len] = '\0';
        ie.description = description;
        ie.flags = 0;
        ie.flags |= rec->ie_units << 16;
        ie.flags |= rec->ie_semantic << 8;

        /* length is inferred from data type */
        switch (ie.type) {
          case FB_OCTET_ARRAY:
          case FB_STRING:
          case FB_BASIC_LIST:
          case FB_SUB_TMPL_LIST:
          case FB_SUB_TMPL_MULTI_LIST:
            ie.len = FB_IE_VARLEN;
            break;
          case FB_UINT_8:
          case FB_INT_8:
          case FB_BOOL:
            ie.len = 1;
            break;
          case FB_UINT_16:
          case FB_INT_16:
            ie.len = 2;
            ie.flags |= FB_IE_F_ENDIAN;
            break;
          case FB_UINT_32:
          case FB_INT_32:
          case FB_DT_SEC:
          case FB_FLOAT_32:
          case FB_IP4_ADDR:
            ie.len = 4;
            ie.flags |= FB_IE_F_ENDIAN;
            break;
          case FB_MAC_ADDR:
            ie.len = 6;
            break;
          case FB_UINT_64:
          case FB_INT_64:
          case FB_DT_MILSEC:
          case FB_DT_MICROSEC:
          case FB_DT_NANOSEC:
          case FB_FLOAT_64:
            ie.len = 8;
            ie.flags |= FB_IE_F_ENDIAN;
            break;
          case FB_IP6_ADDR:
            ie.len = 16;
            break;
          default:
            g_warning("Adding element %s with invalid data type [%d]", name,
                      rec->ie_type);
            ie.len = FB_IE_VARLEN;
        }

        fbInfoModelAddElement(model, &ie);
        return TRUE;
    }

    return FALSE;
}

gboolean fbInfoModelTypeInfoRecord(
    fbTemplate_t            *tmpl)
{
    /* ignore padding. */
    if (fbTemplateContainsAllFlaggedElementsByName(tmpl, ie_type_spec, 0)) {
        return TRUE;
    }

    return FALSE;
}

guint fbInfoModelCountElements(
    const fbInfoModel_t *model)
{
    return g_hash_table_size(model->ie_table);
}

void fbInfoModelIterInit(
    fbInfoModelIter_t   *iter,
    const fbInfoModel_t *model)
{
    g_assert(iter);
    g_hash_table_iter_init(iter, model->ie_table);
}

const fbInfoElement_t *fbInfoModelIterNext(
    fbInfoModelIter_t *iter)
{
    const fbInfoElement_t *ie;
    g_assert(iter);
    if (g_hash_table_iter_next(iter, NULL, (gpointer *)&ie)) {
        return ie;
    }
    return NULL;
}

const fbInfoElement_t     *fbInfoModelAddAlienElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie)
{
    const fbInfoElement_t     *model_ie = NULL;

    if (ex_ie == NULL) {
        return NULL;
    }
    /* Information element not in model. Note it's alien and add it. */
    ex_ie->ref.name = (g_string_chunk_insert_const(
                           model->ie_names, "_alienInformationElement"));
    ex_ie->flags |= FB_IE_F_ALIEN;
    fbInfoModelAddElement(model, ex_ie);
    model_ie = fbInfoModelGetElement(model, ex_ie);
    g_assert(model_ie);

    return model_ie;
}
