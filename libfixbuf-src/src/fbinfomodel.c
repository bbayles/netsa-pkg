/*
 ** fbinfomodel.c
 ** IPFIX Information Model and IE storage management
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2018 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the libfixbuf system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** Copyright 2018 Carnegie Mellon University. All Rights Reserved.
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
 ** License.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 ** Trademark Office by Carnegie Mellon University.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>


#define CERT_PEN 6871

struct fbInfoModel_st {
    GHashTable          *ie_table;
    GHashTable          *ie_byname;
    GStringChunk        *ie_names;
    GStringChunk        *ie_desc;
    GPtrArray           *ie_list;
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

fbInfoModel_t       *fbInfoModelAlloc()
{
    fbInfoModel_t       *model = NULL;

    /* Create an information model */
    model = g_slice_new0(fbInfoModel_t);

    /* Allocate information element tables */
    model->ie_table = g_hash_table_new_full(
            (GHashFunc)fbInfoElementHash, (GEqualFunc)fbInfoElementEqual,
            NULL, (GDestroyNotify)fbInfoElementFree);

    model->ie_byname = g_hash_table_new(g_str_hash, g_str_equal);

    model->ie_list = g_ptr_array_new();

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
    g_hash_table_destroy(model->ie_byname);
    g_string_chunk_free(model->ie_names);
    g_string_chunk_free(model->ie_desc);
    g_hash_table_destroy(model->ie_table);
    g_ptr_array_free(model->ie_list, TRUE);
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

void                fbInfoModelAddElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    fbInfoElement_t     *model_ie = NULL;
    fbInfoElement_t     *found;
    char                revname[FB_IE_REVERSE_BUFSZ];

    /* Allocate a new information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Copy external IE to model IE */

    model_ie->ref.name = g_string_chunk_insert(model->ie_names, ie->ref.name);
    model_ie->midx = 0;
    model_ie->ent = ie->ent;
    model_ie->num = ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;
    model_ie->min = ie->min;
    model_ie->max = ie->max;
    model_ie->type = ie->type;
    if (ie->description) {
        model_ie->description = g_string_chunk_insert(model->ie_desc,
                                                      ie->description);
    }

    /* Insert model IE into tables */
    if ((found = g_hash_table_lookup(model->ie_table, model_ie))) {
        /* replace it if already exists */
        /* insert will replace but only will replace the value, not the key */
        /* since insert frees the value and the key and the value are the */
        /* same - this creates a problem.  g_hash_table_replace replaces */
        /* the key and the value */
        g_hash_table_replace(model->ie_table, model_ie, model_ie);
    } else {
        g_hash_table_insert(model->ie_table, model_ie, model_ie);
    }

    if ((found = g_hash_table_lookup(model->ie_byname, model_ie->ref.name))) {
        g_ptr_array_remove(model->ie_list, found);
    }
    g_ptr_array_add(model->ie_list, model_ie);
    g_hash_table_insert(model->ie_byname, (char *)model_ie->ref.name,model_ie);

    /* Short circuit if not reversible or not IANA-managed */
    if (!(ie->flags & FB_IE_F_REVERSIBLE)) {
        return;
    }

    /* Allocate a new reverse information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Generate reverse name */
    fbInfoModelReversifyName(ie->ref.name, revname, sizeof(revname));

    /* Copy external IE to reverse model IE */
    model_ie->ref.name = g_string_chunk_insert(model->ie_names, revname);
    model_ie->midx = 0;
    model_ie->ent = ie->ent ? ie->ent : FB_IE_PEN_REVERSE;
    model_ie->num = ie->ent ? ie->num | FB_IE_VENDOR_BIT_REVERSE : ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;
    model_ie->min = ie->min;
    model_ie->max = ie->max;
    model_ie->type = ie->type;

    /* Insert model IE into tables */
    g_hash_table_insert(model->ie_table, model_ie, model_ie);
    if ((found = g_hash_table_lookup(model->ie_byname, model_ie->ref.name))) {
        g_ptr_array_remove(model->ie_list, found);
    }
    g_ptr_array_add(model->ie_list, model_ie);
    g_hash_table_insert(model->ie_byname, (char *)model_ie->ref.name,model_ie);
}

void                fbInfoModelAddElementArray(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    for (; ie->ref.name; ie++) fbInfoModelAddElement(model, ie);
}

const fbInfoElement_t     *fbInfoModelGetElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie)
{
    return g_hash_table_lookup(model->ie_table, ex_ie);
}

gboolean            fbInfoElementCopyToTemplate(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie,
    fbInfoElement_t     *tmpl_ie)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElement(model, ex_ie);
    if (!model_ie) {
        /* Information element not in model. Note it's alien and add it. */
        ex_ie->ref.name = g_string_chunk_insert(model->ie_names,
                                                "_alienInformationElement");
        ex_ie->flags |= FB_IE_F_ALIEN;
        fbInfoModelAddElement(model, ex_ie);
        model_ie = fbInfoModelGetElement(model, ex_ie);
        g_assert(model_ie);
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

const fbInfoElement_t     *fbInfoModelGetElementByName(
    fbInfoModel_t       *model,
    const char          *name)
{
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

gboolean            fbInfoElementCopyToTemplateByName(
    fbInfoModel_t       *model,
    const char          *name,
    uint16_t            len_override,
    fbInfoElement_t     *tmpl_ie)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElementByName(model, name);
    if (!model_ie) return FALSE;

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

fbTemplate_t *fbInfoElementAllocTypeTemplate(
    fbInfoModel_t          *model,
    GError                 **err)
{
    fbTemplate_t *tmpl = NULL;

    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, ie_type_spec, 0xffffffff, err))
        return NULL;

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

    if (rec->ie_pen != 0) {

        ie.min = rec->ie_range_begin;
        ie.max = rec->ie_range_end;
        ie.ent = rec->ie_pen;
        ie.num = rec->ie_id;
        ie.type = rec->ie_type;
        strncpy(name, (char *)rec->ie_name.buf, rec->ie_name.len);
        name[rec->ie_name.len] = '\0';
        ie.ref.name = name;
        strncpy(description, (char *)rec->ie_desc.buf, rec->ie_desc.len);
        description[rec->ie_desc.len] = '\0';
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
            break;
          case FB_UINT_32:
          case FB_INT_32:
          case FB_DT_SEC:
          case FB_FLOAT_32:
          case FB_IP4_ADDR:
            ie.len = 4;
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
    return model->ie_list->len;
}

void fbInfoModelIterInit(
    fbInfoModelIter_t   *iter,
    const fbInfoModel_t *model)
{
    iter->model = model;
    iter->index = 0;
}

const fbInfoElement_t *fbInfoModelIterNext(
    fbInfoModelIter_t *iter)
{
    if (iter->index >= iter->model->ie_list->len) {
        return NULL;
    }
    return g_ptr_array_index(iter->model->ie_list, iter->index++);
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
    ex_ie->ref.name = g_string_chunk_insert(model->ie_names,
                                            "_alienInformationElement");
    ex_ie->flags |= FB_IE_F_ALIEN;
    fbInfoModelAddElement(model, ex_ie);
    model_ie = fbInfoModelGetElement(model, ex_ie);
    g_assert(model_ie);

    return model_ie;
}
