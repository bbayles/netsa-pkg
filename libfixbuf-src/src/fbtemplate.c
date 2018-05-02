/*
 ** fbtemplate.c
 ** IPFIX Template implementation
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



void fbTemplateDebug(
    const char      *label,
    uint16_t        tid,
    fbTemplate_t    *tmpl)
{
    int i;

    fprintf(stderr, "%s template %04x [%p] iec=%u sc=%u len=%u\n", label, tid,
            tmpl, tmpl->ie_count, tmpl->scope_count, tmpl->ie_len);

    for (i = 0; i < tmpl->ie_count; i++) {
        fprintf(stderr,"\t%2u ", i);
        fbInfoElementDebug(TRUE, tmpl->ie_ary[i]);
    }
}

fbTemplate_t        *fbTemplateAlloc(
    fbInfoModel_t       *model)
{
    fbTemplate_t    *tmpl = NULL;

    /* create a new template */
    tmpl = g_slice_new0(fbTemplate_t);

    /* fill it in */
    tmpl->model = model;
    tmpl->tmpl_len = 4;
    tmpl->active = FALSE;

    /* allocate indices table */
    tmpl->indices = g_hash_table_new((GHashFunc)fbInfoElementHash,
                                     (GEqualFunc)fbInfoElementEqual);
    return tmpl;
}


void                fbTemplateRetain(
    fbTemplate_t        *tmpl)
{
    /* Increment reference count */
    ++(tmpl->ref_count);
}

void                fbTemplateRelease(
    fbTemplate_t        *tmpl)
{
    /* Decrement reference count */
    --(tmpl->ref_count);
    /* Free if not referenced */
    fbTemplateFreeUnused(tmpl);
}

void                fbTemplateFreeUnused(
    fbTemplate_t        *tmpl)
{
    if (tmpl->ref_count <= 0) {
        fbTemplateFree(tmpl);
    }
}

void                fbTemplateFree(
    fbTemplate_t        *tmpl)
{
    int                 i;

    if (tmpl->ctx_free) {
        tmpl->ctx_free(tmpl->tmpl_ctx, tmpl->app_ctx);
    }
    /* destroy index table if present */
    if (tmpl->indices) g_hash_table_destroy(tmpl->indices);

    /* destroy IE array */
    for (i = 0; i < tmpl->ie_count; i++) {
        g_slice_free(fbInfoElement_t, tmpl->ie_ary[i]);
    }
    g_free(tmpl->ie_ary);

    if (tmpl->metadata_rec && tmpl->metadata_rec->template_name.buf)
    {
        g_free(tmpl->metadata_rec->template_name.buf);
    }

    if (tmpl->metadata_rec)
    {
        g_slice_free(fbTemplateOptRec_t, tmpl->metadata_rec);
    }
    /* destroy offset cache if present */
    if (tmpl->off_cache) g_free(tmpl->off_cache);
    /* destroy template */
    g_slice_free(fbTemplate_t, tmpl);

}

static fbInfoElement_t *fbTemplateExtendElements(
    fbTemplate_t        *tmpl)
{
    if (tmpl->ie_count) {
        tmpl->ie_ary =
            g_renew(fbInfoElement_t*, tmpl->ie_ary, ++(tmpl->ie_count));
    } else {
        tmpl->ie_ary = g_new(fbInfoElement_t*, 1);
        ++(tmpl->ie_count);
    }

    tmpl->ie_ary[tmpl->ie_count - 1] = g_slice_new0(fbInfoElement_t);

    return tmpl->ie_ary[tmpl->ie_count - 1];
}

static void     fbTemplateExtendIndices(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *tmpl_ie)
{
    void                *ign0, *ign1;

    /* search indices table for multiple IE index */
    while (g_hash_table_lookup_extended(tmpl->indices, tmpl_ie, &ign0, &ign1)) {
        ++(tmpl_ie->midx);
    }

    /* increment template lengths */
    tmpl->tmpl_len += tmpl_ie->ent ? 8 : 4;
    if (tmpl_ie->len == FB_IE_VARLEN) {
        tmpl->is_varlen = TRUE;
        tmpl->ie_len += 1;
        if (tmpl_ie->num == FB_IE_BASIC_LIST) {
                tmpl->ie_internal_len += sizeof(fbBasicList_t);
            } else if (tmpl_ie->num == FB_IE_SUBTEMPLATE_LIST) {
                tmpl->ie_internal_len += sizeof(fbSubTemplateList_t);
            } else if (tmpl_ie->num == FB_IE_SUBTEMPLATE_MULTILIST) {
                tmpl->ie_internal_len += sizeof(fbSubTemplateMultiList_t);
            } else {
                tmpl->ie_internal_len += sizeof(fbVarfield_t);
            }
    } else {
        tmpl->ie_len += tmpl_ie->len;
        tmpl->ie_internal_len += tmpl_ie->len;
    }

    /* Add index of this information element to the indices table */
    g_hash_table_insert(tmpl->indices, tmpl_ie,
                        GUINT_TO_POINTER(tmpl->ie_count - 1));
}

gboolean            fbTemplateAppend(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *ex_ie,
    GError              **err)
{
    fbInfoElement_t     *tmpl_ie;

    /* grow information element array */
    tmpl_ie = fbTemplateExtendElements(tmpl);

    /* copy information element out of the info model */
    if (!fbInfoElementCopyToTemplate(tmpl->model, ex_ie, tmpl_ie)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "No such information element %08x:%04x",
                    ex_ie->ent, ex_ie->num);
        return FALSE;
    }

    /* Handle index and counter updates */
    fbTemplateExtendIndices(tmpl, tmpl_ie);

    /* All done */
    return TRUE;
}

gboolean            fbTemplateAppendSpec(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err)
{
    fbInfoElement_t     *tmpl_ie;

    /* Short-circuit on app flags mismatch */
    if (spec->flags && !((spec->flags & flags) == spec->flags)) {
        return TRUE;
    }

    /* grow information element array */
    tmpl_ie = fbTemplateExtendElements(tmpl);
    /* copy information element out of the info model */

    if (!fbInfoElementCopyToTemplateByName(tmpl->model, spec->name,
                                           spec->len_override, tmpl_ie)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NOELEMENT,
                    "No such information element %s", spec->name);
        return FALSE;
    }
    if (spec->len_override == 0 && tmpl_ie->len != FB_IE_VARLEN) {
        tmpl->default_length = TRUE;
    }

    /* Handle index and counter updates */
    fbTemplateExtendIndices(tmpl, tmpl_ie);

    /* All done */
    return TRUE;
}

gboolean            fbTemplateAppendSpecArray(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err)
{
    for (; spec->name; spec++) {
        if (!fbTemplateAppendSpec(tmpl, spec, flags, err)) {
            return FALSE;
        }
    }

    return TRUE;
}

void                fbTemplateSetOptionsScope(
    fbTemplate_t        *tmpl,
    uint16_t            scope_count)
{
    /* Cannot set options scope if we've already done so */
    g_assert(!tmpl->scope_count);

    /* Cannot set scope count higher than IE count */
    g_assert(tmpl->ie_count && tmpl->ie_count >= tmpl->scope_count);

    /* scope count of zero means make the last IE the end of scope */
    tmpl->scope_count = scope_count ? scope_count : tmpl->ie_count;

    /* account for scope count in output */
    tmpl->tmpl_len += 2;
 }

gboolean           fbTemplateContainsElement(
    fbTemplate_t            *tmpl,
    const fbInfoElement_t   *ex_ie)
{
    int i;

    if ( ex_ie == NULL || tmpl == NULL ) {
        return FALSE;
    }

    for (i = 0; i < tmpl->ie_count; i++) {
        if (fbInfoElementEqual(ex_ie, tmpl->ie_ary[i])) return TRUE;
    }

    return FALSE;
}

gboolean           fbTemplateContainsElementByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec)
{
    return fbTemplateContainsElement(
        tmpl, fbInfoModelGetElementByName(tmpl->model, spec->name));
}

gboolean           fbTemplateContainsAllElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec)
{
    for (; spec->name; spec++) {
        if (!fbTemplateContainsElementByName(tmpl, spec)) return FALSE;
    }

    return TRUE;
}

gboolean            fbTemplateContainsAllFlaggedElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t             flags)
{
    for (; spec->name; spec++) {
        if (spec->flags && !((spec->flags & flags) == spec->flags)) {
            continue;
        }
        if (!fbTemplateContainsElementByName(tmpl, spec)) return FALSE;
    }

    return TRUE;
}

uint32_t            fbTemplateCountElements(
    fbTemplate_t        *tmpl)
{
    return tmpl->ie_count;
}

fbInfoElement_t*    fbTemplateGetIndexedIE(
    fbTemplate_t       *tmpl,
    uint32_t            IEindex)
{
    if (IEindex < tmpl->ie_count) {
        return tmpl->ie_ary[IEindex];
    } else {
        return NULL;
    }
}

uint32_t            fbTemplateGetOptionsScope(
    fbTemplate_t        *tmpl)
{
    return tmpl->scope_count;
}

void               *fbTemplateGetContext(
    fbTemplate_t        *tmpl)
{
    return tmpl->tmpl_ctx;
}
