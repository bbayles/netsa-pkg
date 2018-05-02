/*
 ** fbsession.c
 ** IPFIX Transport Session state container
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
#define DEFINE_TEMPLATE_METADATA_SPEC
#include <fixbuf/private.h>


struct fbSession_st {
    /** Information model. */
    fbInfoModel_t               *model;
    /** Current observation domain ID. */
    uint32_t                    domain;
    /**
     * Internal template table. Maps template ID to internal template.
     */
    GHashTable                  *int_ttab;
    /**
     * External template table for current observation domain.
     * Maps template ID to external template.
     */
    GHashTable                  *ext_ttab;

    uint16_t                    *tmpl_pair_array;
    uint16_t                    num_tmpl_pairs;
    /* Callback function to allow an application to assign template
       pairs for transcoding purposes, and to add context to a
       particular template */
    fbNewTemplateCallback_fn    new_template_callback;
    void                        *tmpl_app_ctx;

    /* If TRUE, options records will be exported for enterprise-specific IEs */
    gboolean                    export_info_element_metadata;

    uint16_t                    info_element_metadata_tid;
    /* If TRUE, options records will be exported for templates */
    gboolean                    export_template_metadata;

    uint16_t                    template_metadata_tid;
    uint16_t                    template_info_element_list_tid;
    /**
     * Mutex to guard the ext_ttab when using Spread.  Spread listens for new
     * group memberships.  On a new membership, the Spread transport will send
     * all external templates to the new member privately.  During this
     * process, the external template table cannot be modified, hence the
     * write lock on ext_ttab.
     */
#if HAVE_SPREAD
    pthread_mutex_t             ext_ttab_wlock;
    /**
     * Group External Template Table.
     * Maps group to the external template table
     */
    GHashTable                  *grp_ttab;
    /**
     * Group Sequence Number Table
     * Maps group to sequence number (only looks at first group in list)
     */
    GHashTable                  *grp_seqtab;
    /**
     * Current Group
     */
    unsigned int                group;
    /**
     * Need to keep track of all groups session knows about
     */
    sp_groupname_t              *all_groups;
    /**
     * Number of groups session knows about.
     */
    int                         num_groups;
#endif
    /**
     * Domain external template table.
     * Maps domain to external template table.
     */
    GHashTable                  *dom_ttab;
    /**
     * Last/next sequence number in current observation domain.
     */
    uint32_t                    sequence;
    /**
     * Domain last/next sequence number table.
     * Maps domain to sequence number.
     */
    GHashTable                  *dom_seqtab;
    /**
     * Buffer instance to write template dynamics to.
     */
    fBuf_t                      *tdyn_buf;
    /**
     * Flag to set when an internal template is added or removed. The flag is
     * unset when SetInternalTemplate is called. This ensures the internal
     * template set to the most up-to-date template
     */
    int                          intTmplTableChanged;
    /**
     * Flag to set when an external template is added or removed. The flag is
     * unset when SetExportTemplate is called. This ensures the internal
     * template set to the most up-to-date template
     */
    int                          extTmplTableChanged;
    /**
     * Pointer to collector that was created with session
     */
    fbCollector_t               *collector;
    /**
     * Error description for fbSessionExportTemplates()
     */
    GError                      *tdyn_err;
};

fbSession_t     *fbSessionAlloc(
    fbInfoModel_t   *model)
{
    fbSession_t     *session = NULL;

    /* Create a new session */
    session = g_slice_new0(fbSession_t);
    memset( session, 0, sizeof( fbSession_t ) );

    /* Store reference to information model */
    session->model = model;

    /* Allocate internal template table */
    session->int_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);

#if HAVE_SPREAD
    /* this lock is needed only if Spread is enabled */
    pthread_mutex_init( &session->ext_ttab_wlock, 0 );
#endif

    /* Reset session externals (will allocate domain template tables, etc.) */
    fbSessionResetExternal(session);

    session->tmpl_pair_array = NULL;
    session->num_tmpl_pairs = 0;
    session->new_template_callback = NULL;

    /* All done */
    return session;
}

gboolean fbSessionEnableTypeMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                     **err)

{
    fbTemplate_t *ie_type_template = NULL;
    GError *child_err = NULL;

    session->export_info_element_metadata = enabled;

    ie_type_template = fbInfoElementAllocTypeTemplate(session->model, &child_err);

    if (! ie_type_template)
    {
        g_propagate_error(err, child_err);
        return FALSE;
    }

    session->info_element_metadata_tid = fbSessionAddTemplate(
        session, FALSE, FB_TID_AUTO,
        ie_type_template, &child_err);

    if (! session->info_element_metadata_tid) {
        return FALSE;
    }

    session->info_element_metadata_tid = fbSessionAddTemplate(
        session, TRUE, session->info_element_metadata_tid,
        ie_type_template, &child_err);

    if (! session->info_element_metadata_tid) {
        return FALSE;
    }

    return TRUE;
}





gboolean fbSessionWriteTypeMetadata(
    fbSession_t                *session,
    GError                    **err)
{
    fbInfoModelIter_t iter;
    const fbInfoElement_t *ie = NULL;
    GError *child_err = NULL;

    if (!session->export_info_element_metadata)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Session is not configured to write type metadata");
        return FALSE;
    }

    if (!fBufSetInternalTemplate(
            session->tdyn_buf,
            session->info_element_metadata_tid,
            err)){
        return FALSE;
    }

    if (!fBufSetExportTemplate(
            session->tdyn_buf,
            session->info_element_metadata_tid,
            &child_err))
    {
        return FALSE;
    }

    fbInfoModelIterInit(&iter, session->model);

    while ( (ie = fbInfoModelIterNext(&iter)) )
    {
        /* No need to send metadata for IEs in the standard info model */
        if (ie->ent == 0 || ie->ent == FB_IE_PEN_REVERSE) {
            continue;
        }

        if (!fbInfoElementWriteOptionsRecord(
            session->tdyn_buf,
            ie,
            session->info_element_metadata_tid,
            session->info_element_metadata_tid,
            &child_err))
        {
            g_propagate_error(err, child_err);
            return FALSE;
        }
    }

    return TRUE;

}


gboolean fbSessionEnableTemplateMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                    **err)

{
    GError *child_err = NULL;
    fbTemplate_t *metadata_template = NULL;

    session->export_template_metadata = enabled;

    metadata_template = fbTemplateAlloc(session->model);

    if (!fbTemplateAppendSpecArray(
            metadata_template,
            template_metadata_spec, 0xffffffff, &child_err))
    {
        g_propagate_error(err, child_err);
        return FALSE;
    }

    fbTemplateSetOptionsScope(metadata_template, 2);

    session->template_metadata_tid = fbSessionAddTemplate(
        session, FALSE, FB_TID_AUTO,
        metadata_template, &child_err);

    if (!session->template_metadata_tid) {
        return FALSE;
    }

    session->template_metadata_tid = fbSessionAddTemplate(
        session, TRUE, session->template_metadata_tid,
        metadata_template, &child_err);

    if (!session->template_metadata_tid) {
        return FALSE;
    }

    return TRUE;
}

#ifdef HAVE_SPREAD
gboolean fbSessionSpreadEnableTemplateMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err)

{
    GError *child_err = NULL;
    fbTemplate_t *metadata_template = NULL;

    session->export_template_metadata = enabled;

    metadata_template = fbTemplateAlloc(session->model);

    if (!fbTemplateAppendSpecArray(
            metadata_template,
            template_metadata_spec, 0xffffffff, &child_err))
    {
        g_propagate_error(err, child_err);
        return FALSE;
    }

    fbTemplateSetOptionsScope(metadata_template, 2);

    session->template_metadata_tid = fbSessionAddTemplatesMulticast(
        session, groups, FALSE, FB_TID_AUTO,
        metadata_template, &child_err);

    if (!session->template_metadata_tid) {
        return FALSE;
    }

    session->template_metadata_tid = fbSessionAddTemplate(
        session, TRUE, session->template_metadata_tid,
        metadata_template, &child_err);

    if (!session->template_metadata_tid) {
        return FALSE;
    }

    return TRUE;
}

gboolean fbSessionSpreadEnableTypeMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err)

{
    fbTemplate_t *ie_type_template = NULL;
    GError *child_err = NULL;

    session->export_info_element_metadata = enabled;

    ie_type_template = fbInfoElementAllocTypeTemplate(session->model, &child_err);

    if (! ie_type_template)
    {
        g_propagate_error(err, child_err);
        return FALSE;
    }

    session->info_element_metadata_tid = fbSessionAddTemplatesMulticast(
        session, groups, FALSE, FB_TID_AUTO,
        ie_type_template, &child_err);

    if (! session->info_element_metadata_tid) {
        return FALSE;
    }

    session->info_element_metadata_tid = fbSessionAddTemplate(
        session, TRUE, session->info_element_metadata_tid,
        ie_type_template, &child_err);

    if (! session->info_element_metadata_tid) {
        return FALSE;
    }

    return TRUE;
}


#endif

gboolean fbSessionWriteTemplateMetadata(
    fbSession_t    *session,
    fbTemplate_t   *tmpl,
    GError         **err)
{
    uint16_t old_tid_int, old_tid_ext;

    if (session->export_template_metadata && tmpl->metadata_rec)
    {
        /*printf("writing metadata for : %p (%x)\n", tmpl, session->tdyn_buf);*/

        old_tid_int = fBufGetInternalTemplate(session->tdyn_buf);
        old_tid_ext = fBufGetExportTemplate(session->tdyn_buf);

        if (!fBufSetInternalTemplate(session->tdyn_buf,
                                     session->template_metadata_tid, err)){
            /*printf("fBufSetInternalTemplate failed\n");*/
            return FALSE;
        }


        if (!fBufSetExportTemplate(session->tdyn_buf,
                                   session->template_metadata_tid,
                                   err))
        {
            /*printf("fBufSetExportTemplate failed\n");*/
            return FALSE;
        }

        if (!fBufAppend(session->tdyn_buf, (uint8_t *) tmpl->metadata_rec,
                        sizeof(fbTemplateOptRec_t), err)) {
            /*printf("BufAppend failed\n");*/
            return FALSE;
        }
        /* if (!fBufEmit(session->tdyn_buf, err)) return FALSE; */

        if (!fBufSetInternalTemplate(session->tdyn_buf,
                                     old_tid_int, err)){
            /*printf("fBufSetInternalTemplate failed\n");*/
            return FALSE;
        }

        if (!fBufSetExportTemplate(session->tdyn_buf,
                                   old_tid_ext, err))
        {
            /*printf("restore BufSetExportTemplate failed %s\n", (*err)->message);*/
            return FALSE;
        }

    }

    return TRUE;

}



uint16_t fbSessionAddTemplateWithMetadata(
    fbSession_t         *session,
    gboolean             internal,
    uint16_t             tid,
    fbTemplate_t         *tmpl,
    const char           *name,
    const char           *description,
    GError               **err)
{
    GHashTable      *ttab = NULL;
    static uint16_t next_ext_tid = 0;
    static uint16_t next_int_tid = UINT16_MAX;
    int count = 0;
    fbTemplateOptRec_t *metadata_rec = NULL;

    /* Select a template table to add the template to */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    if (!name) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                        "Template name must be specified");
        return 0;
    }

    /* prevent infinite loop when template tables are full */
    if (g_hash_table_size(ttab) == (UINT16_MAX - FB_TID_MIN_DATA)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                    "Template table is full, no IDs left");
        return 0;
    }

    /* Automatically assign a new template ID */
    if (tid == FB_TID_AUTO) {
        if (internal) {
            if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                next_int_tid = UINT16_MAX;
            }
            while (fbSessionGetTemplate(session, internal, next_int_tid, NULL))
            {
                next_int_tid--;
                if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                    next_int_tid = UINT16_MAX;
                }
            }
            tid = next_int_tid--;
        } else {
            if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            while (fbSessionGetTemplate(session, internal, next_ext_tid, NULL))
            {
                next_ext_tid++;
                if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            }
            tid = next_ext_tid++;
        }
    }

    /* Revoke old template, ignoring missing template error. */
    if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            g_clear_error(err);
        } else {
            return 0;
        }
    }

    if (session->export_template_metadata) {
        count = fbTemplateCountElements(tmpl);

        metadata_rec = g_slice_new0(fbTemplateOptRec_t);
        metadata_rec->template_id = tid;
        metadata_rec->template_name.buf = (uint8_t *) g_strdup(name);
        metadata_rec->template_name.len = strlen(name);

        if (description) {
            metadata_rec->template_description.buf =
                (uint8_t *) g_strdup(description);
            metadata_rec->template_description.len = strlen(description);
        }

        tmpl->metadata_rec = metadata_rec;
    }

    /* Write template to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {

        if (!fbSessionWriteTemplateMetadata(session, tmpl, err)) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                g_clear_error(err);
            } else {
                return 0;
            }
        }

        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;
    }

    /* Insert template into table */
#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
    g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);
    if (internal) {
        session->intTmplTableChanged = 1;
    } else {
        session->extTmplTableChanged = 1;
    }

#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
    fbTemplateRetain(tmpl);

    return tid;
}

fbNewTemplateCallback_fn fbSessionNewTemplateCallback(
    fbSession_t *session)
{
    return session->new_template_callback;
}

void fbSessionAddNewTemplateCallback(
    fbSession_t                 *session,
    fbNewTemplateCallback_fn    callback,
    void                        *app_ctx)
{
    session->new_template_callback = callback;
    session->tmpl_app_ctx = app_ctx;
}

void *fbSessionNewTemplateCallbackAppCtx(
    fbSession_t *session)
{
    return session->tmpl_app_ctx;
}

void fbSessionAddTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid,
    uint16_t        int_tid)
{
    gboolean madeTable = FALSE;

    if (!session->tmpl_pair_array) {
        session->tmpl_pair_array = (uint16_t*)g_slice_alloc0(
                                        sizeof(uint16_t) * (UINT16_MAX + 1));
        madeTable = TRUE;
    }

    if ((ext_tid == int_tid) || (int_tid == 0)) {
        session->tmpl_pair_array[ext_tid] = int_tid;
        session->num_tmpl_pairs++;
        return;
    }

    /* external and internal tids are different */
    /* only add the template pair if the internal template exists */
    if (fbSessionGetTemplate(session, TRUE, int_tid, NULL)) {
        session->tmpl_pair_array[ext_tid] = int_tid;
        session->num_tmpl_pairs++;
    } else {
        if (madeTable) {
            g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                          session->tmpl_pair_array);
            session->tmpl_pair_array = NULL;
        }
    }
}

void fbSessionRemoveTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid)
{
    if (!session->tmpl_pair_array) {
        return;
    }

    if (session->tmpl_pair_array[ext_tid]) {
        session->num_tmpl_pairs--;
        if (!session->num_tmpl_pairs) {
            /* this was the last one, free the array */
            g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                          session->tmpl_pair_array);
            session->tmpl_pair_array = NULL;
            return;
        }
    }
    session->tmpl_pair_array[ext_tid] = 0;
}

uint16_t    fbSessionLookupTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid)
{
    /* if there are no current pairs, just return ext_tid because that means
     * we should decode the entire external template
     */
    if (!session->tmpl_pair_array) {
        return ext_tid;
    }

    return session->tmpl_pair_array[ext_tid];
}

static void     fbSessionFreeOneTemplate(
    void            *vtid __attribute__((unused)),
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    fBufRemoveTemplateTcplan(session->tdyn_buf, tmpl);
    fbTemplateRelease(tmpl);
}

static void     fbSessionResetOneDomain(
    void            *vdomain __attribute__((unused)),
    GHashTable      *ttab,
    fbSession_t     *session)
{
    g_hash_table_foreach(ttab,
                         (GHFunc)fbSessionFreeOneTemplate, session);
}

void            fbSessionResetExternal(
    fbSession_t     *session)
{
    /* Clear out the old domain template table if we have one */
    if (session->dom_ttab) {
        /* Release all the external templates (will free unless shared) */
        g_hash_table_foreach(session->dom_ttab,
                            (GHFunc)fbSessionResetOneDomain, session);
        /* Nuke the domain template table */
        g_hash_table_destroy(session->dom_ttab);
    }

    /* Allocate domain template table */
    session->dom_ttab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal,
                              NULL, (GDestroyNotify)g_hash_table_destroy);

    /* Null out stale external template table */
#if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
    session->ext_ttab = NULL;
    pthread_mutex_unlock( &session->ext_ttab_wlock );
#else
    session->ext_ttab = NULL;
#endif

    /* Clear out the old sequence number table if we have one */
    if (session->dom_seqtab) {
        g_hash_table_destroy(session->dom_seqtab);
    }

    /* Allocate domain sequence number table */
    session->dom_seqtab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                              NULL);

    /* Zero sequence number and domain */
    session->sequence = 0;
    session->domain = 0;

#if HAVE_SPREAD
    if (session->grp_ttab) {
        g_hash_table_destroy(session->grp_ttab);
    }
    /*Allocate group template table */
    session->grp_ttab =
        g_hash_table_new_full(g_direct_hash, g_direct_equal,
                              NULL, (GDestroyNotify)g_hash_table_destroy);
    if (session->grp_seqtab) {
        g_hash_table_destroy(session->grp_seqtab);
    }
    session->grp_seqtab = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                NULL, NULL);

    /** Group 0 just means if we never sent a template on a group -
     * we will multicast to every group we know about */

    session->group = 0;
#endif

    /* Set domain to 0 (initializes external template table) */
    fbSessionSetDomain(session, 0);
}

void            fbSessionFree(
    fbSession_t     *session)
{
    fbSessionResetExternal(session);
    g_hash_table_foreach(session->int_ttab,
                         (GHFunc)fbSessionFreeOneTemplate, session);
    g_hash_table_destroy(session->int_ttab);
    g_hash_table_destroy(session->dom_ttab);
    if (session->dom_seqtab) {
        g_hash_table_destroy(session->dom_seqtab);
    }
    if (session->tmpl_pair_array) {
        g_slice_free1(sizeof(uint16_t) * UINT16_MAX,
                      session->tmpl_pair_array);
        session->tmpl_pair_array = NULL;
    }
#if HAVE_SPREAD
    if (session->grp_ttab) {
        g_hash_table_destroy(session->grp_ttab);
    }
    if (session->grp_seqtab) {
        g_hash_table_destroy(session->grp_seqtab);
    }
#endif
    g_slice_free(fbSession_t, session);
}

void            fbSessionSetDomain(
    fbSession_t     *session,
    uint32_t        domain)
{
    /* Short-circuit identical domain if not initializing */
    if (session->ext_ttab && (domain == session->domain)) return;

    /* Update external template table; create if necessary. */
#if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
    session->ext_ttab = g_hash_table_lookup( session->dom_ttab,
                                             GUINT_TO_POINTER(domain) );
    if (!session->ext_ttab)
    {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->dom_ttab, GUINT_TO_POINTER(domain),
                            session->ext_ttab);
    }
#if HAVE_SPREAD
    pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
    /* Stash current sequence number */
    g_hash_table_insert(session->dom_seqtab,
                        GUINT_TO_POINTER(session->domain),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->dom_seqtab,GUINT_TO_POINTER(domain)));

    /* Stash new domain */
    session->domain = domain;
}

#if HAVE_SPREAD
void fbSessionSetGroupParams(
    fbSession_t     *session,
    sp_groupname_t  *groups,
    int              num_groups)
{
    session->all_groups = groups;
    session->num_groups = num_groups;
}

unsigned int fbSessionGetGroupOffset(
    fbSession_t     *session,
    char            *group)
{
    int loop;

    for (loop = 0; loop < session->num_groups; loop++){
        if (strcmp(group, session->all_groups[loop].name) == 0) {
            return (loop + 1);
        }
    }


    return 0;
}

void            fbSessionSetPrivateGroup(
    fbSession_t      *session,
    char             *group,
    char             *privgroup)
{
    int loop, group_offset = 0;
    char **g;
    GError **err = NULL;

    if (group == NULL || privgroup == NULL) {
        return;
    }

    for (loop = 0; loop < session->num_groups; loop++) {
        if (strncmp(group, session->all_groups[loop].name,
                    strlen(session->all_groups[loop].name)) == 0)
        {
            group_offset = loop + 1;
        }
    }

    if (group_offset == 0){
        g_warning("Private Group requesting membership from UNKNOWN group");
        return;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        if (!fBufEmit(session->tdyn_buf, err)) {
            g_warning("Could not emit buffer %s", (*err)->message);
            g_clear_error(err);
        }
    }

    /*Update external template table; create if necessary. */

    pthread_mutex_lock(&session->ext_ttab_wlock);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));

    if (!session->ext_ttab) {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->grp_ttab, GUINT_TO_POINTER(group_offset),
                            session->ext_ttab);
    }
    pthread_mutex_unlock(&session->ext_ttab_wlock);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    session->group = group_offset;

    g = &privgroup;

    if (fBufGetExporter(session->tdyn_buf)) {
        fBufSetExportGroups(session->tdyn_buf, g, 1, err);
    }

    fbSessionExportTemplates(session, err);
}

static int fbSessionAddTemplatesSpread(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    GError           **err)
{

    int n = 0;
    unsigned int group_offset;
    GHashTable *ttab;

    /*Update external template table per group; create if necessary. */
    while (groups[n]) {
        group_offset = fbSessionGetGroupOffset(session, groups[n]);

        if (group_offset == 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                        "Spread Group Not Recognized.");
            return -1;
        }

        pthread_mutex_lock(&session->ext_ttab_wlock);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab = g_hash_table_new(g_direct_hash,g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        pthread_mutex_unlock(&session->ext_ttab_wlock);
        g_hash_table_insert(session->grp_seqtab,
                            GUINT_TO_POINTER(session->group),
                            GUINT_TO_POINTER(session->sequence));

        /* Get new sequence number */
        session->sequence = GPOINTER_TO_UINT(
            g_hash_table_lookup(session->grp_seqtab,
                                GUINT_TO_POINTER(group_offset)));

        /* keep new group */
        session->group = group_offset;

        /* Select a template table to add the template to */
        ttab = internal ? session->int_ttab : session->ext_ttab;

        /* Revoke old template, ignoring missing template error. */
        if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                g_clear_error(err);
            } else {
                return -1;
            }
        }

        /* Insert template into table */
#if HAVE_SPREAD
        if (!internal)
            pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
        g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);

#if HAVE_SPREAD
        if (!internal)
            pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
        fbTemplateRetain(tmpl);

        if (internal) {
            /* we don't really multicast internal tmpls - we only
               have one internal tmpl table - so once is enough */
            return 0;
        }

        n++;
    }

    /* Now set session to group 1 before we multicast */
    group_offset = fbSessionGetGroupOffset(session, groups[0]);

    pthread_mutex_lock(&session->ext_ttab_wlock);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));
    pthread_mutex_unlock(&session->ext_ttab_wlock);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get sequence number - since it's the first group in list */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    /* keep new group */
    session->group = group_offset;

    return n;

}

/**
 * fbSessionAddTemplatesMulticast
 *
 *
 */
uint16_t        fbSessionAddTemplatesMulticast(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    GError           **err)
{
    uint16_t next_tid = 0;
    int n = 0;

    if (groups == NULL) {
        return 0;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* we are now going to multicast tmpls so we need to emit
           records currently in the buffer */
        if (!fBufEmit(session->tdyn_buf, err)) {
            return 0;
        }
    }

    if (tid == FB_TID_AUTO) {
        if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        while (fbSessionGetTemplate(session, internal, next_tid, NULL)) {
            next_tid++;
            if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        }
        tid = next_tid++;
    }

    n = fbSessionAddTemplatesSpread(session, groups, internal,
                                      tid, tmpl, err);
    if (n < 0) {
        return 0;
    } else if (n == 0) {
        return tid;
    }

    if (fBufGetExporter(session->tdyn_buf)) {
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;

        fBufSetExportGroups(session->tdyn_buf, groups, n, err);
    }

    return tid;

}


/**
 * fbSessionAddTemplatesMulticastWithMetadata
 *
 *
 */
uint16_t        fbSessionAddTemplatesMulticastWithMetadata(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    char             *name,
    char             *description,
    GError           **err)
{
    uint16_t next_tid = 0;
    int n = 0;
    int count = 0;
    fbTemplateOptRec_t *metadata_rec = NULL;

    if (!name) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                    "Template name must be specified");
        return 0;
    }

    if (groups == NULL) {
        return 0;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* we are now going to multicast tmpls so we need to emit
           records currently in the buffer */
        if (!fBufEmit(session->tdyn_buf, err)) {
            return 0;
        }
    }

    if (tid == FB_TID_AUTO) {
        if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        while (fbSessionGetTemplate(session, internal, next_tid, NULL)) {
            next_tid++;
            if (next_tid == 0) next_tid = FB_TID_MIN_DATA;
        }
        tid = next_tid++;
    }

    n = fbSessionAddTemplatesSpread(session, groups, internal,
                                    tid, tmpl, err);

    if (n < 0) {
        return 0;
    } else if (n == 0) {
        return tid;
    }

    if (session->export_template_metadata) {
        count = fbTemplateCountElements(tmpl);

        metadata_rec = g_slice_new0(fbTemplateOptRec_t);
        metadata_rec->template_id = tid;
        metadata_rec->template_name.buf = (uint8_t *) g_strdup(name);
        metadata_rec->template_name.len = strlen(name);

        if (description) {
            metadata_rec->template_description.buf =
                (uint8_t *) g_strdup(description);
            metadata_rec->template_description.len = strlen(description);
        }

        tmpl->metadata_rec = metadata_rec;
    }

    /* Write template to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {

        fBufSetExportGroups(session->tdyn_buf, groups, n, err);

        if (!fbSessionWriteTemplateMetadata(session, tmpl, err)) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                g_clear_error(err);
            } else {
                return 0;
            }
        }

        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;
    }

    return tid;
}

/**
 * fbSessionSetGroup
 *
 *
 */
void            fbSessionSetGroup(
    fbSession_t      *session,
    char             *group)
{
    unsigned int group_offset;
    GError **err = NULL;

    if (group == NULL && session->ext_ttab) {
        /* ext_ttab should already be setup and we are multicasting
           so no need to setup any tables */
        return;
    }

    group_offset = fbSessionGetGroupOffset(session, group);

    if (group_offset == 0) {
        g_warning("Spread Group Not Recognized.");
        return;
    }

    /* short-circut identical group if not initializing */
    if (session->ext_ttab && (session->group == group_offset))  return;

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* Group is changing - meaning tmpls changing - emit now */
        if (!fBufEmit(session->tdyn_buf, err)) {
            g_warning("Could not emit buffer before setting group: %s",
                      (*err)->message);
            g_clear_error(err);
        }
    }
    /*Update external template table; create if necessary. */

    if (fBufGetExporter(session->tdyn_buf)) {
        /* Only need to do this for exporters */
        /* Collector's templates aren't managed per group */
        pthread_mutex_lock(&session->ext_ttab_wlock);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab =g_hash_table_new(g_direct_hash, g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        pthread_mutex_unlock(&session->ext_ttab_wlock);
    }

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    /* keep new group */
    session->group = group_offset;

}

unsigned int    fbSessionGetGroup(
    fbSession_t *session)
{
    return session->group;
}

#endif


uint32_t        fbSessionGetDomain(
    fbSession_t     *session)
{
    return session->domain;
}


uint16_t        fbSessionAddTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    fbTemplate_t    *tmpl,
    GError          **err)
{
    GHashTable      *ttab = NULL;
    static uint16_t next_ext_tid = 0;
    static uint16_t next_int_tid = UINT16_MAX;

    /* Select a template table to add the template to */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    /* prevent infinite loop when template tables are full */
    if (g_hash_table_size(ttab) == (UINT16_MAX - FB_TID_MIN_DATA)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Template table is full, no IDs left");
        return 0;
    }

    /* Automatically assign a new template ID */
    if (tid == FB_TID_AUTO) {
        if (internal) {
            if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                next_int_tid = UINT16_MAX;
            }
            while (fbSessionGetTemplate(session, internal, next_int_tid, NULL))
            {
                next_int_tid--;
                if (next_int_tid == (FB_TID_MIN_DATA - 1)) {
                    next_int_tid = UINT16_MAX;
                }
            }
            tid = next_int_tid--;
        } else {
            if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            while (fbSessionGetTemplate(session, internal, next_ext_tid, NULL))
            {
                next_ext_tid++;
                if (next_ext_tid == 0) next_ext_tid = FB_TID_MIN_DATA;
            }
            tid = next_ext_tid++;
        }
    }

    /* Revoke old template, ignoring missing template error. */
    if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            g_clear_error(err);
        } else {
            return 0;
        }
    }

    /* Write template to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err))
            return 0;
    }

    /* Insert template into table */
#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
    g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);
    if (internal) {
        session->intTmplTableChanged = 1;
    } else {
        session->extTmplTableChanged = 1;
    }

#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif

    fbTemplateRetain(tmpl);

    return tid;
}

gboolean        fbSessionRemoveTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    GError          **err)
{
    GHashTable      *ttab = NULL;
    fbTemplate_t    *tmpl = NULL;
    gboolean        ok = TRUE;

    /* Select a template table to remove the template from */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    /* Get the template to remove */
    tmpl = fbSessionGetTemplate(session, internal, tid, err);
    if (!tmpl) return FALSE;

    /* Write template withdrawal to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {
        ok = fBufAppendTemplate(session->tdyn_buf, tid, tmpl, TRUE, err);
    }

    /* Remove template */
#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
    g_hash_table_remove(ttab, GUINT_TO_POINTER((unsigned int)tid));

    if (internal) {
        session->intTmplTableChanged = 1;
    } else {
        session->extTmplTableChanged = 1;
    }

    fbSessionRemoveTemplatePair(session, tid);

    fBufRemoveTemplateTcplan(session->tdyn_buf, tmpl);

#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
    fbTemplateRelease(tmpl);

    return ok;
}

fbTemplate_t    *fbSessionGetTemplate(
    fbSession_t     *session,
    gboolean        internal,
    uint16_t        tid,
    GError          **err)
{
    GHashTable      *ttab;
    fbTemplate_t    *tmpl;

    /* Select a template table to get the template from */
    ttab = internal ? session->int_ttab : session->ext_ttab;

#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
    tmpl = g_hash_table_lookup(ttab, GUINT_TO_POINTER((unsigned int)tid));
#if HAVE_SPREAD
    if (!internal)
        pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
    /* Check for missing template */
    if (!tmpl) {
        if (internal) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Missing internal template %04hx",
                        tid);
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Missing external template %08x:%04hx",
                        session->domain, tid);
        }
        return NULL;
    }

    return tmpl;
}

gboolean        fbSessionExportTemplate(
    fbSession_t     *session,
    uint16_t        tid,
    GError          **err)
{
    fbTemplate_t    *tmpl = NULL;

    /* short-circuit on no template dynamics buffer */
    if (!fBufGetExporter(session->tdyn_buf))
        return TRUE;

    /* look up template */
    if (!(tmpl = fbSessionGetTemplate(session, FALSE, tid, err)))
        return FALSE;

    fbSessionWriteTemplateMetadata(session, tmpl, err);
    /* export it */
    return fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err);
}

static void fbSessionExportOneTemplateMetadataRecord(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);

    /* The type/template metadata templates should have already been exported */
    if (tid == session->info_element_metadata_tid
        || tid == session->template_metadata_tid)
    {
        return;
    }

    if (!tmpl->metadata_rec) {
        return;
    }

    /* the internal and external template must be set on the fBuf before
       using this function or everything will go to crap */

    if (!fBufAppend(session->tdyn_buf, (uint8_t *) tmpl->metadata_rec,
                    sizeof(fbTemplateOptRec_t), &session->tdyn_err)) {
        /* printf("BufAppend failed\n"); */
        return;
    }
}


static void     fbSessionExportOneTemplate(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);

    /* The type/template metadata templates should have already been exported */
    if (tid == session->info_element_metadata_tid
        || tid == session->template_metadata_tid)
    {
        return;
    }

    /* printf("fbSessionExportOneTemplate: %x\n", tid); */
    if (fBufGetExporter(session->tdyn_buf)) {
        if (session->tdyn_err) return;

        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl,
                                FALSE, &session->tdyn_err)) {
            if (!session->tdyn_err) {
                g_set_error(&session->tdyn_err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "Unspecified template export error");
            }
        }
    }
}

gboolean        fbSessionExportTemplates(
    fbSession_t     *session,
    GError          **err)
{
    gboolean ret = FALSE;
    uint16_t int_tid = fBufGetInternalTemplate(session->tdyn_buf);
    uint16_t ext_tid = fBufGetExportTemplate(session->tdyn_buf);

    g_clear_error(&(session->tdyn_err));

    if (session->export_info_element_metadata) {

        if (!fbSessionExportTemplate(session, session->info_element_metadata_tid,
                                     &(session->tdyn_err)))
        {
            g_propagate_error(err, session->tdyn_err);
            goto err;
        }

        if (!fbSessionWriteTypeMetadata(session, &(session->tdyn_err))) {

            g_propagate_error(err, session->tdyn_err);
            goto err;
        }
    }

    if (session->export_template_metadata) {
        if (!fbSessionExportTemplate(session, session->template_metadata_tid,
                                     &(session->tdyn_err)))
        {
            g_propagate_error(err, session->tdyn_err);
            goto err;
        }
        if (session->ext_ttab && fBufGetExporter(session->tdyn_buf)) {

            if (session->tdyn_err) return FALSE;

            if (!fBufSetInternalTemplate(session->tdyn_buf,
                                         session->template_metadata_tid,
                                         &session->tdyn_err))
            {
                return FALSE;
            }


            if (!fBufSetExportTemplate(session->tdyn_buf,
                                       session->template_metadata_tid,
                                       &session->tdyn_err))
            {
                return FALSE;
            }

#if HAVE_SPREAD
            pthread_mutex_lock( &session->ext_ttab_wlock );
#endif
            /* the fbufsetinternal/fbufsetexport template functions
               can't occur in the GHFunc since pthread_mutex_lock
               has already been called and fBufSetExportTemplate will
               call fbSessionGetTemplate which will try to acquire lock*/

            g_hash_table_foreach(session->ext_ttab,
                                 (GHFunc)fbSessionExportOneTemplateMetadataRecord, session);
#if HAVE_SPREAD
            pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif

        }
    }

#if HAVE_SPREAD
    pthread_mutex_lock( &session->ext_ttab_wlock );
#endif

    if (session->ext_ttab)
    {
        g_hash_table_foreach(session->ext_ttab,
                             (GHFunc)fbSessionExportOneTemplate, session);

        if (session->tdyn_err)
        {
            g_propagate_error(err, session->tdyn_err);
            goto err;
        }
    }


    ret = TRUE;
  err:
#if HAVE_SPREAD
    pthread_mutex_unlock( &session->ext_ttab_wlock );
#endif
    if (int_tid) {
        fBufSetInternalTemplate(session->tdyn_buf, int_tid, err);
    }
    if (ext_tid) {
        fBufSetExportTemplate(session->tdyn_buf, ext_tid, err);
    }
    return ret;
}

static void     fbSessionCloneOneTemplate(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);
    GError          *err = NULL;

    if (!fbSessionAddTemplate(session, TRUE, tid, tmpl, &err)) {
        g_warning("Session clone internal template copy failed: %s",
                  err->message);
    }
}

fbSession_t     *fbSessionClone(
    fbSession_t     *base)
{
    fbSession_t     *session = NULL;

    /* Create a new session using the information model from the base */
    session = fbSessionAlloc(base->model);

    /* Add each internal template from the base session to the new session */
    g_hash_table_foreach(base->int_ttab,
                         (GHFunc)fbSessionCloneOneTemplate, session);

    /* Need to copy over callbacks because in the UDP case we won't have
       access to the session until after we call fBufNext and by that
       time it's too late and we've already missed some templates */
    session->new_template_callback = base->new_template_callback;
    session->tmpl_app_ctx = base->tmpl_app_ctx;

    /* copy collector reference */
    session->collector = base->collector;

    /* Return the new session */
    return session;
}

uint32_t        fbSessionGetSequence(
    fbSession_t     *session)
{
    return session->sequence;
}

void            fbSessionSetSequence(
    fbSession_t     *session,
    uint32_t        sequence)
{
    session->sequence = sequence;
}

void            fbSessionSetTemplateBuffer(
    fbSession_t     *session,
    fBuf_t          *fbuf)
{
    session->tdyn_buf = fbuf;
}

fbInfoModel_t       *fbSessionGetInfoModel(
    fbSession_t         *session)
{
    return session->model;
}

void fbSessionClearIntTmplTableFlag(
    fbSession_t        *session)
{
    session->intTmplTableChanged = 0;
}

void fbSessionClearExtTmplTableFlag(
    fbSession_t        *session)
{
    session->extTmplTableChanged = 0;
}

int fbSessionIntTmplTableFlagIsSet(
    fbSession_t        *session)
{
    return session->intTmplTableChanged;
}

int fbSessionExtTmplTableFlagIsSet(
    fbSession_t        *session)
{
    return session->extTmplTableChanged;
}

void fbSessionSetCollector(
    fbSession_t        *session,
    fbCollector_t      *collector)
{
    session->collector = collector;
}

fbCollector_t *fbSessionGetCollector(
    fbSession_t        *session)
{
    return session->collector;
}
