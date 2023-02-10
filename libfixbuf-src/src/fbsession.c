/*
 ** fbsession.c
 ** IPFIX Transport Session state container
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


/* whether to debug writing of InfoElement and Template metadata */
#ifndef FB_DEBUG_MD
#define FB_DEBUG_MD 0
#endif

/** Size of the tmpl_pair_array */
#define TMPL_PAIR_ARRAY_SIZE    (sizeof(uint16_t) * (1 << 16))

#if HAVE_SPREAD
/* Lock the mutex on session 's' when spread is active */
#define FB_SPREAD_MUTEX_LOCK(s)     pthread_mutex_lock(&(s)->ext_ttab_wlock)

/* Unlock the mutex on session 's' when spread is active */
#define FB_SPREAD_MUTEX_UNLOCK(s)   pthread_mutex_unlock(&(s)->ext_ttab_wlock)
#else
#define FB_SPREAD_MUTEX_LOCK(s)
#define FB_SPREAD_MUTEX_UNLOCK(s)
#endif  /* HAVE_SPREAD */

/* FIXME: Consider changing fbSession so the ext_FOO/int_FOO pairs of
 * members become a FOO[2] array and the `internal` gboolean used by
 * several function is used as the index into those arrays. */

struct fbSession_st {
    /** Information model. */
    fbInfoModel_t               *model;
    /**
     * Internal template table. Maps template ID to internal template.
     */
    GHashTable                  *int_ttab;
    /**
     * External template table for current observation domain.
     * Maps template ID to external template.
     */
    GHashTable                  *ext_ttab;
    /**
     * Array of size 2^16 where index is external TID and value is
     * internal TID.  The number if valid entries in the array is
     * maintained by 'num_tmpl_pairs'.
     */
    uint16_t                    *tmpl_pair_array;
    /**
     * Callback function to allow an application to assign template
     * pairs for transcoding purposes, and to add context to a
     * particular template.  Uses 'tmpl_app_ctx'.
     */
    fbNewTemplateCallback_fn    new_template_callback;
    /**
     * Context the caller provides for 'new_template_callback'.
     */
    void                        *tmpl_app_ctx;
    /**
     * A pointer to the largest template seen in this session.  The
     * size of this template 'largestInternalTemplateLength'.
     */
    fbTemplate_t               *largestInternalTemplate;
    /**
     * Domain external template table.
     * Maps domain to external template table.
     */
    GHashTable                  *dom_ttab;
    /**
     * Domain last/next sequence number table.
     * Maps domain to sequence number.
     */
    GHashTable                  *dom_seqtab;
    /**
     * Current observation domain ID.
     */
    uint32_t                    domain;
    /**
     * Last/next sequence number in current observation domain.
     */
    uint32_t                    sequence;
    /**
     * Pointer to collector that was created with session
     */
    fbCollector_t               *collector;
    /**
     * Buffer instance to write template dynamics to.
     */
    fBuf_t                      *tdyn_buf;
    /**
     * Error description for fbSessionExportTemplates()
     */
    GError                      *tdyn_err;
    /**
     * The number of valid pairs in 'tmpl_pair_array'.  Used to free
     * the array when it is empty.
     */
    uint16_t                    num_tmpl_pairs;
    /**
     * The TID to use for exporting enterprise-specific IEs when
     * export_info_element_metadata is true.
     */
    uint16_t                    info_element_metadata_tid;
    /**
     * The TID to use for exporting template metadata when
     * export_template_metadata is true.
     */
    uint16_t                    template_metadata_tid;
    /**
     * The length of the template in 'largestInternalTemplate'.
     */
    uint16_t                    largestInternalTemplateLength;
    /**
     * Where to begin looking for an unused external template ID when
     * the ID is FB_TID_AUTO.  These begin at FB_TID_MIN_DATA and
     * increment.
     */
    uint16_t                    ext_next_tid;
    /**
     * Where to begin looking for an unused internal template ID when
     * the ID is FB_TID_AUTO.  These begin at UINT16_MAX and
     * decrement.
     */
    uint16_t                    int_next_tid;
    /**
     * If TRUE, options records will be exported for
     * enterprise-specific IEs.  The TID used is
     * 'info_element_metadata_tid'.
     */
    gboolean                    export_info_element_metadata;
    /**
     * If TRUE, options records will be exported for templates that
     * have been given a name.  The TID used is
     * 'template_metadata_tid'.
     */
    gboolean                    export_template_metadata;
    /**
     * Flag to set when an internal template is added or removed. The flag is
     * unset when SetInternalTemplate is called. This ensures the internal
     * template set to the most up-to-date template
     */
    gboolean                     intTmplTableChanged;
    /**
     * Flag to set when an external template is added or removed. The flag is
     * unset when SetExportTemplate is called. This ensures the external
     * template set to the most up-to-date template
     */
    gboolean                     extTmplTableChanged;


#if HAVE_SPREAD
    /**
     * Mutex to guard the ext_ttab when using Spread.  Spread listens for new
     * group memberships.  On a new membership, the Spread transport will send
     * all external templates to the new member privately.  During this
     * process, the external template table cannot be modified, hence the
     * write lock on ext_ttab.
     */
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
     * Need to keep track of all groups session knows about
     */
    sp_groupname_t              *all_groups;
    /**
     * Number of groups session knows about.
     */
    unsigned int                num_groups;
    /**
     * Current Group
     */
    unsigned int                group;
#endif  /* HAVE_SPREAD */
};

static void fbSessionSetLargestInternalTemplateLen(
    fbSession_t    *session);

static uint16_t fbSessionAddTemplateHelper(
    fbSession_t    *session,
    gboolean        internal,
    uint16_t        tid,
    fbTemplate_t   *tmpl,
    const char     *name,
    const char     *description,
    GError         **err);

#if HAVE_SPREAD
static uint16_t fbSessionSpreadAddTemplatesHelper(
    fbSession_t    *session,
    char           **groups,
    gboolean        internal,
    uint16_t        tid,
    fbTemplate_t   *tmpl,
    char           *name,
    char           *description,
    GError         **err);
#endif  /* HAVE_SPREAD */

fbSession_t     *fbSessionAlloc(
    fbInfoModel_t   *model)
{
    fbSession_t     *session = NULL;

    /* Create a new session */
    session = g_slice_new0(fbSession_t);

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

    session->int_next_tid = UINT16_MAX;
    session->ext_next_tid = FB_TID_MIN_DATA;

    /* All done */
    return session;
}

gboolean fbSessionEnableTypeMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                     **err)
{
    return (fbSessionSetMetadataExportElements(
                session, enabled, FB_TID_AUTO, err) != 0);
}

uint16_t fbSessionSetMetadataExportElements(
    fbSession_t                *session,
    gboolean                    enabled,
    uint16_t                    tid,
    GError                     **err)
{
    fbTemplate_t *ie_type_template = NULL;

    session->export_info_element_metadata = enabled;

    /* external */
    ie_type_template = fbInfoElementAllocTypeTemplate2(session->model,
                                                       FALSE, err);
    if (! ie_type_template) {
        return 0;
    }
    session->info_element_metadata_tid = fbSessionAddTemplateHelper(
        session, FALSE, tid, ie_type_template, NULL, NULL, err);
    if (! session->info_element_metadata_tid) {
        fbTemplateFreeUnused(ie_type_template);
        return 0;
    }

    /* internal */
    ie_type_template = fbInfoElementAllocTypeTemplate2(session->model,
                                                       TRUE, err);
    if (! ie_type_template) {
        return 0;
    }
    session->info_element_metadata_tid = fbSessionAddTemplateHelper(
        session, TRUE, session->info_element_metadata_tid,
        ie_type_template, NULL, NULL, err);
    if (! session->info_element_metadata_tid) {
        fbTemplateFreeUnused(ie_type_template);
        return 0;
    }

    return session->info_element_metadata_tid;
}


/*
 *  Writes the info element type metadata for all non-standard
 *  elements in the info model to the template dynamics buffer of
 *  'session'.
 *
 *  Does NOT restore the internal and external templates of the fBuf.
 */
static gboolean fbSessionWriteTypeMetadata(
    fbSession_t                *session,
    GError                    **err)
{
    fbInfoModelIter_t iter;
    const fbInfoElement_t *ie = NULL;
    GError *child_err = NULL;

    if (!session->export_info_element_metadata) {
#if FB_DEBUG_MD
        fprintf(stderr, "Called fbSessionWriteTypeMetadata on a session"
                " that is not configured for element metadata\n");
#endif
        return TRUE;
    }

#if FB_DEBUG_MD
    fprintf(stderr, "Writing info element metadata tmpl %#x to fbuf %p\n",
            session->info_element_metadata_tid, (void *)session->tdyn_buf);
#endif

    if (!fBufSetInternalTemplate(
            session->tdyn_buf, session->info_element_metadata_tid, &child_err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "fBufSetInternalTemplate(%#x) failed: %s\n",
                session->info_element_metadata_tid, child_err->message);
#endif
        g_propagate_error(err, child_err);
        return FALSE;
    }

    if (!fBufSetExportTemplate(
            session->tdyn_buf, session->info_element_metadata_tid, &child_err))
    {
        if (g_error_matches(child_err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
#if FB_DEBUG_MD
            fprintf(stderr,"Ignoring failed fBufSetExternalTemplate(%#x): %s\n",
                    session->info_element_metadata_tid, child_err->message);
#endif
            g_clear_error(&child_err);
            return TRUE;
        }
#if FB_DEBUG_MD
        fprintf(stderr, "fBufSetExternalTemplate(%#x) failed: %s\n",
                session->info_element_metadata_tid, child_err->message);
#endif
        g_propagate_error(err, child_err);
        return FALSE;
    }

    fbInfoModelIterInit(&iter, session->model);

    while ( (ie = fbInfoModelIterNext(&iter)) ) {
        /* No need to send metadata for IEs in the standard info model */
        if (ie->ent == 0 || ie->ent == FB_IE_PEN_REVERSE) {
            continue;
        }

        if (!fbInfoElementWriteOptionsRecord(
            session->tdyn_buf, ie, session->info_element_metadata_tid,
            session->info_element_metadata_tid, &child_err))
        {
#if FB_DEBUG_MD
            fprintf(stderr,"fbInfoElementWriteOptionsRecord(%s) failed: %s\n",
                    ie->ref.name, child_err->message);
#endif
            g_propagate_error(err, child_err);
            return FALSE;
        }
    }

#if FB_DEBUG_MD
    fprintf(stderr, "Finished writing info element type metadata\n");
#endif
    return TRUE;
}

gboolean fbSessionEnableTemplateMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                    **err)
{
    return (fbSessionSetMetadataExportTemplates(
                session, enabled, FB_TID_AUTO, err) != 0);
}

uint16_t fbSessionSetMetadataExportTemplates(
    fbSession_t                *session,
    gboolean                    enabled,
    uint16_t                    tid,
    GError                    **err)
{
    fbTemplate_t *metadata_template = NULL;

    session->export_template_metadata = enabled;

    /* external */
    metadata_template = fbTemplateAllocTemplateMetadataTmpl(session->model,
                                                            FALSE, err);
    if (!metadata_template) {
        return 0;
    }
    session->template_metadata_tid = fbSessionAddTemplateHelper(
        session, FALSE, tid, metadata_template, NULL, NULL, err);
    if (!session->template_metadata_tid) {
        fbTemplateFreeUnused(metadata_template);
        return 0;
    }

    /* internal */
    metadata_template = fbTemplateAllocTemplateMetadataTmpl(session->model,
                                                            TRUE, err);
    if (!metadata_template) {
        return 0;
    }
    session->template_metadata_tid = fbSessionAddTemplateHelper(
        session, TRUE, session->template_metadata_tid,
        metadata_template, NULL, NULL, err);
    if (!session->template_metadata_tid) {
        /* should it be removed from the external session? */
        fbTemplateFreeUnused(metadata_template);
        return 0;
    }

    return session->template_metadata_tid;
}

#if HAVE_SPREAD
gboolean fbSessionSpreadEnableTemplateMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err)
{
    return (fbSessionSpreadSetMetadataExportTemplates(
                session, groups, enabled, FB_TID_AUTO, err) != 0);
}

uint16_t fbSessionSpreadSetMetadataExportTemplates(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    uint16_t                    tid,
    GError                     **err)
{
    fbTemplate_t *metadata_template = NULL;

    session->export_template_metadata = enabled;

    /* external */
    metadata_template = fbTemplateAllocTemplateMetadataTmpl(session->model,
                                                            FALSE, err);
    if (!metadata_template) {
        return 0;
    }
    session->template_metadata_tid = fbSessionSpreadAddTemplatesHelper(
        session, groups, FALSE, tid, metadata_template, NULL, NULL, err);
    if (!session->template_metadata_tid) {
        fbTemplateFreeUnused(metadata_template);
        return 0;
    }

    /* internal */
    metadata_template = fbTemplateAllocTemplateMetadataTmpl(session->model,
                                                            TRUE, err);
    if (!metadata_template) {
        return 0;
    }
    session->template_metadata_tid = fbSessionAddTemplateHelper(
        session, TRUE, session->template_metadata_tid,
        metadata_template, NULL, NULL, err);
    if (!session->template_metadata_tid) {
        /* should it be removed from the external session? */
        fbTemplateFreeUnused(metadata_template);
        return 0;
    }

    return session->template_metadata_tid;
}

gboolean fbSessionSpreadEnableTypeMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err)
{
    return (fbSessionSpreadSetMetadataExportElements(
                session, groups, enabled, FB_TID_AUTO, err) != 0);
}

uint16_t fbSessionSpreadSetMetadataExportElements(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    uint16_t                   tid,
    GError                     **err)
{
    fbTemplate_t *ie_type_template = NULL;

    session->export_info_element_metadata = enabled;

    /* external */
    ie_type_template = fbInfoElementAllocTypeTemplate2(session->model,
                                                       FALSE, err);
    if (!ie_type_template) {
        return 0;
    }
    session->info_element_metadata_tid = fbSessionSpreadAddTemplatesHelper(
        session, groups, FALSE, tid, ie_type_template, NULL, NULL, err);
    if (!session->info_element_metadata_tid) {
        fbTemplateFreeUnused(ie_type_template);
        return 0;
    }

    /* internal */
    ie_type_template = fbInfoElementAllocTypeTemplate2(session->model,
                                                       TRUE, err);
    session->info_element_metadata_tid = fbSessionAddTemplateHelper(
        session, TRUE, session->info_element_metadata_tid,
        ie_type_template, NULL, NULL, err);
    if (!session->info_element_metadata_tid) {
        fbTemplateFreeUnused(ie_type_template);
        return 0;
    }

    return session->info_element_metadata_tid;
}

#endif  /* HAVE_SPREAD */


/* Writes the metadata for 'tmpl' to 'session'. */
static gboolean fbSessionWriteTemplateMetadata(
    fbSession_t    *session,
    fbTemplate_t   *tmpl,
    GError         **err)
{
    uint16_t int_tid, ext_tid;
    GError *child_err = NULL;
    gboolean ret = TRUE;

    if (!session->export_template_metadata || !tmpl->metadata_rec) {
        return TRUE;
    }
#if FB_DEBUG_MD
    fprintf(stderr, "writing metadata for template %p to fBuf %p\n",
            (void *)tmpl, (void *)session->tdyn_buf);
#endif

    int_tid = fBufGetInternalTemplate(session->tdyn_buf);
    ext_tid = fBufGetExportTemplate(session->tdyn_buf);

    if (!fBufSetInternalTemplate(
            session->tdyn_buf, session->template_metadata_tid, err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "fBufSetInternalTemplate(%#x) failed: %s\n",
                session->template_metadata_tid, (err ? (*err)->message : ""));
#endif
        ret = FALSE;
        goto RESET_INT;
    }
    if (!fBufSetExportTemplate(
            session->tdyn_buf, session->template_metadata_tid, err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "fBufSetExportTemplate(%#x) failed: %s\n",
                session->template_metadata_tid, (err ? (*err)->message : ""));
#endif
        ret = FALSE;
        goto RESET_EXT;
    }
    if (!fBufAppend(session->tdyn_buf, (uint8_t *)tmpl->metadata_rec,
                    sizeof(fbTemplateOptRec_t), err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "fBufAppend(%p) failed: %s\n",
                (void *)tmpl->metadata_rec, (err ? (*err)->message : ""));
#endif
        ret = FALSE;
        goto RESET_EXT;
    }
    /* if (!fBufEmit(session->tdyn_buf, err)) goto END; */

  RESET_EXT:
    if (ext_tid
        && !fBufSetExportTemplate(session->tdyn_buf, ext_tid, &child_err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "restore fBufSetExportTemplate(%#x) failed: %s\n",
                ext_tid, child_err->message);
#endif
        if (!ret || g_error_matches(child_err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)){
            /* ignore this error if either an error is already set or
             * this error is an unknown template error */
            g_clear_error(&child_err);
        } else {
            g_propagate_error(err, child_err);
            child_err = NULL;
            ret = FALSE;
        }
    }
  RESET_INT:
    if (int_tid
        && !fBufSetInternalTemplate(session->tdyn_buf, int_tid, &child_err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "restore fBufSetInternalTemplate(%#x) failed: %s\n",
                int_tid, child_err->message);
#endif
        if (!ret || g_error_matches(child_err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)){
            g_clear_error(&child_err);
        } else {
            g_propagate_error(err, child_err);
            child_err = NULL;
            ret = FALSE;
        }
    }

    return ret;
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
    if (!name) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                    "Template name must be specified");
        return 0;
    }
    return fbSessionAddTemplateHelper(session, internal, tid, tmpl,
                                      name, description, err);
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
        session->tmpl_pair_array =
            (uint16_t*)g_slice_alloc0(TMPL_PAIR_ARRAY_SIZE);
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
            g_slice_free1(TMPL_PAIR_ARRAY_SIZE, session->tmpl_pair_array);
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
            g_slice_free1(TMPL_PAIR_ARRAY_SIZE, session->tmpl_pair_array);
            session->tmpl_pair_array = NULL;
            return;
        }
        session->tmpl_pair_array[ext_tid] = 0;
    }
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
    FB_SPREAD_MUTEX_LOCK(session);
    session->ext_ttab = NULL;
    FB_SPREAD_MUTEX_UNLOCK(session);

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
#endif  /* HAVE_SPREAD */

    /* Set domain to 0 (initializes external template table) */
    fbSessionSetDomain(session, 0);
}

void            fbSessionFree(
    fbSession_t     *session)
{
    if (NULL == session) {
        return;
    }
    fbSessionResetExternal(session);
    g_hash_table_foreach(session->int_ttab,
                         (GHFunc)fbSessionFreeOneTemplate, session);
    g_hash_table_destroy(session->int_ttab);
    g_hash_table_destroy(session->dom_ttab);
    if (session->dom_seqtab) {
        g_hash_table_destroy(session->dom_seqtab);
    }
    g_slice_free1(TMPL_PAIR_ARRAY_SIZE, session->tmpl_pair_array);
    session->tmpl_pair_array = NULL;
#if HAVE_SPREAD
    if (session->grp_ttab) {
        g_hash_table_destroy(session->grp_ttab);
    }
    if (session->grp_seqtab) {
        g_hash_table_destroy(session->grp_seqtab);
    }
    pthread_mutex_destroy(&session->ext_ttab_wlock);
#endif  /* HAVE_SPREAD */
    g_slice_free(fbSession_t, session);
}

void            fbSessionSetDomain(
    fbSession_t     *session,
    uint32_t        domain)
{
    /* Short-circuit identical domain if not initializing */
    if (session->ext_ttab && (domain == session->domain)) return;

    /* Update external template table; create if necessary. */
    FB_SPREAD_MUTEX_LOCK(session);
    session->ext_ttab = g_hash_table_lookup( session->dom_ttab,
                                             GUINT_TO_POINTER(domain) );
    if (!session->ext_ttab)
    {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->dom_ttab, GUINT_TO_POINTER(domain),
                            session->ext_ttab);
    }
    FB_SPREAD_MUTEX_UNLOCK(session);

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

/**
 * Find an unused template ID in the template table of `session`.
 */
static uint16_t fbSessionFindUnusedTemplateId(
    fbSession_t     *session,
    gboolean        internal)
{
    /* Select a template table to add the template to */
    GHashTable *ttab = internal ? session->int_ttab : session->ext_ttab;
    uint16_t tid = 0;

    if (internal) {
        if (g_hash_table_size(ttab) == (UINT16_MAX - FB_TID_MIN_DATA)) {
            return 0;
        }
        tid = session->int_next_tid;
        while (g_hash_table_lookup(ttab, GUINT_TO_POINTER((unsigned int)tid))){
            tid = ((tid > FB_TID_MIN_DATA) ? (tid - 1) : UINT16_MAX);
        }
        session->int_next_tid =
            ((tid > FB_TID_MIN_DATA) ? (tid - 1) : UINT16_MAX);
    } else {
        FB_SPREAD_MUTEX_LOCK(session);
        if (g_hash_table_size(ttab) == (UINT16_MAX - FB_TID_MIN_DATA)) {
            FB_SPREAD_MUTEX_UNLOCK(session);
            return 0;
        }
        tid = session->ext_next_tid;
        while (g_hash_table_lookup(ttab, GUINT_TO_POINTER((unsigned int)tid))){
            tid = ((tid < UINT16_MAX) ? (tid + 1) : FB_TID_MIN_DATA);
        }
        session->ext_next_tid =
            ((tid < UINT16_MAX) ? (tid + 1) : FB_TID_MIN_DATA);
        FB_SPREAD_MUTEX_UNLOCK(session);
    }
    return tid;
}

#if HAVE_SPREAD
void fbSessionSetGroupParams(
    fbSession_t     *session,
    sp_groupname_t  *groups,
    unsigned int     num_groups)
{
    session->all_groups = groups;
    session->num_groups = num_groups;
}

unsigned int fbSessionGetGroupOffset(
    fbSession_t     *session,
    char            *group)
{
    unsigned int loop;

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
    unsigned int loop, group_offset = 0;
    char **g;
    GError *err = NULL;

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
        if (!fBufEmit(session->tdyn_buf, &err)) {
            g_warning("Could not emit buffer %s", err->message);
            g_clear_error(&err);
        }
    }

    /*Update external template table; create if necessary. */

    FB_SPREAD_MUTEX_LOCK(session);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));

    if (!session->ext_ttab) {
        session->ext_ttab = g_hash_table_new(g_direct_hash, g_direct_equal);
        g_hash_table_insert(session->grp_ttab, GUINT_TO_POINTER(group_offset),
                            session->ext_ttab);
    }
    FB_SPREAD_MUTEX_UNLOCK(session);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get new sequence number */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    session->group = group_offset;

    g = &privgroup;

    if (fBufGetExporter(session->tdyn_buf)) {
        fBufSetExportGroups(session->tdyn_buf, g, 1, NULL);
    }

    if (!fbSessionExportTemplates(session, &err)) {
        g_clear_error(&err);
    }
}


/**
 *  fbSessionSpreadAddTemplatesHelper
 *
 *    Helper function for fbSessionAddTemplatesMulticast() and
 *    fbSessionAddTemplatesMulticastWithMetadata().
 *
 *    FIXME: Maybe this code should just invoke
 *    fbSessionAddTemplateHelper() when `internal` is TRUE?
 */
static uint16_t fbSessionSpreadAddTemplatesHelper(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    char             *name,
    char             *description,
    GError           **err)
{
    int n;
    unsigned int group_offset;
    GHashTable *ttab;

    g_assert(tmpl);
    g_assert(tid == FB_TID_AUTO || tid >= FB_TID_MIN_DATA);
    g_assert(groups);
    g_assert(err);
    if (groups == NULL) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                    "No groups provided");
        return 0;
    }

    if (fBufGetExporter(session->tdyn_buf) && session->group > 0) {
        /* we are now going to multicast tmpls so we need to emit
           records currently in the buffer */
        if (!fBufEmit(session->tdyn_buf, err)) {
            return 0;
        }
    }

    /* Select a template table to add the template to */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    /* Handle an auto-template-id or an illegal ID */
    if (tid < FB_TID_MIN_DATA) {
        if (tid != FB_TID_AUTO) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Illegal template id %d", tid);
            return 0;
        }
        tid = fbSessionFindUnusedTemplateId(session, internal);
        if (0 == tid) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Template table is full, no IDs left");
            return 0;
        }
    }

    /* Update external template table per group; create if necessary. */
    for (n = 0; groups[n] != NULL; ++n) {
        group_offset = fbSessionGetGroupOffset(session, groups[n]);

        if (group_offset == 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                        "Spread Group Not Recognized.");
            return 0;
        }

        FB_SPREAD_MUTEX_LOCK(session);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab = g_hash_table_new(g_direct_hash,g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        FB_SPREAD_MUTEX_UNLOCK(session);
        g_hash_table_insert(session->grp_seqtab,
                            GUINT_TO_POINTER(session->group),
                            GUINT_TO_POINTER(session->sequence));

        /* Get new sequence number */
        session->sequence = GPOINTER_TO_UINT(
            g_hash_table_lookup(session->grp_seqtab,
                                GUINT_TO_POINTER(group_offset)));

        /* keep new group */
        session->group = group_offset;

        /* Revoke old template, ignoring missing template error. */
        if (!fbSessionRemoveTemplate(session, internal, tid, err)) {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                g_clear_error(err);
            } else {
                return 0;
            }
        }

        /* Insert template into table */
        if (!internal)
            FB_SPREAD_MUTEX_LOCK(session);

        g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);

        if (!internal)
            FB_SPREAD_MUTEX_UNLOCK(session);

        fbTemplateRetain(tmpl);

        if (internal) {
            /* we don't really multicast internal tmpls - we only have
             * one internal tmpl table - so once is enough */
            return tid;
        }
    }

    /* Now set session to group 1 before we multicast */
    group_offset = fbSessionGetGroupOffset(session, groups[0]);

    FB_SPREAD_MUTEX_LOCK(session);
    session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                            GUINT_TO_POINTER(group_offset));
    FB_SPREAD_MUTEX_UNLOCK(session);

    g_hash_table_insert(session->grp_seqtab, GUINT_TO_POINTER(session->group),
                        GUINT_TO_POINTER(session->sequence));

    /* Get sequence number - since it's the first group in list */
    session->sequence = GPOINTER_TO_UINT(
        g_hash_table_lookup(session->grp_seqtab,
                            GUINT_TO_POINTER(group_offset)));

    /* keep new group */
    session->group = group_offset;

    if (name && session->export_template_metadata) {
        fbTemplateAddMetadataRecord(tmpl, tid, name, description);
    }

    if (fBufGetExporter(session->tdyn_buf)) {
        fBufSetExportGroups(session->tdyn_buf, groups, n, NULL);
        if (name && !fbSessionWriteTemplateMetadata(session, tmpl, err)) {
            if (err && g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
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
    return fbSessionSpreadAddTemplatesHelper(
        session, groups, internal, tid, tmpl, NULL, NULL, err);
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
    if (!name) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_SETUP,
                    "Template name must be specified");
        return 0;
    }
    return fbSessionSpreadAddTemplatesHelper(
        session, groups, internal, tid, tmpl, name, description, err);
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
    GError *err = NULL;

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
        if (!fBufEmit(session->tdyn_buf, &err)) {
            g_warning("Could not emit buffer before setting group: %s",
                      err->message);
            g_clear_error(&err);
        }
    }
    /*Update external template table; create if necessary. */

    if (fBufGetExporter(session->tdyn_buf)) {
        /* Only need to do this for exporters */
        /* Collector's templates aren't managed per group */
        FB_SPREAD_MUTEX_LOCK(session);
        session->ext_ttab = g_hash_table_lookup(session->grp_ttab,
                                               GUINT_TO_POINTER(group_offset));

        if (!session->ext_ttab) {
            session->ext_ttab =g_hash_table_new(g_direct_hash, g_direct_equal);
            g_hash_table_insert(session->grp_ttab,
                                GUINT_TO_POINTER(group_offset),
                                session->ext_ttab);
        }

        FB_SPREAD_MUTEX_UNLOCK(session);
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

#endif  /* HAVE_SPREAD */


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
    return fbSessionAddTemplateHelper(session, internal, tid, tmpl,
                                      NULL, NULL, err);
}


/**
 *    Helper function for fbSessionAddTemplate() and
 *    fbSessionAddTemplateWithMetadata().
 */
static uint16_t fbSessionAddTemplateHelper(
    fbSession_t         *session,
    gboolean             internal,
    uint16_t             tid,
    fbTemplate_t         *tmpl,
    const char           *name,
    const char           *description,
    GError               **err)
{
    GHashTable *ttab;

    g_assert(tmpl);
    g_assert(tid == FB_TID_AUTO || tid >= FB_TID_MIN_DATA);
    g_assert(err);

    /* Select a template table to add the template to */
    ttab = internal ? session->int_ttab : session->ext_ttab;

    /* Handle an auto-template-id or an illegal ID */
    if (tid < FB_TID_MIN_DATA) {
        if (tid != FB_TID_AUTO) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Illegal template id %d", tid);
            return 0;
        }
        tid = fbSessionFindUnusedTemplateId(session, internal);
        if (0 == tid) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TMPL,
                        "Template table is full, no IDs left");
            return 0;
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

    if (name && session->export_template_metadata) {
        fbTemplateAddMetadataRecord(tmpl, tid, name, description);
    }

    /* Write template to dynamics buffer */
    if (fBufGetExporter(session->tdyn_buf) && !internal) {
        if (name && !fbSessionWriteTemplateMetadata(session, tmpl, err)) {
            if (err && g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
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
        FB_SPREAD_MUTEX_LOCK(session);
#endif
    g_hash_table_insert(ttab, GUINT_TO_POINTER((unsigned int)tid), tmpl);

    if (internal &&
        tmpl->ie_internal_len > session->largestInternalTemplateLength)
    {
        session->largestInternalTemplate = tmpl;
        session->largestInternalTemplateLength = tmpl->ie_internal_len;
    }

    if (internal) {
        session->intTmplTableChanged = TRUE;
    } else {
        session->extTmplTableChanged = TRUE;
    }

#if HAVE_SPREAD
    if (!internal)
        FB_SPREAD_MUTEX_UNLOCK(session);
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
        FB_SPREAD_MUTEX_LOCK(session);
#endif
    g_hash_table_remove(ttab, GUINT_TO_POINTER((unsigned int)tid));

    if (internal) {
        session->intTmplTableChanged = TRUE;
    } else {
        session->extTmplTableChanged = TRUE;
    }

    fbSessionRemoveTemplatePair(session, tid);

    fBufRemoveTemplateTcplan(session->tdyn_buf, tmpl);

    if (internal && session->largestInternalTemplate == tmpl) {
        session->largestInternalTemplate = NULL;
        session->largestInternalTemplateLength = 0;
        fbSessionSetLargestInternalTemplateLen(session);
    }

#if HAVE_SPREAD
    if (!internal)
        FB_SPREAD_MUTEX_UNLOCK(session);
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
        FB_SPREAD_MUTEX_LOCK(session);
#endif
    tmpl = g_hash_table_lookup(ttab, GUINT_TO_POINTER((unsigned int)tid));
#if HAVE_SPREAD
    if (!internal)
        FB_SPREAD_MUTEX_UNLOCK(session);
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
    }

    return tmpl;
}

gboolean        fbSessionExportTemplate(
    fbSession_t     *session,
    uint16_t        tid,
    GError          **err)
{
    fbTemplate_t    *tmpl = NULL;
    GError          *child_err = NULL;

    /* short-circuit on no template dynamics buffer */
    if (!fBufGetExporter(session->tdyn_buf))
        return TRUE;

    /* look up template */
    if (!(tmpl = fbSessionGetTemplate(session, FALSE, tid, err)))
        return FALSE;

    if (!fbSessionWriteTemplateMetadata(session, tmpl, &child_err)) {
        if (g_error_matches(child_err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
            g_clear_error(&child_err);
        } else {
            g_propagate_error(err, child_err);
            return FALSE;
        }
    }

    /* export it */
    return fBufAppendTemplate(session->tdyn_buf, tid, tmpl, FALSE, err);
}


/*
 *  Appends a single template metadata options record for 'tmpl' to
 *  the template dynamics buffer for 'session'.
 *
 *  This is a callback for g_hash_table_foreach() and is invoked by
 *  fbSessionExportTemplates().
 *
 *  This function assumes the internal and external template for the
 *  fBuf have been set to template_metadata_tid.
 */
static void fbSessionExportOneTemplateMetadataRecord(
    void            *vtid,
    fbTemplate_t    *tmpl,
    fbSession_t     *session)
{
    uint16_t        tid = (uint16_t)GPOINTER_TO_UINT(vtid);

    if (!tmpl->metadata_rec) {
        return;
    }

    /* The type/template metadata templates should have already been exported */
    if (tid == session->info_element_metadata_tid
        || tid == session->template_metadata_tid)
    {
        return;
    }

    if (fBufGetExporter(session->tdyn_buf) && !session->tdyn_err) {
        /* the internal and external template must be set on the fBuf
         * before using this function or everything will go to crap */
        if (!fBufAppend(session->tdyn_buf, (uint8_t *)tmpl->metadata_rec,
                        sizeof(fbTemplateOptRec_t), &session->tdyn_err))
        {
#if FB_DEBUG_MD
            fprintf(stderr, "fBufAppend(%p) failed: %s\n",
                    (void *)tmpl->metadata_rec,
                    (session->tdyn_err ? session->tdyn_err->message : ""));
#endif
            if (!session->tdyn_err) {
                g_set_error(&session->tdyn_err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "Unspecified template export error");
            }
        }
    }
}


/*
 *  Appends a single template record for 'tmpl' to the template
 *  dynamics buffer for 'session'.
 *
 *  This is a callback for g_hash_table_foreach() and is invoked by
 *  fbSessionExportTemplates().
 */
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

    /* fprintf(stderr, "fbSessionExportOneTemplate(%#x, %p)\n", tid, tmpl); */
    if (fBufGetExporter(session->tdyn_buf) && !session->tdyn_err) {
        if (!fBufAppendTemplate(session->tdyn_buf, tid, tmpl,
                                FALSE, &session->tdyn_err))
        {
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
    uint16_t int_tid;
    uint16_t ext_tid;
    GError *child_err = NULL;
    gboolean ret = TRUE;

    /* require an exporter */
    if (!fBufGetExporter(session->tdyn_buf))
        return TRUE;

    int_tid = fBufGetInternalTemplate(session->tdyn_buf);
    ext_tid = fBufGetExportTemplate(session->tdyn_buf);

    if (session->export_info_element_metadata) {
#if FB_DEBUG_MD
        fprintf(stderr, "Exporting info element metadata; template %#x\n",
                session->info_element_metadata_tid);
#endif
        if (!fbSessionExportTemplate(
                session, session->info_element_metadata_tid, err))
        {
#if FB_DEBUG_MD
            fprintf(stderr, "fbSessionExportTemplate(%#x) failed: %s\n",
                    session->info_element_metadata_tid,
                    (err ? (*err)->message : ""));
#endif
            ret = FALSE;
            goto END;
        }
        if (!fbSessionWriteTypeMetadata(session, err)) {
            ret = FALSE;
            goto END;
        }
    }

    if (session->export_template_metadata) {
#if FB_DEBUG_MD
        fprintf(stderr, "Exporting template metadata; template %#x\n",
                session->template_metadata_tid);
#endif
        if (!fbSessionExportTemplate(
                session, session->template_metadata_tid, err))
        {
#if FB_DEBUG_MD
            fprintf(stderr, "fbSessionExportTemplate(%#x) failed: %s\n",
                    session->template_metadata_tid,
                    (err ? (*err)->message : ""));
#endif
            ret = FALSE;
            goto END;
        }
        if (session->ext_ttab && fBufGetExporter(session->tdyn_buf)) {
            if (!fBufSetInternalTemplate(session->tdyn_buf,
                                         session->template_metadata_tid,
                                         &child_err))
            {
#if FB_DEBUG_MD
                fprintf(stderr, "fBufSetInternalTemplate(%#x) failed: %s\n",
                        session->template_metadata_tid, child_err->message);
#endif
                if (g_error_matches(child_err, FB_ERROR_DOMAIN,FB_ERROR_TMPL)){
                    g_clear_error(&child_err);
                }
            } else if (!fBufSetExportTemplate(session->tdyn_buf,
                                              session->template_metadata_tid,
                                              &child_err))
            {
#if FB_DEBUG_MD
                fprintf(stderr, "fBufSetExportTemplate(%#x) failed: %s\n",
                        session->template_metadata_tid, child_err->message);
#endif
                if (g_error_matches(child_err, FB_ERROR_DOMAIN,FB_ERROR_TMPL)){
                    g_clear_error(&child_err);
                }
            } else {
                FB_SPREAD_MUTEX_LOCK(session);
                /* the fbufsetinternal/fbufsetexport template functions
                 * can't occur in the GHFunc since pthread_mutex_lock has
                 * already been called and fBufSetExportTemplate will call
                 * fbSessionGetTemplate which will try to acquire lock */
                g_clear_error(&session->tdyn_err);
                g_hash_table_foreach(
                    session->ext_ttab,
                    (GHFunc)fbSessionExportOneTemplateMetadataRecord, session);
                if (session->tdyn_err) {
                    g_propagate_error(&child_err, session->tdyn_err);
                    session->tdyn_err = NULL;
                }
                FB_SPREAD_MUTEX_UNLOCK(session);
            }
            if (child_err) {
                g_propagate_error(err, child_err);
                child_err = NULL;
                ret = FALSE;
                goto END;
            }
        }
    }

    FB_SPREAD_MUTEX_LOCK(session);
    if (session->ext_ttab) {
        g_clear_error(&session->tdyn_err);
        g_hash_table_foreach(session->ext_ttab,
                             (GHFunc)fbSessionExportOneTemplate, session);
        if (session->tdyn_err) {
            g_propagate_error(err, session->tdyn_err);
            session->tdyn_err = NULL;
            ret = FALSE;
        }
    }
    FB_SPREAD_MUTEX_UNLOCK(session);

  END:
    if (int_tid
        && !fBufSetInternalTemplate(session->tdyn_buf, int_tid, &child_err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "restore fBufSetInternalTemplate(%#x) failed: %s\n",
                int_tid, child_err->message);
#endif
        g_clear_error(&child_err);
    }
    if (ext_tid
        && !fBufSetExportTemplate(session->tdyn_buf, ext_tid, &child_err))
    {
#if FB_DEBUG_MD
        fprintf(stderr, "restore fBufSetExportTemplate(%#x) failed: %s\n",
                ext_tid, child_err->message);
#endif
        g_clear_error(&child_err);
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

    if (!fbSessionAddTemplateHelper(session, TRUE, tid, tmpl, NULL,NULL,&err)) {
        g_warning("Session clone internal template copy failed: %s",
                  err->message);
        g_clear_error(&err);
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
    session->intTmplTableChanged = FALSE;
}

void fbSessionClearExtTmplTableFlag(
    fbSession_t        *session)
{
    session->extTmplTableChanged = FALSE;
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

uint16_t            fbSessionGetLargestInternalTemplateSize(
    fbSession_t        *session)
{
    if (!session->largestInternalTemplateLength) {
        fbSessionSetLargestInternalTemplateLen(session);
    }

    return session->largestInternalTemplateLength;
}

/* Callback function used when scanning the hash table of internal
 * templates. */
static void fbSessionCheckTmplLengthForMax(
    gpointer    key_in,
    gpointer    value_in,
    gpointer    user_value)
{
    /* uint16_t        tid     = GPOINTER_TO_UINT(key_in); */
    fbTemplate_t   *tmpl    = (fbTemplate_t*)value_in;
    fbSession_t    *session = (fbSession_t*)user_value;
    (void)key_in;

    if (tmpl->ie_internal_len > session->largestInternalTemplateLength) {
        session->largestInternalTemplateLength  = tmpl->ie_internal_len;
        session->largestInternalTemplate        = tmpl;
    }
}

static void fbSessionSetLargestInternalTemplateLen(
    fbSession_t    *session)
{
    if (!session || !session->int_ttab) {
        return;
    }
    g_hash_table_foreach(session->int_ttab, fbSessionCheckTmplLengthForMax,
                         session);
}


