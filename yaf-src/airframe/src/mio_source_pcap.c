/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_pcap.c
 *  Multiple I/O pcap source, from files, directories, or live capture
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#define _AIRFRAME_SOURCE_
#include "mio_internal.h"
#include <airframe/mio_source_pcap.h>

#if HAVE_LIBPCAP

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


static char mio_pcap_errbuf[PCAP_ERRBUF_SIZE];

static gboolean
mio_source_next_pcap_offline(
    MIOSourceFn   source_next_file,
    MIOSourceFn   source_close_file,
    MIOSource    *source,
    uint32_t     *flags,
    GError      **err)
{
    MIOSourcePCapFileConfig *cfg = (MIOSourcePCapFileConfig *)source->cfg;
    GError            *cerr = NULL;
    gboolean           ok = TRUE;
    pcap_t            *pcap = NULL;
    struct bpf_program bpf;

    /* Fake vsp type to NULL */
    source->vsp_type = MIO_T_NULL;

    /* Get next filename into name */
    ok = source_next_file(source, flags, err);

    /* fail on file open error */
    if (!ok) {goto end;}

    /* Okay. We have a filename and we own it. Open it as a pcap context. */
    pcap = pcap_open_offline(source->name, mio_pcap_errbuf);

    /* check for pcap open error */
    if (!pcap) {
        ok = FALSE;
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                    "couldn't open pcap file %s: %s",
                    source->name, mio_pcap_errbuf);
        goto errfile;
    }

    /* attach filter */
    if (cfg->filter) {
        if (pcap_compile(pcap, &bpf, cfg->filter, 1, 0) < 0) {
            ok = FALSE;
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "couldn't compile BPF expression %s: %s",
                        cfg->filter, pcap_geterr(pcap));
            goto errbpf;
        }
        pcap_setfilter(pcap, &bpf);
        pcap_freecode(&bpf);
    }

    /* stuff pcap context into vsp */
    source->vsp = pcap;

    goto end;

  errbpf:
    /* close pcap context */
    pcap_close(pcap);

  errfile:
    /* set fatal error flag */
    *flags |= MIO_F_CTL_ERROR;

    /* close file */
    if (!source_close_file(source, flags, &cerr)) {
        g_clear_error(err);
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                    "couldn't close pcap file after pcap error %s: %s",
                    mio_pcap_errbuf, cerr->message);
        g_clear_error(&cerr);
    }

  end:
    /* Restore vsp type */
    source->vsp_type = MIO_T_PCAP;

    return ok;
}


static gboolean
mio_source_next_pcap_file_dir(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_next_pcap_offline(mio_source_next_file_dir,
                                        mio_source_close_file,
                                        source, flags, err);
}


static gboolean
mio_source_next_pcap_file_glob(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_next_pcap_offline(mio_source_next_file_glob,
                                        mio_source_close_file,
                                        source, flags, err);
}


static gboolean
mio_source_next_pcap_file_single(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_next_pcap_offline(mio_source_next_file_single,
                                        mio_source_close_file,
                                        source, flags, err);
}


static gboolean
mio_source_next_pcap_stdin(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_next_pcap_offline(mio_source_check_stdin,
                                        mio_source_close_stdin,
                                        source, flags, err);
}


static gboolean
mio_source_next_pcap_live(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourcePCapLiveConfig *cfg = (MIOSourcePCapLiveConfig *)source->cfg;
    pcap_t *pcap = NULL;
    struct bpf_program       bpf;

    /* Go ahead and stash the name */
    source->name = source->spec;

    pcap = pcap_open_live(source->name, cfg->snaplen, 1,
                          cfg->timeout, mio_pcap_errbuf);

    /* check for pcap open error */
    if (!pcap) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                    "couldn't open pcap interface %s: %s",
                    source->name, mio_pcap_errbuf);
        goto errcap;
    }

    /* attach filter */
    if (cfg->filter) {
        if (pcap_compile(pcap, &bpf, cfg->filter, 1, 0) < 0) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                        "couldn't compile BPF expression %s: %s",
                        cfg->filter, pcap_geterr(pcap));
            goto errbpf;
        }
        pcap_setfilter(pcap, &bpf);
        pcap_freecode(&bpf);
    }

    /* stuff pcap context into vsp */
    source->vsp = pcap;

    return TRUE;

  errbpf:
    /* close context */
    pcap_close(pcap);

  errcap:
    /* bug out. die if we can't open the interface. */
    *flags |= (MIO_F_CTL_ERROR | MIO_F_CTL_TERMINATE);
    return FALSE;
}


static gboolean
mio_source_close_pcap_offline(
    MIOSourceFn   source_close_file,
    MIOSource    *source,
    uint32_t     *flags,
    GError      **err)
{
    gboolean ok;

    /* close down pcap context */
    pcap_close((pcap_t *)source->vsp);

    /* Fake vsp type to NULL */
    source->vsp_type = MIO_T_NULL;

    /* Close file */
    ok = source_close_file(source, flags, err);

    /* Restore vsp type */
    source->vsp_type = MIO_T_PCAP;

    return ok;
}


static gboolean
mio_source_close_pcap_file(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_close_pcap_offline(
        mio_source_close_file, source, flags, err);
}


static gboolean
mio_source_close_pcap_stdin(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    return mio_source_close_pcap_offline(
        mio_source_close_stdin, source, flags, err);
}


static gboolean
mio_source_close_pcap_live(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    /* close down pcap context */
    pcap_close((pcap_t *)source->vsp);

    return TRUE;
}


static gboolean
mio_source_init_pcap_inner(
    MIOSource        *source,
    const char       *spec,
    MIOType           vsp_type,
    void             *cfg,
    MIOSourceFn       next_source,
    MIOSourceFn       close_source,
    MIOSourceFreeFn   free_source,
    GError          **err)
{
    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_PCAP;}

    /* initialize file source */
    source->spec = g_strdup(spec);
    source->name = NULL;
    source->vsp_type = vsp_type;
    source->vsp = NULL;
    source->ctx = NULL;
    source->cfg = cfg;
    source->next_source = next_source;
    source->close_source = close_source;
    source->free_source = free_source;
    source->opened = FALSE;
    source->active = FALSE;

    /* Ensure type is valid */
    if (vsp_type != MIO_T_PCAP) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot create pcap source: type mismatch");
        return FALSE;
    }

    return TRUE;
}


gboolean
mio_source_init_pcap_dir(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* check that specifier is an accessible directory */
    if (!g_file_test(spec, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier %s is not a directory", spec);
        return FALSE;
    }

    /* initialize source */
    return mio_source_init_pcap_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_pcap_file_dir,
                                      mio_source_close_pcap_file,
                                      mio_source_free_file, err);
}


gboolean
mio_source_init_pcap_glob(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* failover to single */
    if (!strchr(spec, '*') && !strchr(spec, '?') && !strchr(spec, '[')) {
        return mio_source_init_pcap_single(source, spec, vsp_type, cfg, err);
    }

    /* initialize source */
    return mio_source_init_pcap_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_pcap_file_glob,
                                      mio_source_close_pcap_file,
                                      mio_source_free_file, err);
}


gboolean
mio_source_init_pcap_single(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* failover to stdin */
    if (!strcmp(spec, "-")) {
        return mio_source_init_pcap_stdin(source, spec, vsp_type, cfg, err);
    }

    /* initialize source */
    return mio_source_init_pcap_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_pcap_file_single,
                                      mio_source_close_pcap_file,
                                      mio_source_free_file, err);
}


gboolean
mio_source_init_pcap_stdin(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    gboolean ok = TRUE;

    /* initialize source */
    ok = mio_source_init_pcap_inner(source, spec, vsp_type, cfg,
                                    mio_source_next_pcap_stdin,
                                    mio_source_close_pcap_stdin,
                                    mio_source_free_file, err);
    if (!ok) {return ok;}

    /* reflect the fact that stdin is already open */
    source->name = C("-");

    return TRUE;
}


gboolean
mio_source_init_pcap_live(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* initialize source */
    return mio_source_init_pcap_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_pcap_live,
                                      mio_source_close_pcap_live,
                                      NULL, err);
}


#else /* if HAVE_LIBCAP */
gboolean
mio_source_init_pcap_dir(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IMPL,
                "libairframe was built without libpcap support");
    return FALSE;
}


gboolean
mio_source_init_pcap_glob(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IMPL,
                "libairframe was built without libpcap support");
    return FALSE;
}


gboolean
mio_source_init_pcap_single(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IMPL,
                "libairframe was built without libpcap support");
    return FALSE;
}


gboolean
mio_source_init_pcap_stdin(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IMPL,
                "libairframe was built without libpcap support");
    return FALSE;
}


gboolean
mio_source_init_pcap_live(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IMPL,
                "libairframe was built without libpcap support");
    return FALSE;
}


#endif /* if HAVE_LIBPCAP */
