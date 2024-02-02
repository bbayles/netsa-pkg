/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_sink_file.c
 *  Multiple I/O regular file sink, by pattern.
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
#include <airframe/mio_sink_file.h>
#include <airframe/mio_stdio.h>
#include <airframe/airutil.h>

typedef struct _MIOSinkFileContext {
    GString  *scratch;
    char     *lpath;
    int       lfd;
} MIOSinkFileContext;

static gboolean
mio_sink_open_file(
    MIOSink   *sink,
    uint32_t  *flags,
    GError   **err)
{
    MIOSinkFileContext *fx = (MIOSinkFileContext *)sink->ctx;
    int fd;

    /* Attempt lock */
    if (*flags & MIO_F_OPT_LOCK) {
        /* Generate lock path */
        if (!fx->scratch) {fx->scratch = g_string_new(NULL);}
        g_string_printf(fx->scratch, "%s.lock", sink->name);
        fx->lpath = g_strdup(fx->scratch->str);
        /* Open lock file */
        fx->lfd = open(fx->lpath, O_WRONLY | O_CREAT | O_EXCL, 0664);
        if (fx->lfd < 0) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_LOCK,
                        "Cannot lock output file %s: %s",
                        sink->name, strerror(errno));
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }
    }

    /* Open the file if necessary */
    if (sink->vsp_type != MIO_T_NULL) {
        /* Not a null type sink. Open the file. */
        fd = open(sink->name, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd < 0) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_LOCK,
                        "Cannot open output file %s: %s",
                        sink->name, strerror(errno));
            *flags |= MIO_F_CTL_ERROR;
            if (fx->lpath) {unlink(fx->lpath);}
            return FALSE;
        }

        /* Determine how to store opened file */
        if (sink->vsp_type == MIO_T_FP) {
            /* As file handle. fdopen should never fail here. */
            sink->vsp = fdopen(fd, "w");
            g_assert(sink->vsp);
        } else {
            /* As file descriptor. Yay Casting! */
            sink->vsp = GINT_TO_POINTER(fd);
        }
    }

    return TRUE;
}


static gboolean
mio_sink_next_file_single(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    /* Name and spec are identical */
    sink->name = g_strdup(sink->spec);

    /* Open the file */
    return mio_sink_open_file(sink, flags, err);
}


static void
mio_sink_file_pattern_decname(
    char  *srcname,
    char **decname,
    char **dirname,
    char **basename,
    char **extname)
{
    if (srcname) {
        *decname = g_strdup(srcname);

        if ((*extname = strrchr(*decname, '.'))) {
            **extname = (char)0;
            (*extname)++;
        } else {
            *extname = NULL;
        }

        if ((*basename = strrchr(*decname, '/'))) {
            **basename = (char)0;
            (*basename)++;
            *dirname = *decname;
        } else {
            *dirname = NULL;
            *basename = *decname;
        }
    } else {
        *decname = g_strdup(".");
        *dirname = *decname;
        *basename = *decname + 1;
        *extname = NULL;
    }
}


static void
mio_sink_file_pattern_to_name(
    MIOSource  *source,
    MIOSink    *sink)
{
    MIOSinkFileContext *fx = (MIOSinkFileContext *)sink->ctx;
    MIOSinkFileConfig  *cfg = (MIOSinkFileConfig *)sink->cfg;
    char *cp = NULL, *decname = NULL,
         *dirname = NULL, *basename = NULL, *extname = NULL;

    /* ensure we have an empty scratch string */
    if (fx->scratch) {
        g_string_truncate(fx->scratch, 0);
    } else {
        fx->scratch = g_string_new(NULL);
    }

    /* iterate over characters in the sink specifier */
    for (cp = sink->spec; *cp; cp++) {
        if (*cp == '%') {
            /* Percent character. Determine what to append based on next. */
            cp++;
            switch (*cp) {
              case (char)0:
                /* Append literal percent for percent at EOS. */
                cp--;
              /* FALLTHROUGH */
              case '%':
                /* %% -> literal percent character. */
                g_string_append_c(fx->scratch, '%');
                break;
              case 'T':
                /* %T -> timestamp */
                air_time_g_string_append(fx->scratch, time(NULL),
                                         AIR_TIME_SQUISHED);
                break;
              case 'S':
                /* %S -> autoincrementing serial number */
                g_string_append_printf(fx->scratch, "%u", cfg->next_serial++);
                break;
              case 'X':
                /* %X -> autoincrementing serial number in hex */
                g_string_append_printf(fx->scratch, "%08x", cfg->next_serial++);
                break;
              case 'd':
                /* %d -> source directory name */
                if (!decname) {
                    mio_sink_file_pattern_decname(source->name, &decname,
                                                  &dirname, &basename,
                                                  &extname);
                }
                if (dirname) {
                    g_string_append_printf(fx->scratch, "%s", dirname);
                } else {
                    /* no dirname - source in cwd */
                    g_string_append_printf(fx->scratch, ".");
                }
                break;
              case 's':
                /* %s -> source basename */
                if (!decname) {
                    mio_sink_file_pattern_decname(source->name, &decname,
                                                  &dirname, &basename,
                                                  &extname);
                }
                if (basename) {
                    g_string_append_printf(fx->scratch, "%s", basename);
                }
                break;
              case 'e':
                /* %e -> source extension */
                if (!decname) {
                    mio_sink_file_pattern_decname(source->name, &decname,
                                                  &dirname, &basename,
                                                  &extname);
                }
                if (extname) {
                    g_string_append_printf(fx->scratch, "%s", extname);
                }

                break;
              default:
                /* eat unknown % patterns */
                break;
            }
        } else {
            /* Normal character. Copy it. */
            g_string_append_c(fx->scratch, *cp);
        }
    }

    /* Clean up decname */
    if (decname) {g_free(decname);}

    /* Copy pattern-generated name to sink */
    sink->name = g_strdup(fx->scratch->str);
}


static gboolean
mio_sink_next_file_pattern(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    /* Generate name based on pattern */
    mio_sink_file_pattern_to_name(source, sink);

    /* Open the file */
    return mio_sink_open_file(sink, flags, err);
}


#define MIO_CLOSE_FILE_ERROR(_action_)                                   \
    {                                                                    \
        ok = FALSE;                                                      \
        if (!errstr) errstr = g_string_new ("I/O error on close:");      \
        g_string_append_printf(errstr, "\nfailed to %s %s: %s",          \
                               (_action_), sink->name, strerror(errno)); \
    }

static gboolean
mio_sink_close_file(
    MIOSource  *source,
    MIOSink    *sink,
    uint32_t   *flags,
    GError    **err)
{
    MIOSinkFileContext *fx = (MIOSinkFileContext *)sink->ctx;
    gboolean            ok = TRUE;
    GString            *errstr = NULL;

    /* Close file pointer or file descriptor as necessary */
    if (sink->vsp_type == MIO_T_FP) {
        if (fclose((FILE *)sink->vsp) < 0) {
            MIO_CLOSE_FILE_ERROR("close");
        }
    } else if (sink->vsp_type == MIO_T_FD) {
        if (close(GPOINTER_TO_INT(sink->vsp)) < 0) {
            MIO_CLOSE_FILE_ERROR("close");
        }
    }

    /* Delete output file on any error */
    if (*flags & (MIO_F_CTL_ERROR | MIO_F_CTL_TRANSIENT)) {
        if (unlink(sink->name) < 0) {
            MIO_CLOSE_FILE_ERROR("delete");
        }
    }

    /* Unlock file */
    if (fx->lfd) {
        close(fx->lfd);
    }
    if (fx->lpath) {unlink(fx->lpath);}

    /* Clear file */
    if (fx->lpath) {
        g_free(fx->lpath);
        fx->lpath = NULL;
    }
    if (sink->name) {
        g_free(sink->name);
        sink->name = NULL;
    }
    sink->vsp = NULL;

    /* Handle error */
    if (!ok) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO, "%s", errstr->str);
        g_string_free(errstr, TRUE);
        *flags |= MIO_F_CTL_ERROR;
    }

    /* all done */
    return ok;
}


static void
mio_sink_free_file(
    MIOSink  *sink)
{
    MIOSinkFileContext *fx = (MIOSinkFileContext *)sink->ctx;

    if (sink->spec) {g_free(sink->spec);}

    if (fx) {
        if (fx->scratch) {g_string_free(fx->scratch, TRUE);}
        g_free(fx);
    }
}


static gboolean
mio_sink_init_file_inner(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    MIOSinkFn    next_sink,
    gboolean     iterative,
    GError     **err)
{
    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_FP;}

    /* Ensure type is valid */
    if (!(vsp_type == MIO_T_NULL ||
          vsp_type == MIO_T_FD ||
          vsp_type == MIO_T_FP))
    {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open file sink: type mismatch");
        return FALSE;
    }

    /* initialize sink */
    sink->spec = g_strdup(spec);
    sink->name = NULL;
    sink->vsp_type = vsp_type;
    sink->vsp = NULL;
    sink->ctx = g_new0(MIOSinkFileContext, 1);
    sink->cfg = cfg;
    sink->next_sink = next_sink;
    sink->close_sink = mio_sink_close_file;
    sink->free_sink = mio_sink_free_file;
    sink->opened = FALSE;
    sink->active = FALSE;
    sink->iterative = iterative;

    return TRUE;
}


gboolean
mio_sink_init_file_pattern(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Sink specifier is empty");
        return FALSE;
    }

    /* failover to single */
    if (!strchr(spec, '%')) {
        return mio_sink_init_file_single(sink, spec, vsp_type, cfg, err);
    }

    return mio_sink_init_file_inner(sink, spec, vsp_type, cfg,
                                    mio_sink_next_file_pattern, TRUE, err);
}


gboolean
mio_sink_init_file_single(
    MIOSink     *sink,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Sink specifier is empty");
        return FALSE;
    }

    /* failover to stdout */
    if (!strcmp(spec, "-")) {
        return mio_sink_init_stdout(sink, spec, vsp_type, cfg, err);
    }

    return mio_sink_init_file_inner(sink, spec, vsp_type, cfg,
                                    mio_sink_next_file_single, FALSE, err);
}
