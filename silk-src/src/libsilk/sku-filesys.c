/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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

/*
**  sku-filesys.c
**
**    A collection of utility routines dealing with the file system.
**
**    Suresh L Konda
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sku-filesys.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>


/* DEFINES AND TYPEDEFS */

/* Maximum size to attempt to mmap at a time */
#define DEFAULT_MAX_MMAPSIZE ((size_t)1 << 26)


/* FUNCTION DEFINITIONS */

char *
skBasename_r(
    char               *dest,
    const char         *src,
    size_t              dest_size)
{
    const char *startp;
    const char *endp;
    size_t src_len;

    /* check input: need space for {'.', '\0'} minimally */
    if (!dest || dest_size < 2) {
        return NULL;
    }

    /* degenerate cases */
    if (!src || (0 == (src_len = strlen(src)))) {
        return strncpy(dest, ".", 2);
    }

    startp = strrchr(src, '/');
    if (!startp) {
        /* no slash; return what we were given */
        startp = src;
        endp = src + src_len;
    } else if ('\0' != *(startp+1)) {
        /* typical case: "/bin/cat" */
        ++startp;
        endp = src + src_len;
    } else {
        /* we could have "/", "///", "usr/", or "/usr/lib/" */
        while (startp > src && *startp == '/') {
            /* remove trailing '/' */
            --startp;
        }
        endp = startp + 1;
        /* go backward until find '/'; startp is char after the '/' */
        while (startp > src) {
            --startp;
            if (*startp == '/') {
                ++startp;
                break;
            }
        }
    }

    /* need to grab everything between startp and endp */
    src_len = endp - startp;
    if (src_len > dest_size-1) {
        return NULL;
    }
    strncpy(dest, startp, src_len);
    dest[src_len] = '\0';

    return dest;
}


char *
skDirname_r(
    char               *dest,
    const char         *src,
    size_t              dest_size)
{
    const char *endp;
    size_t src_len;

    /* check input: need space for {'.', '\0'} minimally */
    if (!dest || dest_size < 2) {
        return NULL;
    }

    /* degenerate cases */
    if (!src || !(endp = strrchr(src, '/'))) {
        return strncpy(dest, ".", 2);
    }

    if ('\0' == *(endp+1)) {
        /* we could have "/", "///", "usr/", or "/usr/lib/" */
        while (endp > src && *endp == '/') {
            /* remove trailing '/' */
            --endp;
        }
        while (endp > src && *endp != '/') {
            /* skip basename */
            --endp;
        }
        if (*endp != '/') {
            /* we're at start of string */
            return strncpy(dest, ".", 2);
        }
    }

    /* handle duplicate '/' chars */
    while (endp > src && *endp == '/') {
        --endp;
    }

    src_len = endp - src + 1;
    if (src_len > dest_size-1) {
        return NULL;
    }

    strncpy(dest, src, src_len);
    dest[src_len] = '\0';

    return dest;
}


char *
skBasename(
    const char         *src)
{
    static char dest[PATH_MAX]; /* return pointer */

    return skBasename_r(dest, src, sizeof(dest));
}


char *
skDirname(
    const char         *src)
{
    static char dest[PATH_MAX]; /* return pointer */

    return skDirname_r(dest, src, sizeof(dest));
}


int
isFIFO(
    const char         *name)
{
    struct stat stBuf;
    if (stat(name, &stBuf) == -1) {
        return 0;
    }
    return (S_ISFIFO(stBuf.st_mode));
}


int
skDirExists(
    const char         *dName)
{
    struct stat stBuf;
    if (stat(dName, &stBuf) == -1) {
        return 0;                   /* does not exist */
    }
    /* return a 1 only if this is a directory */
    return S_ISDIR(stBuf.st_mode);
}


int
skFileExists(
    const char         *fName)
{
    struct stat stBuf;
    if (stat(fName, &stBuf) == -1) {
        return 0;                   /* does not exist */
    }
    /* return a 1 only if this is a regular file */
    return (S_ISREG(stBuf.st_mode) || S_ISFIFO(stBuf.st_mode));
}


off_t
skFileSize(
    const char         *fName)
{
    struct stat stBuf;
    if (stat(fName, &stBuf) == -1) {
        return 0;                   /* does not exist */
    }
    /* it exists. return the size */
    return stBuf.st_size;
}


/*
 *    Lock or unlock the file 'fd'.  See header for details.
 */
int
skFileSetLock(
    int                 fd,
    short               type,
    int                 cmd)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = 0;             /* at SOF */
    lock.l_whence = SEEK_SET;     /* SOF */
    lock.l_len = 0;               /* EOF */

    if (fcntl(fd, cmd, &lock) != -1) {
        /* success */
        return 0;
    }

    return -1;
}


/* Find the file 'base_name' and return its full path in 'buf'.  See
 * the header for details. */
char *
skFindFile(
    const char         *base_name,
    char               *buf,
    size_t              bufsize,
    int                 verbose)
{
    const char *app_name = skAppName();
    char *silkpath = getenv(ENV_SILK_PATH);
    size_t len = 0;
    int rv;

    /* check inputs */
    if (!base_name || !buf || bufsize <= 1) {
        return NULL;
    }

    /* if base_name begins with a slash, use it */
    if (base_name[0] == '/') {
        strncpy(buf, base_name, bufsize);
        buf[bufsize - 1] = '\0';
        return buf;
    }

    /* Check in $SILK_PATH/share/silk and $SILK_PATH/share */
    if (silkpath) {
        rv = snprintf(buf, bufsize, "%s/share/silk/%s", silkpath, base_name);
        if ((size_t)rv < bufsize && skFileExists(buf)) {
            return buf;
        }
        rv = snprintf(buf, bufsize, "%s/share/%s", silkpath, base_name);
        if ((size_t)rv < bufsize && skFileExists(buf)) {
            return buf;
        }
    }

    /* Look in binarypath/../share.  First, get the parent directory of
     * the executable and store in 'buf'. */
    if (app_name == (char *)NULL) {
        goto ERROR;
    }
    if (NULL == skAppDirParentDir(buf, bufsize)) {
        buf[0] = '\0';
        goto ERROR;
    }
    len = strlen(buf);

    /* Now append "/share/silk/<file>" to it */
    rv = snprintf((buf+len), (bufsize - len - 1), "/share/silk/%s", base_name);
    if ((size_t)rv < bufsize && skFileExists(buf)) {
        return buf;
    }

    /* Try appending "/share/<file>" to it */
    rv = snprintf((buf+len), (bufsize - len - 1), "/share/%s", base_name);
    if ((size_t)rv < bufsize && skFileExists(buf)) {
        return buf;
    }

  ERROR:
    if (verbose) {
#define ERR_MSG                                                        \
    "Cannot find file '%s' in $" ENV_SILK_PATH "/share/silk/,\n"       \
    "\tin $" ENV_SILK_PATH "/share/, in $" ENV_SILK_PATH "/, "

        if (!app_name) {
            skAppPrintErr((ERR_MSG "and application not registered"),
                          base_name);
        }
        else if ('\0' == buf[0]) {
            skAppPrintErr((ERR_MSG "and cannot obtain full path to\n"
                           "\tthe application '%s'"),
                          base_name, app_name);
        }
        else {
            buf[len] = '\0';
            skAppPrintErr((ERR_MSG "nor in the share/silk/ and share/\n"
                           "\tsubdirectories under %s/"),
                          base_name, buf);
        }
#undef ERR_MSG
    }

    return NULL;
}


char *
skFindPluginPath(
    const char         *dlPath,
    char               *path,
    size_t              path_size,
    const char         *verbose_prefix)
{
#ifndef SILK_SUBDIR_PLUGINS
    return NULL;
#else
    const char *subdir[] = SILK_SUBDIR_PLUGINS;
    char *silkPath;
    size_t len;
    int i;
    int8_t checkSilkPath = 1;
    int8_t checkExec = 1;

    /* put path into known state */
    path[0] = '\0';

    if (strchr(dlPath, '/')) {
        return NULL;
    }

    /* if dlPath does not contain a slash, first look for the plugin in
     * the SILK_SUBDIR_PLUGINS subdirectory of the environment variable
     * named by ENV_SILK_PATH.  If the plugin does not exist there, pass
     * the dlPath as given to dlopen() which will use LD_LIBRARY_PATH or
     * equivalent.
     */
    while (checkSilkPath || checkExec) {
        if (checkSilkPath) {
            checkSilkPath = 0;
            if (NULL == (silkPath = getenv(ENV_SILK_PATH))) {
                continue;
            }
            strncpy(path, silkPath, path_size);
        } else if (checkExec) {
            checkExec = 0;
            if (NULL == skAppDirParentDir(path, path_size)) {
                /* cannot find executeable path */
                continue;
            }
        }
        path[path_size-1] = '\0';
        len = strlen(path);
        for (i = 0; subdir[i]; ++i) {
            snprintf(path + len, path_size - len - 1, "/%s/%s",
                     subdir[i], dlPath);
            path[path_size-1] = '\0';
            if (verbose_prefix) {
                skAppPrintErr("%s%s", verbose_prefix, path);
            }
            if (skFileExists(path)) {
                return path;
            }
        }
    }

    /* file does not exist.  Fall back to LD_LIBRARY_PATH */
    path[0] = '\0';
    return NULL;
#endif /* SILK_SUBDIR_PLUGINS */
}


/* open a file, stream, or process */
int
skFileptrOpen(
    sk_fileptr_t       *file,
    skstream_mode_t     io_mode)
{
#ifdef SILK_CLOBBER_ENVAR
    const char *clobber_env;
#endif
    char gzip_cmd[16 + PATH_MAX];
    const char *gzip_mode;
    const char *fopen_mode;
    struct stat stbuf;
    size_t len;
    int flags;
    int mode;
    int fd;
    int rv;

    assert(file);
    if (NULL == file->of_name) {
        return SK_FILEPTR_ERR_INVALID;
    }
    switch (io_mode) {
      case SK_IO_READ:
      case SK_IO_WRITE:
      case SK_IO_APPEND:
        break;
      default:
        return SK_FILEPTR_ERR_INVALID; /* NOTREACHED */
    }

    /* handle stdio */
    if (0 == strcmp(file->of_name, "-")) {
        file->of_type = SK_FILEPTR_IS_STDIO;
        switch (io_mode) {
          case SK_IO_READ:
            file->of_fp = stdin;
            return 0;

          case SK_IO_WRITE:
          case SK_IO_APPEND:
            file->of_fp = stdout;
            return 0;
        }
    }
    if (0 == strcmp(file->of_name, "stdin")) {
        if (SK_IO_READ == io_mode) {
            file->of_fp = stdin;
            file->of_type = SK_FILEPTR_IS_STDIO;
            return 0;
        }
        return SK_FILEPTR_ERR_WRITE_STDIN;
    }
    if (0 == strcmp(file->of_name, "stdout")) {
        if (SK_IO_READ == io_mode) {
            return SK_FILEPTR_ERR_READ_STDOUT;
        }
        file->of_fp = stdout;
        file->of_type = SK_FILEPTR_IS_STDIO;
        return 0;
    }
    if (0 == strcmp(file->of_name, "stderr")) {
        if (SK_IO_READ == io_mode) {
            return SK_FILEPTR_ERR_READ_STDERR;
        }
        file->of_fp = stderr;
        file->of_type = SK_FILEPTR_IS_STDIO;
        return 0;
    }

    /* check whether file->of_name indicates file is compressed */
    len = strlen(file->of_name);
    if (len > 3 && 0 == strcmp(&file->of_name[len-3], ".gz")) {
        switch (io_mode) {
          case SK_IO_READ:
            gzip_mode = "-d";
            fopen_mode = "r";
            break;
          case SK_IO_WRITE:
            if (skFileExists(file->of_name)) {
#ifdef SILK_CLOBBER_ENVAR
                if ((clobber_env = getenv(SILK_CLOBBER_ENVAR)) != NULL
                    && *clobber_env && *clobber_env != '0')
                {
                    /* overwrite existing files */
                } else
#endif  /* SILK_CLOBBER_ENVAR */
                {
                    errno = EEXIST;
                    return SK_FILEPTR_ERR_ERRNO;
                }
            }
            gzip_mode = ">";
            fopen_mode = "w";
            break;
          case SK_IO_APPEND:
            if (skFileExists(file->of_name)) {
                gzip_mode = ">>";
            } else {
                gzip_mode = ">";
            }
            fopen_mode = "w";
            break;
          default:
            skAbort();
        }

        rv = snprintf(gzip_cmd, sizeof(gzip_cmd), "gzip -c %s '%s'",
                      gzip_mode, file->of_name);
        if (sizeof(gzip_cmd) < (size_t)rv) {
            return SK_FILEPTR_ERR_TOO_LONG;
        }
        errno = 0;
        file->of_fp = popen(gzip_cmd, fopen_mode);
        if (NULL == file->of_fp) {
            if (errno) {
                return SK_FILEPTR_ERR_ERRNO;
            }
            return SK_FILEPTR_ERR_POPEN;
        }
        file->of_type = SK_FILEPTR_IS_PROCESS;
        return 0;
    }

    /* handle a standard fopen() for read */
    if (SK_IO_READ == io_mode) {
        file->of_fp = fopen(file->of_name, "r");
        if (NULL == file->of_fp) {
            return SK_FILEPTR_ERR_ERRNO;
        }
        file->of_type = SK_FILEPTR_IS_FILE;
        return 0;
    }

    /* handle a standard fopen() for write or append.  use open()
     * first, since it gives us better control. */

    fopen_mode = "w";
    /* standard mode of 0666 */
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    /* assume creating previously non-existent file */
    flags = O_WRONLY | O_CREAT | O_EXCL;

    /* try to open as a brand new file */
    fd = open(file->of_name, flags, mode);
    if (fd == -1) {
        rv = errno;
        if ((rv == EEXIST)
            && (0 == stat(file->of_name, &stbuf)))
        {
            /* file exists.  Try again with different flags when the
             * mode is append, the file is a FIFO, the file is a
             * character device ("/dev/null"), or the SILK_CLOBBER
             * envar is set. */
            if (io_mode == SK_IO_APPEND) {
                flags = O_WRONLY | O_APPEND;
                fopen_mode = "a";
            } else if (S_ISFIFO(stbuf.st_mode)) {
                flags = O_WRONLY;
            } else if (S_ISCHR(stbuf.st_mode)) {
                flags = O_WRONLY | O_NOCTTY;
#ifdef SILK_CLOBBER_ENVAR
            } else if ((clobber_env = getenv(SILK_CLOBBER_ENVAR)) != NULL
                       && *clobber_env && *clobber_env != '0')
            {
                /* overwrite existing file */
                flags = O_WRONLY | O_TRUNC;
#endif  /* SILK_CLOBBER_ENVAR */
            } else {
                errno = rv;
                return SK_FILEPTR_ERR_ERRNO;
            }

            /* try again with the new flags */
            fd = open(file->of_name, flags, mode);
        }
        /* if we (still) have an error, return */
        if (fd == -1) {
            return SK_FILEPTR_ERR_ERRNO;
        }
    }
    file->of_fp = fdopen(fd, fopen_mode);
    if (NULL == file->of_fp) {
        rv = errno;
        close(fd);
        errno = rv;
        return SK_FILEPTR_ERR_ERRNO;
    }

    file->of_type = SK_FILEPTR_IS_FILE;
    return 0;
}


int
skFileptrClose(
    sk_fileptr_t       *file,
    sk_msg_fn_t         err_fn)
{
    int rv = 0;

    assert(file);
    if (NULL == file->of_fp) {
        return 0;
    }

    switch (file->of_type) {
      case SK_FILEPTR_IS_STDIO:
        /* ignore if reading stdin */
        if (file->of_fp != stdin) {
            rv = fflush(file->of_fp);
            if (EOF == rv && err_fn) {
                err_fn("Error flushing %s: %s",
                       (file->of_name ? file->of_name : "stream"),
                       strerror(errno));
            }
        }
        break;

      case SK_FILEPTR_IS_FILE:
        rv = fclose(file->of_fp);
        if (EOF == rv && err_fn) {
            if (file->of_name) {
                err_fn("Error closing file '%s': %s",
                       file->of_name, strerror(errno));
            } else {
                err_fn("Error closing file: %s",
                       strerror(errno));
            }
        }
        break;

      case SK_FILEPTR_IS_PROCESS:
        rv = pclose(file->of_fp);
        if (err_fn) {
            if (-1 == rv) {
                if (file->of_name) {
                    err_fn("Error closing output process for '%s'",
                           file->of_name);
                } else {
                    err_fn("Error closing output process");
                }
            } else if (127 == rv) {
                if (file->of_name) {
                    err_fn("Error starting subprocess for '%s'",
                           file->of_name);
                } else {
                    err_fn("Error starting subprocess");
                }
            }
        }
        break;

      default:
        skAbortBadCase(file->of_type);
    }

    return rv;
}


const char *
skFileptrStrerror(
    int                 errnum)
{
    static char buf[128];

    switch ((sk_fileptr_status_t)errnum) {
      case SK_FILEPTR_OK:
        return "Success";
      case SK_FILEPTR_ERR_ERRNO:
        return strerror(errno);
      case SK_FILEPTR_ERR_WRITE_STDIN:
        return "Cannot write to the standard input";
      case SK_FILEPTR_ERR_READ_STDOUT:
        return "Cannot read from the standard output";
      case SK_FILEPTR_ERR_READ_STDERR:
        return "Cannot read from the standard error";
      case SK_FILEPTR_ERR_POPEN:
        return "Failed to open process";
      case SK_FILEPTR_ERR_TOO_LONG:
        return "Path name is too long";
      case SK_FILEPTR_ERR_INVALID:
        return "Invalid input to function";
      case SK_FILEPTR_PAGER_IGNORED:
        return "Not paging the output";
    }

    snprintf(buf, sizeof(buf), "Unrecognized skFileptrOpen() return value %d\n",
             errnum);
    return buf;
}


/* open file 'FName' for read (mode==0) or write (mode==1).  See header. */
int
skOpenFile(
    const char         *FName,
    int                 mode,
    FILE              **fp,
    int                *isPipe)
{
    char cmd[1024];
    const char *cp;
    int fd;
    unsigned char magic[2];
    ssize_t num_read;

    /* after this while() loop, 'cp' will be NULL if 'FName' is NOT
     * compressed, or non-NULL if 'FName' is compressed. */
    cp = FName;
    while (NULL != (cp = strstr(cp, ".gz"))) {
        if (*(cp + 3) == '\0') {
            /* file ends with ".gz".  Treat it as compressed.  (In
             * truth, this can be fooled by a bad mkstemp-based
             * filename as below, but we'll worry about that
             * later.) */
            break;
        } else if (*(cp + 3) == '.') {
            /* Treat a file that contains ".gz." as a potential
             * compressed file.  We do this to handle compressed files
             * have had mkstemp() extensions added to them.  This is
             * hackish, but it is simple and covers that common case
             * with few false positives.  We then, if possible, check
             * to see if it really is compressed by looking for the
             * gzip magic number (31 139 (see RFC1952)) in the first
             * two bytes.  We do not do this, however, if we are
             * writing to the file or if we are working with a named
             * pipe.  Despite the ability to search for the two-byte
             * marker in a named pipe stream, we have no way to put
             * the bytes back for normal processing.  Another solution
             * would be to use gzopen() and gzread()---which again
             * won't work for writing---and either accept their
             * overhead when working with uncompressed files, or have
             * librw do special things with compressed files.  There
             * is really no good solution here.  Hopefully soon we
             * will be using LZO compression in the body of the data
             * files, but still have an uncompresed SiLK header. */
            if ((1 == mode) || isFIFO(FName)) {
                /* We will assume it is compressed if we are writing
                 * to the file, or it is a FIFO, since we can't get
                 * more information (such as a magic number) from the
                 * file. */
                break;
            }
            fd = open(FName, O_RDONLY);
            if (-1 == fd) {
                /* We couldn't open the file.  Pass it on for normal
                 * processing and error handling. */
                break;
            }
            /* Read the first two bytes of the file. */
            num_read = read(fd, magic, 2);
            if ((num_read != 2) || (magic[0] != 31) || (magic[1] != 139)) {
                /* This cannot be a gzip compressed file, as it does
                 * not contain the gzip magic number.  Setting cp to
                 * NULL indicates that the file is not compressed. */
                cp = NULL;
            }
            close(fd);
            break;
        } else {
            cp += 3;
        }
    }

    if (NULL == cp) {
        /* Regular file or named pipe */
        *isPipe = 0;
        *fp = fopen(FName, mode ? "w" : "r");
    } else if (mode == 0 && skFileExists(FName) == 0) {
        /* Attempting to read from non-existent gzip */
        *fp = NULL;
    } else {
        /* Either writing to gzip or reading from existing gzip */
        if ((sizeof(cmd) - 16u) < strlen(FName)) {
            return 1;
        }
        *isPipe = 1;
        snprintf(cmd, sizeof(cmd), "gzip %s '%s'",
                 (mode ? ">" : "-d -c"), FName);
        *fp = popen(cmd, mode ? "w" : "r");
    }

    if (*fp == (FILE *)NULL) {
        if (mode == 0 && skFileExists(FName) == 0) {
            skAppPrintErr("Cannot open non-existant file '%s'", FName);
        } else {
            skAppPrintErr("Unable to open file '%s' for %s",
                          FName, mode ? "writing" : "reading");
        }
        return 1;                   /* error */
    }

    return 0;
}


/*
 *  status = skMakeDir(path);
 *
 *    Make the complete directory path to 'path', including parent(s)
 *    if required.  Return 0 on success.  Return 1 on failure and
 *    sets errno.
 */
int
skMakeDir(
    const char         *directory)
{
    int rv = 1; /* return value */
    int rv_err = 0; /* errno to set */
    size_t dir_len;
    char *cp;
    char *dir_buf = NULL;
    char **slash_list = NULL;
    int slash_count = 0;
    const mode_t dirMode = /* 0775 */
        S_IRWXU | S_IRGRP | S_IWGRP |  S_IXGRP | S_IROTH | S_IXOTH;

    assert(directory);

    /* Try common case first, where only trailing directory is
     * missing.  AIX does not always set errno to EEXIST for an
     * existing directory, so call skDirExists() as a back-up test. */
    errno = 0;
    if (0 == mkdir(directory, dirMode)
        || errno == EEXIST
        || skDirExists(directory))
    {
        return 0;
    }

    dir_len = strlen(directory);
    if (0 == dir_len) {
        /* ENOENT is what ``mkdir("")'' returns */
        rv_err = ENOENT;
        goto END;
    }

    /* make a copy of the directory name that we can modify, and malloc
     * an array of char*'s that will point to the slashes ('/') in that
     * dir_buf. */
    if (((dir_buf = strdup(directory)) == NULL)
        || ((slash_list = (char**)malloc(dir_len * sizeof(char*))) == NULL))
    {
        rv_err = errno;
        goto END;
    }

    /* point cp at the end of the buffer, then work backward until we
     * find a slash.  Convert the slash to a '\0' and see if the parent
     * dir exists.  If it does not, keep shorting the directory
     * path--stashing the locations of the '/' in slash_list[]--until we
     * find an existing parent directory.  If the parent dir does exist,
     * change the '\0' back to a '/' and start making child
     * directories. */
    cp = &(dir_buf[dir_len]);

    for (;;) {
        /* search for dir-sep */
        while (cp > dir_buf && *cp != '/') {
            --cp;
        }
        if (cp == dir_buf) {
            /* can't search past start of string */
            break;
        }
        /* see if parent dir exists... */
        *cp = '\0';
        if (skDirExists(dir_buf)) {
            /* ...it does, we can start making child directories */
            *cp = '/';
            break;
        }
        /* ...else it does not. Store this location and continue up the path */
        slash_list[slash_count] = cp;
        ++slash_count;
    }

    /* dir_buf should contain a directory we can create */
    for (;;) {
        /* make the child directory */
        if (0 != mkdir(dir_buf, dirMode)) {
            /* perhaps another thread or process created the directory? */
            rv_err = errno;
            if (rv_err != EEXIST && !skDirExists(dir_buf)) {
                goto END;
            }
        }
        if (slash_count == 0) {
            /* we should have created the entire path */
            assert(0 == strcmp(dir_buf, directory));
            break;
        }
        /* convert this '\0' back to a '/' and make next child dir */
        --slash_count;
        *(slash_list[slash_count]) = '/';
    }

    /* success! */
    rv = 0;

  END:
    /* cleanup buffers */
    if (dir_buf) {
        free(dir_buf);
    }
    if (slash_list) {
        free(slash_list);
    }
    if (rv) {
        errno = rv_err;
    }
    return rv;
}


/*
 * skCopyFile:
 *      Copies the file "source" to "dest".  "Dest" may be a file or a
 *      directory.
 * Input: char * source
 *        char * dest
 * Output: 0 on success, errno on failure.
 */
int
skCopyFile(
    const char         *srcPath,
    const char         *destPath)
{
    static size_t max_mapsize = DEFAULT_MAX_MMAPSIZE;
    int fdin = -1, fdout = -1;
    void *src = NULL, *dst = NULL;
    const char *dest = NULL;
    char destBuf[PATH_MAX];
    char base[PATH_MAX];
    struct stat st;
    int saveerrno;
    int rv;
    off_t orv;
    ssize_t wrv;
    off_t offset;
    off_t size;
    size_t mapsize = 0;
    int pagesize = sysconf(_SC_PAGESIZE);

    max_mapsize -= max_mapsize % pagesize;

    /* Handle dest being a directory */
    if (skDirExists(destPath)) {
        skBasename_r(base, srcPath, sizeof(base));
        rv = snprintf(destBuf, sizeof(destBuf), "%s/%s", destPath, base);
        if (rv == -1) {
            return EIO;
        }
        if ((unsigned int)rv > (sizeof(destBuf) - 1)) {
            return ENAMETOOLONG;
        }
        dest = destBuf;
    } else {
        dest = destPath;
    }

    /* Open source */
    fdin = open(srcPath, O_RDONLY);
    if (fdin == -1) {
        goto copy_error;
    }

    /* Get source info */
    rv = fstat(fdin, &st);
    if (rv == -1) {
        goto copy_error;
    }
    size = st.st_size;

    /* Open dest */
    fdout = open(dest, O_RDWR | O_CREAT | O_TRUNC, st.st_mode);
    if (fdout == -1) {
        goto copy_error;
    }

    /* Resize dest to source size (For mmap.  See APUE [Stevens].) */
    orv = lseek(fdout, size - 1, SEEK_SET);
    if (orv == -1) {
        goto copy_error;
    }
    wrv = write(fdout, "", 1);
    if (wrv != 1) {
        goto copy_error;
    }

    offset = 0;
    while (size) {
        mapsize = (size > (off_t)max_mapsize) ? max_mapsize : (size_t)size;

        /* Map source */
        src = mmap(0, mapsize, PROT_READ, MAP_SHARED, fdin, offset);
        if (src == MAP_FAILED) {
            if (errno == ENOMEM) {
                max_mapsize >>= 1;
                max_mapsize -= max_mapsize % pagesize;
                continue;
            }
            goto copy_error;
        }
        /* Map dest */
        dst = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED,
                   fdout, offset);
        if (dst == MAP_FAILED) {
            if (errno == ENOMEM) {
                rv = munmap(src, mapsize);
                if (rv != 0) {
                    goto copy_error;
                }
                max_mapsize >>= 1;
                max_mapsize -= max_mapsize % pagesize;
                continue;
            }
            goto copy_error;
        }

        /* Copy src to dest */
        memcpy(dst, src, mapsize);

        /* Close src and dest */
        rv = munmap(src, mapsize);
        if (rv != 0) {
            goto copy_error;
        }
        rv = munmap(dst, mapsize);
        if (rv != 0) {
            goto copy_error;
        }

        offset += mapsize;
        size -= mapsize;
    }

    rv = close(fdin);
    fdin = -1;
    if (rv == -1) {
        goto copy_error;
    }

    rv = close(fdout);
    fdout = -1;
    if (rv == -1) {
        goto copy_error;
    }

    return 0;

  copy_error:
    saveerrno = errno;

    if (fdin != -1) {
        close (fdin);
    }
    if (fdout != -1) {
        close (fdout);
    }
    if (src) {
        munmap(src, mapsize);
    }
    if (dst) {
        munmap(dst, mapsize);
    }
    if (fdout != -1 || dst) {
        unlink(dest);
    }

    return saveerrno;
}


/*
 * skMoveFile:
 *      Moves the file "source" to "dest".  "Dest" may be a file or a
 *      directory.
 * Input: char * source
 *        char * dest
 * Output: 0 on success, errno on failure.
 */
int
skMoveFile(
    const char         *srcPath,
    const char         *destPath)
{
    const char *dest;
    char destBuf[PATH_MAX];
    char base[PATH_MAX];
    int rv;
    int saveerrno;

    /* Handle dest being a directory */
    if (skDirExists(destPath)) {
        skBasename_r(base, srcPath, sizeof(base));
        rv = snprintf(destBuf, sizeof(destBuf), "%s/%s", destPath, base);
        if (rv == -1) {
            return EIO;
        }
        if ((unsigned int)rv > (sizeof(destBuf) - 1)) {
            return ENAMETOOLONG;
        }
        dest = destBuf;
    } else {
        dest = destPath;
    }

    /* Attempt a simple move */
    rv = rename(srcPath, dest);
    if (rv == -1) {
        if (errno != EXDEV) {
            return errno;
        }

        /* Across filesystems, so copy and delete. */
        rv = skCopyFile(srcPath, dest);
        if (rv != 0) {
            return rv;
        }
        rv = unlink(srcPath);
        if (rv == -1) {
            saveerrno = errno;
            unlink(dest);
            return saveerrno;
        }
    }

    return 0;
}


/* return the temporary directory. */
const char *
skTempDir(
    const char         *user_temp_dir,
    sk_msg_fn_t         err_fn)
{
    const char *tmp_dir = NULL;

    /* Use the user's option if given, or SILK_TMPDIR, TMPDIR, or the
     * default */
    if (NULL == tmp_dir) {
        tmp_dir = user_temp_dir;
    }
    if (NULL == tmp_dir) {
        tmp_dir = getenv(SK_TEMPDIR_ENVAR1);
    }
    if (NULL == tmp_dir) {
        tmp_dir = getenv(SK_TEMPDIR_ENVAR2);
    }
#ifdef SK_TEMPDIR_DEFAULT
    if (NULL == tmp_dir) {
        tmp_dir = SK_TEMPDIR_DEFAULT;
    }
#endif /* SK_TEMPDIR_DEFAULT */
    if (NULL == tmp_dir) {
        if (err_fn) {
            err_fn("Cannot find a value for the temporary directory.");
        }
        return NULL;
    }
    if ( !skDirExists(tmp_dir)) {
        if (err_fn) {
            err_fn("Temporary directory '%s' does not exist", tmp_dir);
        }
        return NULL;
    }
    return tmp_dir;
}


/* paginate the output.  see utils.h */
int
skOpenPagerWhenStdoutTty(
    FILE              **output_stream,
    char              **pager)
{
    FILE *out;
    char *pg;
    pid_t pid;
    int wait_status;

    /* verify input; deference the input variables */
    assert(output_stream);
    assert(pager);
    out = *output_stream;
    pg = *pager;

    /* don't page if output is not "stdout" */
    if (NULL == out) {
        out = stdout;
    } else if (out != stdout) {
        /* no change */
        return 0;
    }

    /* don't page a non-terminal */
    if ( !FILEIsATty(out)) {
        if (pg) {
            /* pager explicitly given but ignored */
            skAppPrintErr("Ignoring the --pager switch");
        }
        return 0;
    }

    /* get pager from environment if not passed in */
    if (NULL == pg) {
        pg = getenv("SILK_PAGER");
        if (NULL == pg) {
            pg = getenv("PAGER");
        }
    }

    /* a NULL or an empty string pager means do nothing */
    if ((NULL == pg) || ('\0' == pg[0])) {
        return 0;
    }

#if 1
    /* invoke the pager */
    out = popen(pg, "w");
    if (NULL == out) {
        skAppPrintErr("Unable to invoke pager '%s'", pg);
        return -1;
    }

    /* see if pager started.  There is a race condition here, and this
     * assumes we have only one child, which should be true. */
    pid = wait4(0, &wait_status, WNOHANG, NULL);
    if (pid) {
        skAppPrintErr("Unable to invoke pager '%s'", pg);
        return -1;
    }
#else
    {
    int pipe_des[2];

    /* create pipe and fork */
    if (pipe(pipe_des) == -1) {
        skAppPrintErr("Cannot create pipe: %s", strerror(errno));
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        skAppPrintErr("Cannot fork: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* CHILD */

        /* close output side of pipe; set input to stdin */
        close(pipe_des[1]);
        if (pipe_des[0] != STDIN_FILENO) {
            dup2(pipe_des[0], STDIN_FILENO);
            close(pipe_des[0]);
        }

        /* invoke pager */
        execlp(pg, NULL);
        skAppPrintErr("Unable to invoke pager '%s': %s",
                      pg, strerror(errno));
        _exit(EXIT_FAILURE);
    }

    /* PARENT */

    /* close input side of pipe */
    close(pipe_des[0]);

    /* try to open the write side of the pipe */
    out = fdopen(pipe_des[1], "w");
    if (NULL == out) {
        skAppPrintErr("Cannot fdopen: %s", strerror(errno));
        return -1;
    }

    /* it'd be nice to have a slight pause here to give child time to
     * die if command cannot be exec'ed, but it's not worth the
     * trouble to use select(), and sleep(1) is too long. */

    /* see if child died unexpectedly */
    if (waitpid(pid, &wait_status, WNOHANG)) {
        skAppPrintErr("Unable to invoke pager '%s'", pg);
        return -1;
    }
    }
#endif /* 1: whether to use popen() */

    /* looks good. set the output variables and return */
    *pager = pg;
    *output_stream = out;
    return 1;
}


int
skFileptrOpenPager(
    sk_fileptr_t       *file,
    const char         *pager)
{
    FILE *out;
    const char *pg;
    pid_t pid;
    int wait_status;

    /* verify input; deference the input variables */
    assert(file);

    /* don't page if output is not "stdout" */
    if (NULL == file->of_fp) {
        /* assume output is stdout */
    } else if (file->of_fp != stdout) {
        /* no change */
        return SK_FILEPTR_PAGER_IGNORED;
    }

    /* don't page a non-terminal */
    if (!FILEIsATty(stdout)) {
        return SK_FILEPTR_PAGER_IGNORED;
    }

    /* get pager from environment if not passed in */
    if (pager) {
        pg = pager;
    } else {
        pg = getenv("SILK_PAGER");
        if (NULL == pg) {
            pg = getenv("PAGER");
        }
    }

    /* a NULL or an empty string pager means do nothing */
    if ((NULL == pg) || ('\0' == pg[0])) {
        return SK_FILEPTR_PAGER_IGNORED;
    }

    /* invoke the pager */
    out = popen(pg, "w");
    if (NULL == out) {
        return SK_FILEPTR_ERR_POPEN;
    }

    /* see if pager started.  There is a race condition here, and this
     * assumes we have only one child, which should be true. */
    pid = wait4(0, &wait_status, WNOHANG, NULL);
    if (pid) {
        pclose(out);
        return SK_FILEPTR_ERR_POPEN;
    }

    /* looks good. set the output variables and return */
    file->of_name = (char*)pg;
    file->of_fp   = out;
    file->of_type = SK_FILEPTR_IS_PROCESS;

    return SK_FILEPTR_OK;
}


/* Close the pager */
void
skClosePager(
    FILE               *pager_stream,
    const char         *pager)
{
    if (pager_stream && (pager_stream != stdout)) {
        if (-1 == pclose(pager_stream)) {
            skAppPrintErr("Error closing pager '%s'", pager);
        }
    }
}


/* Get a line from a file */
int
skGetLine(
    char               *out_buffer,
    size_t              buf_size,
    FILE               *stream,
    const char         *comment_start)
{
    int line_count = 0;
    size_t len;
    char *eol;

    assert(out_buffer && buf_size);

    /* read until end of file */
    while (!feof(stream)) {
        memset(out_buffer, '\0', buf_size);
        if (fgets(out_buffer, buf_size, stream) == NULL) {
            continue;
        }
        line_count++;

        /* find end of line */
        eol = strchr(out_buffer, '\n');
        if (out_buffer == eol) {
            /* empty line; ignore */
            continue;
        }

        if (eol != NULL) {
            /* expected behavior: read an entire line */
            *eol = '\0';
        } else if (feof(stream)) {
            /* okay: last line did not end in newline */
        } else {
            /* bad: line was longer than buf_size.  read
             * until newline or eof, then throw away the line */
            while (fgets(out_buffer, buf_size, stream)
                   && !strchr(out_buffer, '\n'))
                ; /* empty */
            continue;
        }

        /* Terminate line at first comment char */
        if (comment_start && *comment_start
            && (NULL != (eol = strstr(out_buffer, comment_start))))
        {
            if (out_buffer == eol) {
                /* only a comment */
                continue;
            }
            *eol = '\0';
        }

        /* find first non-space character */
        len = strspn(out_buffer, " \t\v\f\r");
        if ((out_buffer + len) == eol) {
            /* whitespace only */
            continue;
        }

        return line_count;
    }

    out_buffer[0] = '\0';
    return 0;
}


/* check that char after % in command is in conversion_chars */
size_t
skSubcommandStringCheck(
    const char         *command,
    const char         *conversion_chars)
{
    const char *cp;

    assert(command);
    assert(conversion_chars);

    cp = command;
    while (NULL != (cp = strchr(cp, (int)'%'))) {
        ++cp;
        switch (*cp) {
          case '%':
            break;
          case '\0':
            return cp - command;
          default:
            if (NULL == strchr(conversion_chars, (int)*cp)) {
                return cp - command;
            }
            break;
        }
        ++cp;
    }
    return 0;
}


/* return a new string that is command with conversions expanded */
char *
skSubcommandStringFill(
    const char         *command,
    const char         *conversion_chars,
    ...)
{
    char *expanded_cmd;
    char *expansion;
    const char *cp;
    const char *sp;
    char *exp_cp;
    va_list args;
    size_t len;

    /* Determine length of buffer needed for the expanded command
     * string and allocate it.  */
    cp = command;
    len = 0;
    while (NULL != (sp = strchr(cp, (int)'%'))) {
        len += sp - cp;
        cp = sp + 1;
        if ('%' == *cp) {
            ++len;
        } else {
            sp = strchr(conversion_chars, (int)*cp);
            if (NULL == sp || '\0' == *sp) {
                return NULL;
            }
            va_start(args, conversion_chars);
            do {
                expansion = va_arg(args, char *);
                --sp;
            } while (sp >= conversion_chars);
            len += strlen(expansion);
            va_end(args);
        }
        ++cp;
    }
    len += strlen(cp);
    expanded_cmd = (char*)malloc(len + 1);
    if (NULL == expanded_cmd) {
        return NULL;
    }

    /* Copy command into buffer, handling %-expansions */
    cp = command;
    exp_cp = expanded_cmd;
    while (NULL != (sp = strchr(cp, (int)'%'))) {
        /* copy text we just jumped over */
        strncpy(exp_cp, cp, sp - cp);
        exp_cp += sp - cp;
        cp = sp + 1;
        /* handle conversion */
        if ('%' == *cp) {
            *exp_cp = '%';
            ++exp_cp;
        } else {
            sp = strchr(conversion_chars, (int)*cp);
            assert(sp && *sp);
            va_start(args, conversion_chars);
            do {
                expansion = va_arg(args, char *);
                --sp;
            } while (sp >= conversion_chars);
            strcpy(exp_cp, expansion);
            exp_cp = strchr(exp_cp, (int)'\0');
            va_end(args);
        }
        ++cp;
        assert(len >= (size_t)(exp_cp - expanded_cmd));
    }
    strcpy(exp_cp, cp);
    expanded_cmd[len] = '\0';

    return expanded_cmd;
}


/*
 *    Use the global 'environ' variable to get the environment table.
 *    On macOS, we must use _NSGetEnviron() to get the environment.
 */
#if defined(SK_HAVE_DECL__NSGETENVIRON) && SK_HAVE_DECL__NSGETENVIRON
#include <crt_externs.h>
#define SK_ENVIRON_TABLE *_NSGetEnviron()
#define SK_COPY_ENVIRONMENT 1
#elif defined(SK_HAVE_DECL_ENVIRON) && SK_HAVE_DECL_ENVIRON
#define SK_ENVIRON_TABLE environ
#define SK_COPY_ENVIRONMENT 1
#endif
#ifndef SK_COPY_ENVIRONMENT
#define SK_COPY_ENVIRONMENT 0
#endif


#if SK_COPY_ENVIRONMENT
/**
 *    Free the copy of the environment that was allocated by
 *    skSubcommandCopyEnvironment().
 */
static void
skSubcommandFreeEnvironment(
    char              **env_copy)
{
    size_t i;

    if (env_copy) {
        for (i = 0; env_copy[i]; ++i) {
            free(env_copy[i]);
        }
        free(env_copy);
    }
}

/**
 *    Make and return a copy of the current environment.
 */
static char **
skSubcommandCopyEnvironment(
    void)
{
    char **env = SK_ENVIRON_TABLE;
    char **env_copy = NULL;
    const size_t step = 100;
    size_t sz = 0;
    size_t i;

    /* Add 1 for the terminating NULL */
    for (i = 0; env[i]; ++i) {
        if (i == sz) {
            char **old = env_copy;
            env_copy = (char **)realloc(old, (sz + step + 1) * sizeof(char *));
            if (NULL == env_copy) {
                old[i] = (char *)NULL;
                skSubcommandFreeEnvironment(old);
                return NULL;
            }
            sz += step;
        }
        env_copy[i] = strdup(env[i]);
        if (NULL == env_copy[i]) {
            skSubcommandFreeEnvironment(env_copy);
            return NULL;
        }
    }
    if (env_copy) {
        env_copy[i] = (char *)NULL;
    } else {
        env_copy = (char **)calloc(1, sizeof(char *));
    }
    return env_copy;
}
#endif  /* SK_COPY_ENVIRONMENT */


/* run the command */
static long int
skSubcommandExecuteHelper(
    const char         *cmd_string,
    char * const        cmd_array[])
{
    sigset_t sigs;
    pid_t pid;

#if SK_COPY_ENVIRONMENT
    char **env_copy = skSubcommandCopyEnvironment();
    if (NULL == env_copy) {
        return -1;
    }
#endif  /* SK_COPY_ENVIRONMENT */

    /* Parent (original process) forks to create Child 1 */
    pid = fork();
    if (-1 == pid) {
        return -1;
    }

    /* Parent reaps Child 1 and returns */
    if (0 != pid) {
#if SK_COPY_ENVIRONMENT
        skSubcommandFreeEnvironment(env_copy);
#endif
        /* Wait for Child 1 to exit. */
        while (waitpid(pid, NULL, 0) == -1) {
            if (EINTR != errno) {
                return -2;
            }
        }
        return (long)pid;
    }

    /* Change our process group, so a server program using this
     * library that is waiting for any of its children (by process
     * group) won't wait for this child. */
    setpgid(0, 0);

    /* Child 1 forks to create Child 2 */
    pid = fork();
    if (pid == -1) {
        skAppPrintSyserror("Child could not fork for to run command");
        _exit(EXIT_FAILURE);
    }

    /* Child 1 immediately exits, so Parent can stop waiting */
    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }

    /* Only Child 2 makes it here */

    /* Unmask signals */
    sigemptyset(&sigs);
    sigprocmask(SIG_SETMASK, &sigs, NULL);

    /* Execute the command */
#if SK_COPY_ENVIRONMENT
    if (cmd_string) {
        execle("/bin/sh", "sh", "-c", cmd_string, (char*)NULL, env_copy);
    } else {
        execve(cmd_array[0], cmd_array, env_copy);
    }
#else  /* SK_COPY_ENVIRONMENT */
    if (cmd_string) {
        execl("/bin/sh", "sh", "-c", cmd_string, (char*)NULL);
    } else {
        execv(cmd_array[0], cmd_array);
    }
#endif  /* SK_COPY_ENVIRONMENT */

    /* only get here when an error occurs */
    if (cmd_string)  {
        skAppPrintSyserror("Error invoking /bin/sh");
    } else {
        skAppPrintSyserror("Error invoking %s", cmd_array[0]);
    }
    _exit(EXIT_FAILURE);
}


long int
skSubcommandExecute(
    char * const        cmd_array[])
{
    return skSubcommandExecuteHelper(NULL, cmd_array);
}


long int
skSubcommandExecuteShell(
    const char         *cmd_string)
{
    return skSubcommandExecuteHelper(cmd_string, NULL);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
