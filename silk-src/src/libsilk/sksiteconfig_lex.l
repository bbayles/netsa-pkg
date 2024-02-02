%{
/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  Tokenizer for silk toolset configuration file.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: sksiteconfig_lex.l b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "sksiteconfig.h"
#include "sksiteconfig_parse.h"
#include <silk/utils.h>


typedef struct sksiteconfig_file_st {
    YY_BUFFER_STATE state;
    char           *name;
    FILE           *fp;
    int             line;
} sksiteconfig_file_t;

/* EXPORTED VARIABLES */

/* LOCAL VARIABLES */

/* count the number of errors that have occurred during processing */
static int sksiteconfig_errors = 0;

/* support for "include" */
static sksiteconfig_file_t sksiteconfig_stack[SKSITECONFIG_MAX_INCLUDE_DEPTH];

/* next stack position */
static int sksiteconfig_stack_depth = 0;

/* current pointer into sksiteconfig_stack[] */
static sksiteconfig_file_t *sksiteconfig_file = NULL;

/* local buffer for reading quoted strings */
#define BUF_SIZE 2048
static char sksiteconfig_buf[BUF_SIZE];
static char *sksiteconfig_buf_end = sksiteconfig_buf + BUF_SIZE - 1;
static char *sksiteconfig_buf_ptr;

/* Macros for checking that we're not overflowing the buffer, returning
 * a string, and appending a single character to a string. */

#define STRING_CHECK                                            \
    if ( sksiteconfig_buf_ptr >= sksiteconfig_buf_end ) {       \
        BEGIN(ST_ERR);                                          \
        return ERR_STR_TOO_LONG;                                \
    }

#define STRING_RETURN                           \
    sksiteconfig_buf_ptr = '\0';                \
    yylval.str = strdup(sksiteconfig_buf);      \
    return TOK_STRING;

#define STRING_APPEND(x) (*sksiteconfig_buf_ptr++ = (x))

SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

%}

%option prefix="sksiteconfig_" outfile="lex.yy.c"
%option never-interactive
%option noinput nounput

    /* %option noyyget_extra noyyset_extra noyyget_leng noyyget_text */
    /* %option noyyget_lineno noyyset_lineno noyyget_in noyyset_in */
    /* %option noyyget_out noyyset_out noyyget_lval noyyset_lval */
    /* %option noyyget_lloc noyyset_lloc noyyget_debug noyyset_debug */


    /* The INITIAL state is used for top-level commands */

    /* The ST_ARGS state is for processing arguments to commands */
%s ST_ARGS

    /* The ST_ERR state is for error recovery, ignores everything to EOL */
%s ST_ERR

    /* The ST_STRING state is for consuming quoted strings */
%s ST_STRING

    /* Whitespace (to be ignored) */
ws          [ \t\r]+

    /* Atoms (symbols) without quotes */
atomchar    [-._/@A-Za-z0-9]
atom        {atomchar}+

    /* Integral numbers (value returned to parser as a string) */
digit       [0-9]
integer     {digit}+

    /* End of line: command separator */
nl          \n

%%

    /* INITIAL state: Throw away comments, whitespace.  Treat any atom
       as a command name, plus "end <atom>".  Valid commands are returned
       as specific tokens.  Unknown commands are returned as strings for
       error reporting purposes.  Anything else implies the whole line
       cannot be interpreted, and enters the ST_ERR state to clear out
       everything to the EOL.  After a valid command, enter the ST_ARGS
       state for argument parsing. */

<INITIAL>{ws}           ;
<INITIAL>#.*\n          { ++sksiteconfig_file->line; return TOK_NL; }
<INITIAL>\n             { ++sksiteconfig_file->line; return TOK_NL; }
<INITIAL>class          { BEGIN(ST_ARGS); return TOK_CLASS; }
<INITIAL>default-class  { BEGIN(ST_ARGS); return TOK_DEF_CLASS; }
<INITIAL>default-types  { BEGIN(ST_ARGS); return TOK_DEF_TYPES; }
<INITIAL>end{ws}class   { BEGIN(ST_ARGS); return TOK_END_CLASS; }
<INITIAL>end{ws}group   { BEGIN(ST_ARGS); return TOK_END_GROUP; }
<INITIAL>end{ws}{atom}  { yylval.str = strdup(yytext);
                          BEGIN(ST_ERR);  return ERR_UNK_CMD; }
<INITIAL>group          { BEGIN(ST_ARGS); return TOK_GROUP; }
<INITIAL>include        { BEGIN(ST_ARGS); return TOK_INCLUDE; }
<INITIAL>path-format    { BEGIN(ST_ARGS); return TOK_PATH_FORMAT; }
<INITIAL>packing-logic  { BEGIN(ST_ARGS); return TOK_PACKING_LOGIC; }
<INITIAL>sensor         { BEGIN(ST_ARGS); return TOK_SENSOR; }
<INITIAL>sensors        { BEGIN(ST_ARGS); return TOK_SENSORS; }
<INITIAL>type           { BEGIN(ST_ARGS); return TOK_TYPE; }
<INITIAL>version        { BEGIN(ST_ARGS); return TOK_VERSION; }
<INITIAL>{atom}         { yylval.str = strdup(yytext);
                          BEGIN(ST_ERR);  return ERR_UNK_CMD; }
<INITIAL>.              { BEGIN(ST_ERR);  return ERR_UNREC; }

    /* ST_ERR state: Throw away everything up to the newline, because we've
       seen something we're unable to interpret. */

<ST_ERR>.*\n            { BEGIN(INITIAL); ++sksiteconfig_file->line;
                          return TOK_NL; }

    /* ST_ARGS state: Ignore whitespace as usual, at a newline or comment,
       return back to the INITIAL state.  Atoms, integers, and quoted
       strings are all valid input in this state. */

<ST_ARGS>{ws}           ;
<ST_ARGS>#.*\n          { BEGIN(INITIAL); ++sksiteconfig_file->line;
                          return TOK_NL; }
<ST_ARGS>\n             { BEGIN(INITIAL); ++sksiteconfig_file->line;
                          return TOK_NL; }
<ST_ARGS>{integer}      { yylval.str = strdup(yytext); return TOK_INTEGER; }
<ST_ARGS>{atom}         { yylval.str = strdup(yytext); return TOK_ATOM; }
<ST_ARGS>\"             { BEGIN(ST_STRING);
                          sksiteconfig_buf_ptr = sksiteconfig_buf; }
<ST_ARGS>.              { BEGIN(ST_ERR);  return ERR_UNREC; }

    /* ST_STRING state: Accepts the remainder of a quoted string (after the
       initial quote) and returns the value.  This is pretty much equivalent
       to quoted strings in C. */

<ST_STRING>\"           { BEGIN(ST_ARGS); STRING_CHECK;
                          *sksiteconfig_buf_ptr = '\0';
                          yylval.str = strdup(sksiteconfig_buf);
                          return TOK_STRING; }

<ST_STRING>\n           { BEGIN(INITIAL); ++sksiteconfig_file->line;
                          return ERR_UNTERM_STRING; }

<ST_STRING>\\[0-7]{1,3} { unsigned int oct_char;
                          STRING_CHECK;
                          (void) sscanf(yytext+1, "%o", &oct_char);
                          if ( oct_char > 0xff ) {
                              BEGIN(ST_ERR);
                              return ERR_INVALID_OCTAL_ESCAPE;
                          };
                          *sksiteconfig_buf_ptr++ = oct_char; }

<ST_STRING>\\[0-9]+     { BEGIN(ST_ERR); return ERR_INVALID_OCTAL_ESCAPE; }

<ST_STRING>\\n          { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\n'; }
<ST_STRING>\\t          { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\t'; }
<ST_STRING>\\r          { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\r'; }
<ST_STRING>\\b          { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\b'; }
<ST_STRING>\\f          { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\f'; }
<ST_STRING>\\\n         { STRING_CHECK; *sksiteconfig_buf_ptr++ = '\n'; }
<ST_STRING>\\.          { STRING_CHECK; *sksiteconfig_buf_ptr++ = yytext[1]; }

<ST_STRING>[^\\\n\"]+   { if ( (sksiteconfig_buf_ptr + yyleng) >
                                       sksiteconfig_buf_end ) {
                              BEGIN(ST_ERR);
                              return ERR_STR_TOO_LONG;
                          };
                          memcpy(sksiteconfig_buf_ptr, yytext, yyleng);
                          sksiteconfig_buf_ptr += yyleng; }

%%

SK_DIAGNOSTIC_IGNORE_POP("-Wwrite-strings")

int
yywrap(
    void)
{
    return sksiteconfigIncludePop();
}


/* Report an error while parsing (printf style) */
#ifndef sksiteconfigErr
void
sksiteconfigErr(
    const char         *fmt,
    ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "%s: Error while parsing site configuration file",
            skAppName());
    if (sksiteconfig_file != NULL && sksiteconfig_file->name != NULL) {
        fprintf(stderr, " at %s:%d",
                sksiteconfig_file->name, sksiteconfig_file->line);
    }
    fprintf(stderr, ":\n\t");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    ++sksiteconfig_errors;
    va_end(ap);
}
#endif /* sksiteconfigErr() */


int
sksiteconfigIncludePop(
    void)
{
    /*  if depth is 0, we are done */
    if ( sksiteconfig_stack_depth == 0 ) {
        return 1;
    }

    /* clean up current state */
    yy_delete_buffer(YY_CURRENT_BUFFER);
    fclose(sksiteconfig_file->fp);
    free(sksiteconfig_file->name);

    /* go to the previous state; if depth is 0, we are done */
    --sksiteconfig_stack_depth;
    if ( sksiteconfig_stack_depth == 0 ) {
        sksiteconfig_file = NULL;
        return 1;
    }
    sksiteconfig_file = &(sksiteconfig_stack[sksiteconfig_stack_depth-1]);
    yy_switch_to_buffer(sksiteconfig_file->state);

    /* let processing continue */
    return 0;
}

static int
sksiteconfigOpenFile(
    char               *filename,
    int                 verbose_error)
{
    sksiteconfig_file_t *new_file;
    const char *action_name = ((sksiteconfig_stack_depth == 0)
                               ? "read config"
                               : "include");

    if (filename == NULL) {
        return -1;
    }

    if (!skFileExists(filename)) {
        if (!verbose_error) {
            /* be silent */
        } else if (0 == sksiteconfig_stack_depth) {
            skAppPrintErr(("Cannot %s '%s': "
                           "File does not exist or is not a regular file"),
                          action_name, filename);
        } else {
            sksiteconfigErr(("Cannot %s '%s': "
                             "File does not exist or is not a regular file"),
                            action_name, filename);
        }
        goto ERROR;
    }

    if (sksiteconfig_stack_depth >= SKSITECONFIG_MAX_INCLUDE_DEPTH) {
        sksiteconfigErr("Failed to %s file '%s' (includes nested too deeply)",
                        action_name, filename);
        goto ERROR;
    }

    new_file = &sksiteconfig_stack[sksiteconfig_stack_depth];
    new_file->name = filename;
    new_file->line = 0;

    /* open the file */
    new_file->fp = fopen(new_file->name, "r");
    if ( !new_file->fp) {
        if (verbose_error) {
            sksiteconfigErr("Failed to %s file '%s' (%s)",
                            action_name, new_file->name, strerror(errno));
        }
        goto ERROR;
    }

    new_file->state = yy_create_buffer(new_file->fp, YY_BUF_SIZE);
    yy_switch_to_buffer(new_file->state);

    /* success */
    sksiteconfig_file = new_file;
    ++sksiteconfig_stack_depth;
    BEGIN(INITIAL);

    return 0;

  ERROR:
    if (filename) {
        free(filename);
    }
    return -1;
}


void
sksiteconfigIncludePush(
    char               *filename)
{
    (void)sksiteconfigOpenFile(filename, 1);
}

int
sksiteconfigParse(
    const char         *filename,
    int                 verbose)
{
    const char *env;

    env = getenv("SKSITECONFIG_TESTING");
    if (env && !(*env == '\0' || *env == '0')) {
        sksiteconfig_testing = 1;
    }

    sksiteconfig_stack_depth = 0;
    if (sksiteconfigOpenFile(strdup(filename), verbose)) {
        return -1;
    }

    (void)yyparse();

    if ( sksiteconfig_errors > 0 ) {
        return -1;
    } else {
        return 0;
    }
}


/*
** Local variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
