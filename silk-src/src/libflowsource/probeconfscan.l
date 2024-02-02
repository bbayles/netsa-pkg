%{
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

/*
**  Tokenizer for probe configuration file.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: probeconfscan.l 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include "probeconfscan.h"
#include "probeconfparse.h"


/* TYPEDEFS AND DEFINES */

typedef struct pcscan_file_st {
    YY_BUFFER_STATE state;
    char           *name;
    FILE           *fp;
    int             line;
} pcscan_file_t;


/* EXPORTED VARIABLES */

/* Global error count for return status of skpcParse */
int pcscan_errors;

/* keyword we read; for printing messages in the parser. */
char pcscan_clause[128];

int (*extra_sensor_verify_fn)(skpc_sensor_t *sensor) = NULL;


/* LOCAL FUNCTION PROTOTYPES */

static int stash(int tok);
static void err_bad_line(int is_id);
static void err_include_arg(void);
static char *get_name(const char *s, int c);
static void filter_start(char unless_when);
static int filter_set_type(char filter_type, char list_type);

/* support for "include" */
static pcscan_file_t pcscan_stack[PCSCAN_MAX_INCLUDE_DEPTH];

/* next stack position */
static int pcscan_stack_depth = 0;

/* current pointer into pcscan_stack[] */
static pcscan_file_t *pcscan_file = NULL;

/* local buffer for reading quoted strings */
#define BUF_SIZE 2048
static char pcscan_buf[BUF_SIZE];
static char *pcscan_buf_end = pcscan_buf + BUF_SIZE - 1;
static char *pcscan_buf_ptr;

/* Check that we're not overflowing the buffer */
#define STRING_CHECK                            \
    if ( pcscan_buf_ptr >= pcscan_buf_end ) {   \
        skpcParseErr("String too long");        \
        BEGIN(ST_ERR);                          \
        return ERR_STR_TOO_LONG;                \
    }

SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

%}

%option prefix="probeconfscan_" outfile="lex.yy.c"
%option never-interactive
%option noinput nounput

    /* %option noyyget_extra noyyset_extra noyyget_leng noyyget_text */
    /* %option noyyget_lineno noyyset_lineno noyyget_in noyyset_in */
    /* %option noyyget_out noyyset_out noyyget_lval noyyset_lval */
    /* %option noyyget_lloc noyyset_lloc noyyget_debug noyyset_debug */


    /* ST_ARGS state says we have read a keyword and are parsing the
     * arguments */

%s ST_ARGS

    /* ST_FILTER state is used to read the token following a
     * 'discard-unless' or 'discard-when' key word */

%s ST_FILTER

    /* ST_ERR state is for an unrecognized keyword at start of line;
     * reads to EOL.  Does not return any token to parser */

%s ST_ERR

    /* ST_ARG_ERR state is for an unrecognized keyword within a
     * statement---that is, after having returned a token to the
     * parser.  It reads to EOL and returns an EOL to the parser so
     * that the parser can put itself into a good state. */

%s ST_ARG_ERR

    /* ST_STRING state is for processing quoted strings */

%s ST_STRING

    /* ST_NEWLINE state is used when a newline is read.  One purpose
     * is to delay incrementing the line count until after the parser
     * has processed the line---so errors are reported on correct
     * line.  A second purpose is to detect when the file does not
     * have a final newline. */

%s ST_NEWLINE

    /* ST_IGNORE_SENSOR state is used to ignore the sensor statements
     * (when parsing a file for flowcap) */

%s ST_IGNORE_SENSOR


    /* basic character classes */

idchar          [-!$%&()*+./0-~]

notidchar       [^-!$%&()*+./0-~\n]

    /* An id must match keywords and sensor names as well as
     * pathnames, hostnames, and IP addresses.  Allow any
     * non-whitespace printable character other than " ' # , */

id              [-!$%&()*+./0-~]+

    /* whitespace; we ignore it */

wschar          [ \t\r\f\v]

wsopt           {wschar}*

ws              {wschar}+

    /* comment; ignore */

comment         {wsopt}#.*


    /* newline, maybe preceded by whitespace */

nl              {wsopt}\n

    /* end of line, maybe preceded by comment; increment line count */

eol             {nl}|{comment}{nl}

%%

    /* ST_NEWLINE state: increment the line-count for the newline we
     * saw at the end of the previous statement.  Stay in the
     * ST_NEWLINE state if this line contains a comment or whitespace.
     * Otherwise, go into the INITIAL state by reading a character
     * then putting it back. */

<ST_NEWLINE>{eol}                       { ++pcscan_file->line; }
<ST_NEWLINE>.                           { yyless(0); ++pcscan_file->line;
                                          BEGIN(INITIAL); }

{ws}                                    ;

    /* handle comment at end of file with no trailing newline */

<INITIAL>{comment}                      { BEGIN(ST_NEWLINE); }
<ST_ARGS>{comment}                      { BEGIN(ST_ERR); }

    /* read first keyword on a line */

<INITIAL,ST_ERR>{eol}                   { BEGIN(ST_NEWLINE);}

<INITIAL>{id}-interfaces?               { yylval.string = get_name(yytext,'-');
                                          return stash(NET_NAME_INTERFACE); }

<INITIAL>{id}-ipblocks?                 { yylval.string = get_name(yytext,'-');
                                          return stash(NET_NAME_IPBLOCK); }

<INITIAL>{id}-ipsets?                   { yylval.string = get_name(yytext,'-');
                                          return stash(NET_NAME_IPSET); }

<INITIAL>{id}-probes                    { yylval.string = get_name(yytext,'-');
                                          return stash(PROBES); }

<INITIAL>accept-from-host               { return stash(ACCEPT_FROM_HOST_T); }
<INITIAL>destination-network            { yylval.net_dir = SKPC_DIR_DST;
                                          return stash(NET_DIRECTION);}
<INITIAL>end{ws}group                   { return stash(END_GROUP_T); }
<INITIAL>end{ws}probe                   { return stash(END_PROBE_T); }
<INITIAL>end{ws}sensor                  { return stash(END_SENSOR_T); }
<INITIAL>group                          { return stash(GROUP_T); }
<INITIAL>include                        { return stash(INCLUDE_T); }
<INITIAL>include{ws}[^\"].*{nl}         { err_include_arg();BEGIN(ST_NEWLINE);}
<INITIAL>interfaces                     { return stash(INTERFACES_T); }
<INITIAL>interface-values               { return stash(INTERFACE_VALUES_T); }
<INITIAL>ipblocks                       { return stash(IPBLOCKS_T); }
<INITIAL>ipsets                         { return stash(IPSETS_T); }
<INITIAL>isp-ips?                       { return stash(ISP_IP_T); }
<INITIAL>listen-as-host                 { return stash(LISTEN_AS_HOST_T); }
<INITIAL>listen-on-port                 { return stash(LISTEN_ON_PORT_T); }
<INITIAL>listen-on-unix-domain-socket   { return stash(LISTEN_ON_USOCKET_T);}
<INITIAL>listen-on-unix-socket          { return stash(LISTEN_ON_USOCKET_T);}
<INITIAL>log-flags                      { return stash(LOG_FLAGS_T); }
<INITIAL>poll-directory                 { return stash(POLL_DIRECTORY_T); }
<INITIAL>priority                       { return stash(PRIORITY_T); }
<INITIAL>probe                          { return stash(PROBE_T); }
<INITIAL>protocol                       { return stash(PROTOCOL_T); }
<INITIAL>quirks                         { return stash(QUIRKS_T); }
<INITIAL>read-from-file                 { return stash(READ_FROM_FILE_T); }
<INITIAL>source-network                 { yylval.net_dir = SKPC_DIR_SRC;
                                          return stash(NET_DIRECTION); }
<INITIAL>sensor                         { if (extra_sensor_verify_fn) {
                                              return stash(SENSOR_T);
                                          } else {
                                              BEGIN(ST_IGNORE_SENSOR);
                                        } }

<INITIAL>.                              { yyless(0); BEGIN(ST_ERR); }

    /* go into the ST_FILTER state */

<INITIAL>discard-unless                 { filter_start('u'); }
<INITIAL>discard-when                   { filter_start('w'); }

    /* ST_FILTER state: handle the second keyword for "discard-when"
     * and "discard-unless" */

<ST_FILTER>any-interfaces?              { return filter_set_type('a', 'n'); }
<ST_FILTER>destination-interfaces?      { return filter_set_type('d', 'n'); }
<ST_FILTER>source-interfaces?           { return filter_set_type('s', 'n'); }

<ST_FILTER>any-ipblocks?                { return filter_set_type('a', 'w'); }
<ST_FILTER>destination-ipblocks?        { return filter_set_type('d', 'w'); }
<ST_FILTER>source-ipblocks?             { return filter_set_type('s', 'w'); }

<ST_FILTER>any-ipsets?                  { return filter_set_type('a', 's'); }
<ST_FILTER>destination-ipsets?          { return filter_set_type('d', 's'); }
<ST_FILTER>source-ipsets?               { return filter_set_type('s', 's'); }

<ST_FILTER>.                            { yyless(0);
                                          filter_set_type('-', '-');
                                          BEGIN(ST_ERR); }


    /* ST_ARGS state: handle text after initial keyword */

<ST_ARGS>{eol}                          { BEGIN(ST_NEWLINE); return EOL; }

<ST_ARGS>remainder                      { return REMAINDER_T; }

<ST_ARGS>{id}                           { yylval.string = strdup(yytext);
                                          return ID; }

<ST_ARGS>\"                             { BEGIN(ST_STRING);
                                          pcscan_buf_ptr = pcscan_buf; }

<ST_ARGS>","                            { return COMMA; }

<ST_ARGS>.                              { yyless(0); BEGIN(ST_ARG_ERR); }


    /* handle errors */

<ST_ERR,ST_ARG_ERR>{idchar}.*           { err_bad_line(1); }

<ST_ERR,ST_ARG_ERR>{notidchar}.*        { err_bad_line(0); }

    /* return EOL so the parser can throw away its current state */

<ST_ARG_ERR>{nl}                        { BEGIN(ST_NEWLINE); return EOL; }


    /* ST_IGNORE_SENSOR state: ignore everything until we reach the
     * "end sensor" line. */

<ST_IGNORE_SENSOR>end{ws}sensor{eol}    { BEGIN(ST_NEWLINE);}
<ST_IGNORE_SENSOR>end{ws}sensor         { BEGIN(ST_ERR); }
<ST_IGNORE_SENSOR>{eol}                 { ++pcscan_file->line; }
<ST_IGNORE_SENSOR>{id}|,                ;


    /* ST_STRING state: Accepts the remainder of a quoted string
     * (after the initial quote) and returns the value.  This is
     * pretty much equivalent to quoted strings in C. */

<ST_STRING>\"           { BEGIN(ST_ARGS);
                          STRING_CHECK;
                          *pcscan_buf_ptr = '\0';
                          yylval.string = strdup(pcscan_buf);
                          return QUOTED_STRING; }

<ST_STRING>\n           { BEGIN(ST_NEWLINE);
                          skpcParseErr("Quoted string missing closing quote");
                          return EOL; }

<ST_STRING>\\n          { STRING_CHECK; *pcscan_buf_ptr++ = '\n'; }
<ST_STRING>\\t          { STRING_CHECK; *pcscan_buf_ptr++ = '\t'; }
<ST_STRING>\\r          { STRING_CHECK; *pcscan_buf_ptr++ = '\r'; }
<ST_STRING>\\b          { STRING_CHECK; *pcscan_buf_ptr++ = '\b'; }
<ST_STRING>\\f          { STRING_CHECK; *pcscan_buf_ptr++ = '\f'; }
<ST_STRING>\\\n         { STRING_CHECK; *pcscan_buf_ptr++ = '\n'; }
<ST_STRING>\\.          { STRING_CHECK; *pcscan_buf_ptr++ = yytext[1]; }

<ST_STRING>[^\\\n\"]+   { if ((pcscan_buf_ptr + yyleng) > pcscan_buf_end ) {
                              BEGIN(ST_ERR);
                              return ERR_STR_TOO_LONG;
                          }
                          memcpy(pcscan_buf_ptr, yytext, yyleng);
                          pcscan_buf_ptr += yyleng; }

%%

SK_DIAGNOSTIC_IGNORE_POP("-Wwrite-strings")

int
yywrap(
    void)
{
    switch (YY_START) {
      case ST_NEWLINE:
        /* this is what we expect */
        break;
      case ST_IGNORE_SENSOR:
        skpcParseErr("Missing \"end sensor\" or final newline");
        break;
      case ST_STRING:
        skpcParseErr("Quoted string missing closing quote");
        break;
      default:
        skpcParseErr("Missing final newline or"
                     " incomplete statement at end-of-file");
        BEGIN(ST_NEWLINE);
        break;
    }
    return skpcParseIncludePop();
}


/*
 *  stash(int)
 *
 *      Stash the current keyword (using the yyleng and yytext
 *      globals), put us into a ST_ARGS start-state, and return the
 *      value we were passed.
 */
static int
stash(
    int                 tok)
{
    /* make certain the keyword fits in our buffer */
    assert(yyleng < ((int)sizeof(pcscan_clause)));

    /* copy it in */
    strncpy(pcscan_clause, yytext, sizeof(pcscan_clause) - 1);

    /* we're processing the arguments */
    BEGIN(ST_ARGS);

    /* return whatever we were passed */
    return tok;
}


/*
 *  string = get_name(input_string, c);
 *
 *    Allocate and return a copy of 'input_string' up to (but not
 *    including) the character 'c'.  If 'input_string' does not
 *    contain 'c', return a copy of the entire string.
 */
static char *
get_name(
    const char         *s,
    int                 c)
{
    const char *cp = strrchr(s, c);
    char *sp;

    if (cp == NULL) {
        return strdup(s);
    }
    sp = (char*)malloc(1 + (cp - s));
    if (sp) {
        strncpy(sp, s, (cp - s));
        sp[(cp - s)] = '\0';
    }
    return sp;
}


/*
 *  filter_start(unless_when);
 *
 *    Handle the "discard-when" and "discard-unless" keywords, and
 *    stash the keyword.  'unless_when' should be 'u' if this is a
 *    "discard-unless" keyword, and a 'w' for "discard-when".  Prepare
 *    to handle the next keyword describing what to
 *    discard-unless/when and the type of data.
 */
static void
filter_start(
    char                unless_when)
{
    /* copy keyword into the pcscan_clause */
    strncpy(pcscan_clause, yytext, sizeof(pcscan_clause) - 1);

    /* initialize filter */
    memset(&yylval.filter, 0, sizeof(skpc_filter_t));

    switch (unless_when) {
      case 'u':
        yylval.filter.f_discwhen = 0;
        break;
      case 'w':
        yylval.filter.f_discwhen = 1;
        break;
      default:
        skpcParseErr("Invalid unless_when '%c'", unless_when);
        skAbort();
    }

    BEGIN(ST_FILTER);
}


/*
 *  filter_set_type(filter_type, list_type);
 *
 *    Handle the second keyword in a "discard-when" or
 *    "discard-unless" statement.  Append this additional text to the
 *    'pcscan_clause' used to report errors.
 *
 *    'filter_type' specifies the first character of the second
 *    keyword ('a'ny, 'd'estination, 's'source), and it determines the
 *    skpc_filter_type_t.
 *
 *    'list_type' is 'n' for numbers (interfaces), 'w' for wildcards
 *    (ipblocks), and 's' for IPsets.
 *
 *    A 'filter_type' of '-' indicates an error parsing the keyword
 *    following the discard-when/discard-unless statement.
 */
static int
filter_set_type(
    char                filter_type,
    char                list_type)
{
    if ('-' == filter_type) {
        /* invalid keyword */
        skpcParseErr("Missing or invalid type for %s", pcscan_clause);
        return -1;
    }

    /* append text into pcscan_clause */
    strncat(pcscan_clause, " ",
            (sizeof(pcscan_clause) - strlen(pcscan_clause) - 1));
    strncat(pcscan_clause, yytext,
            (sizeof(pcscan_clause) - strlen(pcscan_clause) - 1));

    switch (filter_type) {
      case 'a':
        yylval.filter.f_type = SKPC_FILTER_ANY;
        break;
      case 'd':
        yylval.filter.f_type = SKPC_FILTER_DESTINATION;
        break;
      case 's':
        yylval.filter.f_type = SKPC_FILTER_SOURCE;
        break;
      default:
        skpcParseErr("Invalid filter_type '%c'", filter_type);
        skAbort();
    }
    switch (list_type) {
      case 'n':                 /* interface numbers */
        yylval.filter.f_group_type = SKPC_GROUP_INTERFACE;
        break;
      case 'w':                 /* ipblock wildcards */
        yylval.filter.f_group_type = SKPC_GROUP_IPBLOCK;
        break;
      case 's':                 /* IPset filenames */
        yylval.filter.f_group_type = SKPC_GROUP_IPSET;
        break;
      default:
        skpcParseErr("Invalid list_type '%c'", list_type);
        skAbort();
    }

    /* prepare to grab the interfaces, ipblocks, or IPsets */
    BEGIN(ST_ARGS);
    return FILTER;
}


/*
 *  err_bad_line(is_id);
 *
 *    Called when the scanner reads a bad line of input.  This
 *    function prints an error and increases the global error count.
 *
 *    If 'is_id' is 0, we have a single uknown character; otherwise we
 *    have a bad keyword.  At this point yytext holds the entire bad
 *    line.
 */
static void
err_bad_line(
    int                 is_id)
{
    size_t i;

    /* Make sure the parser lets the application know that things failed. */
    ++pcscan_errors;

    /* Handle a bad character; this is easy */
    if (is_id == 0) {
        skpcParseErr("Unexpected character '%c'", yytext[0]);
        return;
    }

    /* Handle a bad keyword.  Copy the first keyword into
     * pcscan_clause[] so we can print it. */
    for (i = 0; i < sizeof(pcscan_clause)-1; ++i) {
        /* This switch has the same character classes as our {idchar}. */
        switch (yytext[i]) {
          case '\0':
            goto END_WORD;
          case '-':
          case '.':
          case '_':
          case '/':
            pcscan_clause[i] = yytext[i];
            break;
          default:
            if (isalnum((int)yytext[i])) {
                pcscan_clause[i] = yytext[i];
            } else {
                goto END_WORD;
            }
            break;
        }
    }
  END_WORD:
    pcscan_clause[i] = '\0';

    skpcParseErr("Unrecognized keyword '%s'", pcscan_clause);
}


/*
 *  err_include_arg();
 *
 *    Print a message about the argument to include statement.
 */
static void
err_include_arg(
    void)
{
    /* Make sure the parser lets the application know that things failed. */
    ++pcscan_errors;

    skpcParseErr("Argument to include must be in \"double quotes\"");
}


#ifndef TEST_PRINTF_FORMATS
int
skpcParseErr(
    const char         *fmt,
    ...)
{
    va_list args;

    va_start(args, fmt);
    if (pcscan_file != NULL && pcscan_file->name != NULL) {
        fprintf(stderr, "%s: Error while parsing file %s at line %d:\n\t",
                skAppName(), pcscan_file->name, pcscan_file->line);
    } else {
        fprintf(stderr, "%s: Error during parsing [no current file]:\n\t",
                skAppName());
    }
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    return 0;
}
#endif  /* TEST_PRINTF_FORMATS */


static int
skpcParseOpenFile(
    char               *filename)
{
    pcscan_file_t *new_file;
    const char *action_name =
        ((pcscan_stack_depth == 0) ? "read sensor-config" : "include");

    if (filename == NULL) {
        goto ERROR;
    }

    if (!skFileExists(filename)) {
        if (0 == pcscan_stack_depth) {
            skAppPrintErr(("Cannot %s '%s': "
                           "File does not exist or is not a regular file"),
                          action_name, filename);
        } else {
            skpcParseErr(("Cannot %s '%s': "
                          "File does not exist or is not a regular file"),
                         action_name, filename);
        }
        goto ERROR;
    }

    if (pcscan_stack_depth >= PCSCAN_MAX_INCLUDE_DEPTH) {
        skpcParseErr("Cannot include file '%s': includes nested too deeply",
                     filename);
        goto ERROR;
    }

    new_file = &pcscan_stack[pcscan_stack_depth];
    new_file->name = filename;
    new_file->line = 0;

    /* open the file */
    new_file->fp = fopen(new_file->name, "r");
    if (!new_file->fp) {
        skpcParseErr("Cannot %s '%s': %s",
                     action_name, filename, strerror(errno));
        goto ERROR;
    }

    /* set up scanner */
    new_file->state = yy_create_buffer(new_file->fp, YY_BUF_SIZE);
    yy_switch_to_buffer(new_file->state);

    /* success */
    pcscan_file = new_file;
    ++pcscan_stack_depth;
    BEGIN(ST_NEWLINE);

    return 0;

  ERROR:
    if (filename) {
        free(filename);
    }
    return -1;
}


int
skpcParseIncludePop(
    void)
{
    if (pcscan_stack_depth == 0) {
        return 1;
    }

    /* free current state */
    yy_delete_buffer(YY_CURRENT_BUFFER);
    fclose(pcscan_file->fp);
    free(pcscan_file->name);

    /* pop to previous state; if no more states, we're done */
    --pcscan_stack_depth;
    if (pcscan_stack_depth == 0) {
        pcscan_file = NULL;
        return 1;
    }

    pcscan_file = &(pcscan_stack[pcscan_stack_depth-1]);
    yy_switch_to_buffer(pcscan_file->state);

    /* let processing continue */
    return 0;
}


int
skpcParseIncludePush(
    char               *filename)
{
    return skpcParseOpenFile(filename);
}


int
skpcParse(
    const char         *filename,
    int               (*site_verify_sensor_fn)(skpc_sensor_t *sensor))
{
    /* store the site-specific sensor-verify function */
    extra_sensor_verify_fn = site_verify_sensor_fn;

    /* clear the error count */
    pcscan_errors = 0;

    /* initialize the include stack */
    pcscan_stack_depth = 0;

    /* send in a copy so we can free it */
    if (skpcParseOpenFile(strdup(filename))) {
        return -1;
    }

    /* parse */
    (void)yyparse();

    /* return non-zero if we had errors */
    if (pcscan_errors > 0) {
        return -1;
    }

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
