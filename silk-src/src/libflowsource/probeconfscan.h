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
#ifndef _PROBECONFSCAN_H
#define _PROBECONFSCAN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_PROBECONFSCAN_H, "$SiLK: probeconfscan.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  probeconfscan.h
**
**  Values needed for the lexer and parser to communicate.
**
*/

#include <silk/utils.h>
#include <silk/probeconf.h>
#include <silk/skvector.h>


/* Provide some grammar debugging info, if necessary */
#define YYDEBUG 1

#define PCSCAN_MAX_INCLUDE_DEPTH 8

/* error message strings */
#define PARSE_MSG_ERROR "Error while parsing file %s at line %d:\n"
#define PARSE_MSG_WARN  "Warning while parsing file %s at line %d:\n"


/* this list of definitions is from the automake info page */
#define yymaxdepth  probeconfscan_maxdepth
#define yyparse     probeconfscan_parse
#define yylex       probeconfscan_lex
#define yyerror     probeconfscan_error
#define yylval      probeconfscan_lval
#define yychar      probeconfscan_char
#define yydebug     probeconfscan_debug
#define yypact      probeconfscan_pact
#define yyr1        probeconfscan_r1
#define yyr2        probeconfscan_r2
#define yydef       probeconfscan_def
#define yychk       probeconfscan_chk
#define yypgo       probeconfscan_pgo
#define yyact       probeconfscan_act
#define yyexca      probeconfscan_exca
#define yyerrflag   probeconfscan_errflag
#define yynerrs     probeconfscan_nerrs
#define yyps        probeconfscan_ps
#define yypv        probeconfscan_pv
#define yys         probeconfscan_s
#define yy_yys      probeconfscan_yys
#define yystate     probeconfscan_state
#define yytmp       probeconfscan_tmp
#define yyv         probeconfscan_v
#define yy_yyv      probeconfscan_yyv
#define yyval       probeconfscan_val
#define yylloc      probeconfscan_lloc
#define yyreds      probeconfscan_reds
#define yytoks      probeconfscan_toks
#define yylhs       probeconfscan_yylhs
#define yylen       probeconfscan_yylen
#define yydefred    probeconfscan_yydefred
#define yydgoto     probeconfscan_yydgoto
#define yysindex    probeconfscan_yysindex
#define yyrindex    probeconfscan_yyrindex
#define yygindex    probeconfscan_yygindex
#define yytable     probeconfscan_yytable
#define yycheck     probeconfscan_yycheck
#define yyname      probeconfscan_yyname
#define yyrule      probeconfscan_yyrule


/* Last keyword */
extern char pcscan_clause[];

/* Global error count for return status of skpcParse */
extern int pcscan_errors;

extern int (*extra_sensor_verify_fn)(skpc_sensor_t *sensor);


int
yyparse(
    void);
int
yylex(
    void);
int
yyerror(
    char               *s);

typedef sk_vector_t number_list_t;

typedef sk_vector_t wildcard_list_t;


int
skpcParseSetup(
    void);

void
skpcParseTeardown(
    void);

#ifdef TEST_PRINTF_FORMATS
#define skpcParseErr printf
#else
int
skpcParseErr(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif

int
skpcParseIncludePop(
    void);

int
skpcParseIncludePush(
    char               *filename);


#if 0
/* Newer versions of flex define these functions.  Declare them here
 * to avoid gcc warnings, and just hope that their signatures don't
 * change. */
int
probeconfscan_get_leng(
    void);
char *
probeconfscan_get_text(
    void);
int
probeconfscan_get_debug(
    void);
void
probeconfscan_set_debug(
    int                 bdebug);
int
probeconfscan_get_lineno(
    void);
void
probeconfscan_set_lineno(
    int                 line_number);
FILE *
probeconfscan_get_in(
    void);
void
probeconfscan_set_in(
    FILE               *in_str);
FILE *
probeconfscan_get_out(
    void);
void
probeconfscan_set_out(
    FILE               *out_str);
int
probeconfscan_lex_destroy(
    void);
#endif  /* #if 0 */

#ifdef __cplusplus
}
#endif
#endif /* _PROBECONFSCAN_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
