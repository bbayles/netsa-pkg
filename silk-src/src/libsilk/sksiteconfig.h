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
#ifndef _SKSITECONFIG_H
#define _SKSITECONFIG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcs_SKSITECONFIG_H, "$SiLK: sksiteconfig.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skvector.h>

#define SKSITECONFIG_MAX_INCLUDE_DEPTH 16

/* from sksite.c */

extern const char path_format_conversions[];


/* from sksiteconfig_parse.y */

extern int
sksiteconfig_error(
    char               *s);
extern int
sksiteconfig_parse(
    void);

extern int sksiteconfig_testing;


/* from sksiteconfig_lex.l */

extern int
sksiteconfig_lex(
    void);

int
sksiteconfigParse(
    const char         *filename,
    int                 verbose);

#ifdef TEST_PRINTF_FORMATS
#define sksiteconfigErr printf
#else
void
sksiteconfigErr(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif

int
sksiteconfigIncludePop(
    void);
void
sksiteconfigIncludePush(
    char               *filename);


/* this list of definitions is from the automake info page */
#define yymaxdepth  sksiteconfig_maxdepth
#define yyparse     sksiteconfig_parse
#define yylex       sksiteconfig_lex
#define yyerror     sksiteconfig_error
#define yylval      sksiteconfig_lval
#define yychar      sksiteconfig_char
#define yydebug     sksiteconfig_debug
#define yypact      sksiteconfig_pact
#define yyr1        sksiteconfig_r1
#define yyr2        sksiteconfig_r2
#define yydef       sksiteconfig_def
#define yychk       sksiteconfig_chk
#define yypgo       sksiteconfig_pgo
#define yyact       sksiteconfig_act
#define yyexca      sksiteconfig_exca
#define yyerrflag   sksiteconfig_errflag
#define yynerrs     sksiteconfig_nerrs
#define yyps        sksiteconfig_ps
#define yypv        sksiteconfig_pv
#define yys         sksiteconfig_s
#define yy_yys      sksiteconfig_yys
#define yystate     sksiteconfig_state
#define yytmp       sksiteconfig_tmp
#define yyv         sksiteconfig_v
#define yy_yyv      sksiteconfig_yyv
#define yyval       sksiteconfig_val
#define yylloc      sksiteconfig_lloc
#define yyreds      sksiteconfig_reds
#define yytoks      sksiteconfig_toks
#define yylhs       sksiteconfig_yylhs
#define yylen       sksiteconfig_yylen
#define yydefred    sksiteconfig_yydefred
#define yydgoto     sksiteconfig_yydgoto
#define yysindex    sksiteconfig_yysindex
#define yyrindex    sksiteconfig_yyrindex
#define yygindex    sksiteconfig_yygindex
#define yytable     sksiteconfig_yytable
#define yycheck     sksiteconfig_yycheck
#define yyname      sksiteconfig_yyname
#define yyrule      sksiteconfig_yyrule

#if 0
/* Newer versions of flex define these functions.  Declare them here
 * to avoid gcc warnings, and just hope that their signatures don't
 * change. */
int
sksiteconfig_get_leng(
    void);
char *
sksiteconfig_get_text(
    void);
int
sksiteconfig_get_debug(
    void);
void
sksiteconfig_set_debug(
    int                 bdebug);
int
sksiteconfig_get_lineno(
    void);
void
sksiteconfig_set_lineno(
    int                 line_number);
FILE *
sksiteconfig_get_in(
    void);
void
sksiteconfig_set_in(
    FILE               *in_str);
FILE *
sksiteconfig_get_out(
    void);
void
sksiteconfig_set_out(
    FILE               *out_str);
int
sksiteconfig_lex_destroy(
    void);
#endif  /* #if 0 */

#ifdef __cplusplus
}
#endif
#endif /* _SKSITECONFIG_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
