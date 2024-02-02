/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ACCEPT_FROM_HOST_T = 258,
     COMMA = 259,
     END_GROUP_T = 260,
     END_PROBE_T = 261,
     END_SENSOR_T = 262,
     EOL = 263,
     GROUP_T = 264,
     INCLUDE_T = 265,
     INTERFACES_T = 266,
     INTERFACE_VALUES_T = 267,
     IPBLOCKS_T = 268,
     IPSETS_T = 269,
     ISP_IP_T = 270,
     LISTEN_AS_HOST_T = 271,
     LISTEN_ON_PORT_T = 272,
     LISTEN_ON_USOCKET_T = 273,
     LOG_FLAGS_T = 274,
     POLL_DIRECTORY_T = 275,
     PRIORITY_T = 276,
     PROBE_T = 277,
     PROTOCOL_T = 278,
     QUIRKS_T = 279,
     READ_FROM_FILE_T = 280,
     REMAINDER_T = 281,
     SENSOR_T = 282,
     ID = 283,
     NET_NAME_INTERFACE = 284,
     NET_NAME_IPBLOCK = 285,
     NET_NAME_IPSET = 286,
     PROBES = 287,
     QUOTED_STRING = 288,
     NET_DIRECTION = 289,
     FILTER = 290,
     ERR_STR_TOO_LONG = 291
   };
#endif
/* Tokens.  */
#define ACCEPT_FROM_HOST_T 258
#define COMMA 259
#define END_GROUP_T 260
#define END_PROBE_T 261
#define END_SENSOR_T 262
#define EOL 263
#define GROUP_T 264
#define INCLUDE_T 265
#define INTERFACES_T 266
#define INTERFACE_VALUES_T 267
#define IPBLOCKS_T 268
#define IPSETS_T 269
#define ISP_IP_T 270
#define LISTEN_AS_HOST_T 271
#define LISTEN_ON_PORT_T 272
#define LISTEN_ON_USOCKET_T 273
#define LOG_FLAGS_T 274
#define POLL_DIRECTORY_T 275
#define PRIORITY_T 276
#define PROBE_T 277
#define PROTOCOL_T 278
#define QUIRKS_T 279
#define READ_FROM_FILE_T 280
#define REMAINDER_T 281
#define SENSOR_T 282
#define ID 283
#define NET_NAME_INTERFACE 284
#define NET_NAME_IPBLOCK 285
#define NET_NAME_IPSET 286
#define PROBES 287
#define QUOTED_STRING 288
#define NET_DIRECTION 289
#define FILTER 290
#define ERR_STR_TOO_LONG 291




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 212 "probeconfparse.y"
{
    char               *string;
    sk_vector_t        *vector;
    uint32_t            u32;
    skpc_direction_t    net_dir;
    skpc_filter_t       filter;
}
/* Line 1529 of yacc.c.  */
#line 129 "probeconfparse.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

