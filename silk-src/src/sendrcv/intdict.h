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
#ifndef _INTDICT_H
#define _INTDICT_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_INTDICT_H, "$SiLK: intdict.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  intdict.h
**
**  Integer dictionaries
**
*/


typedef int32_t intkey_t;

struct int_dict_st;
typedef struct int_dict_st int_dict_t;

struct int_dict_iter_st;
typedef struct int_dict_iter_st int_dict_iter_t;

int_dict_t *
int_dict_create(
    size_t              value_size);

void
int_dict_destroy(
    int_dict_t         *dict);

void *
int_dict_get(
    int_dict_t         *dict,
    intkey_t            key,
    void               *value);

void *
int_dict_get_first(
    int_dict_t         *dict,
    intkey_t           *key,
    void               *value);

void *
int_dict_get_last(
    int_dict_t         *dict,
    intkey_t           *key,
    void               *value);

void *
int_dict_get_next(
    int_dict_t         *dict,
    intkey_t           *key,
    void               *value);

void *
int_dict_get_prev(
    int_dict_t         *dict,
    intkey_t           *key,
    void               *value);

int
int_dict_set(
    int_dict_t         *dict,
    intkey_t            key,
    void               *value);

int
int_dict_del(
    int_dict_t         *dict,
    intkey_t            key);

unsigned int
int_dict_get_count(
    int_dict_t         *dict);

int_dict_iter_t *
int_dict_open(
    int_dict_t         *dict);

void *
int_dict_next(
    int_dict_iter_t    *iter,
    intkey_t           *key,
    void               *value);

void
int_dict_close(
    int_dict_iter_t    *iter);

#ifdef __cplusplus
}
#endif
#endif /* _INTDICT_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
