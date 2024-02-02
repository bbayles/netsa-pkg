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
**  Test a site configuration file.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sksiteconfig-test.c d5c2aee1abcc 2023-05-01 21:10:21Z mthomas $");

#include <silk/sksite.h>
#include <silk/utils.h>
#include "sksiteconfig.h"


static void
print_sensors(
    void)
{
    char                    name[2048];
    const char             *sensor_desc;
    sk_sensor_id_t          sensor_id;
    sk_sensor_id_t          max_sensor_id;
    int                     sensor_maxlen;

    memset(name, 0, sizeof(name));

    max_sensor_id = sksiteSensorGetMaxID();
    if (max_sensor_id == (sk_sensor_id_t)-1) {
        return;
    }
    sensor_maxlen = -1 * (int)sksiteSensorGetMaxNameStrLen();

    printf("Sensors:\n--------\n");
    sensor_id = sksiteSensorGetMinID();
    for ( ; sensor_id <= max_sensor_id; ++sensor_id) {
        if (!sksiteSensorExists(sensor_id)) {
            continue;
        }
        sksiteSensorGetName(name, sizeof(name), sensor_id);
        sensor_desc = sksiteSensorGetDescription(sensor_id);
        if (NULL == sensor_desc) {
            printf("%*s|%5u|\n",
                   sensor_maxlen, name, sensor_id);
        } else {
            printf("%*s|%5u|\"%s\"\n",
                   sensor_maxlen, name, sensor_id, sensor_desc);
        }
    }
    printf("\n");
}


static void
print_sensor_sensorgroups(
    void)
{
    char                    name[2048];
    sk_sensor_id_t          sensor_id;
    sk_sensor_id_t          max_sensor_id;
    sk_sensorgroup_id_t     sensorgroup_id;
    sk_sensorgroup_iter_t   gr_iter;
    int                     sensor_maxlen;

    memset(name, 0, sizeof(name));

    if (sksiteSensorgroupGetMaxID() == (sk_sensorgroup_id_t)-1) {
        return;
    }

    max_sensor_id = sksiteSensorGetMaxID();
    if (max_sensor_id == (sk_sensor_id_t)-1) {
        return;
    }
    sensor_maxlen = -1 * (int)sksiteSensorGetMaxNameStrLen();

    printf("Sensor - Sensorgroups:\n----------------------\n");
    sensor_id = sksiteSensorGetMinID();
    for ( ; sensor_id <= max_sensor_id; ++sensor_id) {
        if (!sksiteSensorExists(sensor_id)) {
            continue;
        }

        sksiteSensorSensorgroupIterator(sensor_id, &gr_iter);
        if (!sksiteSensorgroupIteratorNext(&gr_iter, &sensorgroup_id)) {
            continue;
        }

        sksiteSensorGetName(name, sizeof(name), sensor_id);
        printf("%*s|%5u|",
               sensor_maxlen, name, sensor_id);
        sksiteSensorgroupGetName(name, sizeof(name), sensorgroup_id);
        printf("%s", name);

        while (sksiteSensorgroupIteratorNext(&gr_iter, &sensorgroup_id)) {
            sksiteSensorgroupGetName(name, sizeof(name), sensorgroup_id);
            printf(", %s", name);
        }
        printf("\n");
    }
    printf("\n");
}


static void
print_sensor_classes(
    void)
{
    char                    name[2048];
    sk_sensor_id_t          sensor_id;
    sk_sensor_id_t          max_sensor_id;
    sk_class_id_t           class_id;
    sk_class_iter_t         cl_iter;
    int                     sensor_maxlen;

    memset(name, 0, sizeof(name));

    max_sensor_id = sksiteSensorGetMaxID();
    if (max_sensor_id == (sk_sensor_id_t)-1) {
        return;
    }
    sensor_maxlen = -1 * (int)sksiteSensorGetMaxNameStrLen();

    printf("Sensor - Classes:\n-----------------\n");
    sensor_id = sksiteSensorGetMinID();
    for ( ; sensor_id <= max_sensor_id; ++sensor_id) {
        if (!sksiteSensorExists(sensor_id)) {
            continue;
        }

        sksiteSensorClassIterator(sensor_id, &cl_iter);
        if (!sksiteClassIteratorNext(&cl_iter, &class_id)) {
            continue;
        }

        sksiteSensorGetName(name, sizeof(name), sensor_id);
        printf("%*s|%5u|",
               sensor_maxlen, name, sensor_id);
        sksiteClassGetName(name, sizeof(name), class_id);
        printf("%s", name);

        while (sksiteClassIteratorNext(&cl_iter, &class_id)) {
            sksiteClassGetName(name, sizeof(name), class_id);
            printf(", %s", name);
        }
        printf("\n");
    }
    printf("\n");
}


static void
print_sensorgroups(
    void)
{
    char                    name[2048];
    const char             *comma;
    sk_sensorgroup_id_t     group_id;
    sk_sensorgroup_id_t     max_group_id;
    sk_sensor_id_t          sensor_id;
    sk_sensor_iter_t        sn_iter;
    int                     group_maxlen;

    memset(name, 0, sizeof(name));

    max_group_id = sksiteSensorgroupGetMaxID();
    if (max_group_id == (sk_sensorgroup_id_t)-1) {
        return;
    }
    group_maxlen = -1 * (int)sksiteSensorgroupGetMaxNameStrLen();

    printf("Sensorgroups:\n-------------\n");
    for (group_id = 0; group_id <= max_group_id; ++group_id) {
        if (!sksiteSensorgroupExists(group_id)) {
            continue;
        }
        sksiteSensorgroupGetName(name, sizeof(name), group_id);
        printf("%*s|", group_maxlen, name);

        comma = "";
        sksiteSensorgroupSensorIterator(group_id, &sn_iter);
        while (sksiteSensorIteratorNext(&sn_iter, &sensor_id)) {
            sksiteSensorGetName(name, sizeof(name), sensor_id);
            printf("%s%s(%u)", comma, name, sensor_id);
            if ('\0' == comma[0]) {
                comma = ", ";
            }
        }
        printf("\n");
    }
    printf("\n");
}


static void
print_flowtypes(
    void)
{
    char                    name[2048];
    sk_flowtype_id_t        max_flowtype_id;
    sk_flowtype_id_t        flowtype_id;
    int                     flowtype_maxlen;
    int                     class_maxlen;
    int                     type_maxlen;

    memset(name, 0, sizeof(name));

    max_flowtype_id = sksiteFlowtypeGetMaxID();
    if (max_flowtype_id == (sk_flowtype_id_t)-1) {
        return;
    }

    flowtype_maxlen = -1 * (int)sksiteFlowtypeGetMaxNameStrLen();
    class_maxlen = -1 * (int)sksiteClassGetMaxNameStrLen();
    type_maxlen = -1 * (int)sksiteFlowtypeGetMaxTypeStrLen();

    printf("Flowtypes:\n--------\n");
    for (flowtype_id = 0; flowtype_id <= max_flowtype_id; ++flowtype_id) {
        if (!sksiteFlowtypeExists(flowtype_id)) {
            continue;
        }
        sksiteFlowtypeGetName(name, sizeof(name), flowtype_id);
        printf("%*s|%3u|", flowtype_maxlen, name, flowtype_id);

        sksiteFlowtypeGetClass(name, sizeof(name), flowtype_id);
        printf("%*s|", class_maxlen, name);

        sksiteFlowtypeGetType(name, sizeof(name), flowtype_id);
        printf("%*s|\n", type_maxlen, name);
    }
    printf("\n");
}


static void
print_class_flowtypes(
    void)
{
    char                    name[2048];
    sk_class_id_t           class_id;
    sk_class_id_t           max_class_id;
    sk_flowtype_id_t        flowtype_id;
    sk_flowtype_iter_t      ft_iter;
    int                     class_maxlen;

    memset(name, 0, sizeof(name));

    max_class_id = sksiteClassGetMaxID();
    if (max_class_id == (sk_class_id_t)-1) {
        return;
    }
    class_maxlen = -1 * (int)sksiteClassGetMaxNameStrLen();

    printf("Class - Flowtypes:\n------------------\n");
    for (class_id = 0; class_id <= max_class_id; ++class_id) {
        if (!sksiteClassExists(class_id)) {
            continue;
        }

        sksiteClassFlowtypeIterator(class_id, &ft_iter);
        if (!sksiteFlowtypeIteratorNext(&ft_iter, &flowtype_id)) {
            continue;
        }

        sksiteClassGetName(name, sizeof(name), class_id);
        printf("%*s|", class_maxlen, name);
        sksiteFlowtypeGetName(name, sizeof(name), flowtype_id);
        printf("%s(%u)", name, flowtype_id);

        while (sksiteFlowtypeIteratorNext(&ft_iter, &flowtype_id)) {
            sksiteFlowtypeGetName(name, sizeof(name), flowtype_id);
            printf(", %s(%u)", name, flowtype_id);
        }
        printf("\n");
    }
    printf("\n");
}


static void
print_class_sensors(
    void)
{
    char                    name[2048];
    sk_class_id_t           class_id;
    sk_class_id_t           max_class_id;
    sk_sensor_id_t          sensor_id;
    sk_sensor_iter_t        sn_iter;
    int                     class_maxlen;

    memset(name, 0, sizeof(name));

    max_class_id = sksiteClassGetMaxID();
    if (max_class_id == (sk_class_id_t)-1) {
        return;
    }
    class_maxlen = -1 * (int)sksiteClassGetMaxNameStrLen();

    printf("Class - Sensors:\n----------------\n");
    for (class_id = 0; class_id <= max_class_id; ++class_id) {
        if (!sksiteClassExists(class_id)) {
            continue;
        }

        sksiteClassSensorIterator(class_id, &sn_iter);
        if (!sksiteSensorIteratorNext(&sn_iter, &sensor_id)) {
            continue;
        }

        sksiteClassGetName(name, sizeof(name), class_id);
        printf("%*s|", class_maxlen, name);
        sksiteSensorGetName(name, sizeof(name), sensor_id);
        printf("%s(%u)", name, sensor_id);

        while (sksiteSensorIteratorNext(&sn_iter, &sensor_id)) {
            sksiteSensorGetName(name, sizeof(name), sensor_id);
            printf(", %s(%u)", name, sensor_id);
        }
        printf("\n");
    }
    printf("\n");
}


static void
print_summary(
    void)
{
    printf("\nSummary:\n========\n\n");
    print_sensors();
    print_sensor_sensorgroups();
    print_sensorgroups();
    print_flowtypes();
    print_class_flowtypes();
    print_class_sensors();
    print_sensor_classes();
}


int
main(
    int     argc,
    char  **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int rv = 0;

    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    sksiteconfig_testing = 1;

    if ( argc == 2 ) {
        sksiteSetConfigPath(argv[1]);
        rv = sksiteConfigure(1);
    } else {
        fprintf(stderr, "usage: %s <filename>\n", skAppName());
        rv = -1;
    }
    if (-1 != rv) {
        print_summary();
    }

    skAppUnregister();
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
