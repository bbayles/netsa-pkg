#######################################################################
# Copyright (C) 2007-2023 by Carnegie Mellon University.
#
# @OPENSOURCE_LICENSE_START@
#
# SiLK 3.22.0
#
# Copyright 2023 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
# THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
# ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
# INFRINGEMENT.
#
# Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
#
# Contract No.: FA8702-15-D-0002
# Contractor Name: Carnegie Mellon University
# Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
#
# The Government's rights to use, modify, reproduce, release, perform,
# display, or disclose this software are restricted by paragraph (b)(2) of
# the Rights in Noncommercial Computer Software and Noncommercial Computer
# Software Documentation clause contained in the above identified
# contract. No restrictions apply after the expiration date shown
# above. Any reproduction of the software or portions thereof marked with
# this legend must also reproduce the markings.
#
# Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
# Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each
# subject to its own license.
#
# DM23-0973
#
# @OPENSOURCE_LICENSE_END@
#
#######################################################################

#######################################################################
# $SiLK: site.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

import silk
try:
    import silk.pysilk_pin as pysilk
except ImportError:
    import silk.pysilk as pysilk

import copy
import datetime
import sys

# Python 3.x values() returns iterator over values
if sys.hexversion >= 0x03000000:
    basestring = str
    def itervalues(o):
        return o.values()
else:
    def itervalues(o):
        return o.itervalues()


__all__ = ['sensors', 'classes', 'classtypes', 'types', 'default_types',
           'default_class', 'class_sensors', 'sensor_classes', 'sensor_id',
           'sensor_description', 'classtype_id', 'classtype_from_id',
           'sensor_from_id', 'init_site', 'have_site_config',
           'get_site_config', 'get_data_rootdir',
           'set_data_rootdir', 'repository_iter', 'repository_full_iter',
           'repository_silkfile_iter']

init_site = pysilk.init_site
have_site_config = pysilk.have_site_config
get_site_config = pysilk.get_site_config
get_data_rootdir = pysilk.get_data_rootdir
set_data_rootdir = pysilk.set_data_rootdir

_initialized = False

_sensor_map = {}
_class_map = {}
_flowtype_map = {}
_classtype_map = {}
_default_class = None

# sensor_info() ->
#     {<sensor-id>:
#         {'id': <sensor-id>,
#          'name': <sensor-name>,
#          'classes': <class-id list>},
#      ...}

# class_info() ->
#     {'default': <class-id>,
#      'data':
#          {<class-id>:
#              'id': <class-id>,
#              'name: <class-name>,
#              'sensors: <sensor-id list>,
#              'flowtypes: <flowtype-id list>,
#              'default_flowtypes': <flowtype-id list>},
#           ...}
#     }

# flowtype_info() ->
#     {<flowtype-id>:
#         {'id': <flowtype-id>,
#          'name': <flowtype-name>,
#          'type': <type-name>,
#          'class': <class-id>},
#      ...}

def _init_maps():
    global _initialized
    global _default_class
    if _initialized or not (have_site_config() or init_site()):
        return _initialized
    si = pysilk.sensor_info()
    ci = pysilk.class_info()
    fi = pysilk.flowtype_info()
    default_classid = ci['default']
    ci = ci['data']
    for item in itervalues(si):
        newitem = copy.deepcopy(item)
        newitem['classes'] = tuple(ci[x]['name'] for x in item['classes'])
        _sensor_map[item['name']] = newitem
    if default_classid is not None:
        _default_class = ci[default_classid]['name']
    for item in itervalues(ci):
        newitem = copy.deepcopy(item)
        newitem['sensors'] = tuple(si[x]['name'] for x in item['sensors'])
        newitem['flowtypes'] = tuple(fi[x]['name'] for x in item['flowtypes'])
        newitem['default_flowtypes'] = tuple(fi[x]['name'] for x in
                                             item['default_flowtypes'])
        _class_map[item['name']] = newitem
    for item in itervalues(fi):
        newitem = copy.deepcopy(item)
        newitem['class'] = ci[item['class']]['name']
        _flowtype_map[item['name']] = newitem
        cdict = _classtype_map.setdefault(ci[item['class']]['name'], {})
        cdict[item['type']] = newitem
    _initialized = True
    return True

def default_class():
    "default_class() -> default class (None if site not initialized)"
    _init_maps()
    return _default_class

def sensors():
    "sensors() -> tuple of sensors"
    _init_maps()
    return tuple(_sensor_map)

def class_sensors(cls):
    "class_sensors(class) -> tuple of sensors in class"
    _init_maps()
    return _class_map[cls]['sensors']

def classes():
    "classes() -> tuple of classes"
    _init_maps()
    return tuple(_class_map)

def sensor_classes(sensor):
    "sensor_classes(sensor) -> tuple of classes associated with sensor"
    _init_maps()
    return _sensor_map[sensor]['classes']

def sensor_description(sensor):
    "sensor_description(sensor) -> description of sensor, or None"
    _init_maps()
    return _sensor_map[sensor].get('description')

def classtypes():
    "classtypes() -> tuple of (class, type) pairs"
    _init_maps()
    clinfo = pysilk.class_info()['data']
    return tuple((clinfo[x['class']]['name'], x['type'])
                 for x in itervalues(pysilk.flowtype_info()))

def types(cls):
    "types(class) -> tuple of types in class"
    _init_maps()
    return tuple(_flowtype_map[x]['type']
                 for x in _class_map[cls]['flowtypes'])

def default_types(cls):
    "default_types(class) -> tuple of default types in class"
    _init_maps()
    return tuple(_flowtype_map[x]['type']
                 for x in _class_map[cls]['default_flowtypes'])

def sensor_id(sensor):
    "sensor_id(sensor) -> numeric id of sensor"
    _init_maps()
    return _sensor_map[sensor]['id']

def sensor_from_id(id):
    "sensor_from_id(id) -> sensor from numeric id"
    if not _init_maps():
        raise KeyError(id)
    sinfo = pysilk.sensor_info()
    return sinfo[id]['name']

def classtype_id(classtype):
    "classtype_id((class, type)) -> numeric id of (class, type) pair"
    if not _init_maps():
        raise KeyError(id)
    (c, t) = classtype
    return _classtype_map[c][t]['id']

def classtype_from_id(id):
    "classtype_from_id(id) -> (class, type) pair from numeric id"
    if not _init_maps():
        raise KeyError(id)
    finfo = pysilk.flowtype_info()[id]
    cinfo = pysilk.class_info()['data']
    return (cinfo[finfo['class']]['name'], finfo['type'])


class SiteRepoIter(pysilk.RepoIter):
    def __init__(self,
                 start=None,
                 end=None,
                 classname=None,
                 types=None,
                 classtypes=None,
                 sensors=None,
                 missing=False):
        self.rootdir = get_data_rootdir()
        if start is None:
            if end is not None:
                raise ValueError("end may not be specified without start")
            start = datetime.date.today()
        if classtypes is not None:
            if classname is not None or types is not None:
                raise ValueError("classtypes cannot be specified alongside "
                                 "classname or types")
            if isinstance(classtypes, basestring):
                classtypes = [classtypes]
            if (len(classtypes) == 2
                and isinstance(classtypes[0], basestring)
                and isinstance(classtypes[1], basestring)):
                classtypes = [classtypes]
            for item in classtypes:
                if (len(item) != 2
                    or not isinstance(item[0], basestring)
                    or not isinstance(item[1], basestring)):
                    raise ValueError("\"%s\" is not a valid (class, type) pair"
                                     % (item,))
            classtypes = [tuple(x) for x in classtypes]
        if classname is None:
            if types is not None:
                raise ValueError("types requires classname to be specified")
            elif classtypes is None:
                dc = default_class()
                if dc is not None:
                    classtypes = [(dc, t) for t in default_types(dc)]
        elif types is None:
            classtypes = [(classname, t) for t in default_types(classname)]
        elif isinstance(types, basestring):
            classtypes = [(classname, types)]
        else:
            classtypes = [(classname, t) for t in types]
        if isinstance(sensors, basestring):
            sensors = [sensors]

        pysilk.RepoIter.__init__(self, start, end,
                                 classtypes, sensors, missing)

    def __iter__(self):
        if self.rootdir != get_data_rootdir():
            raise RuntimeError(
                "Underlying root directory changed during iteration")
        return pysilk.RepoIter.__iter__(self)

def repository_iter_(iter):
    for x in iter:
        yield(x[0])

def repository_iter(start=None, end=None, classname=None, types=None,
                    classtypes=None, sensors=None):
    return repository_iter_(
        SiteRepoIter(start, end, classname, types,
                     classtypes, sensors, missing=False))

def repository_full_iter(start=None, end=None, classname=None, types=None,
                         classtypes=None, sensors=None):
    return SiteRepoIter(start, end, classname, types,
                        classtypes, sensors, missing=True)

def repository_silkfile_iter_(iter):
    for x in iter:
        yield(silk.SilkFile(x[0], silk.READ))

def repository_silkfile_iter(start=None, end=None, classname=None, types=None,
                             classtypes=None, sensors=None):
    return repository_silkfile_iter_(
        SiteRepoIter(start, end, classname, types,
                     classtypes, sensors, missing=False))
