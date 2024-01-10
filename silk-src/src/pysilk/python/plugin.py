#######################################################################
# Copyright (C) 2008-2023 by Carnegie Mellon University.
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
# $SiLK: plugin.py 06ff7a1e6c9e 2023-04-14 19:27:24Z mthomas $
#######################################################################

##########################################################################
# Plugin-related code

import sys

# Differences between versions of Python
if sys.hexversion >= 0x02060000:
    # reduce() was moved from base python to functools in 2.6
    from functools import reduce
else:
    # bytes() did not exist prior to 2.6
    bytes = str


if sys.hexversion >= 0x02050000:
    from struct import Struct
else:
    # 2.4 doesn't have struct.Struct, so emulate it
    import struct
    class Struct(object):
        def __init__(self, fmt):
            self.format = fmt
            self.size = struct.calcsize(fmt)
        def pack(self, *args):
            return struct.pack(self.format, *args)
        def unpack(self, arg):
            return struct.unpack(self.format, arg)

if sys.hexversion >= 0x03000000:
    # 3.x doesn't have callable
    def callable(o):
        return hasattr(o, '__call__')
    # 3.x uses items() to get an iterable of items
    def iteritems(o):
        return o.items()
    # Used instead of b'something', which 2.4 would barf on
    def b(o):
        return o.encode("ascii")
else:
    # identity for iteritems
    def iteritems(o):
        return o.iteritems()
    # Used instead of b'something', which 2.4 would barf on
    def b(o):
        return o

__all__ = ['register_field', 'register_filter',
           'register_ipv4_field', 'register_ip_field', 'register_int_field',
           'register_enum_field', 'register_int_sum_aggregator',
           'register_int_min_aggregator', 'register_int_max_aggregator',
           'register_switch']

def _check_type(names, kwds):
    for (kwd, val) in iteritems(kwds):
        if kwd not in names:
            raise ValueError("Illegal argument name '%s'" % kwd)
        name_spec = names[kwd]
        tcheck = name_spec
        check = None
        if isinstance(name_spec, tuple):
            (tcheck, check, errmsg) = name_spec
        if isinstance(tcheck, type):
            if not isinstance(val, tcheck):
                raise TypeError("Argument '%s' must be of type %s"
                                % (kwd, tcheck))
            if check is not None and not check(val):
                raise ValueError("Argument '%s' %s" % (kwd, errmsg))
        elif not callable(val):
            raise TypeError("Argument '%s' must be a function of %d arguments"
                            % (kwd, name_spec))

# Convert str values to bytes (For Python 3.x)
def _byteify_string_values(kwds):
    if sys.hexversion >= 0x03000000:
        for (kwd, val) in kwds.items():
            if isinstance(val, str):
                kwds[kwd] = b(val)

def _register_fieldlike(name, data, names, prereqs, kwds):
    if not isinstance(name, str):
        raise TypeError("Name must be a string")
    str_name = name
    name = b(name)

    for val in data:
        if val['name'] == name:
            raise ValueError("A field '%s' has already been registered"
                             % str_name)

    _check_type(names, kwds)

    # This may throw an error for missing 'bin_bytes' when
    # 'rec_to_bin' is specified even though the plug-in is being used
    # in rwcut which does not use the 'rec_to_bin' function.
    #
    ## Check pre-requisites
    #for (kwd, prereqs) in iteritems(prereqs):
    #    if kwd in kwds:
    #        for pre in prereqs:
    #            if pre not in kwds:
    #                raise ValueError(
    #                    "Argument '%s' requires '%s' to be defined"
    #                    % (kwd, pre))

    _byteify_string_values(kwds)

    kwds['name'] = name
    data.append(kwds)


# The order for these fields must be the same as the order of the
# field_index_t in silkpython.c
_plugin_name_list = ['name', 'description', 'initialize', 'column_width',
                     'rec_to_text', 'bin_bytes', 'rec_to_bin',
                     'bin_to_text', 'add_rec_to_bin', 'bin_merge',
                     'bin_compare', 'initial_value']

def _get_generic_data(data, attr_list):
    retval = []
    for item in data:
        if '__used__' not in item:
            retval.append(tuple([item.get(x, None) for x in attr_list]))
            item['__used__'] = True
    return retval

_plugin_data = []
_plugin_names = {'description': str,
                 'initialize' : 0,
                 'column_width': (int, lambda x: x >= 1, "must be positive"),
                 'rec_to_text': 1,
                 'bin_bytes': (int, lambda x: x >= 1, "must be positive"),
                 'rec_to_bin': 1,
                 'bin_to_text': 1,
                 'add_rec_to_bin': 2,
                 'bin_merge' : 2,
                 'bin_compare' : 2,
                 'initial_value' : bytes}
_plugin_prereq = {'rec_to_bin' : ['bin_bytes'],
                  'rec_to_text' : ['column_width'],
                  'bin_to_text' : ['bin_bytes', 'column_width'],
                  'add_rec_to_bin' : ['bin_bytes'],
                  'bin_merge' : ['bin_bytes'],
                  'bin_compare' : ['bin_bytes']}


def _get_field_data():
    return _get_generic_data(_plugin_data, _plugin_name_list)

def register_field(name, **kwds):
    return _register_fieldlike(name, _plugin_data, _plugin_names,
                               _plugin_prereq, kwds)

# The order for these fields must be the same as the order of the
# filter_index_t in silkpython.c
_filter_name_list = ['filter', 'initialize', 'finalize']

_filter_data = []
_filter_names = {'filter': 1,
                 'initialize' : 0,
                 'finalize' : 0}

def _get_filter_data():
    return _get_generic_data(_filter_data, _filter_name_list)

def register_filter(filter, **kwds):
    kwds['filter'] = filter
    _check_type(_filter_names, kwds)
    _filter_data.append(kwds)

# The order for these fields must be the same as the order of the
# switch_index_t in silkpython.c
_cmd_line_name_list = ['name', 'handler', 'arg', 'help']

_cmd_line_args = []
_cmd_line_names = {'name': str,
                   'handler': 1,
                   'arg': bool,
                   'help': str}

def _get_cmd_line_args():
    return _get_generic_data(_cmd_line_args, _cmd_line_name_list);

def register_switch(name, **kwds):
    kwds['name'] = name
    kwds.setdefault('arg', True)
    kwds.setdefault('help', 'No help for this switch')
    _check_type(_cmd_line_names, kwds)
    _byteify_string_values(kwds)
    _cmd_line_args.append(kwds)

import os
import sys
import traceback

_programname = None

def _no_traceback_exception(t, value, tb):
    global _programname
    if _programname:
        printname = _programname
    else:
        try:
            printname = sys.argv[0]
        except:
            printname = "python"
    sys.stderr.write(printname + ": PySiLK plugin: " + t.__name__)
    if value and str(value):
        sys.stderr.write(": " + str(value))
    sys.stderr.write("\n")
    if os.getenv("SILK_PYTHON_TRACEBACK"):
        traceback.print_tb(tb)

def _init_silkpython_plugin(name):
    global _programname
    _programname = name
    sys.excepthook = _no_traceback_exception


## Register field convenience functions

import silk
struct_fmts = [Struct(x) for x in [b('!B'), b('!H'), b('!L'), b('!Q')]]
struct_map = {}

class convert_from_larger(object):
    def __init__(self, fmt, size):
        self.fmt = fmt
        self.size = -size
        self.pad = b('\0') * (self.fmt.size - size)
    def pack(self, num):
        return self.fmt.pack(num)[self.size:]
    def unpack(self, s):
        return self.fmt.unpack(self.pad + s)

class convert_128(object):
    def __init__(self, conv64):
        self.fmt = Struct(b('!2') + b(conv64.format[-1:]))
    def pack(self, num):
        return self.fmt.pack(num >> 64, num & 0xffffffffffffffff)
    def unpack(self, s):
        (a, b) = self.fmt.unpack(s)
        return ((a << 64) | b,)

def setup_struct_map():
    current = 1
    for fmt in struct_fmts:
        struct_map[fmt.size] = fmt
        for i in range(current, fmt.size):
            struct_map[i] = convert_from_larger(fmt, i)
        current = fmt.size + 1
    if 16 not in struct_map and isinstance(struct_map.get(8), Struct):
        struct_map[16] = convert_128(struct_map[8])

setup_struct_map()

if sys.hexversion < 0x02060000:
    # Python 2.[45] version
    def Int2String(num, nbytes):
        bytes = ['\0']*nbytes
        n, count = num, (nbytes - 1)
        while n:
            bytes[count] = chr(n & 0xff)
            n >>= 8
            count -= 1
        str = ''.join(bytes)
        return str
else:
    # Python >= 2.6 version (uses bytearrays)
    def Int2String(num, nbytes):
        string = bytearray(nbytes)
        n, count = num, (nbytes - 1)
        while n:
            string[count] = chr(n & 0xff)
            n >>= 8
            count -= 1
        return bytes(string)

def int_to_bin(num, nbytes):
    fn =  struct_map.get(nbytes)
    if fn:
        return fn.pack(num)
    return Int2String(num, nbytes)

def String2Int(str):
    num = reduce(lambda x, y: (x << 8) | y, map(ord, str))
    return num

def bin_to_int(str, nbytes):
    fn = struct_map.get(nbytes)
    if fn:
        return fn.unpack(str)[0]
    return String2Int(str)

def bytes_for_val(num):
    n = num
    count = 0
    while n:
        n >>= 8
        count += 1
    return count

def register_ipv4_field(name, ipv4_function, width=15):
    def call_fn(rec):
        res = ipv4_function(rec)
        if not isinstance(res, silk.IPv4Addr):
            err = "%s expects only IPv4 addresses" % name
            raise TypeError(err)
        return res
    def rec_to_bin(rec):
        return int_to_bin(int(call_fn(rec)), 4)
    def rec_to_text(rec):
        return str(call_fn(rec))
    def bin_to_text(bin):
        return str(silk.IPv4Addr(bin_to_int(bin, 4)))
    register_field(name,
                   rec_to_text = rec_to_text,
                   rec_to_bin = rec_to_bin,
                   bin_to_text = bin_to_text,
                   column_width = width,
                   bin_bytes = 4)

def _register_ip_field(name, ip_function, width=39):
    def rec_to_bin(rec):
        ip = ip_function(rec).to_ipv6()
        return int_to_bin(int(ip_function(rec)), 16)
    def rec_to_text(rec):
        return str(ip_function(rec))
    def bin_to_text(bin):
        ipv6 = silk.IPv6Addr(bin_to_int(bin, 16))
        ip = ipv6.to_ipv4()
        ip = ip or ipv6
        return str(ip)
    register_field(name,
                   rec_to_text = rec_to_text,
                   rec_to_bin = rec_to_bin,
                   bin_to_text = bin_to_text,
                   column_width = width,
                   bin_bytes = 16)

if silk.ipv6_enabled():
    register_ip_field = _register_ip_field
else:
    register_ip_field = register_ipv4_field

class int_conv(object):
    def __init__(self, fn, min, max):
        range = max - min + 1
        self.min = min
        self.bytes = bytes_for_val(range)
        self.fn = fn
    def rec_to_bin(self, rec):
        return int_to_bin(self.fn(rec) - self.min, self.bytes)
    def rec_to_text(self, rec):
        return str(self.fn(rec))
    def bin_to_text(self, bin):
        return str(bin_to_int(bin, self.bytes))


def register_int_field(name, int_function, min, max, width=None):
    if min > max:
        raise ValueError("minimum value must be less than the maximum value")
    conv = int_conv(int_function, min, max)
    if width is None:
        width = len(str(max))
    register_field(name,
                   rec_to_text = conv.rec_to_text,
                   rec_to_bin = conv.rec_to_bin,
                   bin_to_text = conv.bin_to_text,
                   column_width = width,
                   bin_bytes = conv.bytes)


class enum_conv(object):
    def __init__(self, fn, ordering):
        self.fn = fn
        self.nextindex = 0
        self.map = {}
        self.list = []
        for item in ordering:
            self.map[item] = self.nextindex
            self.nextindex += 1
            self.list.append(item)

    def rec_to_bin(self, rec):
        key = self.fn(rec)
        i = self.map.get(key)
        if i is None:
            if self.nextindex > 0xffffffff:
                raise RuntimeError("Too many items")
            i = self.nextindex
            self.nextindex += 1
            self.map[key] = i
            self.list.append(key)
        return int_to_bin(i, 4)

    def rec_to_text(self, rec):
        return str(self.fn(rec))

    def bin_to_text(self, bin):
        return str(self.list[bin_to_int(bin, 4)])


def register_enum_field(name, enum_function, width, ordering=[]):
    conv = enum_conv(enum_function, ordering)
    register_field(name,
                   rec_to_text = conv.rec_to_text,
                   rec_to_bin = conv.rec_to_bin,
                   bin_to_text = conv.bin_to_text,
                   column_width = width,
                   bin_bytes = 4)


class int_agg_conv(object):
    def __init__(self, fn, max, name="Aggregate field", agg=None):
        self.bytes = bytes_for_val(max)
        self.fn = fn
        self.maxval = max
        self.name = name
        if agg is None:
            self.agg = self.sum
        else:
            self.agg = agg

    def add_rec_to_bin(self, rec, bin):
        newval = self.agg(bin_to_int(bin, self.bytes), self.fn(rec))
        return int_to_bin(newval, self.bytes)

    def bin_compare(self, b1, b2):
        n1 = bin_to_int(b1, self.bytes)
        n2 = bin_to_int(b2, self.bytes)
        # used instead of cmp(), as Python 3.x doesn't have cmp()
        return (n1 > n2) - (n1 < n2)

    def bin_merge(self, b1, b2):
        newval = self.agg(bin_to_int(b1, self.bytes),
                          bin_to_int(b2, self.bytes))
        return int_to_bin(newval, self.bytes)

    def bin_to_text(self, bin):
        return str(bin_to_int(bin, self.bytes))

    def bin_initial(self, max=None):
        if max:
            val = self.maxval
        else:
            val = 0
        return int_to_bin(val, self.bytes)

    def sum(self, a, b):
        rv = a + b
        if rv > self.maxval:
            raise OverflowError("%s overflowed" % self.name)
        return rv


def register_int_aggregator(name, int_function,
                            max, width, agg=None, init=None):
    conv = int_agg_conv(int_function, max, name=name, agg=agg)
    bytes = bytes_for_val(max)
    if width is None:
        width = len(str(conv.maxval))
    if init is None:
        init = conv.bin_initial()
    elif init == "__maxval__":
        init = conv.bin_initial(max=True)
    elif len(init) != bytes:
        raise ValueError("Bad initial value")
    register_field(name,
                   bin_to_text = conv.bin_to_text,
                   add_rec_to_bin = conv.add_rec_to_bin,
                   bin_compare = conv.bin_compare,
                   bin_merge = conv.bin_merge,
                   initial_value = init,
                   column_width = width,
                   bin_bytes = bytes)


max64 = (1 << 64) - 1
maxfn = max

def register_int_sum_aggregator(name, int_function, max=max64, width=None):
    register_int_aggregator(name, int_function, max, width)

def register_int_max_aggregator(name, int_function, max=max64, width=None):
    register_int_aggregator(name, int_function, max, width, maxfn)

def register_int_min_aggregator(name, int_function, max=max64, width=None):
    register_int_aggregator(name, int_function, max, width, min,
                            init="__maxval__")
