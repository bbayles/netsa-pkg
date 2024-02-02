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
# $SiLK: __init__.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

import sys
import warnings

#  When using PySiLK as a plug-in from a SiLK application, the C parts
#  of the SiLK package (which are in the pysilk module) are compiled
#  into the application itself.  We need to use the 'imp' module to
#  make the "silk.pysilk_pin" code availabe.
if "silk.pysilk_pin" in sys.builtin_module_names:
    try:
        # Do not initialize the package again if we already have it
        mod = sys.modules["silk.pysilk_pin"]
    except KeyError:
        # initialize the built-in package, then make it available as
        # silk.pysilk_pin.  The following is a mystery, but it seems
        # to work.  NOTE: The imp module is deprecated in Python 3.4.
        import imp
        mod = imp.init_builtin("silk.pysilk_pin")
        import silk.pysilk_pin
        silk.pysilk_pin = mod
        import silk.pysilk_pin as pysilk
else:
    # use version that is linked against libsilk.
    import silk.pysilk as pysilk

import silk.site
from silk.fglob import FGlob

# Differences between versions of Python
if sys.hexversion < 0x02060000:
    # Python 2.[45]
    Integral = (int, long)
    def next(it):
        return it.next()
else:
    from numbers import Integral

if sys.hexversion < 0x02050000:
    def any(iterable):
        for element in iterable:
            if element:
                return True
        return False

if sys.hexversion >= 0x03000000:
    # Python 3.x
    basestring = str
    long = int
    def iteritems(o):
        return o.items()
else:
    def iteritems(o):
        return o.iteritems()


__all__ = ['IPAddr', 'IPv4Addr', 'IPv6Addr',
           'IPWildcard', 'IPSet', 'RWRec', 'TCPFlags', 'SilkFile',
           'silkfile_open', 'silkfile_fdopen',
           'PrefixMap', 'AddressPrefixMap', 'ProtoPortPrefixMap', 'Bag',
           'BAG_COUNTER_MAX',
           'IGNORE', 'ASV4', 'MIX', 'FORCE', 'ONLY',
           'READ', 'WRITE', 'APPEND',
           'DEFAULT', 'NO_COMPRESSION', 'ZLIB', 'LZO1X', 'SNAPPY',
           'FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR',
           'TCP_FIN', 'TCP_SYN', 'TCP_RST', 'TCP_PSH',
           'TCP_ACK', 'TCP_URG', 'TCP_ECE', 'TCP_CWR',
           'sensors', 'classes', 'classtypes',
           'init_site', 'have_site_config',
           'silk_version',
           'initial_tcpflags_enabled', 'ipv6_enabled',
           'init_country_codes', 'FGlob']


# Forward objects from the pysilk module to silk
IPAddr = pysilk.IPAddr
IPv4Addr = pysilk.IPv4Addr
IPv6Addr = pysilk.IPv6Addr
IPWildcard = pysilk.IPWildcard
TCPFlags = pysilk.TCPFlags
IGNORE = pysilk.IGNORE
ASV4 = pysilk.ASV4
MIX = pysilk.MIX
FORCE = pysilk.FORCE
ONLY = pysilk.ONLY
READ = pysilk.READ
WRITE = pysilk.WRITE
APPEND = pysilk.APPEND
DEFAULT = pysilk.DEFAULT
NO_COMPRESSION = pysilk.NO_COMPRESSION
ZLIB = pysilk.ZLIB
LZO1X = pysilk.LZO1X
SNAPPY = pysilk.SNAPPY
BAG_COUNTER_MAX = pysilk.BAG_COUNTER_MAX
silk_version = pysilk.silk_version
initial_tcpflags_enabled = pysilk.initial_tcpflags_enabled
ipv6_enabled = pysilk.ipv6_enabled
init_country_codes = pysilk.init_country_codes

rwrec_kwds = set(['application', 'bytes', 'classtype', 'classtype_id',
                  'dip', 'dport', 'duration', 'duration_secs',
                  'etime', 'icmpcode', 'icmptype', 'initial_tcpflags',
                  'input', 'nhip', 'output', 'packets', 'protocol',
                  'sensor', 'sensor_id', 'sip', 'session_tcpflags',
                  'sport', 'stime', 'tcpflags', 'finnoack',
                  'timeout_killed', 'timeout_started', 'uniform_packets'])


class RWRec(pysilk.RWRecBase):

    __slots__ = []

    def __init__(self, rec=None, _clone=None, **kwds):
        """
        RWRec() -> empty RWRec
        RWRec(rec, **kwds) -> clone of rec, updated by given keywords
        RWRec(dict, **kwds) -> RWRec, updated by dict and keywords

        Examples:
          foo = RWRec()
          bar = RWRec(foo, dip="192.168.1.1", dport=2000)
          baz = RWRec(bar.as_dict(), application=1)
        """
        if _clone:
            pysilk.RWRecBase.__init__(self, clone=_clone)
        else:
            if isinstance(rec, dict):
                rec = dict(rec)
                rec.update(kwds)
                kwds = rec
                rec = None
            if rec:
                pysilk.RWRecBase.__init__(self, copy=rec)
            else:
                pysilk.RWRecBase.__init__(self)

        # protocol has to be set first
        protocol = kwds.pop("protocol", None)
        if protocol is not None:
            self.protocol = protocol

        # Save these to set last
        etime = kwds.pop("etime", None)
        initial = kwds.pop("initial_tcpflags", None)
        session = kwds.pop("session_tcpflags", None)

        # handle everything else
        for key, val in iteritems(kwds):
            if key not in rwrec_kwds:
                raise TypeError(("'%s' is an invalid keyword "
                                 "argument for this function") % key)
            setattr(self, key, val)

        # Handle these last
        if etime is not None:
            self.etime = etime
        if initial is not None:
            self.initial_tcpflags = initial
        if session is not None:
            self.session_tcpflags = session

    def as_dict(self):
        """
        Returns the RwRec as a dictionary.
        """
        recdict = dict()
        for x in ['application', 'bytes', 'dip', 'duration', 'stime',
                  'input', 'nhip', 'output', 'packets', 'protocol', 'sip',
                  'finnoack', 'timeout_killed', 'timeout_started',
                  'uniform_packets']:
            recdict[x] = getattr(self, x)

        if silk.site.have_site_config():
            for x in ['classtype', 'sensor']:
                recdict[x] = getattr(self, x)
        else:
            for x in ['classtype_id', 'sensor_id']:
                recdict[x] = getattr(self, x)

        protocol = self.protocol
        if protocol in [6, 17, 132]:
            for x in ['sport', 'dport']:
                recdict[x] = getattr(self, x)

        if self.is_icmp():
            for x in ['icmptype', 'icmpcode']:
                recdict[x] = getattr(self, x)
        elif protocol == 6:
            recdict['tcpflags'] = self.tcpflags

        if self.initial_tcpflags is not None and protocol == 6:
            for x in ['initial_tcpflags', 'session_tcpflags']:
                recdict[x] = getattr(self, x)

        if self.uniform_packets:
            recdict['uniform_packets'] = self.uniform_packets

        return recdict

    def to_ipv4(self):
        """
        Returns a new copy of the record converted to IPv4.
        """
        rawrec = pysilk.RWRecBase.to_ipv4(self)
        if rawrec is None:
            return None
        return RWRec(_clone = rawrec)

    def to_ipv6(self):
        """
        Returns a new copy of the record converted to IPv6.
        """
        rawrec = pysilk.RWRecBase.to_ipv6(self)
        if rawrec is None:
            return None
        return RWRec(_clone = rawrec)

    def __str__(self):
        return self.as_dict().__str__()

    def __repr__(self):
        return ("silk.RWRec(%s)" % self)


class SilkFile(pysilk.SilkFileBase):

    def __init__(self, *args, **kwds):
        pysilk.SilkFileBase.__init__(self, *args, **kwds)

    def read(self):
        rawrec = pysilk.SilkFileBase.read(self)
        if rawrec:
            rawrec = RWRec(_clone = rawrec)
        return rawrec

    def __iter__(self):
        return self

    def next(self):
        rec = self.read()
        if not rec:
            raise StopIteration
        return rec

    # Support with: statement in Python 2.5+
    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.close()

    # Define for Python 3.0
    def __next__(self):
        return self.next()

def silkfile_open(filename, mode, *args, **kwds):
    return SilkFile(filename, mode, *args, **kwds)

def silkfile_fdopen(fileno, mode, filename=None, *args, **kwds):
    if filename is None:
        filename = ("<fileno(%d)>" % fileno)
    return SilkFile(filename, mode, _fileno=fileno, *args, **kwds)


class IPSet(pysilk.IPSetBase):
    """
    IPSet() -> empty IPSet
    IPSet(iterable) -> IPSet with items from the iterable inserted
    """

    def __init__(self, arg=None, _filename=None):
        if _filename:
            pysilk.IPSetBase.__init__(self, _filename)
        else:
            pysilk.IPSetBase.__init__(self)
        if arg:
            self.update(arg)

    @classmethod
    def load(cls, fname):
        """
        IPSet.load(filename) -> IPSet -- Load an IPSet from a file
        """
        return cls(_filename=fname)

    @classmethod
    def supports_ipv6(cls):
        """
        Return whether IPv6 addresses can be added to the set
        """
        return pysilk.ipset_supports_ipv6()

    def __nonzero__(self):
        """
        Return whether the IPSet is non-empty
        """
        try:
            next(iter(self))
        except StopIteration:
            return False
        return True

    # Define for Python 3.0
    def __bool__(self):
        return self.__nonzero__()

    def update(self, *args):
        """
        Update the IPSet with the union of itself and another.
        """
        for arg in args:
            if isinstance(arg, IPSet):
                pysilk.IPSetBase.update(self, arg)
            elif isinstance(arg, IPWildcard):
                pysilk.IPSetBase.add(self, arg)
            elif isinstance(arg, basestring):
                # We don't want to treat strings as iterables
                pysilk.IPSetBase.add(self, IPWildcard(arg))
            else:
                try:
                    # Is this an iterable?
                    iter(arg)
                except TypeError:
                    # It is not an iterable.  Add as an address.
                    pysilk.IPSetBase.add(self, arg)
                else:
                    for item in arg:
                        if isinstance(item, basestring):
                            pysilk.IPSetBase.add(self, IPWildcard(item))
                        else:
                            pysilk.IPSetBase.add(self, item)
        return self

    def add(self, arg):
        """
        Add a single IP Address to the IPSet
        """
        if isinstance(arg, basestring):
            arg = IPAddr(arg)
        if not isinstance(arg, IPAddr):
            raise TypeError("Must be an IPAddr or IP Address string")
        return pysilk.IPSetBase.add(self, arg)

    def add_range(self, start, end):
        """
        Add all IP Address between start and end, inclusive, to the IPSet
        """
        if isinstance(start, basestring):
            start = IPAddr(start)
        if not isinstance(start, IPAddr):
            raise TypeError(
                "First argument must be an IPAddr or IP Address string")
        if isinstance(end, basestring):
            end = IPAddr(end)
        if not isinstance(end, IPAddr):
            raise TypeError(
                "Second argument must be an IPAddr or IP Address string")
        if start > end:
            raise ValueError(
                "First argument must not be greater than the second")

        return pysilk.IPSetBase.add_range(self, start, end)

    def union(self, *args):
        """
        Return the union of two IPSets as a new IPSet.
        (i.e. all elements that are in either IPSet.)
        """
        return self.copy().update(*args)

    def intersection_update(self, *args):
        """
        Update the IPSet with the intersection of itself and another.
        """
        for arg in args:
            if not isinstance(arg, IPSet):
                arg = IPSet(arg)
            pysilk.IPSetBase.intersection_update(self, arg)
        return self

    def intersection(self, *args):
        """
        Return the intersection of two IPSets as a new IPSet.
        (i.e. all elements that are in both IPSets.)
        """
        return self.copy().intersection_update(*args)

    def difference_update(self, *args):
        """
        Remove all elements of another IPSet from this IPSet.
        """
        for arg in args:
            if isinstance(arg, IPSet):
                pysilk.IPSetBase.difference_update(self, arg)
            elif isinstance(arg, IPWildcard):
                pysilk.IPSetBase.discard(self, arg)
            elif isinstance(arg, basestring):
                # We don't want to treat strings as iterables
                pysilk.IPSetBase.discard(self, IPWildcard(arg))
            else:
                try:
                    # Is this an iterable?
                    items = iter(arg)
                except TypeError:
                    # It is not an iterable.  Discard as an address.
                    pysilk.IPSetBase.discard(self, arg)
                else:
                    for addr in items:
                        if isinstance(addr, basestring):
                            pysilk.IPSetBase.discard(self, IPWildcard(addr))
                        else:
                            pysilk.IPSetBase.discard(self, addr)
        return self

    def difference(self, *args):
        """
        Return the difference of two IPSets as a new IPSet.
        (i.e. all elements that are in this IPSet but not the other.)
        """
        return self.copy().difference_update(*args)

    def symmetric_difference(self, arg):
        """
        Return the symmetric difference of two IPSets as a new IPSet.
        (i.e. all elements that are in exactly one of the IPSets.)
        """
        intersect = self.intersection(arg)
        combine = self.union(arg)
        return combine.difference_update(intersect)

    def symmetric_difference_update(self, arg):
        """
        Update the IPSet with the symmetric difference of itself and another.
        """
        intersect = self.intersection(arg)
        self.update(arg)
        return self.difference_update(intersect)

    def issubset(self, arg):
        """
        Report whether another IPSet contains this IPSet.
        """
        return not self.difference(arg)

    def issuperset(self, arg):
        """
        Report whether this IPSet contains another IPSet.
        """
        if isinstance(arg, IPSet):
            newarg = arg
        else:
            newarg = IPSet(arg)
        return not newarg.difference(self)

    def isdisjoint(self, arg):
        """
        Report whether this IPSet has no elements in common with
        another iterable.
        """
        if isinstance(arg, (IPSet, IPWildcard)):
            return pysilk.IPSetBase.isdisjoint(self, arg)
        for item in arg:
            if item in self:
                return False
        return True

    def copy(self):
        """
        Return a copy of this IPSet.
        """
        return IPSet().update(self)

    def __copy__(self):
        return self.copy()

    def discard(self, arg):
        """
        Remove an IP address from an IPSet if it is a member.
        If the IP address is not a member, do nothing.
        """
        if isinstance(arg, basestring):
            arg = IPAddr(arg)
        if not isinstance(arg, IPAddr):
            raise TypeError("Must be an IPAddr or IP Address string")
        pysilk.IPSetBase.discard(self, arg)
        return self

    def remove(self, arg):
        """
        Remove an IP address from an IPSet; it must be a member.
        If the IP address is not a member, raise a KeyError.
        """
        if arg not in self:
            raise KeyError
        return self.discard(arg)

    def __le__(self, arg):
        """
        ipset.issubset(ipset)
        """
        if not isinstance(arg, IPSet):
            raise TypeError("can only compare to an IPSet")
        return self.issubset(arg)

    def __ge__(self, arg):
        """
        ipset.issuperset(ipset)
        """
        if not isinstance(arg, IPSet):
            raise TypeError("can only compare to an IPSet")
        return self.issuperset(arg)

    def __or__(self, arg):
        """
        ipset.union(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.union(arg)

    def __and__(self, arg):
        """
        ipset.intersection(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.intersection(arg)

    def __sub__(self, arg):
        """
        ipset.difference(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.difference(arg)

    def __xor__(self, arg):
        """
        ipset.symmetric_difference(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.symmetric_difference(arg)

    def __ior__(self, arg):
        """
        ipset.update(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.update(arg)

    def __iand__(self, arg):
        """
        ipset.intersection_update(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.intersection_update(arg)

    def __isub__(self, arg):
        """
        ipset.difference_update(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.difference_update(arg)

    def __ixor__(self, arg):
        """
        ipset.symmetric_difference_update(ipset)
        """
        if not isinstance(arg, IPSet):
            return NotImplemented
        return self.symmetric_difference_update(arg)

    def __eq__(self, arg):
        return self <= arg and self >= arg

    def __ne__(self, arg):
        return not (self == arg)

    def pop(self):
        """
        Remove and return an address from the IPSet.
        Raises KeyError if the set is empty.
        """
        for addr in self:
            pysilk.IPSetBase.discard(self, addr)
            return addr
        raise KeyError


class PrefixMap(object):
    """
    PrefixMap(filename) -> Prefix map from prefix map file
    """

    def __new__(cls, filename):
        pmap = pysilk.PMapBase(filename)
        if pmap.content in ['IPv4-address', 'IPv6-address']:
            obj = object.__new__(AddressPrefixMap)
        elif pmap.content == 'proto-port':
            obj = object.__new__(ProtoPortPrefixMap)
        else:
            raise RuntimeError("Unknown pmap content type %s" % pmap.content)
        obj._filename = filename
        obj._pmap = pmap
        obj._valuedict = {}
        obj.name = pmap.name
        return obj

    def _value(self, v):
        try:
            return self._valuedict[v]
        except KeyError:
            rv = self._pmap.get_value_string(v)
            self._valuedict[v] = rv
            return rv

    def __getitem__(self, key):
        """
        pmap.__getitem__(x) <==> pmap[x]
        """
        return self._value(self._pmap[key])

    def get(self, key, default = None):
        """
        pmap.get(k[,d]) -> pmap[k] if k in pmap, else d.  d defaults to None.
        """
        try:
            return self[key]
        except (TypeError, ValueError):
            return default

    def iterranges(self):
        """
        pmap.iterranges() -> an iterator over (start, end, value) ranges
        """
        for (start, end, value) in self._pmap:
            yield (start, end, self._value(value))

    def _itervalues(self):
        for i in range(0, self._pmap.num_values):
            value = self._value(i)
            if value:
                yield value

    def values(self):
        """
        pmap.values() -> list of pmap's values
        """
        return tuple(self._itervalues())

class AddressPrefixMap(PrefixMap):
    pass

class ProtoPortPrefixMap(PrefixMap):
    pass


import itertools
import copy

def _count(n=0, step=1):
    while True:
        yield n
        n += step

class Bag(pysilk.BagBase):
    """
    Bag() -> empty bag
    Bag(mapping) -> bag with items from the mapping inserted
    Bag(seq) ->  bag with items from a sequence of pairs
    """

    def __init__(self,
                 mapping=None,
                 key_type=None,
                 key_len=None,
                 counter_type=None,
                 counter_len=None,
                 _copy=None,
                 _similar=None,
                 _filename=None,
                 **kwds):
        self.type_key = None
        if _filename:
            # Load
            if isinstance(key_type, type):
                # Deprecated in SiLK 3.0.0
                warnings.warn("Use of Python types for key_type is deprecated",
                              DeprecationWarning)
                pysilk.BagBase.__init__(self, filename = _filename)
                self.type_key = key_type
                # When using the deprecated class-based key_type,
                # coerce the bag to use a custom 4 byte key
                pysilk.BagBase.set_info(
                    self, key_type=pysilk.BagBase._get_custom_type(),
                    key_len=4)
                return
            pysilk.BagBase.__init__(self, filename = _filename)
            return
        if _copy is not None:
            # Create an copy of _copy
            self.type_key = _copy.type_key
            pysilk.BagBase.__init__(self, copy = _copy)
            return
        if _similar is not None:
            # Create an empty bag similar to _similar
            self.type_key = _similar.type_key
            pysilk.BagBase.__init__(self, **_similar.get_info())
            return
        if isinstance(key_type, type):
            # Deprecated in SiLK 3.0.0
            warnings.warn("Use of Python types for key_type is deprecated",
                          DeprecationWarning)
            self.type_key = key_type
            key_type = pysilk.BagBase._get_custom_type()
        if key_type is None:
            if key_len is not None and key_len != 16:
                # If given a key_len of less than 16 and no key_type,
                # assume key_type to be "custom"
                key_type = pysilk.BagBase._get_custom_type()
            elif ipv6_enabled():
                # Default key type
                key_type = pysilk.BagBase._get_ipv6_type()
            else:
                key_type = pysilk.BagBase._get_ipv4_type()
        if key_len is not None:
            kwds['key_len'] = key_len
        if counter_type is not None:
            kwds['counter_type'] = counter_type
        if counter_len is not None:
            kwds['counter_len'] = counter_len
        pysilk.BagBase.__init__(self, key_type=key_type, **kwds)

        if mapping:
            self.update(mapping)

    @classmethod
    def ipaddr(cls, mapping=None, **kwds):
        if ipv6_enabled():
            return cls(mapping, key_type=pysilk.BagBase._get_ipv6_type(),
                       **kwds)
        else:
            return cls(mapping, key_type=pysilk.BagBase._get_ipv4_type(),
                       **kwds)

    @classmethod
    def integer(cls, mapping=None, **kwds):
        return cls(mapping, key_type=pysilk.BagBase._get_custom_type(),
                   **kwds)

    @classmethod
    def load(cls, fname, key_type=None):
        """
        Bag.load(filename) -> Bag -- Load a bag from a file
        """
        if key_type is None or isinstance(key_type, type):
            return cls(_filename=fname, key_type=key_type)
        bag = cls(_filename=fname)
        bag.set_info(key_type=key_type)
        return bag

    @classmethod
    def load_ipaddr(cls, fname):
        """
        Bag.load_ipaddr(filename) -> Bag -- Load an IP address bag from a file
        """
        return cls.load(fname, key_type=IPv4Addr)

    @classmethod
    def load_integer(cls, fname):
        """
        Bag.load_integer(filename) -> Bag -- Load a integer bag from a file
        """
        return cls.load(fname, key_type=long)

    def set_info(self, **kwds):
        pysilk.BagBase.set_info(self, **kwds)
        if kwds.get('key_type') is not None:
            self.type_key = None

    def copy(self):
        return Bag(_copy=self)

    def __copy__(self):
        return self.copy()

    def _to_key(self, value):
        if self.type_key is not None:
            return long(value)
        return value

    def _from_key(self, value):
        if self.type_key is not None:
            return self.type_key(value)
        return value

    def intersect(self, container):
        """
        B.intersect(container) -> A new Bag b, where b[x] = B[x] for every
        x in container
        """
        newbag = Bag(**self.get_info())
        if isinstance(container, tuple):
            if any(x.step for x in container if isinstance(x, slice)):
                raise ValueError("Bags do not support stepped slices")
            for key, val in self.iteritems():
                for s in container:
                    if isinstance(s, slice):
                        if s.start and key < s.start:
                            continue
                        if s.stop and key >= s.stop:
                            continue
                    else:
                        try:
                            if key not in s:
                                continue
                        except TypeError:
                            if key != s:
                                continue
                    newbag[key] = val
                    break
        elif isinstance(container, slice):
            if container.step:
                raise ValueError("Bags do not support stepped slices")
            for key, val in self.iteritems():
                if container.start and key < container.start:
                    continue
                if container.stop and key >= container.stop:
                    continue
                newbag[key] = val
        else:
            for key, val in self.iteritems():
                if key in container:
                    newbag[key] = val
        return newbag

    def __getitem__(self, key):
        """
        x.__getitem__(y) <==> x[y]
        """
        if isinstance(key, (slice, tuple, IPSet, IPWildcard)):
            return self.intersect(key)
        return pysilk.BagBase.__getitem__(self, self._to_key(key))

    def __delitem__(self, key):
        """
        x.__delitem__(y) <==> del x[y]
        """
        self[key] = 0

    def __setitem__(self, key, value):
        """
        x.__setitem__(i, y) <==> x[i]=y
        """
        return pysilk.BagBase.__setitem__(self, self._to_key(key), value)

    def __iter__(self):
        """
        x.__iter__() <==> iter(x)
        """
        return self.iterkeys()

    def __contains__(self, key):
        """
        B.__contains__(k) -> True if B has a key k, else False
        """
        return self[key] != 0

    def get(self, key, default=None):
        """
        B.get(k[,d]) -> B[k] if k in B, else d.  d defaults to None.
        """
        retval = self[key]
        if retval:
            return retval
        return default

    def items(self):
        """
        B.items() -> list of B's (key, value) pairs, as 2-tuples
        """
        return list(self.iteritems())

    def iteritems(self):
        """
        B.iteritems() -> an iterator over the (key, value) items of B
        """
        for (key, value) in pysilk.BagBase.__iter__(self):
            yield (self._from_key(key), value)

    def iterkeys(self):
        """
        B.iterkeys() -> an iterator over the keys of B
        """
        for item in self.iteritems():
            yield item[0]

    def itervalues(self):
        """
        B.itervalues() -> an iterator over the values of B
        """
        for item in self.iteritems():
            yield item[1]

    def keys(self):
        """
        B.keys() -> list of B's keys
        """
        return list(self.iterkeys())

    def update(self, arg):
        """
        B.update(mapping) -> updates bag with items from the mapping
        B.update(seq) ->  updates bag with items from a sequence of pairs
        """
        try:
            for key, val in iteritems(arg):
                self[key] = val
        except AttributeError:
            for (key, value) in arg:
                self[key] = value

    def values(self):
        """
        B.values() -> list of B's values
        """
        return list(self.itervalues())

    def add(self, *items):
        """
        B.add(key[, key]...) -> increments B[key] by 1 for each key
        B.add(sequence) -> increments B[key] by 1 for each key in sequence
        """
        if len(items) == 1:
            try:
                self.incr(items[0])
            except TypeError:
                for key in items[0]:
                    self.incr(key)
        else:
            for key in items:
                self.incr(key)

    def remove(self, *items):
        """
        B.remove(key[, key]...) -> decrements B[key] by 1 for each key
        B.remove(sequence) -> decrements B[key] by 1 for each key in sequence
        """
        if len(items) == 1:
            try:
                self.decr(items[0])
            except TypeError:
                for key in items[0]:
                    self.decr(key)
        else:
            for key in items:
                self.decr(key)

    def incr(self, key, value = 1):
        """
        B.incr(key) -> increments B[key] by 1
        B.incr(key, value) -> increments B[key] by value
        """
        return pysilk.BagBase.incr(self, self._to_key(key), value)

    def decr(self, key, value = 1):
        """
        B.decr(key) -> increments B[key] by 1
        B.decr(key, value) -> increments B[key] by value
        """
        return pysilk.BagBase.decr(self, self._to_key(key), value)

    def _update_type(self, other):
        selftype = self.get_info()['key_type']
        othertype = other.get_info()['key_type']
        newtype = self.type_merge(selftype, othertype)
        if newtype != selftype:
            self.set_info(key_type=newtype)

    def __iadd__(self, other):
        """
        B.__iadd__(x) <==> B += x
        """
        if not isinstance(other, Bag):
            return NotImplemented
        return pysilk.BagBase.__iadd__(self, other)

    def __isub__(self, other):
        """
        B.__isub__(x) <==> B -= x
        """
        if not isinstance(other, Bag):
            return NotImplemented
        self._update_type(other)
        for (key, value) in other.iteritems():
            try:
                self.decr(key, value)
            except ValueError:
                del self[key]
        return self

    def __add__(self, other):
        """
        B.__add__(x) <==> B + x
        """
        return self.copy().__iadd__(other)

    def __sub__(self, other):
        """
        B.__sub__(x) <==> B - x
        Will not underflow.
        """
        return self.copy().__isub__(other)

    def group_iterator(self, other):
        """
        B.group_iterator(bag) -> an iterator over (key, B-value, bag-value)
        Will iterate over every key in which one of the bags has a non-zero
        value.  If one of the bags has a zero value, the value returned for
        that bag will be None.

        >>> a = Bag.integer({1: 1, 2: 2})
        >>> b = Bag.integer({1: 3, 3: 4})
        >>> list(a.group_iterator(b))
        [(1L, 1L, 3L), (2L, 3L, None), (3L, None, 4L)]
        """
        if not isinstance(other, Bag):
            raise TypeError("Expected a Bag")
        a = self.sorted_iter()
        b = other.sorted_iter()
        try:
            ak, av = next(a)
        except StopIteration:
            for bk, bv in b:
                yield (bk, None, bv)
            return
        try:
            bk, bv = next(b)
        except StopIteration:
            yield (ak, av, None)
            for ak, av in a:
                yield (ak, av, None)
            return
        while True:
            if ak < bk:
                yield (ak, av, None)
                try:
                    ak, av = next(a)
                except StopIteration:
                    yield (bk, None, bv)
                    for bk, bv in b:
                        yield (bk, None, bv)
                    return
            elif bk < ak:
                yield (bk, None, bv)
                try:
                    bk, bv = next(b)
                except StopIteration:
                    yield (ak, av, None)
                    for ak, av in a:
                        yield (ak, av, None)
            else:
                yield (ak, av, bv)
                try:
                    ak, av = next(a)
                except StopIteration:
                    for bk, bv in b:
                        yield (bk, None, bv)
                    return
                try:
                    bk, bv = next(b)
                except StopIteration:
                    yield (ak, av, None)
                    for ak, av in a:
                        yield (ak, av, None)
                    return

    def min(self, other):
        """
        B.min(bag) -> new bag with minimum value for each key in originals
        """
        if not isinstance(other, Bag):
            raise TypeError("Expected a Bag")
        retval = Bag(_similar=self)
        retval._update_type(other)
        for key, val in self.iteritems():
            retval[key] = min(val, other[key])
        return retval

    def max(self, other):
        """
        B.max(bag) -> new bag with maximum value for each key in originals
        """
        if not isinstance(other, Bag):
            raise TypeError("Expected a Bag")
        retval = Bag(_similar=self)
        retval._update_type(other)
        for key, val in other.iteritems():
            retval[key] = max(val, self[key])
        for key, val in self.iteritems():
            retval[key] = max(val, other[key])
        return retval

    def __div__(self, other):
        """
        B.__div__(bag) -> new bag c where c[key] = B[key] / bag[key]
        """
        if not isinstance(other, Bag):
            return NotImplemented
        retval = Bag(_similar=self)
        retval._update_type(other)
        for key, a in self.iteritems():
            b = other[key]
            if b:
                v, r = divmod(a, b)
                if r * 2 >= b:
                    v += 1
                retval[key] = v
        return retval

    # Define for Python 3.0
    def __truediv__(self, other):
        return self.__div__(other)

    def __imul__(self, other):
        if not isinstance(other, Integral):
            return NotImplemented
        for key, value in self.iteritems():
            self[key] = value * other
        return self

    def __mul__(self, other):
        if not isinstance(other, Integral):
            return NotImplemented
        return self.copy().__imul__(other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def complement_intersect(self, other):
        retval = Bag(_similar=self)
        for key, value in self.iteritems():
            if key not in other:
                retval[key] = value
        return retval

    def ipset(self):
        return IPSet(self.iterkeys())

    def __eq__(self, other):
        if len(self) != len(other):
            return False
        for key, val in self.iteritems():
            if val != other[key]:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def constrain_values(self, min = None, max = None):
        if not (min or max):
            raise ValueError("Must supply at least one of min, max")
        for key, value in self.iteritems():
            if (min and value < min) or (max and value > max):
                del self[key]

    def constrain_keys(self, min = None, max = None):
        if not (min or max):
            raise ValueError("Must supply at least one of min, max")
        for key in self:
            if (min and key < min) or (max and key > max):
                del self[key]

    def inversion(self):
        retval = Bag.integer()
        retval.add((min(x, 0xFFFFFFFF) for x in self.itervalues()))
        return retval


# Set global variables for the basic TCP flags
TCP_FIN = TCPFlags('F')
TCP_SYN = TCPFlags('S')
TCP_RST = TCPFlags('R')
TCP_PSH = TCPFlags('P')
TCP_ACK = TCPFlags('A')
TCP_URG = TCPFlags('U')
TCP_ECE = TCPFlags('E')
TCP_CWR = TCPFlags('C')

# Deprecated names as of SiLK 3.0.0
FIN = TCP_FIN
SYN = TCP_SYN
RST = TCP_RST
PSH = TCP_PSH
ACK = TCP_ACK
URG = TCP_URG
ECE = TCP_ECE
CWR = TCP_CWR

def classes():
    # Deprecated in SiLK 3.0.0
    warnings.warn("Use of classes() from the silk module is deprecated.  "
                  "Please use silk.site.classes() instead.",
                  DeprecationWarning)
    return silk.site.classes()

def sensors():
    # Deprecated in SiLK 3.0.0
    warnings.warn("Use of sensors() from the silk module is deprecated.  "
                  "Please use silk.site.sensors() instead.",
                  DeprecationWarning)
    return silk.site.sensors()

def classtypes():
    # Deprecated in SiLK 3.0.0
    warnings.warn("Use of classtypes() from the silk module is deprecated.  "
                  "Please use silk.site.classtypes() instead.",
                  DeprecationWarning)
    return silk.site.classtypes()

def init_site(*args, **kwds):
    # Deprecated in SiLK 3.0.0
    warnings.warn("Use of init_site() from the silk module is deprecated.  "
                  "Please use silk.site.init_site() instead.",
                  DeprecationWarning)
    return silk.site.init_site(*args, **kwds)

def have_site_config():
    # Deprecated in SiLK 3.0.0
    warnings.warn("Use of have_site_config() from the silk module is "
                  "deprecated.  "
                  "Please use silk.site.have_site_config() instead.",
                  DeprecationWarning)
    return silk.site.have_site_config()


def get_configuration(name=None):
    conf = {
        'COMPRESSION_METHODS' : pysilk.get_compression_methods(),
        'INITIAL_TCPFLAGS_ENABLED' : pysilk.initial_tcpflags_enabled(),
        'IPV6_ENABLED' : pysilk.ipv6_enabled(),
        'SILK_VERSION' : pysilk.silk_version(),
        'TIMEZONE_SUPPORT' : pysilk.get_timezone_support(),
    }
    if name is None:
        return conf
    return conf.get(name)
