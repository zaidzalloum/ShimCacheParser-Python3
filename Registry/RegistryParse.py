#!/usr/bin/env python3

#    This file is part of python-registry.
#
#   Copyright 2011 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Python 3 port: fixed print statements, .next() -> next(), and bytes vs str comparisons.

import struct
from datetime import datetime

# Constants
RegSZ = 0x0001
RegExpandSZ = 0x0002
RegBin = 0x0003
RegDWord = 0x0004
RegMultiSZ = 0x0007
RegQWord = 0x000B
RegNone = 0x0000
RegBigEndian = 0x0005
RegLink = 0x0006
RegResourceList = 0x0008
RegFullResourceDescriptor = 0x0009
RegResourceRequirementsList = 0x000A

_global_warning_messages = []

def warn(msg):
    if msg not in _global_warning_messages:
        _global_warning_messages.append(msg)
        print("Warning: %s" % (msg))  # Python 3: print is a function


def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)


class RegistryException(Exception):
    """
    Base Exception class for Windows Registry access.
    """
    def __init__(self, value):
        super().__init__()
        self._value = value

    def __str__(self):
        return "Registry Exception: %s" % (self._value)


class RegistryStructureDoesNotExist(RegistryException):
    """
    Exception to be raised when a structure or block is requested which does not exist.
    """
    def __init__(self, value):
        super().__init__(value)

    def __str__(self):
        return "Registry Structure Does Not Exist Exception: %s" % (self._value)


class ParseException(RegistryException):
    """
    An exception to be thrown during Windows Registry parsing.
    """
    def __init__(self, value):
        super().__init__(value)

    def __str__(self):
        return "Registry Parse Exception(%s)" % (self._value)


class UnknownTypeException(RegistryException):
    """
    An exception to be raised when an unknown data type is encountered.
    """
    def __init__(self, value):
        super().__init__(value)

    def __str__(self):
        return "Unknown Type Exception(%s)" % (self._value)


class RegistryBlock(object):
    """
    Base class for structure blocks in the Windows Registry.
    """
    def __init__(self, buf, offset, parent):
        self._buf = buf
        self._offset = offset
        self._parent = parent

    def unpack_word(self, offset):
        return struct.unpack_from("<H", self._buf, self._offset + offset)[0]

    def unpack_dword(self, offset):
        return struct.unpack_from("<I", self._buf, self._offset + offset)[0]

    def unpack_int(self, offset):
        return struct.unpack_from("<i", self._buf, self._offset + offset)[0]

    def unpack_qword(self, offset):
        return struct.unpack_from("<Q", self._buf, self._offset + offset)[0]

    def unpack_string(self, offset, length):
        # Returns bytes in Python 3
        return struct.unpack_from("<%ds" % (length), self._buf, self._offset + offset)[0]

    def absolute_offset(self, offset):
        return self._offset + offset

    def parent(self):
        return self._parent

    def offset(self):
        return self._offset


class REGFBlock(RegistryBlock):
    """
    The Windows Registry file header.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

        _id = self.unpack_dword(0)
        if _id != 0x66676572:
            raise ParseException("Invalid REGF ID")

        _seq1 = self.unpack_dword(0x4)
        _seq2 = self.unpack_dword(0x8)

        if _seq1 != _seq2:
            pass  # registry was not synchronized

    def major_version(self):
        return self.unpack_dword(0x14)

    def minor_version(self):
        return self.unpack_dword(0x18)

    def hive_name(self):
        return self.unpack_string(0x30, 64).decode("utf-16-le", errors="replace").rstrip("\x00")

    def last_hbin_offset(self):
        return self.unpack_dword(0x28)

    def first_key(self):
        first_hbin = next(self.hbins())  # Python 3: use next() instead of .next()

        key_offset = first_hbin.absolute_offset(self.unpack_dword(0x24))

        d = HBINCell(self._buf, key_offset, first_hbin)
        return NKRecord(self._buf, d.data_offset(), first_hbin)

    def hbins(self):
        """
        A generator that enumerates all HBIN structures in this Windows Registry.
        """
        h = HBINBlock(self._buf, 0x1000, self)
        yield h

        while h.has_next():
            h = h.next()
            yield h


class HBINCell(RegistryBlock):
    """
    HBIN data cell.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)
        self._size = self.unpack_int(0x0)

    def __str__(self):
        if self.is_free():
            return "HBIN Cell (free) at 0x%x" % (self._offset)
        else:
            return "HBIN Cell at 0x%x" % (self._offset)

    def is_free(self):
        return self._size > 0

    def size(self):
        if self.is_free():
            return self._size
        else:
            return self._size * -1

    def next(self):
        try:
            return HBINCell(self._buf, self._offset + self.size(), self.parent())
        except:
            raise RegistryStructureDoesNotExist("HBINCell does not exist at 0x%x" % (self._offset + self.size()))

    def offset(self):
        return self._offset

    def data_offset(self):
        return self._offset + 0x4

    def raw_data(self):
        return self._buf[self.data_offset():self.data_offset() + self.size()]

    def data_id(self):
        # Returns bytes; callers must compare with b"xx" literals
        return self.unpack_string(0x4, 2)

    def abs_offset_from_hbin_offset(self, offset):
        h = self.parent()
        while h.__class__.__name__ != "HBINBlock":
            h = h.parent()
        return h.first_hbin().offset() + offset

    def child(self):
        if self.is_free():
            raise RegistryStructureDoesNotExist("HBINCell is free at 0x%x" % (self.offset()))

        id_ = self.data_id()

        if id_ == b"vk":
            return VKRecord(self._buf, self.data_offset(), self)
        elif id_ == b"nk":
            return NKRecord(self._buf, self.data_offset(), self)
        elif id_ == b"lf":
            return LFRecord(self._buf, self.data_offset(), self)
        elif id_ == b"lh":
            return LHRecord(self._buf, self.data_offset(), self)
        elif id_ == b"li":
            return LIRecord(self._buf, self.data_offset(), self)
        elif id_ == b"ri":
            return RIRecord(self._buf, self.data_offset(), self)
        elif id_ == b"sk":
            return SKRecord(self._buf, self.data_offset(), self)
        elif id_ == b"db":
            return DBRecord(self._buf, self.data_offset(), self)
        else:
            return DataRecord(self._buf, self.data_offset(), self)


class Record(RegistryBlock):
    """
    Abstract class for Records contained by cells in HBINs.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def abs_offset_from_hbin_offset(self, offset):
        h = self.parent()
        while h.__class__.__name__ != "HBINBlock":
            h = h.parent()
        return h.first_hbin().offset() + offset


class DataRecord(Record):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "Data Record at 0x%x" % (self.offset())


class DBIndirectBlock(Record):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "Large Data Block at 0x%x" % (self.offset())

    def large_data(self, length):
        b = bytearray()
        count = 0
        while length > 0:
            off = self.abs_offset_from_hbin_offset(self.unpack_dword(4 * count))
            size = min(0x3fd8, length)
            b += HBINCell(self._buf, off, self).raw_data()[0:size]
            count += 1
            length -= size
        return bytes(b)


class DBRecord(Record):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != b"db":
            raise ParseException("Invalid DB Record ID")

    def __str__(self):
        return "Large Data Block at 0x%x" % (self.offset())

    def large_data(self, length):
        off = self.abs_offset_from_hbin_offset(self.unpack_dword(0x4))
        cell = HBINCell(self._buf, off, self)
        dbi = DBIndirectBlock(self._buf, cell.data_offset(), cell)
        return dbi.large_data(length)


class VKRecord(Record):
    """
    The VKRecord holds one name-value pair.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != b"vk":
            raise ParseException("Invalid VK Record ID")

    def data_type_str(self):
        data_type = self.data_type()
        if data_type == RegSZ:            return "RegSZ"
        elif data_type == RegExpandSZ:    return "RegExpandSZ"
        elif data_type == RegBin:         return "RegBin"
        elif data_type == RegDWord:       return "RegDWord"
        elif data_type == RegMultiSZ:     return "RegMultiSZ"
        elif data_type == RegQWord:       return "RegQWord"
        elif data_type == RegNone:        return "RegNone"
        elif data_type == RegBigEndian:   return "RegBigEndian"
        elif data_type == RegLink:        return "RegLink"
        elif data_type == RegResourceList:             return "RegResourceList"
        elif data_type == RegFullResourceDescriptor:   return "RegFullResourceDescriptor"
        elif data_type == RegResourceRequirementsList: return "RegResourceRequirementsList"
        else:
            raise UnknownTypeException("Unknown VK Record type 0x%x at 0x%x" % (data_type, self.offset()))

    def __str__(self):
        name = self.name() if self.has_name() else "(default)"
        data_type = self.data_type()
        if data_type in (RegSZ, RegExpandSZ):
            data = str(self.data())[0:16] + "..."
        elif data_type == RegMultiSZ:
            data = str(len(self.data())) + " strings"
        elif data_type in (RegDWord, RegQWord):
            data = str(hex(self.data()))
        elif data_type == RegNone:
            data = "(none)"
        elif data_type == RegBin:
            data = "(binary)"
        else:
            data = "(unsupported)"
        return "VKRecord(Name: %s, Type: %s, Data: %s) at 0x%x" % (
            name, self.data_type_str(), data, self.offset())

    def has_name(self):
        return self.unpack_word(0x2) != 0

    def has_ascii_name(self):
        return self.unpack_word(0x10) & 1 == 1

    def name(self):
        if not self.has_name():
            return ""
        name_length = self.unpack_word(0x2)
        raw = self.unpack_string(0x14, name_length)
        # Decode: ASCII flag set means ASCII, otherwise UTF-16-LE
        if self.has_ascii_name():
            return raw.decode("ascii", errors="replace")
        else:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    def data_type(self):
        return self.unpack_dword(0xC)

    def data_length(self):
        return self.unpack_dword(0x4)

    def data_offset(self):
        if self.data_length() < 5 or self.data_length() >= 0x80000000:
            return self.absolute_offset(0x8)
        else:
            return self.abs_offset_from_hbin_offset(self.unpack_dword(0x8))

    def data(self):
        data_type = self.data_type()
        data_length = self.data_length()
        data_offset = self.data_offset()

        if data_type in (RegSZ, RegExpandSZ):
            if data_length >= 0x80000000:
                s = struct.unpack_from("<%ds" % (4), self._buf, data_offset)[0]
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == b"db":
                    s = d.child().large_data(data_length)
                else:
                    s = d.raw_data()[:data_length]
            else:
                d = HBINCell(self._buf, data_offset, self)
                s = struct.unpack_from("<%ds" % (data_length), self._buf, d.data_offset())[0]

            # Python 3: decode bytes to str
            try:
                s = s.decode("utf-16-le", errors="replace")
            except Exception:
                try:
                    s = s.decode("utf-8", errors="replace")
                except Exception:
                    print("Warning: could not decode string value.")
                    s = repr(s)
            s = s.partition('\x00')[0]
            return s

        elif data_type in (RegBin, RegNone):
            if data_length >= 0x80000000:
                data_length -= 0x80000000
                return self._buf[data_offset:data_offset + data_length]
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == b"db":
                    return d.child().large_data(data_length)
                else:
                    return d.raw_data()[:data_length]
            return self._buf[data_offset + 4:data_offset + 4 + data_length]

        elif data_type == RegDWord:
            return self.unpack_dword(0x8)

        elif data_type == RegMultiSZ:
            if data_length >= 0x80000000:
                return []
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == b"db":
                    s = d.child().large_data(data_length)
                else:
                    s = d.raw_data()[:data_length]
            else:
                s = self._buf[data_offset + 4:data_offset + 4 + data_length]
            s = s.decode("utf-16-le", errors="replace")
            return s.split("\x00")

        elif data_type == RegQWord:
            d = HBINCell(self._buf, data_offset, self)
            return struct.unpack_from("<Q", self._buf, d.data_offset())[0]

        elif data_type == RegBigEndian:
            warn("Data type RegBigEndian not yet supported")
            return False
        elif data_type == RegLink:
            warn("Data type RegLink not yet supported")
            return False
        elif data_type == RegResourceList:
            warn("Data type RegResourceList not yet supported")
            return False
        elif data_type == RegFullResourceDescriptor:
            warn("Data type RegFullResourceDescriptor not yet supported")
            return False
        elif data_type == RegResourceRequirementsList:
            warn("Data type RegResourceRequirementsList not yet supported")
            return False
        else:
            raise UnknownTypeException("Unknown VK Record type 0x%x at 0x%x" % (data_type, self.offset()))


class SKRecord(Record):
    """
    Security Record.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != b"sk":
            raise ParseException("Invalid SK Record ID")

        self._offset_prev_sk = self.unpack_dword(0x4)
        self._offset_next_sk = self.unpack_dword(0x8)

    def __str__(self):
        return "SK Record at 0x%x" % (self.offset())


class ValuesList(HBINCell):
    """
    A ValuesList is a simple structure of fixed length pointers/offsets to VKRecords.
    """
    def __init__(self, buf, offset, parent, number):
        super().__init__(buf, offset, parent)
        self._number = number

    def __str__(self):
        return "ValueList(Length: %d) at 0x%x" % (self.parent().values_number(), self.offset())

    def values(self):
        value_item = 0x0
        for _ in range(0, self._number):
            value_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(value_item))
            d = HBINCell(self._buf, value_offset, self)
            v = VKRecord(self._buf, d.data_offset(), self)
            value_item += 4
            yield v


class SubkeyList(Record):
    """
    Base class for structures recording the subkeys of a Registry key.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "SubkeyList(Length: %d) at 0x%x" % (0, self.offset())

    def _keys_len(self):
        return self.unpack_word(0x2)

    def keys(self):
        return
        yield  # make it a generator


class RIRecord(SubkeyList):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "RIRecord at 0x%x" % (self.offset())

    def keys(self):
        key_index = 0x4
        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))
            d = HBINCell(self._buf, key_offset, self)
            try:
                for k in d.child().keys():
                    yield k
            except RegistryStructureDoesNotExist:
                raise ParseException("Unsupported subkey list encountered.")
            key_index += 4


class DirectSubkeyList(SubkeyList):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "DirectSubkeyList(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

    def keys(self):
        key_index = 0x4
        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))
            d = HBINCell(self._buf, key_offset, self)
            yield NKRecord(self._buf, d.data_offset(), self)
            key_index += 8


class LIRecord(DirectSubkeyList):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

    def __str__(self):
        return "LIRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

    def keys(self):
        key_index = 0x4
        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))
            d = HBINCell(self._buf, key_offset, self)
            yield NKRecord(self._buf, d.data_offset(), self)
            key_index += 4


class LFRecord(DirectSubkeyList):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != b"lf":
            raise ParseException("Invalid LF Record ID")

    def __str__(self):
        return "LFRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())


class LHRecord(DirectSubkeyList):
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != b"lh":
            raise ParseException("Invalid LH Record ID")

    def __str__(self):
        return "LHRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())


class NKRecord(Record):
    """
    The NKRecord defines the tree-like structure of the Windows Registry.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != b"nk":
            raise ParseException("Invalid NK Record ID")

    def __str__(self):
        classname = self.classname() if self.has_classname() else "(none)"
        if self.is_root():
            return "Root NKRecord(Class: %s, Name: %s) at 0x%x" % (classname, self.name(), self.offset())
        else:
            return "NKRecord(Class: %s, Name: %s) at 0x%x" % (classname, self.name(), self.offset())

    def has_classname(self):
        return self.unpack_dword(0x30) != 0xFFFFFFFF

    def classname(self):
        if not self.has_classname():
            return ""
        classname_offset = self.unpack_dword(0x30)
        classname_length = self.unpack_word(0x4A)
        offset = self.abs_offset_from_hbin_offset(classname_offset)
        d = HBINCell(self._buf, offset, self)
        raw = struct.unpack_from("<%ds" % (classname_length), self._buf, d.data_offset())[0]
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    def timestamp(self):
        return parse_windows_timestamp(self.unpack_qword(0x4))

    def name(self):
        name_length = self.unpack_word(0x48)
        raw = self.unpack_string(0x4C, name_length)
        # NK record names are stored as ASCII (extended) or UTF-16-LE
        try:
            return raw.decode("ascii", errors="replace")
        except Exception:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    def path(self):
        name = self.name()
        p = self
        while p.has_parent_key():
            p = p.parent_key()
            name = p.name() + "\\" + name
        return name

    def is_root(self):
        return self.unpack_word(0x2) == 0x2C

    def has_parent_key(self):
        if self.is_root():
            return False
        try:
            self.parent_key()
            return True
        except ParseException:
            return False

    def parent_key(self):
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x10))
        d = HBINCell(self._buf, offset, self.parent())
        return NKRecord(self._buf, d.data_offset(), self.parent())

    def sk_record(self):
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x2C))
        d = HBINCell(self._buf, offset, self)
        return SKRecord(self._buf, d.data_offset(), d)

    def values_number(self):
        num = self.unpack_dword(0x24)
        if num == 0xFFFFFFFF:
            return 0
        return num

    def values_list(self):
        if self.values_number() == 0:
            raise RegistryStructureDoesNotExist("NK Record has no associated values.")
        values_list_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x28))
        d = HBINCell(self._buf, values_list_offset, self)
        return ValuesList(self._buf, d.data_offset(), self, self.values_number())

    def subkey_number(self):
        number = self.unpack_dword(0x14)
        if number == 0xFFFFFFFF:
            return 0
        return number

    def subkey_list(self):
        if self.subkey_number() == 0:
            raise RegistryStructureDoesNotExist("NKRecord has no subkey list at 0x%x" % (self.offset()))

        subkey_list_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x1C))
        d = HBINCell(self._buf, subkey_list_offset, self)
        id_ = d.data_id()

        if id_ == b"lf":
            return LFRecord(self._buf, d.data_offset(), self)
        elif id_ == b"lh":
            return LHRecord(self._buf, d.data_offset(), self)
        elif id_ == b"ri":
            return RIRecord(self._buf, d.data_offset(), self)
        elif id_ == b"li":
            return LIRecord(self._buf, d.data_offset(), self)
        else:
            print("%s subkey list" % id_)  # Python 3: print is a function
            raise ParseException("Subkey list with type %s encountered, but not yet supported." % (id_))


class HBINBlock(RegistryBlock):
    """
    An HBINBlock is the basic allocation block of the Windows Registry.
    """
    def __init__(self, buf, offset, parent):
        super().__init__(buf, offset, parent)

        _id = self.unpack_dword(0)
        if _id != 0x6E696268:
            raise ParseException("Invalid HBIN ID")

        self._reloffset_next_hbin = self.unpack_dword(0x8)
        self._offset_next_hbin = self._reloffset_next_hbin + self._offset

    def __str__(self):
        return "HBIN at 0x%x" % (self._offset)

    def first_hbin(self):
        reloffset_from_first_hbin = self.unpack_dword(0x4)
        return HBINBlock(self._buf, (self.offset() - reloffset_from_first_hbin), self.parent())

    def has_next(self):
        regf = self.first_hbin().parent()
        if regf.last_hbin_offset() == self.offset():
            return False
        try:
            HBINBlock(self._buf, self._offset_next_hbin, self.parent())
            return True
        except ParseException:
            return False

    def next(self):
        return HBINBlock(self._buf, self._offset_next_hbin, self.parent())

    def cells(self):
        c = HBINCell(self._buf, self._offset + 0x20, self)
        while c.offset() < self._offset_next_hbin:
            yield c
            c = c.next()

    def records(self):
        c = HBINCell(self._buf, self._offset + 0x20, self)
        while c.offset() < self._offset_next_hbin:
            yield c
            try:
                c = c.next()
            except RegistryStructureDoesNotExist:
                break
