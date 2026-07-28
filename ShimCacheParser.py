#!/usr/bin/env python3
# ShimCacheParser.py
#
# Andrew Davis, andrew.davis@mandiant.com
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.

import sys
import struct
import zipfile
import argparse
import binascii
import datetime
import codecs
import io
import xml.etree.ElementTree as et
from os import path
from csv import writer

# Try importing winreg for Windows systems
try:
    import winreg
except ImportError:
    winreg = None

# Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = b'00ts'

# Magic value used by Windows 8.1
WIN81_MAGIC = b'10ts'

# Values used by Windows 10
WIN10_STATS_SIZE = 0x30
WIN10_CREATORS_STATS_SIZE = 0x34
WIN10_MAGIC = b'10ts'
CACHE_HEADER_SIZE_NT6_4 = 0x30
CACHE_MAGIC_NT6_4 = 0x30

bad_entry_data = 'N/A'
g_verbose = False
g_usebom = False
output_header  = ["Last Modified", "Last Update", "Path", "File Size", "Exec Flag"]

# Date Formats
DATE_MDY = "%m/%d/%y %H:%M:%S"
DATE_ISO = "%Y-%m-%d %H:%M:%S"
g_timeformat = DATE_ISO

# Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
class CacheEntryNt5(object):

    def __init__(self, is32bit, data=None):

        self.is32bit = is32bit
        if data != None:
            self.update(data)

    def update(self, data):

        if self.is32bit:
            entry = struct.unpack('<2H 3L 2L', data)
        else:
            entry = struct.unpack('<2H 4x Q 2L 2L', data)
        self.wLength = entry[0]
        self.wMaximumLength =  entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.dwFileSizeLow = entry[5]
        self.dwFileSizeHigh = entry[6]

    def size(self):

        if self.is32bit:
            return NT5_2_ENTRY_SIZE32
        else:
            return NT5_2_ENTRY_SIZE64

# Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2)
class CacheEntryNt6(object):

    def __init__(self, is32bit, data=None):

        self.is32bit = is32bit
        if data != None:
            self.update(data)

    def update(self, data):

        if self.is32bit:
            entry = struct.unpack('<2H 7L', data)
        else:
            entry = struct.unpack('<2H 4x Q 4L 2Q', data)
        self.wLength = entry[0]
        self.wMaximumLength =  entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.FileFlags = entry[5]
        self.Flags = entry[6]
        self.BlobSize = entry[7]
        self.BlobOffset = entry[8]

    def size(self):

        if self.is32bit:
            return NT6_1_ENTRY_SIZE32
        else:
            return NT6_1_ENTRY_SIZE64

# Convert FILETIME to datetime.
def convert_filetime(dwLowDateTime, dwHighDateTime):

    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time//10)
    except OverflowError:
        return None

# Return a unique list while preserving ordering.
def unique_list(li):

    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list

# Write the Log.
def write_it(rows, outfile=None):

    try:

        if not rows:
            print("[-] No data to write...")
            return

        if not outfile:
            for row in rows:
                print(" ".join(["%s"%x for x in row]))
        else:
            print("[+] Writing output to %s..."%outfile)
            try:
                # Use encoding utf-8, newline='' for CSV compliance in Python 3
                with open(outfile, 'w', newline='', encoding='utf-8') as f:
                    if g_usebom:
                        f.write(codecs.BOM_UTF8.decode('utf-8'))
                    csv_writer = writer(f, delimiter=',')
                    csv_writer.writerows(rows)
            except IOError as err:
                print("[-] Error writing output file: %s" % str(err))
                return

    except UnicodeEncodeError as err:
        print("[-] Error writing output file: %s" % str(err))
        return

# Read the Shim Cache format, return a list of last modified dates/paths.
def read_cache(cachebin, quiet=False):

    if len(cachebin) < 16:
        return None

    try:
        magic = struct.unpack("<L", cachebin[0:4])[0]

        if magic == CACHE_MAGIC_NT5_2:
            test_size = struct.unpack("<H", cachebin[8:10])[0]
            test_max_size = struct.unpack("<H", cachebin[10:12])[0]
            if (test_max_size-test_size == 2 and
                struct.unpack("<L", cachebin[12:16])[0] ) == 0:
                if not quiet:
                    print("[+] Found 64bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(False)
                return read_nt5_entries(cachebin, entry)

            else:
                if not quiet:
                    print("[+] Found 32bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(True)
                return read_nt5_entries(cachebin, entry)

        elif magic == CACHE_MAGIC_NT6_1:
            test_size = (struct.unpack("<H",
                         cachebin[CACHE_HEADER_SIZE_NT6_1:
                         CACHE_HEADER_SIZE_NT6_1 + 2])[0])
            test_max_size = (struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1+2:
                             CACHE_HEADER_SIZE_NT6_1 + 4])[0])

            if (test_max_size-test_size == 2 and
                struct.unpack("<L", cachebin[CACHE_HEADER_SIZE_NT6_1+4:
                CACHE_HEADER_SIZE_NT6_1 + 8])[0] ) == 0:
                if not quiet:
                    print("[+] Found 64bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(False)
                return read_nt6_entries(cachebin, entry)
            else:
                if not quiet:
                    print("[+] Found 32bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(True)
                return read_nt6_entries(cachebin, entry)

        elif magic == WINXP_MAGIC32:
            if not quiet:
                print("[+] Found 32bit Windows XP Shim Cache data...")
            return read_winxp_entries(cachebin)

        elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN8_MAGIC:
            if not quiet:
                print("[+] Found Windows 8/2k12 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN8_MAGIC)

        elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN81_MAGIC:
            if not quiet:
                print("[+] Found Windows 8.1 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN81_MAGIC)

        elif len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE:WIN10_STATS_SIZE+4] == WIN10_MAGIC:
            if not quiet:
                print("[+] Found Windows 10 Apphelp Cache data...")
            return read_win10_entries(cachebin, WIN10_MAGIC)

        elif len(cachebin) > WIN10_CREATORS_STATS_SIZE and cachebin[WIN10_CREATORS_STATS_SIZE:WIN10_CREATORS_STATS_SIZE+4] == WIN10_MAGIC:
            if not quiet:
                print("[+] Found Windows 10 Creators Update Apphelp Cache data...")
            return read_win10_entries(cachebin, WIN10_MAGIC, creators_update=True)

        else:
            print("[-] Got an unrecognized magic value of 0x%x... bailing" % magic)
            return None

    except (RuntimeError, TypeError, NameError) as err:
        print("[-] Error reading Shim Cache data: %s" % err)
        return None

# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic):
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    cache_data = bin_data[WIN8_STATS_SIZE:]

    data = io.BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        if magic != ver_magic:
            raise Exception("Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0])

        entry_data = io.BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            file_path = 'None'
        else:
            file_path = entry_data.read(path_len).decode('utf-16le', 'replace')

        # Check for package data
        package_len = struct.unpack('<H', entry_data.read(2))[0]
        if package_len > 0:
            entry_data.seek(package_len, 1)

        # Read the remaining entry data
        flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack('<LLLLL', entry_data.read(20))

        # Check the flag set in CSRSS
        if (flags & CSRSS_FLAG):
            exec_flag = 'True'
        else:
            exec_flag = 'False'

        last_mod_date = convert_filetime(low_datetime, high_datetime)
        try:
            last_mod_date = last_mod_date.strftime(g_timeformat)
        except ValueError:
            last_mod_date = bad_entry_data

        row = [last_mod_date, 'N/A', file_path, 'N/A', exec_flag]
        entry_list.append(row)

    return entry_list

# Read Windows 10 Apphelp Cache entry format
def read_win10_entries(bin_data, ver_magic, creators_update=False):
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    if creators_update:
        cache_data = bin_data[WIN10_CREATORS_STATS_SIZE:]
    else:
        cache_data = bin_data[WIN10_STATS_SIZE:]

    data = io.BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        if magic != ver_magic:
            raise Exception("Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0])

        entry_data = io.BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            file_path = 'None'
        else:
            file_path = entry_data.read(path_len).decode('utf-16le', 'replace')

        # Read the remaining entry data
        low_datetime, high_datetime = struct.unpack('<LL', entry_data.read(8))

        last_mod_date = convert_filetime(low_datetime, high_datetime)
        try:
            last_mod_date = last_mod_date.strftime(g_timeformat)
        except ValueError:
            last_mod_date = bad_entry_data

        # Skip the unrecognized Microsoft App entry format for now
        if last_mod_date == bad_entry_data:
            continue

        row = [last_mod_date, 'N/A', file_path, 'N/A', 'N/A']
        entry_list.append(row)

    return entry_list

# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry):

    try:
        entry_list = []
        contains_file_size = False
        entry_size = entry.size()
        exec_flag = ''

        num_entries = struct.unpack('<L', bin_data[4:8])[0]
        if num_entries == 0:
            return None

        for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2,
                            entry_size):

            entry.update(bin_data[offset:offset+entry_size])

            if entry.dwFileSizeLow > 3:
                contains_file_size = True
                break

        for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries  * entry_size) + CACHE_HEADER_SIZE_NT5_2,
                            entry_size):

            entry.update(bin_data[offset:offset+entry_size])

            last_mod_date = convert_filetime(entry.dwLowDateTime, entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime(g_timeformat)
            except ValueError:
                last_mod_date = bad_entry_data
            file_path = bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le', 'replace')
            file_path = file_path.replace("\\??\\", "")

            # It contains file size data.
            if contains_file_size:
                hit = [last_mod_date, 'N/A', file_path, str(entry.dwFileSizeLow), 'N/A']
                if hit not in entry_list:
                    entry_list.append(hit)

            # It contains flags.
            else:
                if (entry.dwFileSizeLow & CSRSS_FLAG):
                    exec_flag = 'True'
                else:
                    exec_flag = 'False'

                hit = [last_mod_date, 'N/A', file_path, 'N/A', exec_flag]
                if hit not in entry_list:
                    entry_list.append(hit)

        return entry_list

    except (RuntimeError, ValueError, NameError) as err:
        print("[-] Error reading Shim Cache data: %s..." % err)
        return None

# Read the Shim Cache Windows 7/2k8-R2 entry format,
# return a list of last modifed dates/paths.
def read_nt6_entries(bin_data, entry):

    try:
        entry_list = []
        exec_flag = ""
        entry_size = entry.size()
        num_entries = struct.unpack('<L', bin_data[4:8])[0]

        if num_entries == 0:
            return None

        for offset in range(CACHE_HEADER_SIZE_NT6_1,
                            num_entries*entry_size + CACHE_HEADER_SIZE_NT6_1,
                            entry_size):

            entry.update(bin_data[offset:offset+entry_size])
            last_mod_date = convert_filetime(entry.dwLowDateTime,
                                             entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime(g_timeformat)
            except ValueError:
                last_mod_date = 'N/A'
            file_path = (bin_data[entry.Offset:entry.Offset +
                          entry.wLength].decode('utf-16le','replace'))
            file_path = file_path.replace("\\??\\", "")

            # Test to see if the file may have been executed.
            if (entry.FileFlags & CSRSS_FLAG):
                exec_flag = 'True'
            else:
                exec_flag = 'False'

            hit = [last_mod_date, 'N/A', file_path, 'N/A', exec_flag]

            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list

    except (RuntimeError, ValueError, NameError) as err:
        print('[-] Error reading Shim Cache data: %s...' % err)
        return None

# Read the WinXP Shim Cache data.
def read_winxp_entries(bin_data):

    entry_list = []

    try:
        num_entries = struct.unpack('<L', bin_data[8:12])[0]
        if num_entries == 0:
            return None

        for offset in range(WINXP_HEADER_SIZE32,
                            (num_entries*WINXP_ENTRY_SIZE32) + WINXP_HEADER_SIZE32, WINXP_ENTRY_SIZE32):

            path_len = bin_data[offset:offset+(MAX_PATH + 8)].find(b"\x00\x00")

            if path_len == 0:
                continue
            file_path = bin_data[offset:offset+path_len + 1].decode('utf-16le')

            # Clean up the pathname.
            file_path = file_path.replace('\\??\\', '')
            if len(file_path) == 0: continue

            entry_data = (offset+(MAX_PATH+8))

            # Get last mod time.
            last_mod_time = struct.unpack('<2L', bin_data[entry_data:entry_data+8])
            try:
                last_mod_time = convert_filetime(last_mod_time[0],
                                                 last_mod_time[1]).strftime(g_timeformat)
            except ValueError:
                last_mod_time = 'N/A'

            # Get last file size.
            file_size = struct.unpack('<2L', bin_data[entry_data + 8:entry_data + 16])[0]
            if file_size == 0:
                file_size = bad_entry_data

            # Get last update time.
            exec_time = struct.unpack('<2L', bin_data[entry_data + 16:entry_data + 24])
            try:
                exec_time = convert_filetime(exec_time[0],
                                             exec_time[1]).strftime(g_timeformat)
            except ValueError:
                exec_time = bad_entry_data

            hit = [last_mod_time, exec_time, file_path, file_size, 'N/A']
            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list

    except (RuntimeError, ValueError, NameError) as err:
        print("[-] Error reading Shim Cache data %s" % err)
        return None

# Get Shim Cache data from a registry hive.
def read_from_hive(hive):
    out_list = []
    tmp_list = []

    try:
        from Registry import Registry
    except ImportError:
        print("[-] Hive parsing requires Registry.py... Didn\'t find it, bailing...")
        sys.exit(2)

    try:
        reg = Registry.Registry(hive)
    except Exception as err:
        print("[-] Error parsing %s: %s" % (hive, err))
        sys.exit(1)

    # Partial hive
    partial_hive_path = ('Session Manager', 'AppCompatCache', 'AppCompatibility')
    if reg.root().path() in partial_hive_path:
        if reg.root().path() == 'Session Manager':
            print("[+] Partial hive -- 'Session Manager'")
            if reg.root().find_key('AppCompatCache').values():
                print("[+] Partial hive -- 'AppCompatCache' or 'AppCompatibility'")
                keys = reg.root().find_key('AppCompatCache').values()
        else:
            keys = reg.root().values()
        for k in keys:
            bin_data = k.value()
            tmp_list = read_cache(bin_data)

            if tmp_list:
                for row in tmp_list:
                    if g_verbose:
                        row.append(k.name())
                    if row not in out_list:
                        out_list.append(row)
    else:
        # Complete hive
        root = reg.root().subkeys()
        for key in root:
            try:
                if 'controlset' in key.name().lower():
                    session_man_key = reg.open('%s\\Control\\Session Manager' % key.name())
                    for subkey in session_man_key.subkeys():
                        if ('appcompatibility' in subkey.name().lower() or
                            'appcompatcache' in subkey.name().lower()):
                            bin_data = subkey['AppCompatCache'].value()
                            tmp_list = read_cache(bin_data)

                            if tmp_list:
                                for row in tmp_list:
                                    if g_verbose:
                                        row.append(subkey.path())
                                    if row not in out_list:
                                        out_list.append(row)

            except Exception:
                continue

    if len(out_list) == 0:
        return None
    else:
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Get Shim Cache data from MIR registry output file.
def read_mir(xml_file, quiet=False):
    out_list = []
    tmp_list = []

    try:
        for (_, reg_item) in et.iterparse(xml_file, events=('end',)):
            if reg_item.tag != 'RegistryItem':
                continue

            path_name = reg_item.find("Path").text
            if not path_name:
                print("[-] Error XML missing Path")
                reg_item.clear()
                continue
            path_name = path_name.lower()

            if 'control\\session manager\\appcompatcache\\appcompatcache' in path_name \
                or 'control\\session manager\\appcompatibility\\appcompatcache' in path_name:
                bin_data = binascii.a2b_base64(reg_item.find('Value').text)
                tmp_list = read_cache(bin_data, quiet)

                if tmp_list:
                    for row in tmp_list:
                        if g_verbose:
                            row.append(path_name)
                        if row not in out_list:
                            out_list.append(row)
            reg_item.clear()

    except (AttributeError, TypeError, IOError) as err:
        print("[-] Error reading MIR XML: %s" % str(err))
        return None

    if len(out_list) == 0:
        return None
    else:
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Get Shim Cache data from .reg file.
def read_from_reg(reg_file, quiet=False):
    out_list = []

    if not path.exists(reg_file):
        return None

    with open(reg_file, 'rb') as f:
        file_contents = f.read()

    try:
        file_contents = file_contents.decode('utf-16')
    except UnicodeDecodeError:
        try:
            file_contents = file_contents.decode('ascii')
        except:
            pass

    if not file_contents.startswith('Windows Registry Editor'):
        print("[-] Unable to properly decode .reg file: %s" % reg_file)
        return None

    path_name = None
    relevant_lines = []
    found_appcompat = False
    appcompat_keys = 0
    for line in file_contents.split("\r\n"):
        if '\"appcompatcache\"=hex:' in line.lower():
            relevant_lines.append(line.partition(":")[2])
            found_appcompat = True
        elif '\\appcompatcache]' in line.lower() or '\\appcompatibility]' in line.lower():
            path_name = line.partition('[')[2].partition(']')[0]
            appcompat_keys += 1
        elif found_appcompat and "," in line and '\"' not in line:
            relevant_lines.append(line)
        elif found_appcompat and (len(line) == 0 or '\"' in line):
            hex_str = "".join(relevant_lines).replace('\\', '').replace(' ', '').replace(',', '')
            bin_data = binascii.unhexlify(hex_str)
            tmp_list = read_cache(bin_data, quiet)

            if tmp_list:
                for row in tmp_list:
                    if g_verbose:
                        row.append(path_name)
                    if row not in out_list:
                        out_list.append(row)

            found_appcompat = False
            path_name = None
            relevant_lines = []
            break

    if appcompat_keys <= 0:
        print("[-] Unable to find value in .reg file: %s" % reg_file)
        return None

    if len(out_list) == 0:
        return None
    else:
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Acquire the current system's Shim Cache data.
def get_local_data():

    tmp_list = []
    out_list = []
    global g_verbose

    if not winreg:
        print("[-] This does not appear to be a Windows system (winreg not found).")
        sys.exit(1)

    hReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    hSystem = winreg.OpenKey(hReg, r'SYSTEM')
    for i in range(1024):
        try:
            control_name = winreg.EnumKey(hSystem, i)
            if 'controlset' in control_name.lower():
                hSessionMan = winreg.OpenKey(hReg,
                                             'SYSTEM\\%s\\Control\\Session Manager' % control_name)
                for i in range(1024):
                    try:
                        subkey_name = winreg.EnumKey(hSessionMan, i)
                        if ('appcompatibility' in subkey_name.lower()
                            or 'appcompatcache' in subkey_name.lower()):

                            appcompat_key = winreg.OpenKey(hSessionMan, subkey_name)
                            bin_data = winreg.QueryValueEx(appcompat_key,
                                                           'AppCompatCache')[0]
                            tmp_list = read_cache(bin_data)
                            if tmp_list:
                                path_name = 'SYSTEM\\%s\\Control\\Session Manager\\%s' % (control_name, subkey_name)
                                for row in tmp_list:
                                    if g_verbose:
                                        row.append(path_name)
                                    if row not in out_list:
                                        out_list.append(row)
                    except EnvironmentError:
                        break
        except EnvironmentError:
            break

    if len(out_list) == 0:
        return None
    else:
        if g_verbose:
            out_list.insert(0, output_header + ['Key Path'])
            return out_list
        else:
            out_list = unique_list(out_list)
            out_list.insert(0, output_header)
            return out_list

# Read a MIR XML zip archive.
def read_zip(zip_name):

    zip_contents = []
    final_list = []
    out_list = []
    hostname = ""

    try:
        archive = zipfile.ZipFile(zip_name)
        for zip_file in archive.infolist():
            zip_contents.append(zip_file.filename)

        print("[+] Processing %d registry acquisitions..." % len(zip_contents))
        for item in zip_contents:
            try:
                if '_w32registry.xml' not in item:
                    continue
                filename = item.split('/')
                if len(filename) > 0:
                    filename = filename.pop()
                else:
                    continue
                hostname = '-'.join(filename.split('-')[:-3])
                with archive.open(item) as xml_file:
                    try:
                        out_list = read_mir(xml_file, quiet=True)
                    except(struct.error, et.ParseError):
                        print("[-] Error reading XML data from host: %s, data looks corrupt. Continuing..." % hostname)
                        continue

                if not out_list or len(out_list) == 0:
                    continue
                else:
                    for li in out_list:
                        if "Last Modified" not in li[0]:
                            li.insert(0, hostname)
                            final_list.append(li)

            except IOError as err:
                print("[-] Error opening file: %s in MIR archive: %s" % (item, err))
                continue
        final_list.insert(0, ("Hostname", "Last Modified", "Last Update",
                              "Path", "File Size", "File Executed", "Key Path"))
        return final_list

    except (IOError, zipfile.BadZipfile, struct.error) as err:
        print("[-] Error reading zip archive: %s" % zip_name)
        return None

def main(argv=[]):

    global g_verbose
    global g_timeformat
    global g_usebom

    parser = argparse.ArgumentParser(description="Parses Application Compatibilty Shim Cache data")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Toggles verbose output")
    parser.add_argument("-t","--isotime", action="store_const", dest="timeformat", const=DATE_ISO, default=DATE_MDY,
        help="Use YYYY-MM-DD ISO format instead of MM/DD/YY default")
    parser.add_argument("-B", "--bom", action="store_true", help="Write UTF8 BOM to CSV for easier Excel 2007+ import")

    group = parser.add_argument_group()
    group.add_argument("-o", "--out", metavar="FILE", help="Writes to CSV data to FILE (default is STDOUT)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--local", action="store_true", help="Reads data from local system")
    group.add_argument("-b", "--bin", metavar="BIN", help="Reads data from a binary BIN file")
    group.add_argument("-m", "--mir", metavar="XML", help="Reads data from a MIR XML file")
    group.add_argument("-z", "--zip", metavar="ZIP", help="Reads ZIP file containing MIR registry acquisitions")
    group.add_argument("-i", "--hive", metavar="HIVE", help="Reads data from a registry reg HIVE")
    group.add_argument("-r", "--reg", metavar="REG", help="Reads data from a .reg registry export file")

    args = parser.parse_args(argv[1:])

    if args.verbose:
        g_verbose = True

    g_timeformat = args.timeformat

    if args.bom:
        g_usebom = True

    if args.mir:
        print("[+] Reading MIR output XML file: %s..." % args.mir)
        try:
            with open(args.mir, 'rb') as xml_data:
                entries = read_mir(xml_data)
                if not entries:
                    print("[-] No Shim Cache entries found...")
                    return
                else:
                    write_it(entries, args.out)
        except IOError as err:
            print("[-] Error opening binary file: %s" % str(err))
            return

    elif args.zip:
        print("[+] Reading MIR XML zip archive: %s..." % args.zip)
        entries = read_zip(args.zip)
        if not entries:
            print("[-] No Shim Cache entries found...")
        else:
            write_it(entries, args.out)

    elif args.bin:
        print("[+] Reading binary file: %s..." % args.bin)
        try:
            with open(args.bin, 'rb') as bin_data:
                bin_data_content = bin_data.read()
        except IOError as err:
            print("[-] Error opening binary file: %s" % str(err))
            return
        entries = read_cache(bin_data_content)
        if not entries:
            print("[-] No Shim Cache entries found...")
        else:
            write_it(entries, args.out)

    elif args.reg:
        print("[+] Reading .reg file: %s..." % args.reg)
        entries = read_from_reg(args.reg)
        if not entries:
            print("[-] No Shim Cache entries found...")
        else:
            write_it(entries, args.out)

    elif args.hive:
        print("[+] Reading registry hive: %s..." % args.hive)
        try:
            entries = read_from_hive(args.hive)
            if not entries:
                print("[-] No Shim Cache entries found...")
            else:
                write_it(entries, args.out)
        except IOError as err:
            print("[-] Error opening hive file: %s" % str(err))
            return

    elif args.local:
        print("[+] Dumping Shim Cache data from the current system...")
        entries = get_local_data()
        if not entries:
            print("[-] No Shim Cache entries found...")
        else:
            write_it(entries, args.out)

if __name__ == '__main__':
    main(sys.argv)
