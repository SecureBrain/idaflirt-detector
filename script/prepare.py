#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# idaflirt-detector
# https://github.com/SecureBrain/idaflirt-detector
# Copyright (c) 2022 SecureBrain

import collections
import glob
import json
import math
import os
import re
import struct
import subprocess
import sys
try:
    import idaapi
    import idautils
    import idc
except ImportError:
    idapro = False
else:
    idapro = True


ENTROPY_THRESHOLD = 7.2


# Entropy
def entropy(file):
    size = os.path.getsize(file)
    with open(file, 'rb') as f:
        ent = -sum(map(lambda x: x * math.log(x, 2),
                       map(lambda x: float(x) / size,
                           collections.Counter(f.read()).values())))
    return ent


# Get ELF Attributes
# 3:pc, 4:mc68k, 8:mips, 20:ppc, 40:arm, 42:sh3, 62:pc
def get_elf_attr(file):
    bits = machine = None
    with open(file, 'rb') as f:
        buf = f.read(20)
        if buf[:4] == b'\x7FELF':
            endian = {1: '<', 2: '>'}.get(buf[5])
            if endian:
                bits = {1: 32, 2: 64}.get(buf[4])
                machine, = struct.unpack(endian + '18xH', buf)
    return bits, machine


# Is Packed
def is_packed(file):
    return entropy(file) >= ENTROPY_THRESHOLD


# Get IDA Pro Path
def get_idapro_path():
    idapro = glob.glob(os.path.join(os.environ['ProgramFiles'], 'IDA Pro*'))
    if len(idapro) != 1:
        print(idapro, file=sys.stderr)
        sys.exit(-1)
    idapro = idapro[0]
    return os.path.join(idapro, 'idat.exe'), os.path.join(idapro, 'idat64.exe')


# IDA Python
def exec_ida(idapro, script, file):
    subprocess.run((idapro, '-A', '-B', '-c', '-S\"' + script + '\"', file))
    # 削除
    for ext in ('.asm', '.i64', '.id0', '.id1',
                '.id2', '.idb', '.nam', '.til'):
        f = file + ext
        if os.path.exists(f):
            os.remove(f)


# Make functions from independent codes
def functionalize_single_instruction():
    seg = idc.get_first_seg()
    while seg != idc.BADADDR:
        ea = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        st = idc.BADADDR
        while ea < end:
            if idc.is_code(idc.get_full_flags(ea)) \
                    and idc.get_func_flags(ea) == -1:
                if st == idc.BADADDR:
                    st = ea
            elif st != idc.BADADDR:
                for xref in idautils.XrefsTo(ea):
                    if not st <= xref.frm < ea:
                        idc.add_func(st, ea)
                        st = idc.BADADDR
                        break
            ea = idc.get_item_end(ea)
        if st != idc.BADADDR:
            idc.add_func(st, ea)
        seg = idc.get_next_seg(seg)


# Apply Signature
def apply_signature():
    # Read JSON
    root, _ = os.path.splitext(os.path.abspath(idc.get_idb_path()))
    file = root + '_chksig.json'
    if os.path.exists(file):
        with open(file) as f:
            result = set(filter(None,
                                json.load(f).get('result', {}).values()))
            for i in range(idaapi.get_idasgn_qty()):
                n, _ = idaapi.get_idasgn_desc(i)
                result.discard(n)
            if result:
                for name in result:
                    idc.plan_to_apply_idasgn(name)
                idc.auto_wait()


# Normalize Function Name
def true_up_function_name():
    # Library Function Name
    file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'name_alternate.csv')
    libfunc = {}
    if os.path.exists(file):
        with open(file) as f:
            for s in f:
                e = s.strip().split(',')
                libfunc.update({k: e[0] for k in e})
    # Library Flag
    for ea in idautils.Functions():
        name = idc.get_name(ea)
        if name in libfunc:
            truename = libfunc[name]
            if name != truename \
                    and idc.get_name_ea_simple(truename) == idc.BADADDR:
                idc.set_name(ea, truename)
            flags = idc.get_func_flags(ea)
            if flags != -1 and not flags & idc.FUNC_LIB:
                idc.set_func_flags(ea, flags | idc.FUNC_LIB)


# Get C main
def get_c_main():
    addr = idc.get_name_ea_simple('main')
    r = re.compile(r'main_([0-9A-Fa-f]+)')
    seg = idc.get_first_seg()
    while seg != idc.BADADDR and addr == idc.BADADDR:
        ea = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        while ea < end:
            name = idc.get_name(ea)
            m = r.fullmatch(name)
            if m and int(m.group(1), 16) == ea:
                addr = ea
                break
            ea = idc.get_item_end(ea)
        seg = idc.get_next_seg(seg)
    return addr


# Detect and create main
def register_c_main():
    if get_c_main() == idc.BADADDR:
        addr = set()
        ea = idc.get_inf_attr(idc.INF_START_EA)
        ed = idc.get_func_attr(ea, idc.FUNCATTR_END)
        ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
        while ea < ed:
            for xref in idautils.XrefsFrom(ea):
                if xref.type == idc.dr_O \
                        and not idc.hasName(idc.get_full_flags(xref.to)):
                    addr.add(xref.to)
            ea = idc.get_item_end(ea)
        if len(addr) == 1:
            addr = addr.pop()
            idc.set_name(addr, 'main_{:X}'.format(addr))


# Load Type Library
def load_type_library():
    return idc.add_default_til('gnuunx64'
                               if idaapi.get_inf_structure().is_64bit()
                               else 'gnuunx')


# Set Type
def set_type(ea, newtype):
    ret = True
    if newtype:
        pt = idc.parse_decl(newtype, idc.PT_SILENT)  # silent
        if pt is None:
            ret = False
    else:
        pt = None
    return ret and idc.apply_type(ea, pt)


# Apply Function Type
def apply_function_type():
    # Read
    root, _ = os.path.splitext(os.path.abspath(__file__))
    file = root + '.txt'
    decl = {}
    with open(file) as f:
        r = re.compile(r'.*?(\w+)\s*\(.*')
        for s in map(lambda s: s.strip(), f):
            m = r.fullmatch(s)
            if m:
                decl[m.group(1)] = s
    # Library Function Name
    file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'name_alternate.csv')
    if os.path.exists(file):
        with open(file) as f:
            for s in f:
                e = s.strip().split(',')
                for n1 in e:
                    if n1 not in decl:
                        for n2 in e:
                            if n2 in decl:
                                decl[n1] = decl[n2]
                                break
    # Search Matched Name and Apply the Function Declaration
    r = re.compile(r'(\w+?)(_[0-9a-fA-F]+)')
    seg = idc.get_first_seg()
    while seg != idc.BADADDR:
        ea = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        while ea < end:
            name = idc.get_name(ea, idc.GN_VISIBLE)
            if name:
                api = None
                if name in decl:
                    api = name
                else:
                    m = r.fullmatch(name)
                    if m:
                        n = m.group(1)
                        if n in decl:
                            api = n
                if api:
                    try:
                        set_type(ea, decl[api])
                    except Exception:
                        print('Except:', name)
            ea = idc.get_item_end(ea)
        seg = idc.get_next_seg(seg)


initialized = False


def init_idb():
    global initialized
    if not initialized:
        functionalize_single_instruction()
        apply_signature()
        true_up_function_name()
        register_c_main()
        load_type_library()
        apply_function_type()
        initialized = True


if __name__ == '__main__':
    if idapro:
        init_idb()
    else:
        # Read
        argc = len(sys.argv)
        if argc >= 2:
            with open(sys.argv[1]) as f:
                indata = f.read()
        elif not sys.stdin.isatty():
            indata = sys.stdin.read()
        else:
            sys.exit('usage: ' + __file__ + ' infile outfile')
        indata = indata.splitlines()
        # Normalize Function Name
        alternate = set()
        file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'name_alternate.csv')
        if os.path.exists(file):
            with open(file) as f:
                for s in f:
                    e = s.strip().split(',')
                    alternate.update(e[1:])
        # Regular Expression
        r_decl = re.compile(r'.*?(\w+)\s*\(.*')
        r_sort = re.compile(r'[^\da-zA-Z]')
        r_space = re.compile(r'\s*(\W)\s*')
        # Process
        outdate = []
        for i, s in enumerate(indata):
            if s:
                m = r_decl.fullmatch(s)
                if m:
                    n = m.group(1)
                    outdate.append((r_sort.sub('', n).lower(), n,
                                    r_space.sub(r'\1', ' '.join(s.split()))
                                    .replace('*', ' *').replace(',', ', ')))
                    if n in alternate:
                        print('Name:', i, n, file=sys.stderr)
                else:
                    sys.exit('Syntax: ' + str(i) + ' ' + s)
        outdate = '\n'.join(map(lambda t: t[2], sorted(outdate)))
        # Write
        if argc >= 2:
            with open(sys.argv[min(argc, 3) - 1], 'w', newline='\n') as f:
                f.write(outdate + '\n')
        else:
            print(outdate)
