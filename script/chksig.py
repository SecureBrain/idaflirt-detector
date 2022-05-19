#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# idaflirt-detector
# https://github.com/SecureBrain/idaflirt-detector
# Copyright (c) 2022 SecureBrain


import argparse
import glob
import importlib
import json
import os
import re
import sys
try:
    import elftools.elf.elffile
except ImportError:
    pyelftools = False
else:
    pyelftools = True
try:
    import idc
except ImportError:
    idapro = False
else:
    idapro = True
try:
    importlib.reload(prepare)
except NameError:
    import prepare


# True if Library Identification is Necessary
if pyelftools:
    def is_strip(file):
        ret = False
        with open(file, 'rb') as f:
            try:
                elf = elftools.elf.elffile.ELFFile(f)
                ret = True
                for section in elf.iter_sections():
                    if isinstance(section,
                                  elftools.elf.sections.SymbolTableSection):
                        ret = False
                        break
            except elftools.common.exceptions.ELFParseError:
                pass
        return ret
else:
    def is_strip(file):
        return True


def is_result(file):
    ret = False
    if os.path.exists(file):
        with open(file) as f:
            libjson = json.load(f)
        if 'result' in libjson:
            ret = True
    return ret


if __name__ == '__main__':
    script = os.path.abspath(__file__)
    root, _ = os.path.splitext(script)
    basename = os.path.basename(root)
    if idapro:
        libname = ('_libc_', '_libgcc_')
        # Signature
        name = get_inf_attr(INF_PROCNAME)
        if name.lower().startswith('arm'):
            cpu = 'arm'
        elif name.lower().startswith('mips'):
            cpu = 'mips'
        elif len(name) >= 3 \
                and name.lower().startswith('sh') and name[2].isdigit():
            cpu = 'sh3'
        elif name.lower().startswith('ppc'):
            cpu = 'ppc'
        elif re.fullmatch(r'68\d*(|ex|k)', name, re.IGNORECASE):
            cpu = 'mc68k'
        else:
            cpu = 'pc'
        dir = os.path.dirname(os.path.abspath(sys.executable))
        signame = set(os.path.basename(p)
                      for p in glob.glob(os.path.join(dir,
                                                      'sig', cpu, '_*_*.sig')))
        # Read JSON
        root, _ = os.path.splitext(os.path.abspath(get_idb_path()))
        file = root + '_' + basename + '.json'
        if os.path.exists(file):
            with open(file) as f:
                libjson = json.load(f)
        else:
            libjson = {}
        edit = True
        if 'estimate' in libjson:
            diff = frozenset(libjson['estimate']) - signame
            if diff:
                for n in diff:
                    del libjson['estimate'][n]
            elif 'result' in libjson:
                edit = False
        else:
            libjson['estimate'] = {}
        # Apply Signature
        diff = signame - frozenset(libjson['estimate'])
        if diff:
            # Estimation
            for name in sorted(diff):
                for ea in Functions():
                    flags = get_func_flags(ea)
                    if flags != -1 and flags & FUNC_LIB:
                        set_func_flags(ea, flags & ~FUNC_LIB)
                auto_wait()
                plan_to_apply_idasgn(name)
                auto_wait()
                count = 0
                for ea in Functions():
                    flags = get_func_flags(ea)
                    if flags != -1 and flags & FUNC_LIB:
                        count += 1
                libjson['estimate'][name] = count
            edit = True
        # Result
        if edit:
            libjson['result'] = {}
            signame = sorted(signame)
            for ln in libname:
                name = None
                estimate = 1
                for n in signame:
                    if n.startswith(ln) and estimate < libjson['estimate'][n]:
                        name = n
                        estimate = libjson['estimate'][n]
                libjson['result'][ln] = name
            # Update JSON
            with open(file, 'w', newline='\n') as f:
                json.dump(libjson, f, indent=2, sort_keys=True)
        # Exit
        if idc.ARGV:
            qexit(0)
    else:
        parser = argparse.ArgumentParser(description='Check Signature.')
        parser.add_argument('path', nargs='+', help='ELF file')
        parser.add_argument('-f', '--force', action='store_true',
                            help='force check signature')
        parser.add_argument('-i', '--ignore', action='store_true',
                            help='ignore machine and strip')
        parser.add_argument('--ignore-entropy', action='store_true',
                            help='ignore entropy')
        parser.add_argument('--ignore-machine', action='store_true',
                            help='ignore machine')
        parser.add_argument('--ignore-strip', action='store_true',
                            help='ignore strip')
        args = vars(parser.parse_args())
        if args.pop('ignore'):
            args.update({'ignore_entropy': True,
                         'ignore_machine': True,
                         'ignore_strip':   True})

        # File/Folder
        idapro32, idapro64 = prepare.get_idapro_path()
        for arg in args['path']:
            for path in glob.glob(arg):
                root, _ = os.path.splitext(os.path.abspath(path))
                file = root + '_' + basename + '.json'
                if args['force'] and os.path.exists(file):
                    os.remove(file)
                if not is_result(file):
                    bits, machine = prepare.get_elf_attr(path)
                    if bits and (args['ignore_machine']
                                 or machine in (3, 8, 20, 40, 42, 62)) \
                        and (args['ignore_strip'] or is_strip(path)) \
                        and (args['ignore_entropy']
                             or not prepare.is_packed(path)):
                        idapro = {32: idapro32, 64: idapro64}[bits]
                        prepare.exec_ida(idapro, script, path)
                    else:
                        with open(file, 'w', newline='\n') as f:
                            json.dump({'result': {}},
                                      f, indent=2, sort_keys=True)
