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


# ライブラリの特定が必要ならばTrue
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
        # シグネチャ
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
        signame = set()
        dir = os.path.dirname(os.path.abspath(sys.executable))
        for p in glob.glob(os.path.join(dir, 'sig', cpu, '_*_*.sig')):
            signame.add(os.path.basename(p))
        # JSON読み込み
        root, _ = os.path.splitext(os.path.abspath(get_idb_path()))
        file = root + '_' + basename + '.json'
        if os.path.exists(file):
            with open(file) as f:
                libjson = json.load(f)
        else:
            libjson = {}
        edit = False
        for k in ('estimate', 'determine'):
            if k in libjson:
                diff = frozenset(libjson[k]) - signame
                if diff:
                    for n in diff:
                        del libjson[k][n]
                    edit = True
            else:
                libjson[k] = {}
        if 'result' in libjson \
                and not all(lambda n: libjson['result'][n] in signame,
                            libname):
            del libjson['result']
            edit = True
        # シグネチャ適用
        diff = signame - frozenset(libjson['estimate'])
        if diff:
            # 概算
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
        elif 'result' not in libjson:
            # 決定
            signame = sorted(signame)
            for ln in libname:
                name = None
                estimate = 0
                determine = 1
                for n in signame:
                    if n.startswith(ln):
                        if n in libjson['determine']:
                            if determine < libjson['determine'][n]:
                                determine = libjson['determine'][n]
                        else:
                            if estimate < libjson['estimate'][n]:
                                name = n
                                estimate = libjson['estimate'][n]
                if estimate >= determine:
                    plan_to_apply_idasgn(name)
                    auto_wait()
                    count = 0
                    for ea in Functions():
                        flags = get_func_flags(ea)
                        if flags != -1 and flags & FUNC_LIB:
                            count += 1
                    libjson['determine'][name] = count
                    edit = True
                    break
            # 終了判定
            result = {}
            for ln in libname:
                name = None
                estimate = determine = 0
                for n in signame:
                    if n.startswith(ln):
                        if n in libjson['determine']:
                            if determine < libjson['determine'][n]:
                                name = n
                                determine = libjson['determine'][n]
                        else:
                            if estimate < libjson['estimate'][n]:
                                estimate = libjson['estimate'][n]
                if estimate < max(determine, 1):
                    result[ln] = name
            if frozenset(result) == frozenset(libname):
                libjson['result'] = result
                edit = True
        # JSON更新
        if edit:
            with open(file, 'w', newline='\n') as f:
                json.dump(libjson, f, indent=2, sort_keys=True)
        # 終了
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

        # ファイル・フォルダ
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
                        while not is_result(file):
                            epoch = os.path.getmtime(file) \
                                                if os.path.exists(file) else -1
                            prepare.exec_ida(idapro, script, path)
                            if not os.path.exists(file) \
                                    or epoch == os.path.getmtime(file):
                                break
                    else:
                        with open(file, 'w', newline='\n') as f:
                            json.dump({'result': {}},
                                      f, indent=2, sort_keys=True)
