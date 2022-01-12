#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# idaflirt-detector
# https://github.com/SecureBrain/idaflirt-detector
# Copyright (c) 2022 SecureBrain


import glob
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.parse


if __name__ == '__main__':
    # パッケージ定義
    architecture = [('arm',   'armv4l'),
                    ('arm',   'armv5l'),
                    ('mc68k', 'm68k'),
                    ('mips',  'mips'),
                    ('mips',  'mipsel'),
                    ('pc',    'i586'),
                    ('pc',    'i686'),
                    ('pc',    'x86_64'),
                    ('ppc',   'powerpc'),
                    ('sh3',   'sh4')]
    firmware = [('0.9.30.1', 'ppc', 'powerpc-440fp')]
    for version in ('0.9.30', '0.9.30.1'):
        for cpu, label in architecture:
            firmware.append((version, cpu, label))
    architecture.extend((('arm',  'armv4tl'),
                         ('arm',  'armv6l'),
                         ('mips', 'mips64'),
                         ('pc',   'i486')))
    aboriginal = [('1.2.6', 'arm', 'armv7l', 'bz2')]
    for version in ('1.2.4', '1.2.5', '1.2.6',
                    '1.2.7', '1.2.8', '1.2.9', '1.3.0'):
        for cpu, label in architecture:
            aboriginal.append((version, cpu, label, 'bz2'))
    for version in ('1.4.0', '1.4.1'):
        for cpu, label in architecture:
            aboriginal.append((version, cpu, label, 'gz'))
    architecture.extend((('sh3', 'sh2eb'), ('sh3', 'sh2elf')))
    for version in ('1.4.2', '1.4.3'):
        for cpu, label in architecture:
            aboriginal.append((version, cpu, label, 'gz'))
    architecture.append(('ppc', 'powerpc-440fp'))
    for version in ('1.4.4', '1.4.5'):
        for cpu, label in architecture:
            aboriginal.append((version, cpu, label, 'gz'))
    aboriginal.remove(('1.4.3', 'arm',  'armv6l', 'gz'))
    aboriginal.remove(('1.4.3', 'mips', 'mips64', 'gz'))
    aboriginal.remove(('1.4.4', 'arm',  'armv4l', 'gz'))
    archive = {}
    for version, cpu, label in firmware:
        name = 'firmware-' + version + '-' + label
        archive[name] = {}
        archive[name]['cpu'] = cpu
        archive[name]['pkg'] = 'firmware' + os.sep + version
        archive[name]['url'] = 'https://www.uclibc.org/downloads/binaries/' \
            + version + '/cross-compiler-' + label + '.tar.bz2'
    for version, cpu, label, ext in aboriginal:
        name = 'aboriginal-' + version + '-' + label
        archive[name] = {}
        archive[name]['cpu'] = cpu
        archive[name]['pkg'] = 'aboriginal' + os.sep + version
        archive[name]['url'] \
            = 'https://landley.net/aboriginal/downloads/old/binaries/' \
            + version + '/cross-compiler-' + label + '.tar.' + ext

    # CPU
    cpu_opt = (('arm',   ('-r104:0:0',)),
               ('mc68k', ()),
               ('mips',  ('-r10:0:0', '-r46:0:0')),
               ('pc',    ()),
               ('ppc',   ('-r67:0:0', '-r87:0:0')),
               ('sh3',   ('-r2:0:0',  '-r147:0:0')))
    # 実行環境
    cur_dir = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 \
        else os.path.dirname(os.path.abspath(__file__))
    pf = platform.system()
    if pf == 'Windows':
        dir = 'win'
        ext = '.exe'
    else:
        if pf == 'Darwin':
            dir = 'mac' if platform.machine() == 'x86_64' else 'armmac'
        else:
            dir = 'linux'
        ext = ''
    flair = glob.glob(os.path.join(cur_dir, 'flair??'))
    flair.sort()
    flair = [cur_dir, os.path.basename(flair[-1])] if flair else [cur_dir]
    flair.extend(('bin', dir))
    while flair:
        pelf = os.path.join(cur_dir, *flair, 'pelf' + ext)
        sigmake = os.path.join(cur_dir, *flair, 'sigmake' + ext)
        if os.path.exists(pelf) and os.path.exists(sigmake):
            break
        flair.pop(1 if len(flair) > 1 else 0)
    else:
        pelf = 'pelf' + ext
        sigmake = 'sigmake' + ext

    # ディレクトリ作成
    pkg_dir = os.path.join(cur_dir, 'pkg')
    lib_dir = os.path.join(cur_dir, 'lib')
    pat_dir = os.path.join(cur_dir, 'pat')
    sig_dir = os.path.join(cur_dir, 'sig')
    tmp_dir = os.path.join(cur_dir, 'tmp')
    sub_dir = set()
    for name in archive:
        sub_dir.add(os.path.join(cur_dir, 'pkg', archive[name]['pkg']))
        cpu = archive[name]['cpu']
        for dir in ('lib', 'pat', 'sig'):
            sub_dir.add(os.path.join(cur_dir, dir, cpu))
    for dir in sub_dir:
        os.makedirs(dir, exist_ok=True)

    # パッケージ
    table = str.maketrans({c: '-' for c in '!\"#$&\'()*+;<>?[\\]^`{|}~'})
    libname = ('libc', 'libgcc')
    libfile = {ln + '.a': ln for ln in libname}
    for name in sorted(archive):
        # ダウンロード
        cpu = archive[name]['cpu']
        url = archive[name]['url']
        file = os.path.join(pkg_dir, archive[name]['pkg'],
                            os.path.basename(urllib.parse.urlparse(url).path))
        if not os.path.exists(file):
            subprocess.run(('wget', '-O', file, url))

        # ライブラリ収集
        if not any(map(lambda f: glob.glob(f),
                       (os.path.join(lib_dir,
                                     cpu,
                                     '_' + ln + '_' + name + '*')
                        for ln in libname))):
            # 展開
            os.makedirs(tmp_dir, exist_ok=True)
            _, ext = os.path.splitext(file)
            c = {'.gz': 'z', '.bz2': 'j', '.xz': 'J'}[ext]
            path = []
            for f in subprocess.run(('tar', '--warning=no-unknown-keyword',
                                     '-' + c + 'tf', file),
                                    stdout=subprocess.PIPE). \
                    stdout.decode().splitlines():
                if os.path.basename(f) in libfile:
                    path.append(f)
            if path:
                subprocess.run(['tar', '--warning=no-unknown-keyword',
                                '-' + c + 'xf', file, '-C', tmp_dir] + path)
            # 移動
            path = {lf: set() for lf in libfile}
            for dirpath, _, filename in os.walk(tmp_dir):
                for file in filename:
                    p = os.path.join(dirpath, file)
                    if not os.path.islink(p) and file in libfile:
                        path[file].add(p)
            for lf in libfile:
                count = {}
                for p in path[lf]:
                    for i, e in enumerate(p.split(os.sep)):
                        if i not in count:
                            count[i] = set()
                        count[i].add(e)
                for i in count:
                    count[i] = len(count[i])
                for p in path[lf]:
                    element = [name]
                    for i, e in enumerate(p.split(os.sep)[:-1]):
                        if count[i] > 1:
                            element.append(e)
                    os.rename(p, os.path.join(lib_dir,
                                              cpu,
                                              '_' + libfile[lf] + '_'
                                              + '-'.join(element).
                                              translate(table)) + '.a')
            shutil.rmtree(tmp_dir)

    for cpu, opt in cpu_opt:
        # パターン作成
        pattern = []
        libpath = glob.glob(os.path.join(lib_dir, cpu, '*.a'))
        libpath.sort()
        for lib in libpath:
            root, _ = os.path.splitext(lib)
            name = os.path.basename(root)
            pat = os.path.join(pat_dir, cpu, name + '.pat')
            if not os.path.exists(pat):
                subprocess.run((pelf,) + opt + (lib, pat))
            if os.path.exists(pat):
                with open(pat) as f:
                    s = tuple(f)
                    if len(s) > 0 and s[-1].strip() == '---':
                        pattern.append(pat)
        # 重複パターンを削除
        pattern.sort()
        pat_path = pattern.copy()
        pat_size = {p: os.path.getsize(p) for p in pattern}
        pat_hash = {}
        while pat_path:
            pat = pat_path.pop(0)
            for p in pat_path.copy():
                if pat_size[pat] == pat_size[p]:
                    if pat not in pat_hash:
                        with open(pat, 'rb') as f:
                            pat_hash[pat] = hashlib.sha256(f.read()).digest()
                    if p not in pat_hash:
                        with open(p, 'rb') as f:
                            pat_hash[p] = hashlib.sha256(f.read()).digest()
                    if pat_hash[pat] == pat_hash[p]:
                        root, _ = os.path.splitext(pat)
                        with open(p, 'w') as f:
                            f.write(os.path.basename(root) + '\n')
                        pattern.remove(p)
                        pat_path.remove(p)
        # シグネチャ作成
        for pat in pattern:
            root, _ = os.path.splitext(pat)
            name = os.path.basename(root)
            sig = os.path.join(sig_dir, cpu, name + '.sig')
            if not os.path.exists(sig):
                subprocess.run((sigmake, '-r', '-n' + name, pat, sig))

    # 名前ファイル作成
    re_hex = re.compile(r'-?[\da-fA-F]+')
    pattern = []
    for cpu, _ in cpu_opt:
        pattern.extend(glob.glob(os.path.join(pat_dir, cpu, '*.pat')))
    pattern.sort()
    file = os.path.join(cur_dir, 'name_alternate.csv')
    if not os.path.exists(file) or os.path.getmtime(file) \
            < max(map(lambda p: os.path.getmtime(p), pattern)):
        symbol = []
        for pat in pattern:
            with open(pat) as f:
                for s in f:
                    entry = {}
                    element = s.strip().split()
                    if len(element) >= 5:
                        element = element[4:]
                        while len(element) >= 2:
                            e = element.pop(0)
                            if e.startswith(':'):
                                e = e.lstrip(':').rstrip('@')
                                if re_hex.fullmatch(e):
                                    k = int(e, 16)
                                    if k not in entry:
                                        entry[k] = set()
                                    entry[k].add(element.pop(0))
                    for v in entry.values():
                        for s in symbol:
                            if not v.isdisjoint(s):
                                v.update(s)
                                s.clear()
                        while frozenset() in symbol:
                            symbol.remove(frozenset())
                        symbol.append(v)
        symbol = map(lambda sym: sorted(sym,
                                        key=lambda s: (len(s), s.swapcase())),
                     symbol)
        with open(file, 'w') as f:
            for s in sorted(symbol):
                f.write(','.join(s) + '\n')

    pattern = tuple(pat for pat in pattern
                    if os.path.basename(pat).startswith('_libgcc_'))
    file = os.path.join(cur_dir, 'name_ignore.txt')
    if not os.path.exists(file) or os.path.getmtime(file) \
            < max(map(lambda p: os.path.getmtime(p), pattern)):
        symbol = set()
        for pat in pattern:
            with open(pat) as f:
                for s in f:
                    element = s.strip().split()
                    if len(element) >= 5:
                        element = element[4:]
                        while len(element) >= 2:
                            e = element.pop(0)
                            if e.startswith(':'):
                                e = e.lstrip(':').rstrip('@')
                                if re_hex.fullmatch(e):
                                    symbol.add(element.pop(0))
        with open(file, 'w') as f:
            for s in sorted(symbol):
                f.write(s + '\n')
