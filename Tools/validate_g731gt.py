#!/usr/bin/env python3
"""Validate G731GT resources against the hardware dump and optional built kext."""
import argparse
from pathlib import Path
import plistlib
import re
import struct
import zlib

REPO = Path(__file__).resolve().parents[1]
CODEC = 0x10EC0294
LAYOUT = 29


def plist(data):
    if data.lstrip().startswith(b'<dict>'):
        data = b'<plist version="1.0">' + data + b'</plist>'
    return plistlib.loads(data)


def embedded_resources(binary):
    sections = []
    offset = 32
    for _ in range(struct.unpack_from('<I', binary, 16)[0]):
        command, size = struct.unpack_from('<II', binary, offset)
        if command == 0x19:
            for i in range(struct.unpack_from('<I', binary, offset + 64)[0]):
                address, length, start = struct.unpack_from('<QQI', binary, offset + 72 + 80*i + 32)
                sections.append((address, length, start))
        offset += size

    def translate(pointer):
        for address, length, start in sections:
            if address <= pointer < address + length:
                return start + pointer - address
        raise ValueError('Unmapped address')

    matches = []
    for offset in range(0, len(binary) - 80, 8):
        if struct.unpack_from('<H', binary, offset + 8)[0] != (CODEC & 0xFFFF):
            continue
        _, _, _, _, platforms, count_p, layouts, count_l, _, _ = struct.unpack_from('<QH6xQQQQQQQQ', binary, offset)
        if not (0 < count_p < 40 and 0 < count_l < 40):
            continue
        result = {}
        try:
            for name, pointer, count in [('Platforms', platforms, count_p), ('layout', layouts, count_l)]:
                table = translate(pointer)
                for i in range(count):
                    pointer, length, _, _, layout = struct.unpack_from('<QIIII', binary, table + 24*i)
                    if layout == LAYOUT:
                        start = translate(pointer)
                        result[name] = plist(zlib.decompress(binary[start:start+length]))
        except (ValueError, struct.error, zlib.error, plistlib.InvalidFileException):
            continue
        if len(result) == 2:
            matches.append(result)
    assert len(matches) == 1, 'Exactly one embedded ALC294/layout29 table required'
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kext', type=Path)
    parser.add_argument('--dump', type=Path, help='Optional private Realtek codec dump; never uploaded by this tool')
    args = parser.parse_args()
    nodes, pins = {}, {}
    if args.dump:
        dump = args.dump.read_text().split('Codec: Intel', 1)[0]
        assert 'Vendor Id: 0x10ec0294' in dump and 'Subsystem Id: 0x1043184e' in dump
        nodes = {int(n, 16): body for n, body in re.findall(r'Node 0x([0-9a-f]+) ([\s\S]*?)(?=\nNode 0x|\Z)', dump)}
        pins = {n: int(m[1], 16) for n, body in nodes.items() if (m := re.search(r'Pin Default 0x([0-9a-f]+)', body))}
        connected = {n for n, value in pins.items() if value >> 30 != 1}
        assert connected == {0x12, 0x14, 0x21}
    info = plist((REPO / 'Resources/ALC294/Info.plist').read_bytes())
    sources = {}
    for name, kind in [('layout', 'Layouts'), ('Platforms', 'Platforms')]:
        entries = [e for e in info['Files'][kind] if e['Id'] == LAYOUT]
        assert len(entries) == 1 and entries[0]['Path'] == f'{name}29.xml.zlib'
        sources[name] = plist((REPO / f'Resources/ALC294/{name}29.xml').read_bytes())
    platform = sources['Platforms']
    layout = sources['layout']
    assert layout['LayoutID'] == LAYOUT and len(layout['PathMapRef']) == 1
    ref = layout['PathMapRef'][0]
    assert ref['CodecID'] == [CODEC] and ref['PathMapID'] == LAYOUT
    assert ref['Inputs'] == ['Mic'] and ref['Outputs'] == ['IntSpeaker', 'Headphone']
    assert len(platform['PathMaps']) == 1
    assert platform['PathMaps'][0]['PathMapID'] == LAYOUT
    paths = []

    def walk(item):
        if isinstance(item, list):
            if item and all(isinstance(n, dict) and 'NodeID' in n for n in item):
                paths.append([n['NodeID'] for n in item])
            else:
                for child in item:
                    walk(child)

    walk(platform['PathMaps'][0]['PathMap'])
    assert sorted(paths) == sorted([[7, 0x24, 0x12], [0x14, 2], [0x21, 3]])
    for path in paths if nodes else []:
        for node, upstream in zip(path, path[1:]):
            match = re.search(r'Connection: \d+\s*\n([^\n]+)', nodes[node])
            assert match and upstream in [int(n, 16) for n in re.findall(r'0x([0-9a-f]+)', match[1])]
    pin_info = plist((REPO / 'Resources/PinConfigs.kext/Contents/Info.plist').read_bytes())
    entries = [e for p in pin_info['IOKitPersonalities'].values() for e in p.get('HDAConfigDefault', [])
               if e.get('CodecID') == CODEC and e.get('LayoutID') == LAYOUT]
    assert len(entries) == 1
    pin = entries[0]
    reconstructed = {}
    verbs = pin['ConfigData']
    assert len(verbs) % 4 == 0
    for (value,) in struct.iter_unpack('>I', verbs):
        assert value >> 28 == 0, 'Wrong codec address'
        node, command, payload = (value >> 20) & 255, (value >> 8) & 0xFFF, value & 255
        if 0x71C <= command <= 0x71F:
            reconstructed[node] = reconstructed.get(node, 0) | (payload << ((command - 0x71C)*8))
    if pins:
        assert reconstructed == pins, 'Pin defaults differ from the dump'
    assert {n for n, value in reconstructed.items() if value >> 30 != 1} == {0x12, 0x14, 0x21}
    assert pin['WakeVerbReinit'] is True
    if args.kext:
        built = plist((args.kext / 'Contents/Info.plist').read_bytes())
        entries = [e for p in built['IOKitPersonalities'].values() for e in p.get('HDAConfigDefault', [])
                   if e.get('CodecID') == CODEC and e.get('LayoutID') == LAYOUT]
        assert entries == [pin], 'Compiled kext pin configuration differs'
        binary = (args.kext / 'Contents/MacOS/AppleALC').read_bytes()
        assert struct.unpack_from('<II', binary) == (0xFEEDFACF, 0x01000007), 'Expected x86_64 Mach-O'
        assert embedded_resources(binary) == sources, 'Compiled resources differ from source'
        print(f'PASS: built {built["CFBundleVersion"]} x86_64 resources and pin configuration match source')
    print('PASS: layout29 and PathMap29 resource consistency')
    if args.dump:
        print('PASS: all pin defaults and three routes match the private codec dump')


if __name__ == '__main__':
    main()
