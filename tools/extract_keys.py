"""Collects every translatable English text from the web project.

Used to keep Resources/SharedResource.sr-Latn.resx complete:
    python3 tools/extract_keys.py            -> prints keys missing a translation
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(__file__), '..', 'IdentityToMvc.Web')
PATTERNS = [
    r'(?:\bL|\b_t|\bT|\bt)\["((?:[^"\\]|\\.)*)"',
    r'Display\(Name = "((?:[^"\\]|\\.)*)"',
    r'ErrorMessage = "((?:[^"\\]|\\.)*)"',
]


def unescape(value):
    return value.replace('\\"', '"').replace('\\\\', '\\')


def collect_keys():
    keys = set()
    files = glob.glob(os.path.join(ROOT, '**', '*.cs'), recursive=True) + \
        glob.glob(os.path.join(ROOT, '**', '*.cshtml'), recursive=True)
    for path in files:
        if os.sep + 'obj' + os.sep in path or os.sep + 'bin' + os.sep in path:
            continue
        text = open(path, encoding='utf-8').read()
        for pattern in PATTERNS:
            for match in re.finditer(pattern, text):
                keys.add(unescape(match.group(1)))
    return keys


def translated_keys(culture='sr-Latn'):
    path = os.path.join(ROOT, 'Resources', f'SharedResource.{culture}.resx')
    if not os.path.exists(path):
        return set()
    return {node.get('name') for node in ET.parse(path).getroot().iter('data')}


if __name__ == '__main__':
    keys = collect_keys()
    missing = sorted(keys - translated_keys())
    for key in missing:
        print(key)
    print(f'{len(keys)} keys, {len(missing)} missing', file=sys.stderr)
    sys.exit(1 if missing else 0)
