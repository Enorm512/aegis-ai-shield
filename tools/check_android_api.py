"""Find JDK API calls in compiled core classes that are newer than the app's minSdk.

Android lint only inspects app-module sources, not the pure-Java `core` library, so a call such as List.of (API 30)
would compile, pass host tests, and crash on Android 8-10. This reads `javap -c` output and the Android SDK's
api-versions.xml. Usage: check_android_api.py <classes-dir> <api-versions.xml> [minSdk=26]
Calls D8 rewrites (records, string concat, lambdas) are ignored.
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

classes_dir, api_xml = Path(sys.argv[1]), sys.argv[2]
min_sdk = int(sys.argv[3]) if len(sys.argv) > 3 else 26

apis = {}
for _, el in ET.iterparse(api_xml, events=('end',)):
    if el.tag == 'class':
        since = int(el.get('since', '1'))
        parents = [e.get('name') for e in el if e.tag in ('extends', 'implements')]
        methods = {m.get('name'): int(m.get('since', since)) for m in el if m.tag == 'method'}
        apis[el.get('name')] = (since, parents, methods)
        el.clear()

def lookup(cls, sig, seen=None):
    seen = seen or set()
    if cls in seen or cls not in apis:
        return None
    seen.add(cls)
    since, parents, methods = apis[cls]
    if sig in methods:
        return methods[sig]
    for p in parents:
        r = lookup(p, sig, seen)
        if r is not None:
            return r
    return None

IGNORED = ('java/lang/Record', 'java/lang/runtime/', 'java/lang/invoke/', 'java/lang/StringBuilder', 'java/lang/Object')
ref = re.compile(r'// (?:Interface)?Method ([\w/$]+)\.([^:]+):(\S+)')
cls_ref = re.compile(r'// class ((?:java|javax)/[\w/$]+)')
problems = {}
files = sorted(classes_dir.rglob('*.class'))
out = subprocess.run(['javap', '-c', '-p'] + [str(f) for f in files], capture_output=True, text=True, check=True).stdout
for line in out.splitlines():
    m = ref.search(line)
    if m and m.group(1).startswith(('java/', 'javax/')) and not m.group(1).startswith(IGNORED):
        cls, name, desc = m.groups()
        if name == '<init>':
            since = apis.get(cls, (1,))[0]
            key = f'{cls}.<init>'
        else:
            since = lookup(cls, name + desc)
            key = f'{cls}.{name}'
            if since is None:
                since = apis.get(cls, (1,))[0]
        if since > min_sdk:
            problems.setdefault(key, since)
    c = cls_ref.search(line)
    if c and not c.group(1).startswith(IGNORED):
        since = apis.get(c.group(1), (1,))[0]
        if since > min_sdk:
            problems.setdefault(c.group(1), since)

if problems:
    print(f'FAIL: {len(problems)} API(s) newer than minSdk {min_sdk}:')
    for k, v in sorted(problems.items(), key=lambda kv: kv[1]):
        print(f'  API {v}: {k}')
    sys.exit(1)
print(f'PASS: no JDK API newer than API {min_sdk} referenced by {len(files)} classes')
