"""Release-APK gates that Gradle does not enforce. Usage: check_release_apk.py <apk> [build-tools-dir]

1. Native libraries are 16 KB page-size compatible (ELF LOAD segment alignment >= 16384) - required by Google Play for
   apps targeting Android 15+.
2. The published debug test key is NOT among the trusted threat-feed keys (matched by key id, so a real production key
   can be added later without weakening this check). Any other key is reported, not rejected.
3. The package is not the debug application id, and the APK contains no leftover test files.
4. Optional: zipalign -P 16 check when a build-tools directory is given.
"""
import base64
import hashlib
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

apk = sys.argv[1]
bt = sys.argv[2] if len(sys.argv) > 2 else None
root = Path(__file__).resolve().parents[1]
debug_pub = (root / "tools/debug-test-key/debug.public").read_text().strip()
DEBUG_KEY_ID = hashlib.sha256(base64.b64decode(debug_pub)).hexdigest()[:16]
problems = []


def tool(name):
    exe = Path(bt) / (name + '.exe')
    return str(exe if exe.exists() else Path(bt) / name)


with zipfile.ZipFile(apk) as z:
    names = z.namelist()
    libs = [n for n in names if n.endswith('.so')]
    for n in libs:
        d = z.read(n)
        if d[:4] != b'\x7fELF' or d[4] != 2:
            continue  # only 64-bit ELF are inspected here
        phoff, = struct.unpack_from('<Q', d, 0x20)
        phentsize, phnum = struct.unpack_from('<HH', d, 0x36)
        aligns = []
        for i in range(phnum):
            base = phoff + i * phentsize
            ptype, = struct.unpack_from('<I', d, base)
            if ptype == 1:  # PT_LOAD
                aligns.append(struct.unpack_from('<Q', d, base + 0x30)[0])
        status = 'ok' if aligns and min(aligns) >= 16384 else 'NOT 16KB aligned'
        print(f'  {n}: LOAD p_align={sorted(set(aligns))} -> {status}')
        if status != 'ok':
            problems.append(f'{n} is not 16 KB aligned')
    if not libs:
        print('  no native libraries')
    for n in names:
        if re.search(r'(^|/)(debug|test|androidTest)[^/]*$', n, re.I) and n.startswith('assets/'):
            problems.append(f'unexpected test/debug asset {n}')
    if 'assets/trusted_threat_keys.txt' in names:
        keys = [l.strip() for l in z.read('assets/trusted_threat_keys.txt').decode().splitlines() if l.strip() and not l.startswith('#')]
        ids = [hashlib.sha256(base64.b64decode(k)).hexdigest()[:16] for k in keys]
        print(f'  trusted threat keys shipped: {len(keys)} {ids}')
        if DEBUG_KEY_ID in ids:
            problems.append(f'release trusts the published DEBUG test key {DEBUG_KEY_ID}')
    else:
        problems.append('assets/trusted_threat_keys.txt missing')
if bt:
    r = subprocess.run([tool('aapt2'), 'dump', 'badging', apk], capture_output=True, text=True)
    m = re.search(r"package: name='([^']+)'", r.stdout)
    if m:
        print('  package:', m.group(1))
        if m.group(1).endswith('.debug'):
            problems.append('release package id ends with .debug')
    r = subprocess.run([tool('zipalign'), '-c', '-P', '16', '4', apk], capture_output=True, text=True)
    print('  zipalign -P 16:', 'ok' if r.returncode == 0 else 'FAILED ' + (r.stdout + r.stderr).strip()[:200])
    if r.returncode != 0:
        problems.append('zipalign -P 16 check failed (apk not page-aligned)')
if problems:
    print('FAIL:'); [print('  -', p) for p in problems]; sys.exit(1)
print('PASS: release APK gates')
