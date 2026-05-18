#!/usr/bin/env python3
"""One-time cleanup: strip em and en dashes from public-facing darkmatter files."""
import re
from pathlib import Path

patterns = [
    'README.md', 'scripts/*.js',
    'public/*.html', 'public/docs/*.html',
    'public/integrations/*.html', 'public/blog-*.html',
]
skip = {'public/admindashboard.html', 'public/dashboard.html', 'public/admin.html'}

files = set()
for p in patterns:
    for f in Path('.').glob(p):
        rel = f.as_posix()
        if rel in skip:
            continue
        files.add(f)

total_em, total_en = 0, 0
modified = []
for f in sorted(files):
    try:
        text = f.read_text(encoding='utf-8')
    except Exception:
        continue
    em_count = text.count('—')
    en_count = text.count('–')
    if em_count == 0 and en_count == 0:
        continue
    new = text
    new = re.sub(r' — ', ', ', new)
    new = re.sub(r' – ', ', ', new)
    new = re.sub(r'—', ',', new)
    new = re.sub(r'–', ',', new)
    new = re.sub(r',\s*,', ',', new)
    if new != text:
        f.write_text(new, encoding='utf-8')
        modified.append((f.as_posix(), em_count, en_count))
        total_em += em_count
        total_en += en_count

print(f'Modified {len(modified)} files. Removed {total_em} em dashes, {total_en} en dashes.')
for f, e, n in modified:
    print(f'  {f}  (em={e}, en={n})')
