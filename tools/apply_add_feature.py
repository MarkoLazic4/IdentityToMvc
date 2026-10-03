"""Follows an ADD-<feature>.md like a person would (used by CI to prove the steps work).

    apply_add_feature.py <solution folder> <ADD-feature.md>

Every step inserts (or removes) its code at the line it names. Steps marked "Only if your app has ..."
are applied only when every feature they name matches the HAS environment variable (a regex),
e.g. HAS="two-factor authentication|the devices page"; without HAS they are skipped.
"""
import re, sys, os
root, md = sys.argv[1], sys.argv[2]
text = open(md).read()
for sec in re.split(r'\n## \d+\. ', text)[1:]:
    head = sec.split('\n', 1)[0]
    f = re.search(r'`([^`]+)`', head).group(1)
    code = re.search(r'```\w*\n(.*?)\n```', sec, re.S).group(1)
    m_only = re.search(r'Only if your app has (.*)\.', sec)
    has = os.environ.get('HAS', '')
    if m_only and not (has and all(re.fullmatch(has, part.strip()) for part in m_only.group(1).split(' and '))):
        print('skip', f); continue
    if 'Skip this step if your app already has' in sec and os.environ.get('HAS_OTHER_PROVIDER'):
        print('skip', f); continue
    path = os.path.join(root, f); src = open(path, encoding='utf-8-sig').read()
    if head.startswith('Remove'):
        assert code in src, f; src = src.replace(code + '\n', ''); print('removed from', f)
    else:
        m = re.search(r'(Put it just above this line|Put it below this line \(in the same block\)|Put it at the top of the \{ \} block that follows this line): `(.*)`', sec)
        kind, anchor = m.group(1), m.group(2)
        lines = src.split('\n'); idx = [i for i, l in enumerate(lines) if l.strip() == anchor]
        assert len(idx) == 1, (f, anchor, len(idx))
        i = idx[0] if kind.startswith('Put it just above') else idx[0] + (2 if 'top of the' in kind else 1)
        lines[i:i] = code.split('\n'); src = '\n'.join(lines); print('added to', f)
    open(path, 'w', encoding='utf-8').write(src)
