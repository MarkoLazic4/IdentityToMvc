"""Builds the "identitymvc-add" item template from the project template.

    python3 tools/build_feature_template.py          -> writes templates/feature/**
    python3 tools/build_feature_template.py --check  -> exits 1 if the files are out of date (CI)

The project template (.template.config/template.json) is the single source of truth:
- the files of a feature are the ones its "(!Feature)" modifier excludes;
- the code a feature adds to shared files (Program.cs, _Layout, appsettings...) is every
  #if block that mentions the feature. Those blocks become a step-by-step ADD-<feature>.md.
"""
import json, os, re, sys, fnmatch, glob

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
OUT = os.path.join(ROOT, 'templates', 'feature')

# --feature value -> (display name, template symbols it switches on)
FEATURES = {
    'profile': ('Profile page', ['Profile']),
    'email-change': ('Email change', ['EmailChange']),
    'personal-data': ('Personal data (GDPR)', ['PersonalData']),
    'unlock-link': ('Unlock link', ['UnlockLink']),
    'breached-passwords': ('Breached password check', ['BreachedPasswords']),
    'two-factor': ('Two-factor authentication', ['TwoFactor']),
    'sudo': ('Sudo mode', ['Sudo']),
    'passkeys': ('Passkeys', ['Passkeys']),
    'google': ('Google login', ['Google', 'ExternalLogins']),
    'facebook': ('Facebook login', ['Facebook', 'ExternalLogins']),
    'notifications': ('Security emails', ['Notifications']),
    'devices': ('Devices page', ['Devices']),
    'activity': ('Security activity page', ['Activity']),
    'admin': ('Admin panel', ['Admin', 'AdminRequiresMfa']),
    'tests': ('Tests', ['Tests']),
}
OPT = {'profile': 'optProfile', 'email-change': 'optEmailChange', 'personal-data': 'optPersonalData',
       'unlock-link': 'optUnlockLink', 'breached-passwords': 'optBreachedPasswords', 'two-factor': 'optTwoFactor',
       'sudo': 'optSudo', 'passkeys': 'optPasskeys', 'google': 'optGoogle', 'facebook': 'optFacebook',
       'notifications': 'optNotifications', 'devices': 'optDevices', 'activity': 'optActivity',
       'admin': 'optAdmin', 'tests': 'optTests'}

MARKER = re.compile(r'^\s*(?:#|//#|@\*#|<!--#)(if|elif|else|endif)\b(.*?)(?:\*@|-->)?\s*$')


def load_project_template():
    with open(os.path.join(ROOT, '.template.config', 'template.json'), encoding='utf-8') as f:
        return json.load(f)


def feature_files(template, symbol):
    for modifier in template['sources'][0]['modifiers']:
        if modifier['condition'] == f'(!{symbol})':
            return modifier['exclude']
    return []


def expand(patterns):
    files = set()
    for pattern in patterns:
        for path in glob.glob(os.path.join(ROOT, pattern), recursive=True):
            if os.path.isfile(path):
                files.add(os.path.relpath(path, ROOT).replace(os.sep, '/'))
    return files


def source_files():
    skip = ('/bin/', '/obj/', '/.git/', '/wwwroot/lib/', '/Migrations/', '/templates/', '/.template.config/')
    exts = ('.cs', '.cshtml', '.json', '.csproj', '.js', '.yml')
    for path in glob.glob(os.path.join(ROOT, '**', '*'), recursive=True):
        rel = '/' + os.path.relpath(path, ROOT).replace(os.sep, '/')
        if os.path.isfile(path) and path.endswith(exts) and not any(s in rel for s in skip) \
                and not rel.startswith('/.github/') and not rel.startswith('/docs/'):
            yield rel[1:]


def file_owners():
    """File -> the feature symbol whose "(!Feature)" modifier drops it."""
    project = load_project_template()
    owners = {}
    for modifier in project['sources'][0]['modifiers']:
        m = re.fullmatch(r'\(!(\w+)\)', modifier['condition'])
        if m:
            for rel in expand(modifier['exclude']):
                owners[rel] = m.group(1)
    return owners


def blocks_for(symbols, owned):
    """#if blocks in shared files whose condition mentions one of the symbols."""
    word = re.compile(r'\b(' + '|'.join(symbols) + r')\b')
    result = []
    for rel in sorted(source_files()):
        if rel in owned:
            continue
        lines = open(os.path.join(ROOT, rel), encoding='utf-8-sig').read().split('\n')
        stack = []  # (condition, start line, body lines)
        for i, line in enumerate(lines):
            m = MARKER.match(line)
            if m and m.group(1) == 'if':
                stack.append([m.group(2).strip(), i, []])
                continue
            if m and m.group(1) in ('elif', 'else'):
                if stack:
                    cond, start, body = stack[-1]
                    if word.search(cond) and body:
                        result.append((rel, cond, start, body, i))
                    stack[-1] = [f'{m.group(1)} {m.group(2).strip()} (after {cond})', i, []]
                continue
            if m and m.group(1) == 'endif':
                if stack:
                    cond, start, body = stack.pop()
                    if word.search(cond) and body:
                        result.append((rel, cond, start, body, i))
                    if stack:
                        stack[-1][2].extend(body)
                continue
            if stack:
                stack[-1][2].append(line)
    return result


def _core_lines(rel):
    """Lines of a file with a flag telling whether every app has them (outside any #if block)."""
    lines = open(os.path.join(ROOT, rel), encoding='utf-8-sig').read().split('\n')
    core, level = [], 0
    for line in lines:
        m = MARKER.match(line)
        if m and m.group(1) == 'if':
            level += 1
        core.append(level == 0 and not m)
        if m and m.group(1) == 'endif':
            level -= 1
    return lines, core


def _usable(lines, core, j):
    text = lines[j].strip()
    return core[j] and len(text.strip('{}();,<>/ ')) > 3 and sum(1 for l in lines if l.strip() == text) == 1


def anchor(rel, start, end):
    """Where the code goes: in front of the next line every app has, or else after the previous one."""
    lines, core = _core_lines(rel)
    for j in range(end + 1, min(end + 6, len(lines))):
        if _usable(lines, core, j):
            return 'Put it just above this line', lines[j].strip()
        if lines[j].strip() and core[j]:
            break
    for j in range(start - 1, -1, -1):
        if _usable(lines, core, j):
            if j + 1 < start and lines[j + 1].strip() == '{':
                return 'Put it at the top of the { } block that follows this line', lines[j].strip()
            return 'Put it below this line (in the same block)', lines[j].strip()
    return None


# Human wording for symbols in "only if" notes
NAMES = {'Profile': 'the profile page', 'EmailChange': 'email change', 'PersonalData': 'personal data',
         'UnlockLink': 'the unlock link', 'BreachedPasswords': 'the breached password check',
         'TwoFactor': 'two-factor authentication', 'Sudo': 'sudo mode', 'Passkeys': 'passkeys',
         'Google': 'Google login', 'Facebook': 'Facebook login', 'ExternalLogins': 'Google or Facebook login',
         'Notifications': 'security emails', 'Devices': 'the devices page', 'Activity': 'the activity page',
         'Admin': 'the admin panel', 'AdminRequiresMfa': 'two-factor authentication or passkeys',
         'Tests': 'the test project', 'LangSr': 'Serbian', 'LangEn': 'English', 'LangBoth': 'both languages',
         'DbSqlServer': 'SQL Server', 'DbPostgres': 'PostgreSQL', 'DbSqlite': 'SQLite'}


def describe(condition, skip):
    """Turns "(Admin && (TwoFactor || Passkeys))" into "two-factor authentication or passkeys"."""
    text = condition
    for name in sorted(NAMES, key=len, reverse=True):
        if name in skip:
            text = re.sub(r'\b' + name + r'\b', 'true', text)
    text = re.sub(r'\(\s*true\s*\)', 'true', text)
    text = re.sub(r'true\s*&&\s*|\s*&&\s*true', '', text).strip()
    if text in ('true', '(true)', '') or re.search(r'\|\|\s*true|true\s*\|\|', text) or '!true' in text:
        return None
    for name in sorted(NAMES, key=len, reverse=True):
        text = re.sub(r'!\b' + name + r'\b', 'no ' + NAMES[name], text)
        text = re.sub(r'\b' + name + r'\b', NAMES[name], text)
    return text.replace('&&', 'and').replace('||', 'or').strip('() ')


LANG = {'.cs': 'csharp', '.cshtml': 'cshtml', '.json': 'json', '.csproj': 'xml', '.js': 'js', '.yml': 'yaml'}


def instructions(feature, title, symbols, owned):
    out = [f'# Add: {title}', '',
           f'`dotnet new identitymvc-add --feature {feature}` copied the files that belong to this feature.',
           'Finish by adding the code below to the shared files of your project (in the same order).', '',
           'A block marked "only if ..." applies only when your app also has that feature.',
           'Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.', '']
    found = blocks_for(symbols, owned)
    if feature == 'tests':
        out.append('First add the test project to the solution: `dotnet sln add IdentityToMvc.Tests/IdentityToMvc.Tests.csproj`.')
        out.append('')
    if not found:
        out.append('Nothing else to change - the feature is self-contained.')
    owners = file_owners()
    for n, (rel, cond, start, body, end) in enumerate(found, 1):
        negated = all(f'!{s}' in cond for s in symbols if s in cond)
        what = 'Remove this code from' if negated and cond.startswith('(!') else 'Add to'
        out.append(f'## {n}. {what} `{rel}`')
        out.append('')
        notes = []
        if rel in owners:
            owner = 'Admin' if owners[rel] == 'AdminRequiresMfa' else owners[rel]
            notes.append(NAMES.get(owner, owner))
        derived = [x for x in symbols if x != 'AdminRequiresMfa']
        condition = describe(cond, derived) if not cond.startswith(('elif', 'else')) else describe(cond.split(' (after')[0].split(' ', 1)[-1], derived)
        if condition and what == 'Add to':
            notes.append(condition)
        if notes:
            out.append('Only if your app has ' + ' and '.join(notes) + '.')
            out.append('')
        other = {'google': 'Facebook', 'facebook': 'Google'}.get(feature)
        if other and 'ExternalLogins' in cond and what == 'Add to':
            out.append(f'Skip this step if your app already has {other} login - the code is already there.')
            out.append('')
        a = anchor(rel, start, end)
        if a and what == 'Add to':
            out.append(f'{a[0]}: `{a[1]}`')
            out.append('')
        body = [l for l in body if not MARKER.match(l)]
        out.append('```' + LANG.get(os.path.splitext(rel)[1], ''))
        out.extend(body)
        out.append('```')
        out.append('')
    return '\n'.join(out).rstrip() + '\n'


def build():
    project = load_project_template()
    files = {}
    params = {k: v for k, v in project['symbols'].items() if v.get('type') == 'parameter' and k != 'skipRestore'}
    symbols = dict(params)
    symbols['feature'] = {
        'type': 'parameter', 'datatype': 'choice', 'isRequired': True, 'displayName': 'Feature',
        'description': 'The feature to add to an app created from the identitymvc template.',
        'choices': [{'choice': k, 'displayName': v[0]} for k, v in FEATURES.items()]}
    for name, value in project['symbols'].items():
        if value.get('type') == 'computed':
            expr = value['value']
            for feature, (_, syms) in FEATURES.items():
                expr = expr.replace(OPT[feature], f'({OPT[feature]} || feature == "{feature}")')
            symbols[name] = {'type': 'computed', 'value': expr}
    for name in ('templateRepo', 'templateName'):
        symbols[name] = project['symbols'][name]

    modifiers = []
    for feature, (title, syms) in FEATURES.items():
        patterns = []
        for s in syms:
            own = feature_files(project, s)
            patterns += own
            app_files = sorted(p for p in own if not p.startswith('IdentityToMvc.Tests/') and not p.endswith('.sln'))
            test_files = sorted(p for p in own if p.startswith('IdentityToMvc.Tests/'))
            # "Symbol" is the computed value for the app after adding the feature, so files of a
            # combination (e.g. admin + 2FA) only come along when the app really has it.
            other = {'google': 'optFacebook', 'facebook': 'optGoogle'}.get(feature)
            extra = f' && !{other}' if s == 'ExternalLogins' and other else ''
            if app_files:
                modifiers.append({'condition': f'(feature == "{feature}" && {s}{extra})', 'include': app_files})
            if test_files:
                # Test files only go into apps that have the test project (or when adding the tests themselves)
                modifiers.append({'condition': f'(feature == "{feature}" && {s} && Tests)', 'include': test_files})
        if feature == 'tests':
            # Tests of features the app doesn't have stay out
            for other_feature, (_, other_syms) in FEATURES.items():
                for o in other_syms:
                    own_tests = [p for p in feature_files(project, o) if p.startswith('IdentityToMvc.Tests/')]
                    if own_tests and o != 'Tests':
                        modifiers.append({'condition': f'(feature == "tests" && !{o})', 'exclude': own_tests})
        owned = expand(patterns)
        files[f'instructions/ADD-{feature}.md'] = instructions(feature, title, syms, owned)

    template = {
        '$schema': 'http://json.schemastore.org/template',
        'author': project['author'],
        'classifications': ['Web', 'MVC', 'Identity'],
        'identity': 'IdentityToMvc.Templates.Feature',
        'name': 'Add a feature to an IdentityToMvc app',
        'description': 'Copies the files of one feature (admin panel, passkeys, two-factor...) into an app created with "dotnet new identitymvc", '
                       'plus ADD-<feature>.md with the code to add to the shared files. Run it in the solution folder with the same -n and options the app was created with.',
        'shortName': 'identitymvc-add',
        'sourceName': 'IdentityToMvc',
        'tags': {'language': 'C#', 'type': 'item'},
        'symbols': symbols,
        'sources': [
            {'source': '../../', 'target': './', 'include': ['__nothing__'],
             'exclude': ['**/[Bb]in/**', '**/[Oo]bj/**'], 'modifiers': modifiers},
        ] + [
            {'source': './instructions', 'target': './', 'include': [f'ADD-{f}.md'], 'condition': f'(feature == "{f}")'}
            for f in FEATURES
        ],
        'SpecialCustomOperations': project['SpecialCustomOperations'],
        'postActions': [{
            'description': 'Finish the setup', 'actionId': 'AC1156F7-BB77-4DB8-B28F-24EEBCCA1E5C',
            'manualInstructions': [{'text': 'Open ADD-<feature>.md in the solution folder and add the listed code to the shared files, then build.'}],
            'continueOnError': True}],
    }
    files['.template.config/template.json'] = json.dumps(template, indent=2, ensure_ascii=False) + '\n'
    host = {'$schema': 'http://json.schemastore.org/dotnetcli.host', 'symbolInfo': {}}
    project_host = json.load(open(os.path.join(ROOT, '.template.config', 'dotnetcli.host.json'), encoding='utf-8'))
    for k, v in project_host['symbolInfo'].items():
        if k in symbols:
            host['symbolInfo'][k] = v
    host['symbolInfo']['feature'] = {'longName': 'feature', 'shortName': ''}
    files['.template.config/dotnetcli.host.json'] = json.dumps(host, indent=2) + '\n'
    return files


def main():
    files = build()
    stale = []
    for rel, content in files.items():
        path = os.path.join(OUT, rel)
        current = open(path, encoding='utf-8').read() if os.path.exists(path) else None
        if current != content:
            stale.append(rel)
            if '--check' not in sys.argv:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, 'w', encoding='utf-8').write(content)
    if '--check' in sys.argv and stale:
        print('Out of date (run python3 tools/build_feature_template.py):', *stale, sep='\n  ')
        sys.exit(1)
    print(f'{len(files)} files, {len(stale)} updated')


if __name__ == '__main__':
    main()
