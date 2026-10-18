"""Acquire the capability surface of a LOCAL hermes installation.

Out-of-band acquisition, same role as acquire-upstreams.ps1: it reads an external
installation once and writes an inert data file that the Node cataloguer consumes.
Nothing here runs hermes, imports its modules, or contacts its gateway -- tool
contracts are recovered by static AST analysis of the source only.

Usage:  python scripts/acquire-hermes-local.py <hermes-install-dir> [out.json]
"""
import ast
import hashlib
import json
import os
import re
import sys

NAME_RE = re.compile(r'[a-z][a-z0-9_]{2,}$')
# Applies to the Python source tree only. The skills tree uses SKILL_SKIP_DIRS: a skill
# directory is legitimately named "web", and skipping it silently drops a real skill.
# tests/ and evals/ declare tool-shaped fixtures (fixture_echo, good_tool, charizard, noop).
# They parse exactly like production contracts, so omitting them is what keeps the inventory
# a capability surface instead of a mix of capabilities and test doubles.
SKIP_DIRS = {'venv', 'node_modules', '__pycache__', '.git', 'web', 'website', 'locales',
             'tests', 'tests-js', 'evals'}
SKILL_SKIP_DIRS = {'node_modules', '__pycache__', '.git'}


def text_of(node, scope, seen=()):
    """Literal text only. f-string interpolations are dropped, never guessed."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = [v.value for v in node.values
                 if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        return ''.join(parts) or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = text_of(node.left, scope, seen), text_of(node.right, scope, seen)
        return (left or '') + (right or '') if (left or right) else None
    if isinstance(node, ast.Name):
        if node.id in scope and node.id not in seen:
            return text_of(scope[node.id], scope, seen + (node.id,))
        return None
    if isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == 'join' and node.args:
        return text_of(node.args[0], scope, seen)
    return None


def props_of(node):
    """Parameter names and required names from a JSON-Schema parameters dict.

    Returns None when there is no parameters schema at all. That distinction is the only
    structural difference between a tool contract and a UI theme (hermes_cli/skin_engine.py
    declares themes as name+description+colors dicts, identical in shape to a tool), so a
    dict without parameters is not treated as a tool.
    """
    params, required = [], []
    if not isinstance(node, ast.Dict):
        return None
    for key, value in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant):
            continue
        if key.value == 'properties' and isinstance(value, ast.Dict):
            params = [k.value for k in value.keys
                      if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        elif key.value == 'required':
            try:
                got = ast.literal_eval(value)
            except Exception:
                got = None
            if isinstance(got, list):
                required = [x for x in got if isinstance(x, str)]
    return params, required


def literal_list(node):
    try:
        got = ast.literal_eval(node)
    except Exception:
        return []
    return [x for x in got if isinstance(x, str)] if isinstance(got, list) else []


def extract_tools(agent_root):
    """Every declared tool contract: name, description, parameter names, required names."""
    found = {}

    def record(name, desc, params, required, rel):
        if not isinstance(name, str) or not NAME_RE.match(name) or not desc:
            return
        desc = ' '.join(desc.split())
        prev = found.get(name)
        if prev is None or len(desc) > len(prev['description']):
            found[name] = {'name': name, 'description': desc, 'parameters': params,
                           'required': required, 'module': rel}

    for dirpath, dirnames, filenames in os.walk(agent_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith('.py'):
                continue
            full = os.path.join(dirpath, filename)
            try:
                tree = ast.parse(open(full, encoding='utf-8', errors='replace').read())
            except Exception:
                continue
            rel = os.path.relpath(full, agent_root).replace(os.sep, '/')
            scope = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            scope[target.id] = node.value
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    keys = {k.value: v for k, v in zip(node.keys, node.values)
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                    if 'name' in keys and 'description' in keys:
                        got = props_of(keys.get('parameters'))
                        if got is not None:
                            record(text_of(keys['name'], scope), text_of(keys['description'], scope),
                                   got[0], got[1], rel)
                if isinstance(node, ast.Call):
                    fname = getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
                    if fname and fname.endswith('schema') and len(node.args) >= 2:
                        params = []
                        if len(node.args) >= 3 and isinstance(node.args[2], ast.Dict):
                            params = [k.value for k in node.args[2].keys
                                      if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                        required = literal_list(node.args[3]) if len(node.args) >= 4 else []
                        record(text_of(node.args[0], scope), text_of(node.args[1], scope),
                               params, required, rel)
    return found


def toolset_posture(agent_root):
    """The declared tool groups, including the least-authority subset for untrusted input."""
    src = open(os.path.join(agent_root, 'toolsets.py'), encoding='utf-8').read()

    def names_between(start, end):
        chunk = src[src.index(start):src.index(end)]
        return sorted(set(re.findall(r'"([a-z][a-z0-9_]{2,})"', chunk)))

    return {
        'core': names_between('_HERMES_CORE_TOOLS', '_HERMES_WEBHOOK_SAFE_TOOLS'),
        'webhookSafe': names_between('_HERMES_WEBHOOK_SAFE_TOOLS', '_FEISHU_TOOLS'),
    }


def extract_skills(skills_root):
    """Each SKILL.md: frontmatter name/description plus its heading outline."""
    out = []
    for dirpath, dirnames, filenames in os.walk(skills_root):
        dirnames[:] = [d for d in dirnames if d not in SKILL_SKIP_DIRS]
        if 'SKILL.md' not in filenames:
            continue
        full = os.path.join(dirpath, 'SKILL.md')
        raw = open(full, 'rb').read()
        text = raw.decode('utf-8', errors='replace')
        rel = os.path.relpath(dirpath, skills_root).replace(os.sep, '/')
        meta = {}
        if text.startswith('---'):
            end = text.find('\n---', 3)
            front = text[3:end] if end > 0 else ''
            for line in front.split('\n'):
                match = re.match(r'^(name|description):\s*(.*)$', line)
                if match:
                    meta[match.group(1)] = match.group(2).strip().strip('"').strip("'")
        headings = [re.sub(r'<[^>]+>', '', h).strip()
                    for h in re.findall(r'^#{1,4}\s+(.+)$', text, re.M)]
        file_count = sum(len(files) for _, _, files in os.walk(dirpath))
        out.append({
            'path': '.' if rel == '.' else rel,
            'name': meta.get('name'),
            'description': meta.get('description'),
            'headings': headings,
            'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw),
            'fileCount': file_count,
        })
    return sorted(out, key=lambda skill: skill['path'])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    install = os.path.abspath(sys.argv[1])
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'upstream/hermes-local-surface.json'
    agent_root = os.path.join(install, 'hermes-agent')
    skills_root = os.path.join(install, 'skills')
    for path in (agent_root, skills_root):
        if not os.path.isdir(path):
            print('not a hermes installation: missing ' + path, file=sys.stderr)
            return 1

    stamp_path = os.path.join(agent_root, 'install-stamp.json')
    stamp = json.load(open(stamp_path, encoding='utf-8')) if os.path.exists(stamp_path) else {}

    tools = extract_tools(agent_root)
    surface = {
        'schemaVersion': 1,
        'acquisition': {
            'method': 'static-ast-and-frontmatter',
            'ranHermes': False,
            'note': 'Read-only. No hermes module was imported and no gateway was contacted.',
        },
        'install': {
            'commit': stamp.get('commit'),
            'branch': stamp.get('branch'),
            'dirty': stamp.get('dirty'),
            'displayVersion': stamp.get('displayVersion'),
            'baseVersion': stamp.get('baseVersion'),
            'builtAt': stamp.get('builtAt'),
        },
        'posture': toolset_posture(agent_root),
        'tools': [tools[key] for key in sorted(tools)],
        'skills': extract_skills(skills_root),
    }
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(surface, handle, indent=1, sort_keys=True)
        handle.write('\n')
    print('tools: {0}  skills: {1}'.format(len(surface['tools']), len(surface['skills'])))
    print('install commit: {0} dirty={1}'.format(surface['install']['commit'],
                                                 surface['install']['dirty']))
    print('wrote ' + out_path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
