import json, subprocess, re

def get_changed_lines():
    """Returns {filepath: set of added/modified line numbers} from last commit."""
    diff = subprocess.run(
        ['git', 'diff', 'HEAD~1', 'HEAD', '--unified=0', '--', '*.php'],
        capture_output=True, text=True
    ).stdout

    changed = {}
    current_file = None
    current_line = None

    for line in diff.splitlines():
        if line.startswith('+++ b/'):
            current_file = line[6:]
            changed.setdefault(current_file, set())

        elif line.startswith('@@'):
            # @@ -old +new_start,new_count @@
            match = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if match:
                new_start = int(match.group(1))
                new_count = int(match.group(2)) if match.group(2) is not None else 1
                # count=0 means pure deletion, no added lines
                current_line = new_start if new_count > 0 else None

        elif line.startswith('+') and not line.startswith('+++'):
            if current_file and current_line is not None:
                changed[current_file].add(current_line)
                current_line += 1

        elif not line.startswith('-'):
            if current_line is not None:
                current_line += 1

    return changed


with open('semgrep-report.json') as f:
    data = json.load(f)

changed_lines = get_changed_lines()
print(f"Changed files and lines: { {k: sorted(v) for k, v in changed_lines.items()} }")

filtered = []
for result in data.get('results', []):
    path = result['path']
    line = result['start']['line']

    if path in changed_lines and line in changed_lines[path]:
        print(f"  INCLUDED: {path}:{line}")
        filtered.append(result)
    else:
        print(f"  EXCLUDED (not in diff): {path}:{line}")

data['results'] = filtered

with open('semgrep-report.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f"Result: {len(filtered)} finding(s) after filtering.")
