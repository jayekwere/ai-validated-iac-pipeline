"""Structural workflow invariants checked without a YAML dependency."""
import re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for file in (root/'.github/workflows').glob('*.yml'):
    text=file.read_text()
    assert 'pull_request_target' not in text, file
    assert not re.search(r'terraform\s+apply',text), file
    assert 'permissions:' in text and 'contents: read' in text,file
    assert 'persist-credentials: false' in text,file
    for uses in re.findall(r'uses:\s*(\S+)',text): assert re.fullmatch(r'[\w.-]+/[\w.-]+@[a-f0-9]{40}',uses),uses
    for line in text.splitlines():
        if 'run:' in line: assert '${{' not in line, 'Expression in executable shell'
    if 'secrets.' in text: assert 'pull_request:' not in text and 'workflow_dispatch:' in text,file
    if 'contents: write' in text: assert 'environment: pr-publication' in text and "github.ref == 'refs/heads/main'" in text,file
print('Workflow references, permissions, event boundaries and shell interpolation checks passed')

ci=(root/'.github/workflows/ci.yml').read_text()
assert 'environment: maintainer-approval' in ci
assert 'needs: tests' in ci
assert 'required_deployments' in (root/'.github/review-ruleset.json').read_text()
