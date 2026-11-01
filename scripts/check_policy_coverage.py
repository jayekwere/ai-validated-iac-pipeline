"""Keep both allowed/denied regression cases for every finding ID."""
from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
rules=set(re.findall(r'"id"\s*:\s*"([A-Z_]+)"',(root/'policy/v1/plan.rego').read_text()))
tests=(root/'policy/v1/rules_test.rego').read_text()
missing=[f'test_{rule.lower()}_{case}' for rule in sorted(rules) for case in ['allowed','denied'] if not re.search(r'\btest_'+rule.lower()+'_'+case+r'\s+if\b',tests)]
if missing:raise SystemExit('Missing rule regressions: '+', '.join(missing))
print(f'{len(rules)} rule IDs have named allowed and denied cases; OPA executes them separately.')
