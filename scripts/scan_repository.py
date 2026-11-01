"""Pinned scanner checks secrets and dependency vulnerabilities. Any tool error fails."""
import json, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
    out=Path(d)/'scan.json'
    command=[str(root/'.tools/trivy'),'fs','--scanners','secret,vuln','--include-dev-deps','--skip-version-check','--skip-dirs','.tools','--skip-dirs','node_modules','--skip-dirs','.work','--skip-dirs','evidence','--format','json','--output',str(out),'--exit-code','1','--severity','HIGH,CRITICAL',str(root)]
    result=subprocess.run(command,cwd=root,timeout=300,check=False)
    if result.returncode:raise SystemExit(result.returncode)
    report=json.loads(out.read_text())
    if not isinstance(report.get('Results'),list):raise SystemExit('Scanner returned no result set')
    (root/'evidence/repository-scan.json').write_text(json.dumps(report,indent=2)+'\n')
print('Repository dependency and secret scan passed')
