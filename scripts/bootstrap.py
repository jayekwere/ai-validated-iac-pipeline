"""Download only pinned public tool artifacts. Never run remote installer scripts."""
import hashlib, io, json, os, platform, stat, sys, tarfile, urllib.request, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    system=platform.system().lower(); machine={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64'}.get(platform.machine())
    target=f'{system}_{machine}'
    if target not in ('darwin_arm64','linux_amd64'): raise SystemExit('Supported hosts: macOS arm64 and Linux amd64')
    lock=json.loads((ROOT/'tools.lock.json').read_text()); tools=ROOT/'.tools'; tools.mkdir(exist_ok=True)
    verify='--verify' in sys.argv
    for name,item in lock.items():
        artifact=item[target]; dest=tools/(name+'.download')
        if not dest.exists() or hashlib.sha256(dest.read_bytes()).hexdigest()!=artifact['sha256']:
            if verify: raise SystemExit('Missing or invalid artifact: '+name)
            with urllib.request.urlopen(artifact['url'],timeout=120) as r: data=r.read(300_000_000)
            if hashlib.sha256(data).hexdigest()!=artifact['sha256']: raise SystemExit('Checksum mismatch: '+name)
            dest.write_bytes(data)
        data=dest.read_bytes()
        if name=='aws':
            mirror=tools/'mirror/registry.terraform.io/hashicorp/aws';mirror.mkdir(parents=True,exist_ok=True)
            provider=mirror/f'terraform-provider-aws_{item["version"]}_{target}.zip'
            if verify:
                if not provider.exists() or provider.read_bytes()!=data: raise SystemExit('Provider integrity failure')
            else: provider.write_bytes(data)
        else:
            if name=='terraform': data=zipfile.ZipFile(io.BytesIO(data)).read('terraform')
            if name=='trivy':
                with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tf: data=tf.extractfile('trivy').read()
            binary=tools/name
            if verify:
                if not binary.exists() or binary.is_symlink() or binary.read_bytes()!=data: raise SystemExit('Tool integrity failure: '+name)
            else: binary.write_bytes(data);binary.chmod(0o755)
    config='provider_installation {\n filesystem_mirror {\n path = '+json.dumps(str(tools/'mirror'))+'\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\ndisable_checkpoint = true\n'
    if verify:
        if not (tools/'terraform.rc').exists() or (tools/'terraform.rc').read_text()!=config: raise SystemExit('Terraform CLI configuration integrity failure')
        print('All pinned tool artifacts, executable bytes and mirror configuration verified'); return
    (tools/'terraform.rc').write_text(config)
    print('Verified Terraform, AWS provider, OPA and Trivy. Offline verification is ready.')
if __name__=='__main__': main()
