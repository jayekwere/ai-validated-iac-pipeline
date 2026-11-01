import {readFileSync,writeFileSync,mkdirSync,renameSync,chmodSync,existsSync} from 'node:fs';import {join} from 'node:path';import assert from 'node:assert/strict';
import {verify,ROOT,execTool} from '../src/pipeline.ts';import {parseText} from '../src/spec.ts';import {sample,parseTerraform} from '../src/engine.ts';import {escapeHtml} from '../src/report.ts';
const text=readFileSync(join(ROOT,'examples/platform.json'),'utf8');const s=parseText(text);const records:any[]=[];const base=join(ROOT,'evidence/adversarial');mkdirSync(base,{recursive:true});
const mutations:Record<string,(t:any)=>unknown>={
 'public-storage':t=>{t.resource.aws_s3_bucket_public_access_block.logs.block_public_acls=false;return t;},
 'admin-ingress':t=>{t.resource.aws_security_group.app.ingress[0].from_port=22;t.resource.aws_security_group.app.ingress[0].to_port=22;t.resource.aws_security_group.app.ingress[0].cidr_blocks=['0.0.0.0/0'];return t;},
 'wildcard-iam':t=>{t.resource.aws_iam_role_policy.reader.policy=JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['*'],Resource:['*']}]});return t;},
 'missing-encryption':t=>{delete t.resource.aws_s3_bucket_server_side_encryption_configuration;return t;},
 'unapproved-module':t=>({...t,module:{evil:{source:'git::https://evil.invalid/module'}}}),
 'external-command':t=>({...t,resource:{...t.resource,terraform_data:{evil:{provisioner:{'local-exec':{command:'touch /tmp/iac-untrusted-executed'}}}}}}),
 'policy-bypass':t=>({...t,'policy/v1/plan.rego':'allow := true'}),
 'workflow-injection':t=>({...t,'.github/workflows/owned.yml':'permissions: write-all'}),
 'malformed-terraform':()=>parseTerraform('{invalid'),
};
for(const [name,mutate] of Object.entries(mutations)){
 const report=await verify(text,join(base,name),{mode:'adversarial fixture',async generate(){return mutate(sample(s));}});assert.equal(report.passed,false,name);records.push({name,expected:'REJECT',actual:'REJECT',gate:report.gates.find((g:any)=>!g.passed)});
}
assert.equal(existsSync('/tmp/iac-untrusted-executed'),false,'Generated external command must never execute');
for(const name of ['missing-scanner','tampered-scanner']){
 const scanner=join(ROOT,'.tools/trivy'),backup=scanner+'.adversarial-backup';renameSync(scanner,backup);
 try{if(name==='tampered-scanner'){writeFileSync(scanner,'#!/bin/sh\nexit 42\n');chmodSync(scanner,0o755);}
 const report=await verify(text,join(base,name));assert.equal(report.passed,false);assert.ok(report.gates.some((g:any)=>g.name==='Tool integrity'&&!g.passed));records.push({name,expected:'REJECT',actual:'REJECT',gate:report.gates.find((g:any)=>!g.passed)});
 }finally{if(existsSync(scanner)){const {unlinkSync}=await import('node:fs');unlinkSync(scanner);}renameSync(backup,scanner);}
}
// Independent semantic policy checks use real plan data, never generated mocks.
const original=JSON.parse(readFileSync(join(ROOT,'evidence/platform/plan.json'),'utf8'));
for(const name of ['public-storage','admin-ingress','wildcard-iam','missing-encryption']){
 const plan=structuredClone(original);const find=(type:string)=>plan.resource_changes.find((r:any)=>r.type===type);
 if(name==='public-storage')find('aws_s3_bucket_public_access_block').change.after.block_public_acls=false;
 if(name==='admin-ingress')find('aws_security_group').change.after.ingress=[{from_port:22,to_port:22,protocol:'tcp',cidr_blocks:['0.0.0.0/0']}];
 if(name==='wildcard-iam')find('aws_iam_role_policy').change.after.policy=JSON.stringify({Statement:[{Effect:'Allow',Action:['*'],Resource:['*']}]});
 if(name==='missing-encryption')plan.resource_changes=plan.resource_changes.filter((r:any)=>r.type!=='aws_s3_bucket_server_side_encryption_configuration');
 const file=join(base,name+'-plan.json');writeFileSync(file,JSON.stringify(plan));const r=execTool(join(ROOT,'.tools/opa'),['eval','--format=json','--data',join(ROOT,'policy/v1/plan.rego'),'--input',file,'data.iac.v1.decision'],ROOT,ROOT);
 assert.equal(r.status,0);const decision=JSON.parse(r.stdout.toString()).result[0].expressions[0].value;assert.equal(decision.allow,false,name);writeFileSync(join(base,name+'-opa.json'),JSON.stringify(decision,null,2));records.push({name:name+'-independent-OPA',expected:'REJECT',actual:'REJECT',findings:decision.findings});
 const scanner=execTool('python3',[join(ROOT,'scripts/scan.py'),file],ROOT,ROOT);assert.equal(scanner.status,1,name+' scanner');
}
writeFileSync(join(base,'summary.json'),JSON.stringify(records,null,2)+'\n');writeFileSync(join(base,'report.html'),`<!doctype html><meta charset="utf-8"><title>Adversarial verification</title><style>body{background:#0c1424;color:#dce6f8;font:16px system-ui;max-width:1000px;margin:40px auto;padding:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#142239;padding:24px;border-radius:12px}h1{color:#72e6ba}</style><h1>${records.length} adversarial checks passed</h1><p>Every listed malicious candidate was rejected by the actual engine or independent policy evaluator. No generated commands executed.</p><pre>${escapeHtml(JSON.stringify(records,null,2))}</pre>`);console.log(`${records.length} adversarial demonstrations passed`);
