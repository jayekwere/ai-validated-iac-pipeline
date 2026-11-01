import {existsSync,readFileSync,mkdirSync,writeFileSync,lstatSync,readdirSync} from 'node:fs';import {join} from 'node:path';import {verify} from '../src/pipeline.ts';import {parseTerraform} from '../src/engine.ts';
const dir='incoming/generated';if(existsSync(dir)){
 if(lstatSync(dir).isSymbolicLink()||!lstatSync(dir).isDirectory())throw Error('Generated path must be a real directory');
 const allowed=['main.tf.json','spec.json','verification.json'];for(const f of readdirSync(dir)){if(!allowed.includes(f))throw Error('Unexpected generated file');const st=lstatSync(join(dir,f));if(!st.isFile()||st.isSymbolicLink()||st.size>2097152)throw Error('Invalid generated file');}
 const text=readFileSync(join(dir,'spec.json'),'utf8'),output=parseTerraform(readFileSync(join(dir,'main.tf.json'),'utf8'));
 const r=await verify(text,'evidence/pr',{mode:'untrusted PR candidate',async generate(){return output;}});if(!r.passed)process.exitCode=1;
}else console.log('No generated candidate in this PR');
