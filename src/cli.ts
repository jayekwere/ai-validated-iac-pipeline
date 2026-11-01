import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';import {resolve,join} from 'node:path';
import {ROOT,verify} from './pipeline.ts';import {kinds} from './spec.ts';import {OpenAIGenerator} from './ai.ts';
const args=process.argv.slice(2);const command=args.shift();
try{
 if(command==='demo'){
 const results=[];for(const kind of kinds){const r=await verify(readFileSync(join(ROOT,`examples/${kind}.json`),'utf8'),join(ROOT,`evidence/${kind}`));results.push({kind,passed:r.passed,gates:r.gates});console.log(`${kind}: ${r.passed?'PASS':'FAIL'} ${r.gates.filter((g:any)=>!g.passed).map((g:any)=>g.name+': '+g.detail).join('; ')}`);}
 mkdirSync(join(ROOT,'evidence'),{recursive:true});writeFileSync(join(ROOT,'evidence/summary.json'),JSON.stringify(results,null,2)+'\n');process.exitCode=results.every(r=>r.passed)?0:1;
 }else if(command==='verify'){
 const file=args.shift();if(!file)throw Error('Usage: verify SPEC [OUTPUT]');const output=args.shift()||'evidence/request';if(args.length)throw Error('Unexpected arguments');
 const r=await verify(readFileSync(resolve(file),'utf8'),resolve(output));console.log(r.passed?'PASS: human review required':'FAIL: review denied');process.exitCode=r.passed?0:1;
 }else if(command==='generate-ai'){
 if(!args.includes('--authorize-paid-api'))throw Error('Explicit --authorize-paid-api required');const file=args[0];if(!file||file.startsWith('--'))throw Error('Specification path required');
 const g=new OpenAIGenerator(process.env.OPENAI_API_KEY||'',process.env.OPENAI_MODEL||'gpt-4.1-mini',true);const r=await verify(readFileSync(resolve(file),'utf8'),'evidence/ai',g);console.log(r.passed?'PASS: human review required':'FAIL: AI output rejected');process.exitCode=r.passed?0:1;
 }else throw Error('Usage: demo | verify SPEC [OUTPUT] | generate-ai SPEC --authorize-paid-api');
}catch(e){console.error(e instanceof Error?e.message:'Failed');process.exitCode=1;}
