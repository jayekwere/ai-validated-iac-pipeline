import {readFileSync,writeFileSync,mkdirSync,readdirSync,lstatSync} from 'node:fs';import {join,resolve} from 'node:path';
import {parseText} from './spec.ts';import {OpenAIGenerator} from './ai.ts';import {SampleGenerator,parseTerraform,validateOutput,type Generator} from './engine.ts';import {verify} from './pipeline.ts';
const [command,dir]=process.argv.slice(2);if(!dir)throw Error('candidate command and directory required');
if(command==='generate'){
 const specPath=process.env.SPEC_PATH||'examples/storage.json';if(!/^examples\/(storage|compute|iam|network|load-balancer|audit|platform)\.json$/.test(specPath))throw Error('Unapproved specification path');
 const text=readFileSync(specPath,'utf8'),spec=parseText(text);let g:Generator=new SampleGenerator();
 if(process.env.GENERATION_MODE==='ai'){if(process.env.AUTHORIZE_PAID_API!=='true')throw Error('Explicit paid API authorization required');g=new OpenAIGenerator(process.env.OPENAI_API_KEY||'',process.env.OPENAI_MODEL||'gpt-4.1-mini',true);}
 const value=await g.generate(spec);validateOutput(spec,value);mkdirSync(dir,{recursive:true});writeFileSync(join(dir,'main.tf.json'),JSON.stringify(value,null,2)+'\n');writeFileSync(join(dir,'spec.json'),JSON.stringify(spec,null,2)+'\n');writeFileSync(join(dir,'mode.json'),JSON.stringify({mode:g.mode})+'\n');
}else if(command==='verify'){
 const entries=readdirSync(dir).sort();if(JSON.stringify(entries)!==JSON.stringify(['main.tf.json','mode.json','spec.json']))throw Error('Candidate must contain exactly three data files');
 for(const n of entries){const st=lstatSync(join(dir,n));if(!st.isFile()||st.isSymbolicLink()||st.size>131072)throw Error('Invalid candidate file');}
 const text=readFileSync(join(dir,'spec.json'),'utf8');const output=parseTerraform(readFileSync(join(dir,'main.tf.json'),'utf8'));const mode=JSON.parse(readFileSync(join(dir,'mode.json'),'utf8')).mode;
 if(!['deterministic non-AI','AI: OpenAI Responses API'].includes(mode))throw Error('Invalid generation mode');
 const report=await verify(text,resolve('evidence/candidate'),{mode,async generate(){return output;}});if(!report.passed)process.exitCode=1;
}else throw Error('Unknown command');
