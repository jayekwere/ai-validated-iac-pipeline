import {readFileSync,readdirSync} from 'node:fs';import {parseText} from '../src/spec.ts';
for(const f of readdirSync('examples').filter(f=>/\.(json|yaml)$/.test(f))){parseText(readFileSync('examples/'+f,'utf8'));console.log('PASS '+f);}
