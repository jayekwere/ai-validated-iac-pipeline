import type {TF} from './engine.ts';
// Trusted, deterministic rendering for scanners whose Terraform JSON adapters
// lose nested resource links. Input has already passed the closed grammar.
const blocks=new Set(['rule','apply_server_side_encryption_by_default','versioning_configuration','metadata_options','root_block_device','access_logs','default_action','fixed_response','ingress','egress']);
function attrs(x:any,indent='  '):string {return Object.entries(x).map(([key,value])=>{if(blocks.has(key)&&!(Array.isArray(value)&&value.length===0)){const entries=Array.isArray(value)?value:[value];return entries.map(v=>`${indent}${key} {\n${attrs(v,indent+'  ')}${indent}}\n`).join('');}return `${indent}${key} = ${JSON.stringify(value)}\n`;}).join('');}
export function scannerHcl(tf:TF):string{return Object.entries(tf.resource).flatMap(([type,items])=>Object.entries(items).map(([name,value])=>`resource "${type}" "${name}" {\n${attrs(value)}}\n`)).join('\n');}
