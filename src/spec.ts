import {parseDocument} from 'yaml';
export type Kind='storage'|'compute'|'iam'|'network'|'load-balancer'|'audit'|'platform';
export type Spec={version:1;cloud:'aws';kind:Kind;name:string;region:'ca-central-1'|'us-east-1'|'us-west-2';environment:'dev'|'prod';encryption:'aws:kms';public:false;cidr:string;ami:string;certificateArn:string;accountId:string};
export const kinds:Kind[]=['storage','compute','iam','network','load-balancer','audit','platform'];
export function parseSpec(value:unknown):Spec {
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('SPEC_OBJECT: object required');
 const x=value as Record<string,unknown>; const keys=['version','cloud','kind','name','region','environment','encryption','public','cidr','ami','certificateArn','accountId'];
 if(Object.keys(x).some(k=>!keys.includes(k))||Object.keys(x).length!==keys.length)throw Error('SPEC_FIELDS: unknown or missing fields; instructions are forbidden');
 if(x.version!==1||x.cloud!=='aws'||!kinds.includes(x.kind as Kind)||typeof x.name!=='string'||!/^[a-z][a-z0-9-]{2,30}$/.test(x.name)||!['ca-central-1','us-east-1','us-west-2'].includes(String(x.region))||!['dev','prod'].includes(String(x.environment))||x.encryption!=='aws:kms'||x.public!==false||typeof x.cidr!=='string'||!/^10\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0\.0\/16$/.test(x.cidr)||typeof x.ami!=='string'||!/^ami-[0-9a-f]{17}$/.test(x.ami)||typeof x.accountId!=='string'||!/^\d{12}$/.test(x.accountId)||x.certificateArn!==`arn:aws:acm:${x.region}:${x.accountId}:certificate/00000000-0000-4000-8000-000000000001`)throw Error('SPEC_SECURITY: invalid value or insecure request');
 return x as Spec;
}
export function parseText(text:string):Spec {
 if(Buffer.byteLength(text)>16384)throw Error('SPEC_SIZE');
 const doc=parseDocument(text,{uniqueKeys:true,version:'1.2',schema:'core'});
 if(doc.warnings.length)throw Error('SPEC_PARSE: unsupported YAML tag');
 if(doc.errors.length)throw Error('SPEC_PARSE: '+doc.errors[0].message);
 return parseSpec(doc.toJS({maxAliasCount:0}));
}
