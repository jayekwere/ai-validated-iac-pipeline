import {createHash} from 'node:crypto';
import type {Spec} from './spec.ts';
export {parseSpec} from './spec.ts';
export function canonical(x:unknown):string {if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';if(x&&typeof x==='object')return '{'+Object.entries(x).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>JSON.stringify(k)+':'+canonical(v)).join(',')+'}';return JSON.stringify(x);}
export function hash(x:unknown):string{return createHash('sha256').update(canonical(x)).digest('hex');}
export const ref=(x:string)=>'${'+x+'}';
export type TF={terraform:object;provider:object;resource:Record<string,Record<string,any>>};
export function sample(s:Spec):TF {
 const resource:TF['resource']={}; const add=(t:string,n:string,v:object)=>{(resource[t]??={})[n]=v;};
 const tags={Environment:s.environment,ManagedBy:'ai-validated-iac-pipeline'};
 const kms=ref('aws_kms_key.main.arn');
 add('aws_kms_key','main',{description:`${s.name} encryption`,enable_key_rotation:true,deletion_window_in_days:30,policy:JSON.stringify({Version:'2012-10-17',Statement:[{Sid:'AccountKeyAdministration',Effect:'Allow',Principal:{AWS:`arn:aws:iam::${s.accountId}:root`},Action:['kms:CreateAlias','kms:DescribeKey','kms:EnableKeyRotation','kms:GetKeyPolicy','kms:PutKeyPolicy','kms:ScheduleKeyDeletion','kms:TagResource','kms:Encrypt','kms:Decrypt','kms:GenerateDataKey'],Resource:'*'}]}),tags});
 const bucket=(name:string,logging:boolean)=>{
 add('aws_s3_bucket',name,{bucket:`${s.name}-${name}`,force_destroy:false,tags});
 add('aws_s3_bucket_public_access_block',name,{bucket:ref(`aws_s3_bucket.${name}.id`),block_public_acls:true,block_public_policy:true,ignore_public_acls:true,restrict_public_buckets:true});
 add('aws_s3_bucket_server_side_encryption_configuration',name,{bucket:ref(`aws_s3_bucket.${name}.id`),rule:[{apply_server_side_encryption_by_default:[{...(name==='logs'?{sse_algorithm:'AES256'}:{sse_algorithm:'aws:kms',kms_master_key_id:kms})}],bucket_key_enabled:true}]});
 add('aws_s3_bucket_versioning',name,{bucket:ref(`aws_s3_bucket.${name}.id`),versioning_configuration:[{status:'Enabled'}]});
 add('aws_s3_bucket_policy',name,{bucket:ref(`aws_s3_bucket.${name}.id`),policy:JSON.stringify({Version:'2012-10-17',Statement:[{Sid:'DenyInsecureTransport',Effect:'Deny',Principal:'*',Action:'s3:*',Resource:[ref(`aws_s3_bucket.${name}.arn`),ref(`aws_s3_bucket.${name}.arn`)+'/*'],Condition:{Bool:{'aws:SecureTransport':'false'}}}]})});
 if(logging)add('aws_s3_bucket_logging',name,{bucket:ref(`aws_s3_bucket.${name}.id`),target_bucket:ref('aws_s3_bucket.logs.id'),target_prefix:`${name}/`});
 };
 bucket('logs',false);
 if(['storage','platform'].includes(s.kind))bucket('storage',true);
 if(['network','compute','load-balancer','platform'].includes(s.kind)){
 add('aws_vpc','main',{cidr_block:s.cidr,enable_dns_hostnames:true,enable_dns_support:true,tags});
 for(const [i,n] of ['app_a','app_b','data_a','data_b'].entries())add('aws_subnet',n,{vpc_id:ref('aws_vpc.main.id'),cidr_block:s.cidr.replace('0.0/16',`${i+1}.0/24`),availability_zone:s.region+(i%2?'b':'a'),map_public_ip_on_launch:false,tags});
 for(const tier of ['app','data']){add('aws_route_table',tier,{vpc_id:ref('aws_vpc.main.id'),tags});for(const suffix of ['a','b'])add('aws_route_table_association',tier+'_'+suffix,{subnet_id:ref(`aws_subnet.${tier}_${suffix}.id`),route_table_id:ref(`aws_route_table.${tier}.id`)});}
 add('aws_flow_log','main',{vpc_id:ref('aws_vpc.main.id'),traffic_type:'ALL',log_destination_type:'s3',log_destination:ref('aws_s3_bucket.logs.arn'),max_aggregation_interval:60,tags});
 add('aws_default_security_group','default',{vpc_id:ref('aws_vpc.main.id'),ingress:[],egress:[],tags});
 add('aws_security_group','app',{name:`${s.name}-app`,description:'Private application TLS only',vpc_id:ref('aws_vpc.main.id'),ingress:[{description:'Internal TLS',from_port:443,to_port:443,protocol:'tcp',cidr_blocks:[s.cidr],ipv6_cidr_blocks:[],prefix_list_ids:[],security_groups:[],self:false}],egress:[],tags});
 }
 if(['compute','platform'].includes(s.kind))add('aws_instance','app',{ami:s.ami,instance_type:'t3.micro',subnet_id:ref('aws_subnet.app_a.id'),vpc_security_group_ids:[ref('aws_security_group.app.id')],associate_public_ip_address:false,monitoring:true,metadata_options:[{http_endpoint:'enabled',http_tokens:'required',http_put_response_hop_limit:1}],root_block_device:[{encrypted:true,kms_key_id:kms,volume_type:'gp3',volume_size:20}],tags});
 if(['iam','platform'].includes(s.kind)){
 add('aws_iam_role','reader',{name:`${s.name}-reader`,assume_role_policy:JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{Service:'ec2.amazonaws.com'},Action:'sts:AssumeRole'}]}),tags});
 add('aws_iam_role_policy','reader',{name:'read-one-prefix',role:ref('aws_iam_role.reader.id'),policy:JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:['s3:GetObject'],Resource:[`arn:aws:s3:::${s.name}-logs/approved/*`]}]})});
 }
 if(['load-balancer','platform'].includes(s.kind)){
 add('aws_lb','app',{name:s.name,internal:true,load_balancer_type:'application',subnets:[ref('aws_subnet.app_a.id'),ref('aws_subnet.app_b.id')],security_groups:[ref('aws_security_group.app.id')],drop_invalid_header_fields:true,enable_deletion_protection:true,access_logs:[{bucket:ref('aws_s3_bucket.logs.id'),prefix:'alb',enabled:true}],tags});
 add('aws_lb_listener','https',{load_balancer_arn:ref('aws_lb.app.arn'),port:443,protocol:'HTTPS',ssl_policy:'ELBSecurityPolicy-TLS13-1-2-2021-06',certificate_arn:s.certificateArn,default_action:[{type:'fixed-response',fixed_response:[{content_type:'text/plain',message_body:'Private service',status_code:'200'}]}]});
 }
 if(['audit','platform'].includes(s.kind)){
 add('aws_cloudwatch_log_group','audit',{name:`/iac/${s.name}`,retention_in_days:365,kms_key_id:kms,tags});
 add('aws_cloudtrail','audit',{name:s.name,s3_bucket_name:ref('aws_s3_bucket.logs.id'),is_multi_region_trail:true,include_global_service_events:true,enable_log_file_validation:true,enable_logging:true,kms_key_id:kms,tags});
 }

 const logsPolicy=JSON.parse(resource.aws_s3_bucket_policy.logs.policy);
 logsPolicy.Statement.push({Sid:'S3LogDelivery',Effect:'Allow',Principal:{Service:'logging.s3.amazonaws.com'},Action:'s3:PutObject',Resource:ref('aws_s3_bucket.logs.arn')+'/*',Condition:{StringEquals:{'aws:SourceAccount':s.accountId},ArnLike:{'aws:SourceArn':`arn:aws:s3:::${s.name}-*`}}});
 if(['network','compute','load-balancer','platform'].includes(s.kind))logsPolicy.Statement.push({Sid:'VPCLogDelivery',Effect:'Allow',Principal:{Service:'delivery.logs.amazonaws.com'},Action:'s3:PutObject',Resource:ref('aws_s3_bucket.logs.arn')+`/AWSLogs/${s.accountId}/*`,Condition:{StringEquals:{'aws:SourceAccount':s.accountId,'s3:x-amz-acl':'bucket-owner-full-control'},ArnLike:{'aws:SourceArn':`arn:aws:logs:${s.region}:${s.accountId}:*`}}},{Sid:'VPCLogAcl',Effect:'Allow',Principal:{Service:'delivery.logs.amazonaws.com'},Action:'s3:GetBucketAcl',Resource:ref('aws_s3_bucket.logs.arn'),Condition:{StringEquals:{'aws:SourceAccount':s.accountId}}});
 if(['load-balancer','platform'].includes(s.kind))logsPolicy.Statement.push({Sid:'ALBLogDelivery',Effect:'Allow',Principal:{Service:'logdelivery.elasticloadbalancing.amazonaws.com'},Action:'s3:PutObject',Resource:ref('aws_s3_bucket.logs.arn')+`/alb/AWSLogs/${s.accountId}/*`});
 if(['audit','platform'].includes(s.kind)){
 const trailArn=`arn:aws:cloudtrail:${s.region}:${s.accountId}:trail/${s.name}`;
 logsPolicy.Statement.push({Sid:'CloudTrailAcl',Effect:'Allow',Principal:{Service:'cloudtrail.amazonaws.com'},Action:'s3:GetBucketAcl',Resource:ref('aws_s3_bucket.logs.arn'),Condition:{StringEquals:{'aws:SourceArn':trailArn}}},{Sid:'CloudTrailDelivery',Effect:'Allow',Principal:{Service:'cloudtrail.amazonaws.com'},Action:'s3:PutObject',Resource:ref('aws_s3_bucket.logs.arn')+`/AWSLogs/${s.accountId}/*`,Condition:{StringEquals:{'aws:SourceArn':trailArn,'s3:x-amz-acl':'bucket-owner-full-control'}}});
 const kp=JSON.parse(resource.aws_kms_key.main.policy);kp.Statement.push({Sid:'CloudTrailEncryption',Effect:'Allow',Principal:{Service:'cloudtrail.amazonaws.com'},Action:['kms:GenerateDataKey*','kms:DescribeKey'],Resource:'*',Condition:{StringEquals:{'aws:SourceArn':trailArn}}},{Sid:'CloudWatchLogsEncryption',Effect:'Allow',Principal:{Service:`logs.${s.region}.amazonaws.com`},Action:['kms:Encrypt','kms:Decrypt','kms:ReEncrypt*','kms:GenerateDataKey*','kms:DescribeKey'],Resource:'*',Condition:{ArnEquals:{'kms:EncryptionContext:aws:logs:arn':`arn:aws:logs:${s.region}:${s.accountId}:log-group:/iac/${s.name}`}}});resource.aws_kms_key.main.policy=JSON.stringify(kp);
 resource.aws_cloudtrail.audit.depends_on=['aws_s3_bucket_policy.logs'];
 }
 resource.aws_s3_bucket_policy.logs.policy=JSON.stringify(logsPolicy);
 const singleBlocks=new Set(['rule','apply_server_side_encryption_by_default','versioning_configuration','metadata_options','root_block_device','access_logs','default_action','fixed_response']);
 function normalize(x:any):any {if(Array.isArray(x))return x.map(normalize);if(x&&typeof x==='object')return Object.fromEntries(Object.entries(x).map(([k,v])=>[k,singleBlocks.has(k)&&Array.isArray(v)&&v.length===1?normalize(v[0]):normalize(v)]));return x;}
 return {terraform:{required_version:'= 1.9.8',required_providers:{aws:{source:'hashicorp/aws',version:'= 5.76.0'}}},provider:{aws:{region:s.region,skip_credentials_validation:true,skip_requesting_account_id:true,skip_metadata_api_check:true}},resource:normalize(resource)};
}
export function validateOutput(s:Spec,x:unknown):void {
 if(Buffer.byteLength(canonical(x))>131072)throw Error('OUTPUT_SIZE');
 if(canonical(x)!==canonical(sample(s))){const paths:string[]=[];function diff(a:any,b:any,path:string){if(paths.length>=12||canonical(a)===canonical(b))return;if(!a||!b||typeof a!=='object'||typeof b!=='object'){paths.push(path);return;}for(const k of new Set([...Object.keys(a),...Object.keys(b)]))diff(a[k],b[k],path+'.'+k);}diff(sample(s),x,'$');throw Error('OUTPUT_ALLOWLIST: unapproved differences at '+paths.join(', '));}
}
export interface Generator {readonly mode:string;generate(s:Spec):Promise<unknown>}
export class SampleGenerator implements Generator {readonly mode='deterministic non-AI';async generate(s:Spec){return sample(s);}}
export function parseTerraform(text:string):unknown {if(Buffer.byteLength(text)>131072)throw Error('OUTPUT_SIZE');return JSON.parse(text);}
