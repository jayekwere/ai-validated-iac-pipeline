"""Independent plan scanner. No code from generated output is imported or evaluated."""
import json, sys

def scan(plan):
    if not isinstance(plan,dict) or not isinstance(plan.get('resource_changes'),list): raise ValueError('PLAN_FORMAT')
    def dig(value,*path):
        try:
            for key in path:value=value[key]
            return value
        except (KeyError,IndexError,TypeError):return None
    findings=[]; resources=plan['resource_changes']; addresses={r['address'] for r in resources}
    def fail(r,rule,msg): findings.append({'id':rule,'address':r['address'],'message':msg,'severity':'HIGH'})
    for r in resources:
        a=r['change']['after']; t=r['type']
        if not isinstance(a,dict): fail(r,'UNKNOWN_VALUES','No planned values');continue
        if t=='aws_s3_bucket':
            for companion in ['aws_s3_bucket_public_access_block','aws_s3_bucket_server_side_encryption_configuration','aws_s3_bucket_versioning','aws_s3_bucket_policy']:
                if r['address'].replace('aws_s3_bucket.',companion+'.') not in addresses: fail(r,'S3_COMPANION','Missing '+companion)
        if t=='aws_s3_bucket_public_access_block' and any(a.get(k) is not True for k in ['block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets']): fail(r,'PUBLIC_STORAGE','All public access controls required')
        if t=='aws_s3_bucket_server_side_encryption_configuration' and dig(a,'rule',0,'apply_server_side_encryption_by_default',0,'sse_algorithm')!=('AES256' if r.get('name')=='logs' else 'aws:kms'):fail(r,'ENCRYPTION','Approved encryption required')
        if t=='aws_security_group':
            ingress=a.get('ingress')
            if not isinstance(ingress,list):fail(r,'INGRESS_UNKNOWN','Ingress must be known');continue
            for rule in ingress:
                if '0.0.0.0/0' in rule.get('cidr_blocks',[]) or '::/0' in rule.get('ipv6_cidr_blocks',[]):fail(r,'PUBLIC_INGRESS','Unrestricted network ingress')
        if t=='aws_instance':
            if a.get('associate_public_ip_address') is not False:fail(r,'PUBLIC_COMPUTE','Public IP prohibited')
            disks=a.get('root_block_device')
            if not isinstance(disks,list) or not disks or any(not isinstance(d,dict) or d.get('encrypted') is not True for d in disks):fail(r,'DISK_ENCRYPTION','Encrypted root disk required')
            if dig(a,'metadata_options',0,'http_tokens')!='required':fail(r,'IMDS','IMDSv2 required')
        if t=='aws_iam_role_policy':
            try: document=json.loads(a.get('policy',''))
            except (ValueError,TypeError): fail(r,'IAM_DOCUMENT','Invalid IAM JSON');continue
            statements=document.get('Statement') if isinstance(document,dict) else None
            if isinstance(statements,dict):statements=[statements]
            if not isinstance(statements,list) or not statements:fail(r,'IAM_DOCUMENT','Explicit IAM statements required');continue
            def strings(value):return isinstance(value,str) and bool(value) or isinstance(value,list) and bool(value) and all(isinstance(x,str) and bool(x) for x in value)
            for stmt in statements:
                if not isinstance(stmt,dict):fail(r,'IAM_DOCUMENT','IAM statement must be an object');continue
                if stmt.get('Effect')=='Allow' and ('NotAction' in stmt or 'NotResource' in stmt):fail(r,'IAM_NEGATION','Allow statements cannot use NotAction or NotResource')
                actions=stmt.get('Action',stmt.get('NotAction')); resources_=stmt.get('Resource',stmt.get('NotResource'))
                if stmt.get('Effect') not in ('Allow','Deny') or not strings(actions) or not strings(resources_) or {'Action','NotAction'}<=stmt.keys() or {'Resource','NotResource'}<=stmt.keys():fail(r,'IAM_DOCUMENT','Malformed IAM statement');continue
                actions=[actions] if isinstance(actions,str) else actions
                resources_=[resources_] if isinstance(resources_,str) else resources_
                if stmt.get('Effect')=='Allow' and (any('*' in x for x in actions) or '*' in resources_):fail(r,'WILDCARD_IAM','Wildcard action or global resource')
        if t=='aws_lb' and a.get('internal') is not True:fail(r,'PUBLIC_LB','Internal load balancer required')
        if t=='aws_lb_listener' and (a.get('protocol')!='HTTPS' or a.get('port')!=443):fail(r,'TLS','HTTPS 443 required')
        if t=='aws_cloudtrail' and (a.get('enable_log_file_validation') is not True or a.get('is_multi_region_trail') is not True):fail(r,'AUDIT','Validated multi-region trail required')
    return findings
if __name__=='__main__':
    try:
        findings=scan(json.load(open(sys.argv[1])));print(json.dumps({'scanner':'independent-plan-scanner/v1','findings':findings}));sys.exit(bool(findings))
    except (ValueError,KeyError,TypeError,OSError,IndexError) as e:
        print(json.dumps({'error':str(e)}));sys.exit(2)
