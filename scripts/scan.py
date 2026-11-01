"""Independent plan scanner. No code from generated output is imported or evaluated."""
import json, sys

def scan(plan):
    if not isinstance(plan,dict) or not isinstance(plan.get('resource_changes'),list): raise ValueError('PLAN_FORMAT')
    findings=[]; resources=plan['resource_changes']; addresses={r['address'] for r in resources}
    def fail(r,rule,msg): findings.append({'id':rule,'address':r['address'],'message':msg,'severity':'HIGH'})
    for r in resources:
        a=r['change']['after']; t=r['type']
        if not isinstance(a,dict): fail(r,'UNKNOWN_VALUES','No planned values');continue
        if t=='aws_s3_bucket':
            for companion in ['aws_s3_bucket_public_access_block','aws_s3_bucket_server_side_encryption_configuration','aws_s3_bucket_versioning','aws_s3_bucket_policy']:
                if r['address'].replace('aws_s3_bucket.',companion+'.') not in addresses: fail(r,'S3_COMPANION','Missing '+companion)
        if t=='aws_s3_bucket_public_access_block' and any(a.get(k) is not True for k in ['block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets']): fail(r,'PUBLIC_STORAGE','All public access controls required')
        if t=='aws_s3_bucket_server_side_encryption_configuration' and a.get('rule',[{}])[0].get('apply_server_side_encryption_by_default',[{}])[0].get('sse_algorithm')!=('AES256' if r.get('name')=='logs' else 'aws:kms'):fail(r,'ENCRYPTION','Approved encryption required')
        if t=='aws_security_group':
            for rule in a.get('ingress',[]):
                if '0.0.0.0/0' in rule.get('cidr_blocks',[]) or '::/0' in rule.get('ipv6_cidr_blocks',[]):fail(r,'PUBLIC_INGRESS','Unrestricted network ingress')
        if t=='aws_instance':
            if a.get('associate_public_ip_address') is not False:fail(r,'PUBLIC_COMPUTE','Public IP prohibited')
            if not all(d.get('encrypted') is True for d in a.get('root_block_device',[])) or not a.get('root_block_device'):fail(r,'DISK_ENCRYPTION','Encrypted root disk required')
        if t=='aws_iam_role_policy':
            for stmt in json.loads(a['policy']).get('Statement',[]):
                actions=stmt.get('Action',[]);actions=[actions] if isinstance(actions,str) else actions
                resources_=stmt.get('Resource',[]);resources_=[resources_] if isinstance(resources_,str) else resources_
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
