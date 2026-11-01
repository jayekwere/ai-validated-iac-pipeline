import importlib.util, json, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('scan',Path(__file__).resolve().parents[1]/'scripts/scan.py')
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)
def plan(t,after):return {'resource_changes':[{'address':t+'.x','type':t,'change':{'after':after}}]}
class ScannerTests(unittest.TestCase):
    def test_invalid(self):
        for value in [None,{},[]]:
            with self.assertRaises(ValueError):scan.scan(value)
    def test_public(self):self.assertTrue(scan.scan(plan('aws_s3_bucket_public_access_block',{})))
    def test_encryption(self):self.assertTrue(scan.scan(plan('aws_s3_bucket_server_side_encryption_configuration',{})))
    def test_companions(self):self.assertEqual(len(scan.scan(plan('aws_s3_bucket',{}))),4)
    def test_admin(self):self.assertTrue(scan.scan(plan('aws_security_group',{'ingress':[{'cidr_blocks':['0.0.0.0/0'],'from_port':22}]})))
    def test_ipv6(self):self.assertTrue(scan.scan(plan('aws_security_group',{'ingress':[{'ipv6_cidr_blocks':['::/0']}]})))
    def test_compute(self):self.assertEqual(len(scan.scan(plan('aws_instance',{}))),2)
    def test_iam(self):
        for action,resource in [('*','arn:aws:s3:::one'),('s3:GetObject','*')]:self.assertTrue(scan.scan(plan('aws_iam_role_policy',{'policy':json.dumps({'Statement':[{'Effect':'Allow','Action':action,'Resource':resource}]})})))
    def test_iam_single_statement_object(self):
        ids={f['id'] for f in scan.scan(plan('aws_iam_role_policy',{'policy':json.dumps({'Statement':{'Effect':'Allow','Action':'*','Resource':'*'}})}))}
        self.assertIn('WILDCARD_IAM',ids)
    def test_iam_negation(self):
        for k in ['NotAction','NotResource']:
            stmt={'Effect':'Allow','Action':'s3:GetObject','Resource':'arn:aws:s3:::b',k:'iam:*'}
            self.assertIn('IAM_NEGATION',{f['id'] for f in scan.scan(plan('aws_iam_role_policy',{'policy':json.dumps({'Statement':[stmt]})}))})
    def test_iam_scoped_allowed(self):self.assertEqual(scan.scan(plan('aws_iam_role_policy',{'policy':json.dumps({'Statement':{'Effect':'Allow','Action':'s3:GetObject','Resource':'arn:aws:s3:::b/k'}})})),[])
    def test_lb(self):self.assertTrue(scan.scan(plan('aws_lb',{'internal':False})))
    def test_tls(self):self.assertTrue(scan.scan(plan('aws_lb_listener',{'protocol':'HTTP','port':80})))
    def test_audit(self):self.assertTrue(scan.scan(plan('aws_cloudtrail',{})))
    def test_unknown(self):self.assertTrue(scan.scan(plan('aws_instance',None)))
    def test_secure(self):self.assertEqual(scan.scan(plan('aws_security_group',{'ingress':[{'cidr_blocks':['10.0.0.0/16']}]})),[])
if __name__=='__main__':unittest.main()
