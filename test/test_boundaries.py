import copy, importlib.util, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('boundaries',Path(__file__).resolve().parents[1]/'scripts/check_github_boundaries.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.branch={'enforce_admins':{'enabled':True},'required_pull_request_reviews':{'required_approving_review_count':1,'require_code_owner_reviews':True,'dismiss_stale_reviews':True},'required_status_checks':{'contexts':['tests','admission','trusted-candidate']}}
        self.env={'protection_rules':[{'type':'required_reviewers','reviewers':[{'id':1}],'prevent_self_review':True}],'deployment_branch_policy':{'protected_branches':True}}
    def test_valid(self):m.check(self.branch,[self.env,self.env])
    def test_admin(self):
        self.branch['enforce_admins']['enabled']=False
        with self.assertRaises(AssertionError):m.check(self.branch,[self.env])
    def test_reviews(self):
        self.branch['required_pull_request_reviews']['required_approving_review_count']=0
        with self.assertRaises(AssertionError):m.check(self.branch,[self.env])
    def test_checks(self):
        self.branch['required_status_checks']['contexts']=[]
        with self.assertRaises(AssertionError):m.check(self.branch,[self.env])
    def test_self_review(self):
        self.env['protection_rules'][0]['prevent_self_review']=False
        with self.assertRaises(AssertionError):m.check(self.branch,[self.env])
    def test_unprotected_environment(self):
        self.env['protection_rules']=[]
        with self.assertRaises(AssertionError):m.check(self.branch,[self.env])
