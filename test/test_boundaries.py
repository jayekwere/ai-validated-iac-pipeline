import copy, importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('boundaries',ROOT/'scripts/check_github_boundaries.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads((ROOT/'.github/review-ruleset.json').read_text());self.rules=copy.deepcopy(self.policy['rules'])
        self.env={'can_admins_bypass':False,'protection_rules':[{'type':'required_reviewers','reviewers':[{'id':1}],'prevent_self_review':True}],'deployment_branch_policy':{'protected_branches':True}}
    def check(self):m.check(self.rules,[self.env,self.env])
    def test_valid(self):self.check()
    def test_empty_rules(self):
        self.rules=[]
        with self.assertRaises(ValueError):self.check()
    def test_missing_reviews(self):
        self.rules[0]['parameters']['required_approving_review_count']=0
        with self.assertRaises(ValueError):self.check()
    def test_missing_checks(self):
        self.rules[1]['parameters']['required_status_checks']=[]
        with self.assertRaises(ValueError):self.check()
    def test_wrong_check_source(self):
        self.rules[1]['parameters']['required_status_checks'][0]['integration_id']=999
        with self.assertRaises(ValueError):self.check()
    def test_self_review(self):
        self.env['protection_rules'][0]['prevent_self_review']=False
        with self.assertRaises(ValueError):self.check()
    def test_unprotected_environment(self):
        self.env['protection_rules']=[]
        with self.assertRaises(ValueError):self.check()
    def test_administrator_environment_bypass(self):
        self.env['can_admins_bypass']=True
        with self.assertRaises(ValueError):self.check()
    def test_missing_history_rule(self):
        self.rules.pop()
        with self.assertRaises(ValueError):self.check()
    def test_setup_disallows_ruleset_bypass(self):
        self.assertEqual(self.policy['bypass_actors'],[]);self.assertEqual(self.policy['enforcement'],'active')
