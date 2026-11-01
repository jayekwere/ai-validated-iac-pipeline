import copy, importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('boundaries',ROOT/'scripts/check_github_boundaries.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads((ROOT/'.github/review-ruleset.json').read_text());self.rules=copy.deepcopy(self.policy['rules'])
        self.envs=[{'name':name,'can_admins_bypass':False,'protection_rules':[{'type':'required_reviewers','reviewers':[{'type':'User','reviewer':{'login':'jayekwere'}}],'prevent_self_review':False}],'deployment_branch_policy':{'protected_branches':True,'custom_branch_policies':False}} for name in ['ai-generation','pr-publication','maintainer-approval']]
        self.envs[2]['deployment_branch_policy']={'protected_branches':False,'custom_branch_policies':True};self.envs[2]['allowed_branch_patterns']=['refs/pull/*/merge']
    def check(self):m.check(self.rules,self.envs)
    def test_valid(self):self.check()
    def test_empty_rules(self):
        self.rules=[]
        with self.assertRaises(ValueError):self.check()
    def test_no_manual_merge_gate(self):
        self.rules=[r for r in self.rules if r['type']!='required_deployments']
        with self.assertRaises(ValueError):self.check()
    def test_wrong_manual_merge_gate(self):
        self.rules[-1]['parameters']['required_deployment_environments']=['fake']
        with self.assertRaises(ValueError):self.check()
    def test_no_checks(self):
        self.rules[1]['parameters']['required_status_checks']=[]
        with self.assertRaises(ValueError):self.check()
    def test_wrong_check_source(self):
        self.rules[1]['parameters']['required_status_checks'][0]['integration_id']=999
        with self.assertRaises(ValueError):self.check()
    def test_self_review_lockout(self):
        self.envs[0]['protection_rules'][0]['prevent_self_review']=True
        with self.assertRaises(ValueError):self.check()
    def test_no_reviewers(self):
        self.envs[0]['protection_rules'][0]['reviewers']=[]
        with self.assertRaises(ValueError):self.check()
    def test_wrong_reviewer(self):
        self.envs[0]['protection_rules'][0]['reviewers'][0]['reviewer']['login']='github-actions[bot]'
        with self.assertRaises(ValueError):self.check()
    def test_unprotected_environment(self):
        self.envs[0]['protection_rules']=[]
        with self.assertRaises(ValueError):self.check()
    def test_administrator_environment_bypass(self):
        self.envs[0]['can_admins_bypass']=True
        with self.assertRaises(ValueError):self.check()
    def test_missing_history_rule(self):
        self.rules=[r for r in self.rules if r['type']!='non_fast_forward']
        with self.assertRaises(ValueError):self.check()
    def test_wrong_pr_pattern(self):
        self.envs[2]['allowed_branch_patterns']=['*']
        with self.assertRaises(ValueError):self.check()
    def test_wrong_generation_policy(self):
        self.envs[0]['deployment_branch_policy']['protected_branches']=False
        with self.assertRaises(ValueError):self.check()
    def test_missing_environment(self):
        self.envs.pop()
        with self.assertRaises(ValueError):self.check()
    def test_pr_review_lockout(self):
        self.rules[0]['parameters']['required_approving_review_count']=1
        with self.assertRaises(ValueError):self.check()
    def test_setup_disallows_ruleset_bypass(self):
        self.assertEqual(self.policy['bypass_actors'],[]);self.assertEqual(self.policy['enforcement'],'active')
