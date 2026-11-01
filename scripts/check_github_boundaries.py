"""Verify active branch rules and protected environments with a read-only token.

Administrative setup also verifies there are no ruleset bypass actors. GitHub
only exposes that list to writers; runtime reads the effective active rules.
"""
import json, os, urllib.request
REPO='jayekwere/ai-validated-iac-pipeline'

def require(condition,message):
    if not condition: raise ValueError(message)

def check(rules,envs):
    require(isinstance(rules,list) and rules,'Active branch rules required')
    reviews=[r.get('parameters',{}) for r in rules if r.get('type')=='pull_request']
    require(any(r.get('required_approving_review_count',0)>=1 and r.get('require_code_owner_review') is True and r.get('dismiss_stale_reviews_on_push') is True and r.get('required_review_thread_resolution') is True for r in reviews),'Protected code-owner review required')
    statuses=[r.get('parameters',{}) for r in rules if r.get('type')=='required_status_checks']
    require(any(r.get('strict_required_status_checks_policy') is True and {'tests','admission','trusted-candidate'}<={s.get('context') for s in r.get('required_status_checks',[]) if s.get('integration_id')==15368} for r in statuses),'Required GitHub Actions checks missing')
    require({'required_linear_history','deletion','non_fast_forward'}<={r.get('type') for r in rules},'Branch history protections missing')
    require(len(envs)==2,'Both protected environments required')
    for env in envs:
        require(env.get('can_admins_bypass') is False,'Environment administrator bypass must be disabled')
        reviewers=[r for r in env.get('protection_rules',[]) if r.get('type')=='required_reviewers']
        require(reviewers and reviewers[0].get('reviewers') and reviewers[0].get('prevent_self_review') is True,'Required reviewers and self-review prevention missing')
        policy=env.get('deployment_branch_policy')
        require(policy and policy.get('protected_branches') is True,'Protected branches only required')

def main():
    token=os.environ.get('GH_TOKEN','')
    if not token:raise SystemExit('GitHub authentication required')
    def get(path):
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
    # This endpoint returns only active rules and needs Metadata:read, rather
    # than the Administration:read required by legacy protection endpoints.
    check(get('/rules/branches/main?per_page=100'),[get('/environments/'+n) for n in ['ai-generation','pr-publication']])
    print('Active branch rules and protected review environments verified')
if __name__=='__main__':main()
