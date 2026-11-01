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
    require(any(r.get('required_approving_review_count')==0 and r.get('require_code_owner_review') is False and r.get('dismiss_stale_reviews_on_push') is True and r.get('required_review_thread_resolution') is True for r in reviews),'Solo PR policy requires the native manual deployment gate')
    approvals=[r.get('parameters',{}).get('required_deployment_environments',[]) for r in rules if r.get('type')=='required_deployments']
    require(any('maintainer-approval' in names for names in approvals),'Native maintainer approval deployment must be required before merge')
    statuses=[r.get('parameters',{}) for r in rules if r.get('type')=='required_status_checks']
    require(any(r.get('strict_required_status_checks_policy') is True and {'tests','admission','trusted-candidate'}<={s.get('context') for s in r.get('required_status_checks',[]) if s.get('integration_id')==15368} for r in statuses),'Required GitHub Actions checks missing')
    require({'required_linear_history','deletion','non_fast_forward'}<={r.get('type') for r in rules},'Branch history protections missing')
    require(len(envs)==3 and {e.get('name') for e in envs}=={'maintainer-approval','ai-generation','pr-publication'},'All three protected approval environments required')
    for env in envs:
        require(env.get('can_admins_bypass') is False,'Environment administrator bypass must be disabled')
        reviewers=[r for r in env.get('protection_rules',[]) if r.get('type')=='required_reviewers']
        require(len(reviewers)==1 and reviewers[0].get('prevent_self_review') is False,'Solo maintainer must be allowed to review their own run')
        people=reviewers[0].get('reviewers',[])
        require(len(people)==1 and people[0].get('type')=='User' and people[0].get('reviewer',{}).get('login')=='jayekwere','Only the human maintainer may approve')
        policy=env.get('deployment_branch_policy')
        if env.get('name')=='maintainer-approval':
            require(policy and policy.get('custom_branch_policies') is True and policy.get('protected_branches') is False,'PR approval must use a dedicated branch policy')
            require(env.get('allowed_branch_patterns')==['refs/pull/*/merge'],'PR approval must only accept PR merge refs')
        else:
            require(policy and policy.get('protected_branches') is True and policy.get('custom_branch_policies') is False,'Protected branches only required')

def main():
    token=os.environ.get('GH_TOKEN','')
    if not token:raise SystemExit('GitHub authentication required')
    def get(path):
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
    # This endpoint returns only active rules and needs Metadata:read, rather
    # than the Administration:read required by legacy protection endpoints.
    envs=[get('/environments/'+n) for n in ['ai-generation','pr-publication','maintainer-approval']]
    patterns=get('/environments/maintainer-approval/deployment-branch-policies?per_page=100')
    envs[2]['allowed_branch_patterns']=sorted(p['name'] for p in patterns.get('branch_policies',[]) if p.get('type')=='branch')
    check(get('/rules/branches/main?per_page=100'),envs)
    print('Active branch rules and protected review environments verified')
if __name__=='__main__':main()
