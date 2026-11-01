"""Require remote review boundaries before secret-bearing generation or publication."""
import json, os, urllib.request
REPO='jayekwere/ai-validated-iac-pipeline'
def check(branch,envs):
    assert branch.get('enforce_admins',{}).get('enabled') is True,'Administrator enforcement required'
    reviews=branch.get('required_pull_request_reviews',{})
    assert reviews.get('required_approving_review_count',0)>=1 and reviews.get('require_code_owner_reviews') and reviews.get('dismiss_stale_reviews'),'Protected human review required'
    statuses=branch.get('required_status_checks',{})
    names=set(statuses.get('contexts',[]))|{s['context'] for s in statuses.get('checks',[])}
    assert {'tests','admission','trusted-candidate'}<=names,'Required checks missing'
    for env in envs:
        rules=[r for r in env.get('protection_rules',[]) if r.get('type')=='required_reviewers']
        assert rules and rules[0].get('reviewers') and rules[0].get('prevent_self_review') is True,'Required environment reviewers and self-review prevention missing'
        policy=env.get('deployment_branch_policy')
        assert policy and policy.get('protected_branches') is True,'Protected branches only required'
def main():
    token=os.environ.get('GH_TOKEN','')
    if not token:raise SystemExit('GitHub authentication required')
    def get(path):
        req=urllib.request.Request('https://api.github.com/repos/'+REPO+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
    check(get('/branches/main/protection'),[get('/environments/'+n) for n in ['ai-generation','pr-publication']]);print('Protected review boundaries verified')
if __name__=='__main__':main()
