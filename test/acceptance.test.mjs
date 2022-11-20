import test from 'node:test';
import assert from 'node:assert/strict';
import {auditNames,TOOL_ID,LIMITS} from '../src/index.mjs';

const policy=()=>({schemaVersion:'1',complete:true,environments:['dev','prod']});
const s3=(name='dev-app-data',account='111111111111')=>({provider:'aws',service:'s3-bucket',partition:'aws',account,region:'us-east-1',name,tags:{environment:'dev',owner:'team-a'}});
const lambda=(name='dev_app_worker',region='us-east-1')=>({provider:'aws',service:'lambda-function',partition:'aws',account:'111111111111',region,name,tags:{environment:'dev',owner:'team-a'}});
const inventory=()=>({schemaVersion:'1',complete:true,resources:[s3(),lambda(),lambda('dev_app_worker','us-west-2')]});

test('valid service names and same Lambda name in different regions pass',()=>{
  const r=auditNames(policy(),inventory(),{now:()=>0});assert.equal(TOOL_ID,'cloud-resource-naming-auditor');assert.equal(r.status,'pass');assert.equal(r.summary.checked,3);assert.deepEqual(r.findings,[]);
});
test('a Lambda-valid underscore name is not assumed S3-valid',()=>{
  const d=inventory();d.resources=[lambda('dev_app_worker'),s3('dev_app_worker')];
  const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'fail');assert.deepEqual(r.findings.map(f=>f.ruleId),['name-invalid']);assert.equal(r.findings[0].location.pointer,'/resources/1/name');
});
test('a valid S3 name may contain adjacent hyphens',()=>{
  const d=inventory();d.resources=[s3('dev--app-data')];
  const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'pass');assert.deepEqual(r.findings,[]);
});
test('S3 names collide across accounts in a partition; Lambda names are regional',()=>{
  const d=inventory();d.resources=[s3(),s3('dev-app-data','222222222222')];
  const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.findings[0].ruleId,'name-duplicate');
  const l=inventory();l.resources=[lambda(),lambda()];assert.equal(auditNames(policy(),l,{now:()=>0}).findings[0].ruleId,'name-duplicate');
});
test('missing owner and unapproved environment markers fail without echoing values',()=>{
  const d=inventory();delete d.resources[0].tags.owner;d.resources[1].tags.environment='private-stage';
  const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'fail');assert.deepEqual(r.findings.map(f=>f.ruleId),['owner-missing','environment-invalid']);assert.doesNotMatch(JSON.stringify(r),/private-stage|team-a/);
});
test('unusable tag containers are incomplete, while an empty tag object has missing markers',()=>{
  for(const bad of [undefined,null,[],42,'private-tags']){
    const d=inventory();if(bad===undefined)delete d.resources[0].tags;else d.resources[0].tags=bad;
    const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'incomplete');assert.ok(r.findings.some(f=>f.ruleId==='resource-invalid'));assert.ok(!r.findings.some(f=>f.ruleId==='environment-missing'||f.ruleId==='owner-missing'));assert.doesNotMatch(JSON.stringify(r),/private-tags/);
  }
  const d=inventory();d.resources[0].tags={};const r=auditNames(policy(),d,{now:()=>0});assert.equal(r.status,'fail');assert.deepEqual(r.findings.map(f=>f.ruleId),['environment-missing','owner-missing']);
});
test('unknown service or absent completeness is incomplete, never a pass',()=>{
  const d=inventory();d.resources[0].service='unlisted-service';assert.equal(auditNames(policy(),d,{now:()=>0}).status,'incomplete');
  const p=policy();delete p.complete;assert.equal(auditNames(p,inventory(),{now:()=>0}).status,'incomplete');
  const e=inventory();delete e.complete;assert.equal(auditNames(policy(),e,{now:()=>0}).status,'incomplete');
});
test('resource and depth limits accept N and refuse N+1',()=>{
  const d=inventory();d.resources=Array.from({length:LIMITS.resources},(_,i)=>lambda(`fn_${i}`,'us-east-1'));
  assert.equal(auditNames(policy(),d,{now:()=>0}).status,'pass');d.resources.push(lambda('fn_extra'));assert.equal(auditNames(policy(),d,{now:()=>0}).findings[0].ruleId,'record-limit');
  const p=policy(),e=inventory();let x=e;for(let i=0;i<LIMITS.depth;i++){x.extra={};x=x.extra;}assert.equal(auditNames(p,e,{now:()=>0}).status,'pass');x.extra={};assert.equal(auditNames(p,e,{now:()=>0}).findings[0].ruleId,'depth-limit');
});
test('environment count and policy depth accept N and refuse N+1',()=>{
  const p=policy(),d=inventory();p.environments=['dev',...Array.from({length:LIMITS.environments-1},(_,i)=>`e${i}`)];assert.equal(auditNames(p,d,{now:()=>0}).status,'pass');
  p.environments.push('extra');assert.equal(auditNames(p,d,{now:()=>0}).findings[0].ruleId,'record-limit');
  const q=policy();let x=q;for(let i=0;i<LIMITS.depth;i++){x.extra={};x=x.extra;}assert.equal(auditNames(q,d,{now:()=>0}).status,'pass');x.extra={};assert.equal(auditNames(q,d,{now:()=>0}).findings[0].ruleId,'depth-limit');
});
test('service-specific name length boundaries do not reject their legal edges',()=>{
  for(const name of ['abc','a'.repeat(63)])assert.equal(auditNames(policy(),{...inventory(),resources:[s3(name)]},{now:()=>0}).status,'pass');
  for(const name of ['ab','a'.repeat(64)])assert.equal(auditNames(policy(),{...inventory(),resources:[s3(name)]},{now:()=>0}).findings[0].ruleId,'name-invalid');
  for(const name of ['a','a'.repeat(64)])assert.equal(auditNames(policy(),{...inventory(),resources:[lambda(name)]},{now:()=>0}).status,'pass');
  assert.equal(auditNames(policy(),{...inventory(),resources:[lambda('a'.repeat(65))]},{now:()=>0}).findings[0].ruleId,'name-invalid');
});
test('same S3 name in different partitions is not a collision',()=>{
  const d=inventory();d.resources=[s3(),{...s3(),partition:'aws-cn'}];assert.equal(auditNames(policy(),d,{now:()=>0}).status,'pass');
});
test('injected deadline accepts 5000 and rejects 5001 milliseconds',()=>{
  const clock=n=>{let first=true;return()=>{if(first){first=false;return 0;}return n;};};
  assert.equal(auditNames(policy(),inventory(),{now:clock(5000)}).status,'pass');assert.equal(auditNames(policy(),inventory(),{now:clock(5001)}).findings[0].ruleId,'time-limit');
});
