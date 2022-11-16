export const TOOL_ID='cloud-resource-naming-auditor';
export const LIMITS=Object.freeze({policyBytes:262144,inventoryBytes:1048576,environments:20,resources:1000,depth:16,milliseconds:5000});
export const RULE_SEVERITY=Object.freeze({'input-unreadable':'warning','input-invalid':'warning','export-incomplete':'warning','byte-limit':'warning','record-limit':'warning','depth-limit':'warning','time-limit':'warning','environment-duplicate':'warning','resource-invalid':'warning','unsupported-service':'warning','name-invalid':'error','name-duplicate':'error','environment-missing':'error','environment-invalid':'error','owner-missing':'error'});
const MESSAGES=Object.freeze({'input-unreadable':'Input could not be read, decoded, or parsed.','input-invalid':'Policy or inventory structure is invalid.','export-incomplete':'Policy or inventory does not assert complete coverage.','byte-limit':'Input exceeds its declared byte limit.','record-limit':'Policy or inventory exceeds a declared record limit.','depth-limit':'JSON nesting exceeds depth 16.','time-limit':'Evaluation exceeded 5000 milliseconds.','environment-duplicate':'Environment marker is duplicated in policy.','resource-invalid':'Resource scope or marker evidence is unusable.','unsupported-service':'Provider or service has no supported naming profile.','name-invalid':'Resource name violates its service naming profile.','name-duplicate':'Resource name collides within its service namespace.','environment-missing':'Environment marker is absent.','environment-invalid':'Environment marker is outside the approved set.','owner-missing':'Owner marker is absent.'});
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safe=x=>typeof x==='string'&&x.length>0&&x.length<=256&&x.trim().length>0&&!/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\p{Cf}]/u.test(x);
const environment=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,31}$/.test(x);
function finding(ruleId,file,pointer=''){if(!Object.hasOwn(RULE_SEVERITY,ruleId))throw Error('unknown rule');return {ruleId,severity:RULE_SEVERITY[ruleId],message:MESSAGES[ruleId],location:{file,pointer}};}
function report(findings,checked=0){findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));const status=findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':'pass';return {schemaVersion:'1',tool:TOOL_ID,status,summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};}
export function incomplete(ruleId,file){return report([finding(ruleId,file)]);}
function tooDeep(value){const stack=[[value,0]];while(stack.length){const [item,depth]=stack.pop();if(depth>LIMITS.depth)return true;if(item&&typeof item==='object')for(const child of Object.values(item))stack.push([child,depth+1]);}return false;}
function validPolicy(x){return object(x)&&x.schemaVersion==='1'&&(x.complete===undefined||typeof x.complete==='boolean')&&Array.isArray(x.environments)&&x.environments.length>0;}
function validInventory(x){return object(x)&&x.schemaVersion==='1'&&(x.complete===undefined||typeof x.complete==='boolean')&&Array.isArray(x.resources)&&x.resources.length>0;}
function validName(service,name){
  if(service==='s3-bucket')return name.length>=3&&name.length<=63&&/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(name)&&!/\.\.|\.-|-\./.test(name)&&!/^\d+\.\d+\.\d+\.\d+$/.test(name);
  if(service==='lambda-function')return name.length>=1&&name.length<=64&&/^[A-Za-z0-9_-]+$/.test(name);
  return false;
}
function scopeKey(item){return item.service==='s3-bucket'?`${item.partition}\u0000s3\u0000${item.name}`:`${item.partition}\u0000lambda\u0000${item.account}\u0000${item.region}\u0000${item.name}`;}

export function auditNames(policy,inventory,{now=()=>performance.now()}={}){
  const start=now(),findings=[];const timed=()=>now()-start>LIMITS.milliseconds;
  if(tooDeep(policy))findings.push(finding('depth-limit','@policy'));
  if(tooDeep(inventory))findings.push(finding('depth-limit','@inventory'));
  if(findings.length)return report(findings);
  if(!validPolicy(policy))findings.push(finding('input-invalid','@policy'));
  if(!validInventory(inventory))findings.push(finding('input-invalid','@inventory'));
  if(findings.length)return report(findings);
  if(policy.complete!==true)findings.push(finding('export-incomplete','@policy','/complete'));
  if(inventory.complete!==true)findings.push(finding('export-incomplete','@inventory','/complete'));
  if(findings.length)return report(findings);
  if(policy.environments.length>LIMITS.environments)findings.push(finding('record-limit','@policy','/environments'));
  if(inventory.resources.length>LIMITS.resources)findings.push(finding('record-limit','@inventory','/resources'));
  if(findings.length)return report(findings);
  const allowed=new Set();
  for(const [i,item] of policy.environments.entries()){
    if(!environment(item))findings.push(finding('input-invalid','@policy',`/environments/${i}`));
    else if(allowed.has(item))findings.push(finding('environment-duplicate','@policy',`/environments/${i}`));
    else allowed.add(item);
  }
  if(findings.length)return report(findings);
  const seen=new Set();let checked=0;
  for(const [i,item] of inventory.resources.entries()){
    if(timed())return incomplete('time-limit','@inventory');
    const pointer=`/resources/${i}`;
    if(!object(item)){findings.push(finding('resource-invalid','@inventory',pointer));continue;}
    if(item.provider!=='aws'||!['s3-bucket','lambda-function'].includes(item.service)){findings.push(finding('unsupported-service','@inventory',`${pointer}/service`));continue;}
    if(!['aws','aws-cn','aws-us-gov'].includes(item.partition)||typeof item.account!=='string'||!/^\d{12}$/.test(item.account)||typeof item.region!=='string'||!/^[a-z0-9-]{1,32}$/.test(item.region)||!safe(item.name)){
      findings.push(finding('resource-invalid','@inventory',pointer));continue;
    }
    checked++;
    if(!validName(item.service,item.name))findings.push(finding('name-invalid','@inventory',`${pointer}/name`));
    else {const key=scopeKey(item);if(seen.has(key))findings.push(finding('name-duplicate','@inventory',`${pointer}/name`));else seen.add(key);}
    const tags=object(item.tags)?item.tags:{};
    if(tags.environment===undefined)findings.push(finding('environment-missing','@inventory',`${pointer}/tags/environment`));
    else if(!environment(tags.environment))findings.push(finding('resource-invalid','@inventory',`${pointer}/tags/environment`));
    else if(!allowed.has(tags.environment))findings.push(finding('environment-invalid','@inventory',`${pointer}/tags/environment`));
    if(tags.owner===undefined||tags.owner===null||tags.owner==='')findings.push(finding('owner-missing','@inventory',`${pointer}/tags/owner`));
    else if(!safe(tags.owner)||tags.owner.length>128)findings.push(finding('resource-invalid','@inventory',`${pointer}/tags/owner`));
  }
  if(timed())return incomplete('time-limit','@inventory');
  return report(findings,checked);
}
