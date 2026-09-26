import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const cli=new URL('../bin/cloud-resource-naming-auditor.mjs',import.meta.url).pathname;
const policy={schemaVersion:'1',complete:true,environments:['dev','prod']};
const inventory={schemaVersion:'1',complete:true,resources:[{provider:'aws',service:'s3-bucket',partition:'aws',account:'111111111111',region:'us-east-1',name:'dev-app-data',tags:{environment:'dev',owner:'team-a'}}]};
function fixture(run){const root=mkdtempSync(join(tmpdir(),'resource-name-'));try{writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory));return run(root);}finally{rmSync(root,{recursive:true,force:true});}}
const invoke=root=>spawnSync(process.execPath,[cli,'--root',root,'--policy','policy.json','--inventory','inventory.json'],{encoding:'utf8'});

test('CLI good report is deterministic and does not echo resource names',()=>fixture(root=>{
  const a=invoke(root),b=invoke(root);assert.equal(a.status,0);assert.equal(a.stdout,b.stdout);assert.equal(JSON.parse(a.stdout).status,'pass');assert.doesNotMatch(a.stdout,/dev-app-data|team-a/);
}));
test('bad usage has empty stdout; missing input has incomplete JSON',()=>fixture(root=>{
  const bad=spawnSync(process.execPath,[cli,'--oops'],{encoding:'utf8'});assert.equal(bad.status,2);assert.equal(bad.stdout,'');
  const missing=spawnSync(process.execPath,[cli,'--root',root,'--policy','policy.json','--inventory','missing.json'],{encoding:'utf8'});assert.equal(missing.status,2);assert.equal(JSON.parse(missing.stdout).findings[0].ruleId,'input-unreadable');
}));
test('policy and inventory byte limits accept N and refuse N+1',()=>fixture(root=>{
  for(const [name,base,limit] of [['policy.json',JSON.stringify(policy),262144],['inventory.json',JSON.stringify(inventory),1048576]]){
    writeFileSync(join(root,name),base+' '.repeat(limit-Buffer.byteLength(base)));assert.equal(invoke(root).status,0);
    writeFileSync(join(root,name),base+' '.repeat(limit+1-Buffer.byteLength(base)));const over=invoke(root);assert.equal(over.status,2);assert.equal(JSON.parse(over.stdout).findings[0].ruleId,'byte-limit');writeFileSync(join(root,name),base);
  }
}));
test('escaping inventory symlink is incomplete and cannot reveal outside bytes',()=>{
  const root=mkdtempSync(join(tmpdir(),'resource-root-')),outside=mkdtempSync(join(tmpdir(),'resource-out-'));
  try{writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(outside,'private.json'),'PRIVATE_SENTINEL');symlinkSync(join(outside,'private.json'),join(root,'inventory.json'));const r=invoke(root);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'input-unreadable');assert.doesNotMatch(r.stdout,/PRIVATE_SENTINEL/);}
  finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});
test('duplicate decoded JSON keys reject ambiguous policy and inventory',()=>fixture(root=>{
  writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory).replace('"complete":true','"complete":false,"comple\\u0074e":true'));
  const uncertain=invoke(root);assert.equal(uncertain.status,2);assert.equal(JSON.parse(uncertain.stdout).status,'incomplete');
  writeFileSync(join(root,'inventory.json'),JSON.stringify(inventory));
  writeFileSync(join(root,'policy.json'),JSON.stringify(policy).replace('"complete":true','"complete":false,"comple\\u0074e":true'));
  const invalid=invoke(root);assert.equal(invalid.status,2);assert.equal(invalid.stdout,'');
}));
test('invalid UTF-8 and malformed JSON are incomplete without leaking input',()=>fixture(root=>{
  const head=JSON.stringify(inventory).slice(0,-1)+',"extra":"';writeFileSync(join(root,'inventory.json'),Buffer.concat([Buffer.from(head),Buffer.from([0xff]),Buffer.from('"}')]));
  const utf=invoke(root);assert.equal(utf.status,2);assert.equal(JSON.parse(utf.stdout).findings[0].ruleId,'input-unreadable');
  writeFileSync(join(root,'inventory.json'),'PRIVATE_SENTINEL');const malformed=invoke(root);assert.equal(malformed.status,2);assert.equal(JSON.parse(malformed.stdout).findings[0].ruleId,'input-unreadable');assert.doesNotMatch(malformed.stdout+malformed.stderr,/PRIVATE_SENTINEL/);
}));
