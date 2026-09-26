#!/usr/bin/env node
import {readFile,realpath,stat} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {auditNames,incomplete,LIMITS} from '../src/index.mjs';

function duplicateKeys(text){
  const stack=[];
  for(const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]/gs)){
    const token=match[0],top=stack.at(-1);
    if(token==='{'){stack.push({kind:'object',key:true,seen:new Set()});continue;}
    if(token==='['){stack.push({kind:'array'});continue;}
    if(token==='}'||token===']'){stack.pop();continue;}
    if(token===','){if(top?.kind==='object')top.key=true;continue;}
    if(token===':')continue;
    if(top?.kind==='object'&&top.key){const key=JSON.parse(token);if(top.seen.has(key))return true;top.seen.add(key);top.key=false;}
  }
  return false;
}

const args=process.argv.slice(2);
if(args.length===1&&args[0]==='--help'){
  process.stdout.write('Usage: cloud-resource-naming-auditor --root DIR --policy FILE --inventory FILE [--human]\nChecks an exported inventory against two documented AWS naming profiles.\n');
}else{
  let root,policyName,inventoryName,human=false;
  try{
    for(let i=0;i<args.length;i++){
      const key=args[i];
      if(key==='--human'){if(human)throw Error('duplicate');human=true;continue;}
      if(!['--root','--policy','--inventory'].includes(key)||i+1>=args.length||args[i+1].startsWith('--'))throw Error('option');
      const value=args[++i];
      if(key==='--root'){if(root)throw Error('duplicate');root=value;}
      if(key==='--policy'){if(policyName)throw Error('duplicate');policyName=value;}
      if(key==='--inventory'){if(inventoryName)throw Error('duplicate');inventoryName=value;}
    }
    if(!root||!policyName||!inventoryName||isAbsolute(policyName)||isAbsolute(inventoryName))throw Error('required');
    root=await realpath(root);
    if(!(await stat(root)).isDirectory())throw Error('root');
  }catch{process.stderr.write('Invalid configuration. Use --help.\n');process.exit(2);}
  const inside=path=>{const rel=relative(root,path);return rel!==''&&rel!=='..'&&!rel.startsWith(`..${sep}`)&&!isAbsolute(rel);};
  async function document(name,file,limit){
    try{
      const path=await realpath(resolve(root,name));
      if(!inside(path)||!(await stat(path)).isFile())throw Error('unreadable');
      const metadata=await stat(path);
      if(metadata.size>limit)return {error:incomplete('byte-limit',file)};
      const bytes=await readFile(path,{signal:AbortSignal.timeout(LIMITS.milliseconds)});
      if(bytes.length>limit)return {error:incomplete('byte-limit',file)};
      const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);
      if(duplicateKeys(text))return file==='@policy'?{invalidConfig:true}:{error:incomplete('input-invalid',file)};
      return {value};
    }catch{return {error:incomplete('input-unreadable',file)};}
  }
  const p=await document(policyName,'@policy',LIMITS.policyBytes);
  if(p.invalidConfig){process.stderr.write('Invalid policy configuration.\n');process.exit(2);}
  const i=await document(inventoryName,'@inventory',LIMITS.inventoryBytes);
  const result=p.error||i.error||auditNames(p.value,i.value);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if(human)process.stderr.write(`Resource names: ${result.status}; ${result.summary.checked} resources checked.\n`);
  process.exitCode=result.status==='pass'?0:result.status==='fail'?1:2;
}
