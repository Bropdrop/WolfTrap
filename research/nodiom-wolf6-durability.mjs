#!/usr/bin/env node
/**
 * Wolf #6: genuine source-pinned Nodiom crash-consistency experiment.
 *
 * Only disposable files. The child process deliberately SIGKILLs itself after
 * an instrumented partial write; this is NOT a power-loss test.
 *
 * Usage: node nodiom-wolf6-durability.mjs CORE_ROOT EVIDENCE_FILE
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,readFile,writeFile,open,rename,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {basename,dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const sha=(s)=>createHash('sha256').update(s).digest('hex');
const script=fileURLToPath(import.meta.url);
const makeEIO=(stage)=>Object.assign(new Error('synthetic EIO at '+stage),{code:'EIO'});
const originalWriteFile=fs.promises.writeFile;

async function withInjectedFileWrite(target,override,action){
  const original=fs.promises.writeFile;
  fs.promises.writeFile=async (path,...args)=>{
    if(String(path)===target) return override(path,...args);
    return original.call(fs.promises,path,...args);
  };
  syncBuiltinESMExports();
  try{return await action();}
  finally{fs.promises.writeFile=original;syncBuiltinESMExports();}
}

async function crashChild(){
  assert.equal(process.argv.length,5);
  const core=resolve(process.argv[3]),target=resolve(process.argv[4]);
  const {Nodiom}=await import(pathToFileURL(join(core,'dist','index.js')).href);
  const doc=await Nodiom.fromFile(target,{lock:true,lockTimeout:3000});
  doc.append('## Tasks','- [ ] POST-CRASH-SYNTHETIC');
  await withInjectedFileWrite(target,async(path,value)=>{
    const handle=await open(path,'w');
    try{
      const buffer=Buffer.from(String(value),'utf8');
      await handle.write(buffer.subarray(0,Math.min(48,buffer.length)));
    }finally{await handle.close();}
    process.kill(process.pid,'SIGKILL');
    await new Promise(()=>{});
  },()=>doc.save());
  process.exitCode=13; // unreachable unless injection did not kill the process
}

if(process.argv[2]==='--crash-child'){
  await crashChild();
}else{
  assert.equal(process.argv.length,4,'Usage: node nodiom-wolf6-durability.mjs CORE_ROOT EVIDENCE_FILE');
  const core=resolve(process.argv[2]),out=resolve(process.argv[3]);
  const {Nodiom}=await import(pathToFileURL(join(core,'dist','index.js')).href);
  const temp=await mkdtemp(join(tmpdir(),'wolf6-nodiom-fixtures-'));
  const base='# Wolf6 Synthetic\n\n## Tasks\n\n- [ ] baseline retained\n';
  const results=[];
  const test=async(id,fn)=>{
    try {results.push({id,status:'EXECUTED',...await fn()});}
    catch(e){results.push({id,status:'INCONCLUSIVE',error:String(e)});}
  };
  const fresh=async(name)=>{const p=join(temp,name);await writeFile(p,base);return p;};

  // Reference implementation only: does not alter Nodiom, and does not
  // establish the effect of sudden host power loss on any real filesystem.
  async function referenceAtomicReplace(target,text,failpoint){
    const temporary=join(dirname(target),'.'+basename(target)+'.wolf6-tmp');
    const file=await open(temporary,'wx',0o600);
    try {await file.writeFile(text);await file.sync();}
    finally {await file.close();}
    try{
      if(failpoint==='before-rename')throw makeEIO(failpoint);
      await rename(temporary,target);
      if(failpoint==='after-rename')throw makeEIO(failpoint);
      const directory=await open(dirname(target),'r');
      try{await directory.sync();}finally{await directory.close();}
    } finally {await rm(temporary,{force:true});}
  }

  try {
    await test('DUR-01-TRUNCATE-THEN-EIO',async()=>{
      const target=await fresh('truncate.md'),before=await readFile(target,'utf8');
      const doc=await Nodiom.fromFile(target);
      doc.append('## Tasks','- [ ] NOT-COMMITTED');
      let failure=null;
      await withInjectedFileWrite(target,async(path)=>{
        const handle=await open(path,'w');
        await handle.close();
        throw makeEIO('after-truncate');
      },async()=>{try{await doc.save();}catch(e){failure=e.code||String(e);}});
      const after=await readFile(target,'utf8');
      assert.equal(failure,'EIO');
      assert.equal(after.length,0);
      return {injectedEio:true,oldBytesLost:before.length>0&&after.length===0,
        previousSha256:sha(before),resultSha256:sha(after),
        scope:'injected native file writer; actual Nodiom save path'};
    });

    await test('DUR-02-PARTIAL-WRITE-THEN-EIO',async()=>{
      const target=await fresh('partial.md');
      const before=await readFile(target,'utf8'),doc=await Nodiom.fromFile(target);
      doc.append('## Tasks','- [ ] NOT-COMMITTED');
      let failure=null;
      await withInjectedFileWrite(target,async(path,value)=>{
        const handle=await open(path,'w');
        try{await handle.write(Buffer.from(String(value)).subarray(0,23));}
        finally{await handle.close();}
        throw makeEIO('partial-write');
      },async()=>{try{await doc.save();}catch(e){failure=e.code||String(e);}});
      const after=await readFile(target,'utf8');
      assert.equal(failure,'EIO');assert.equal(after,doc.toString().slice(0,23));
      return {injectedEio:true,oldBytesLost:after!==before,partialLength:after.length,
        previousSha256:sha(before),partialSha256:sha(after)};
    });

    await test('DUR-03-SIGKILL-AFTER-PARTIAL-WRITE',async()=>{
      const target=await fresh('kill.md'),before=await readFile(target,'utf8');
      const result=spawnSync(process.execPath,[script,'--crash-child',core,target],
        {timeout:20000,stdio:'ignore',env:{...process.env,HOME:temp}});
      const after=await readFile(target,'utf8');
      const lockDir=target+'.lock';
      let lockRemained=false;
      try{lockRemained=(await stat(lockDir)).isDirectory();}
      catch(e){if(e.code!=='ENOENT')throw e;}
      await rm(lockDir,{force:true,recursive:true});
      assert.equal(result.signal,'SIGKILL','Expected child SIGKILL, got '+result.signal+'/'+result.status);
      assert(after!==before&&after.length<=48,'Expected truncated synthetic document');
      return {observedSignal:result.signal,oldBytesLost:true,partialLength:after.length,
        abandonedLockDirectory:lockRemained,
        caveat:'instrumented native writeFile and process SIGKILL, not sudden host power loss'};
    });

    await test('DUR-04-ATOMIC-REFERENCE-BEFORE-RENAME-FAULT',async()=>{
      const target=await fresh('atomic-before.md'),before=await readFile(target,'utf8');
      let error=null;
      try{await referenceAtomicReplace(target,base+'- [ ] NEW\n','before-rename');}
      catch(e){error=e.code;}
      const after=await readFile(target,'utf8');
      assert.equal(error,'EIO');assert.equal(after,before);
      return {oldDocumentIntact:true,expectedFailure:error,
        finalSha256:sha(after),implementation:'independent illustrative reference'};
    });

    await test('DUR-05-ATOMIC-REFERENCE-AFTER-RENAME-FAULT',async()=>{
      const target=await fresh('atomic-after.md');
      const update=base+'- [ ] REPLACED\n';
      let error=null;
      try{await referenceAtomicReplace(target,update,'after-rename');}
      catch(e){error=e.code;}
      const after=await readFile(target,'utf8');
      assert.equal(error,'EIO');assert.equal(after,update);
      return {newDocumentVisible:true,dirSyncNotReached:true,expectedFailure:error,
        finalSha256:sha(after),caveat:'not a simulated kernel reboot or disk power loss'};
    });

    await test('DUR-06-ATOMIC-REFERENCE-FULL-SUCCESS',async()=>{
      const target=await fresh('atomic-success.md');
      const update=base+'- [ ] REPLACED\n';
      await referenceAtomicReplace(target,update,null);
      const after=await readFile(target,'utf8');
      assert.equal(after,update);
      return {replacementVisible:true,fileSyncAndDirSyncReturned:true,finalSha256:sha(after),
        caveat:'reference model, not integrated into Nodiom'};
    });

    await test('DUR-07-CORE-SAVE-SOURCE-REVIEW',async()=>{
      const source=await readFile(join(core,'src','index.ts'),'utf8');
      const start=source.indexOf('async save(): Promise<void>');
      const end=source.indexOf('async saveAs(',start);
      assert(start>=0&&end>start);
      const block=source.slice(start,end);
      const directWriteFile=block.includes('await writeFile(this.filePath, this.source');
      const explicitSync=/\.(?:sync|datasync)\s*\(|\bfsync\s*\(/.test(block);
      const explicitVersionCheck=/etag|version|hash|compareAndSwap|expectedRevision|oldDigest/.test(block);
      assert.equal(directWriteFile,true);
      return {directInPlaceWrite:true,explicitSyncInSave:explicitSync,
        explicitVersionCheckInSave:explicitVersionCheck,sourceBlockSha256:sha(block),
        caveat:'source-level review; no kernel or storage durability claim'};
    });

    await test('DUR-08-RELOAD-AFTER-ABORT',async()=>{
      const target=await fresh('recovery.md');
      const doc=await Nodiom.fromFile(target);
      doc.append('## Tasks','- [ ] UNCOMMITTED');
      let failure=null;
      await withInjectedFileWrite(target,async(path,value)=>{
        const handle=await open(path,'w');
        try{await handle.write(Buffer.from(String(value)).subarray(0,12));}
        finally{await handle.close();}
        throw makeEIO('reload-fail');
      },async()=>{try{await doc.save();}catch(e){failure=e.code;}});
      let reloadSucceeded=false,raw='';
      try{const reloaded=await Nodiom.fromFile(target);raw=reloaded.toString();reloadSucceeded=true;}
      catch(e){raw=String(e);}
      assert.equal(failure,'EIO');
      return {reloadSucceeded,observedContentBytes:reloadSucceeded?raw.length:null,
        partialDocumentRecognized:reloadSucceeded&&raw.length===12,
        caveat:'parser acceptance does not prove semantic recovery'};
    });

    const inconclusive=results.filter(x=>x.status!=='EXECUTED');
    const report={schema:'wolftrap.nodiom.wolf6.durability/v1',
      scope:'GENUINE PINNED NODIOM CORE, CONTROLLED I/O FAULTS AND SIGKILL ON DISPOSABLE FILES',
      evidenceType:'CONTROLLED_FAULT_INJECTION_NOT_REAL_POWER_LOSS',
      counts:{attempted:results.length,executed:results.length-inconclusive.length,inconclusive:inconclusive.length},
      results,verdict:inconclusive.length?'INCONCLUSIVE':'BOUNDED_LOCAL_FAULTS_EXECUTED'};
    await mkdir(dirname(out),{recursive:true});
    await writeFile(out,JSON.stringify(report,null,2)+'\n');
    console.log('Wolf6 durability: '+report.verdict+' '+report.counts.executed+'/'+report.counts.attempted);
    if(inconclusive.length)process.exitCode=2;
  }finally{await rm(temp,{recursive:true,force:true});}
}
