#!/usr/bin/env node
/**
 * WolfTrap Wolf #5 — source-pinned Nodiom core hostile-state experiments.
 * All paths and data are synthetic, created exclusively in a disposable /tmp.
 * This script never contacts a network service and never modifies vendor sources.
 */
import assert from 'node:assert/strict';
import {chmod, mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, unlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

assert.equal(process.argv.length,4,'usage: node nodiom-wolf5-core.mjs CORE_ROOT OUTPUT_JSON');
const core=resolve(process.argv[2]),output=resolve(process.argv[3]);
const {Nodiom,AmbiguousSelectorError}=await import(pathToFileURL(join(core,'dist','index.js')).href);
const root=await mkdtemp(join(tmpdir(),'wolf5-core-boundaries-'));
const sha=s=>createHash('sha256').update(s).digest('hex');
const seed='# Wolf5 Fictional\n\n## Tasks\n\n- [ ] seed\n';
const results=[];
const check=async(id,func)=>{
 try{results.push({id,status:'EXECUTED',...await func()});}
 catch(e){results.push({id,status:'INCONCLUSIVE',error:String(e)});}
};
const file=async(p,content=seed)=>{const target=join(root,p);await writeFile(target,content);return target;};
try{
  await check('CORE-01-MIXED-LOCK-PARTICIPATION',async()=>{
    const target=await file('mixed.md');
    const first=await Nodiom.fromFile(target,{lock:true,lockTimeout:3000});
    try {
      const second=await Nodiom.fromFile(target);
      first.append('## Tasks','- [ ] LOCKED-ONLY-Q91');
      await first.save();
      second.append('## Tasks','- [ ] UNLOCKED-ONLY-Q92');
      await second.save();
    }finally{await first.unlock();}
    const text=await readFile(target,'utf8');
    return {lockedMarkerRetained:text.includes('LOCKED-ONLY-Q91'),
      unlockedMarkerRetained:text.includes('UNLOCKED-ONLY-Q92'),
      advisoryLockCannotFenceUnlockedWriter:!text.includes('LOCKED-ONLY-Q91')&&text.includes('UNLOCKED-ONLY-Q92'),
      documentSha256:sha(text)};
  });

  await check('CORE-02-SYMLINK-REBOUND-WITH-LOCK',async()=>{
    const a=await file('symlink-A.md'),b=await file('symlink-B.md');
    const alias=join(root,'editable-link.md');
    await symlink(a,alias);
    const originalA=await readFile(a,'utf8'),originalB=await readFile(b,'utf8');
    const doc=await Nodiom.fromFile(alias,{lock:true,lockTimeout:3000});
    try{
      await unlink(alias);
      await symlink(b,alias);
      doc.append('## Tasks','- [ ] SYMLINK-REBOUND-MARKER');
      await doc.save();
    }finally{await doc.unlock();}
    const afterA=await readFile(a,'utf8'),afterB=await readFile(b,'utf8');
    return {firstTargetUnchanged:afterA===originalA,
      secondTargetChanged:afterB!==originalB,
      secondTargetContainsStaleWrite:afterB.includes('SYMLINK-REBOUND-MARKER'),
      fileIdentityWasRebound:afterA===originalA&&afterB.includes('SYMLINK-REBOUND-MARKER'),
      firstSha256:sha(afterA),secondSha256:sha(afterB)};
  });

  await check('CORE-03-LOCK-ON-READ-FAILURE',async()=>{
    const directory=join(root,'not-a-markdown-file');
    await mkdir(directory);
    let observedError='NO_ERROR';
    try{const doc=await Nodiom.fromFile(directory,{lock:true,lockTimeout:300});await doc.unlock();}
    catch(e){observedError=String(e).slice(0,170);}
    const lockDir=directory+'.lock';
    let lockRemains=false;
    try{lockRemains=(await stat(lockDir)).isDirectory();}catch(e){if(e?.code!=='ENOENT')throw e;}
    // Clean up only the synthetic lock directory; core did not give back a handle.
    await rm(lockDir,{recursive:true,force:true});
    return {readFailed:observedError!=='NO_ERROR',lockDirectoryLeftBehind:lockRemains,
      errorClass:observedError.split(':')[0]};
  });

  await check('CORE-04-LOCK-ON-SAVE-FAILURE',async()=>{
    const path=await file('save-fails.md');
    const doc=await Nodiom.fromFile(path,{lock:true,lockTimeout:3000});
    let failed=false,lockRemains=false;
    try{
      doc.append('## Tasks','- [ ] WILL-NOT-PERSIST');
      await chmod(path,0o400);
      try{await doc.save();}catch(e){failed=e?.code==='EACCES'||e?.code==='EPERM';}
      try{lockRemains=(await stat(path+'.lock')).isDirectory();}
      catch(e){if(e?.code!=='ENOENT')throw e;}
    }finally{
      await chmod(path,0o600);
      await doc.unlock();
    }
    return {permissionFailureObserved:failed,lockRemainedUntilExplicitUnlock:lockRemains,
      fileAfterFailureSha256:sha(await readFile(path,'utf8'))};
  });

  await check('CORE-05-POSITIONAL-SELECTOR-RETARGET',async()=>{
    const doc=Nodiom.fromString('# Fixture\n\n## Tasks\n\n- [ ] original task\n- [ ] other task\n');
    const originallyRead=doc.read('## Tasks > li[0]');
    doc.delete('## Tasks > li[0]'); // another actor's authorized edit
    doc.write('## Tasks > li[0]','- [x] stale-agent-update');
    const after=doc.toString();
    return {originallyRead,originalItemWasRemoved:!after.includes('original task'),
      staleIndexNowModifiedOtherTask:!after.includes('other task')&&after.includes('stale-agent-update'),
      documentSha256:sha(after)};
  });

  await check('CORE-06-CONTENT-SELECTOR-ID-TRANSFER',async()=>{
    const doc=Nodiom.fromString(
      '# Fixture\n\n## Tasks\n\n- [ ] Alice <!-- nodiom: id=c_aa -->\n- [ ] Bob <!-- nodiom: id=c_bb -->\n');
    const selector='## Tasks > li[contains="id=c_aa"]';
    const before=doc.read(selector);
    // Both writes are authorized at this layer; demonstrate ID has no external owner.
    doc.write('## Tasks > li[0]','- [ ] Alice <!-- nodiom: id=retired -->');
    doc.write('## Tasks > li[1]','- [ ] Bob <!-- nodiom: id=c_aa -->');
    doc.write(selector,'- [x] changed-via-old-id');
    const after=doc.toString();
    return {before,oldContentSelectorChangedSubject:
      after.includes('Alice <!-- nodiom: id=retired -->')&&after.includes('changed-via-old-id')&&!after.includes('Bob'),
      documentSha256:sha(after)};
  });

  await check('CORE-07-AMBIGUOUS-CONTENT-DENIED',async()=>{
    const doc=Nodiom.fromString('# Fixture\n\n## Tasks\n\n- [ ] same token\n- [ ] same token\n');
    let caught=false;
    try{doc.write('## Tasks > li[contains="same token"]','- [x] replaced');}
    catch(e){caught=e instanceof AmbiguousSelectorError;}
    return {ambiguousSelectorDenied:caught,documentUnaffected:
      doc.toString().split('same token').length-1===2};
  });

  await check('CORE-08-YAML-FRONTMATTER-PRESERVED',async()=>{
    const fm='---\nclass: fiction\nprivate: false\n---\n';
    const doc=Nodiom.fromString(fm+'\n# Fixture\n\n## Tasks\n\n- [ ] seed\n');
    doc.append('## Tasks','- [ ] added');
    return {frontmatterByteIdentical:doc.toString().startsWith(fm),newTaskPresent:doc.toString().includes('- [ ] added')};
  });

  await check('CORE-09-HEADING-CONTENT-STRUCTURE-CROSSING',async()=>{
    const doc=Nodiom.fromString('# Fictional\n\n## Tasks\n\n- [ ] work\n\n## Review\n\n- [ ] pending\n');
    const prior=doc.tree().map(x=>JSON.stringify(x)).join('');
    doc.append('## Tasks','## Spoofed Review\n\n- [x] REVIEW COMPLETE');
    const after=doc.toString();
    return {newHeadingNowInOutline:JSON.stringify(doc.tree()).includes('Spoofed Review'),
      insertedCompletionText:after.includes('REVIEW COMPLETE'),priorOutlineSha256:sha(prior),
      documentSha256:sha(after)};
  });

  await check('CORE-10-EMPTY-AND-DUPLICATE-HEADING',async()=>{
    const doc=Nodiom.fromString('# Fictional\n\n## Todo\n\n## Todo\n\n- [ ] action\n');
    let ambiguity=false;
    try{doc.read('## Todo');}catch(e){ambiguity=e instanceof AmbiguousSelectorError;}
    const addressable=doc.read('## Todo[1]').includes('action');
    return {ambiguousHeadingDenied:ambiguity,indexedHeadingWorks:addressable};
  });

  await check('CORE-11-NO-AUTOMATIC-VERSION-CAS',async()=>{
    const target=await file('cas.md');
    const first=await Nodiom.fromFile(target);
    const second=await Nodiom.fromFile(target);
    first.append('## Tasks','- [ ] first');
    await first.save();
    second.append('## Tasks','- [ ] second');
    await second.save();
    const after=await readFile(target,'utf8');
    return {bothSaveCallsFulfilled:true,firstMarkerRetained:after.includes('first'),
      secondMarkerRetained:after.includes('second'),
      sha256:sha(after)};
  });

  const inconclusive=results.filter(x=>x.status!=='EXECUTED');
  const required=['CORE-07-AMBIGUOUS-CONTENT-DENIED','CORE-08-YAML-FRONTMATTER-PRESERVED','CORE-10-EMPTY-AND-DUPLICATE-HEADING'];
  const missingPositive=results.filter(x=>required.includes(x.id)).filter(x=>!(
    (x.ambiguousSelectorDenied&&x.documentUnaffected)||(x.frontmatterByteIdentical&&x.newTaskPresent)||(x.ambiguousHeadingDenied&&x.indexedHeadingWorks)
  ));
  const result={schema:'wolftrap.nodiom.wolf5.core/v1',
    scope:'GENUINE PINNED CORE; DISPOSABLE FILES; NO NETWORK; NO EXTERNAL TARGET',
    status:inconclusive.length||missingPositive.length?'INCONCLUSIVE':'EXECUTED',
    counters:{attempted:results.length,executed:results.length-inconclusive.length,
      inconclusive:inconclusive.length,positiveControlFailures:missingPositive.length},
    results};
  await writeFile(output,JSON.stringify(result,null,2)+'\n');
  console.log('Wolf5 core executed '+result.counters.executed+'/'+result.counters.attempted+'; inconclusive='+inconclusive.length);
  if(result.status!=='EXECUTED')process.exitCode=2;
}finally{
  await rm(root,{recursive:true,force:true});
}
