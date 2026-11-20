#!/usr/bin/env node
/**
 * Wolf #6: deterministic source-pinned Nodiom metamorphic document corpus.
 * No external documents, no network, no mutation of upstream source.
 * Signals are observations; an invariant mismatch does not itself prove
 * an unauthorized effect or a vulnerability.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFile,mkdir} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

assert.equal(process.argv.length,4,'Usage: node nodiom-wolf6-fuzz.mjs CORE_ROOT OUTPUT_JSON');
const core=resolve(process.argv[2]),out=resolve(process.argv[3]);
const {Nodiom}=await import(pathToFileURL(join(core,'dist','index.js')).href);
const sha=x=>createHash('sha256').update(x).digest('hex');
let prng=0xA91B27C3;
const random=()=>{prng=(Math.imul(prng,1664525)+1013904223)>>>0;return prng;};
const choose=a=>a[random()%a.length];
const fence=String.fromCharCode(96).repeat(3);
const BODY=[
  'Plain paragraph\n',
  'Plain paragraph\n\n',
  '- [ ] pending\n',
  '- [x] complete\n- [ ] pending\n',
  'First line with  trailing spaces  \n',
  'A [link](https://example.invalid/path) and inline-code.\n',
  fence+'md\n## Fake Heading\n- [x] UNTRUSTED\n'+fence+'\n',
  '| Key | Value |\n| --- | --- |\n| a | b |\n',
  '> Blockquote paragraph\n',
  '<!-- synthetic: id=q17 -->\n\n- [ ] task\n',
  'Emoji 🐺 and combining cafe\u0301\n',
  '- [ ] a\n  - [ ] nested\n',
  'one\n\ntwo\n',
  '\n',
  ''
];
const SNIPPET='SIBLING-FIXTURE-UNIQUE';
const SIBLING='## Other\n\n- [ ] '+SNIPPET+'\n';
const total=512;
const stats={cases:total,completed:0,errors:0,
  parserRoundTrips:0,noOpReadWriteByteIdentical:0,noOpMismatch:0,
  siblingPreservedOnNoOp:0,siblingPreservedOnWrite:0,
  siblingPreservedOnAppend:0,siblingPreservedOnDelete:0,
  frontmatterPreserved:0,frontmatterCases:0};
const samples=[],errors=[];
for(let i=0;i<total;i++){
  const body=choose(BODY);
  const withFrontmatter=(random()&3)===0;
  const crlf=(random()&3)===0;
  const trailing=choose(['','\n','\n\n']);
  const fm=withFrontmatter?'---\nsynthetic: true\nid: test-'+i+'\n---\n\n':'';
  let input=fm+'# Wolf6 Synthetic\n\n## Target\n\n'+body+'\n'+SIBLING+trailing;
  if(crlf)input=input.replace(/\n/g,'\r\n');
  const siblingPos=input.indexOf('## Other');
  const originalSuffix=input.slice(siblingPos);
  const originalFrontmatter=withFrontmatter?input.slice(0,input.indexOf('# Wolf6 Synthetic')):'';
  try{
    const doc=Nodiom.fromString(input);
    if(doc.toString()===input)stats.parserRoundTrips++;
    const read=doc.read('## Target');
    doc.write('## Target',read);
    const after=doc.toString();
    if(after===input)stats.noOpReadWriteByteIdentical++;
    else{
      stats.noOpMismatch++;
      if(samples.length<8)samples.push({case:i,bodyIndex:BODY.indexOf(body),crlf,frontmatter:withFrontmatter,
        beforeSha256:sha(input),afterSha256:sha(after),originalLength:input.length,resultLength:after.length});
    }
    if(after.slice(after.indexOf('## Other'))===originalSuffix)stats.siblingPreservedOnNoOp++;
    const writer=Nodiom.fromString(input);
    writer.write('## Target','REPLACED WOLF6 CONTENT');
    if(writer.toString().slice(writer.toString().indexOf('## Other'))===originalSuffix)
      stats.siblingPreservedOnWrite++;
    const append=Nodiom.fromString(input);
    append.append('## Target','- [ ] WOLF6 ADDED');
    if(append.toString().slice(append.toString().indexOf('## Other'))===originalSuffix)
      stats.siblingPreservedOnAppend++;
    const deletion=Nodiom.fromString(input);
    deletion.delete('## Target');
    if(deletion.toString().slice(deletion.toString().indexOf('## Other'))===originalSuffix)
      stats.siblingPreservedOnDelete++;
    if(withFrontmatter){
      stats.frontmatterCases++;
      if(after.startsWith(originalFrontmatter))stats.frontmatterPreserved++;
    }
    stats.completed++;
  }catch(e){
    stats.errors++;
    if(errors.length<8)errors.push({case:i,name:e.name,message:String(e.message).slice(0,180)});
  }
}
assert.equal(stats.parserRoundTrips,stats.completed,
  'Parser/fromString roundtrip positive control failed');
const report={schema:'wolftrap.nodiom.wolf6.metamorphic/v1',
  scope:'GENUINE PINNED CORE; 512 SYNTHETIC MARKDOWN DOCUMENTS; NO EXTERNAL INPUT',
  deterministicSeed:'0xA91B27C3',result:stats,sampleMismatches:samples,
  sampleErrors:errors,
  claimBoundary:'No-op differences may be formatting/fidelity defects, not security vulnerabilities. Fuzz corpus exercises only its enumerated grammar, not general soundness.',
  verdict:stats.errors===0?'COMPLETE':'COMPLETE_WITH_CASE_ERRORS'};
await mkdir(dirname(out),{recursive:true});
await writeFile(out,JSON.stringify(report,null,2)+'\n');
console.log('Wolf6 fuzz: '+JSON.stringify(stats));
