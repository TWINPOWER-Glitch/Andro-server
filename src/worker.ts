import 'dotenv/config';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, chmod, readdir, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { createClient } from '@supabase/supabase-js';
import type { BuildJob } from './store.js';

const serverUrl=(process.env.ANDRO_SERVER_URL||'http://localhost:8787').replace(/\/$/,'');
const token=process.env.ANDRO_WORKER_TOKEN;
const pollMs=Number(process.env.ANDRO_POLL_MS||2000);
const timeoutMs=Number(process.env.ANDRO_BUILD_TIMEOUT_MS||1200000);
const runnerImage=process.env.ANDRO_RUNNER_IMAGE||'andro-android-runner:latest';
const artifactBucket=process.env.ANDRO_ARTIFACT_BUCKET||'andro-artifacts';
const workRoot=process.env.ANDRO_WORK_ROOT||tmpdir();
const supabaseUrl=process.env.SUPABASE_URL;
const supabaseSecret=process.env.SUPABASE_SECRET_KEY||process.env.SUPABASE_SERVICE_ROLE_KEY;
const storage=supabaseUrl&&supabaseSecret?createClient(supabaseUrl,supabaseSecret,{auth:{persistSession:false,autoRefreshToken:false}}):undefined;
if(!token) throw new Error('ANDRO_WORKER_TOKEN is required');
const auth={authorization:`Bearer ${token}`,'content-type':'application/json'};
async function api(path:string,body?:unknown){
  const r=await fetch(`${serverUrl}${path}`,{method:'POST',headers:auth,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
  if(!r.ok) throw new Error(`Andro API ${path} returned HTTP ${r.status}`);
  return r.json() as Promise<any>;
}
async function log(id:string,line:string){ try { await api(`/internal/jobs/${id}/logs`,{line:line.slice(0,4000)}); } catch(e) { console.error('Failed to send log:',e); } }
function shellQuote(value:string){ return `'${value.replace(/'/g, `'\\''`)}'`; }
function dockerBuild(job:BuildJob, work:string):Promise<number>{
  return new Promise((resolve,reject)=>{
    const ref=job.ref;
    if(!/^[A-Za-z0-9._/-]+$/.test(ref)||ref.startsWith('-')||ref.includes('..')) return reject(new Error('Git ref contains unsupported characters'));
    const task=job.task;
    if(!/^[A-Za-z0-9:_-]+$/.test(task)) return reject(new Error('Gradle task contains unsupported characters'));
    const command=[
      'set -eu',
      `git clone --depth 1 --branch ${shellQuote(ref)} -- ${shellQuote(job.repoUrl)} /workspace/repo`,
      'cd /workspace/repo',
      'chmod +x ./gradlew',
      `./gradlew --no-daemon ${shellQuote(task)}`,
      'mkdir -p /workspace/out',
      `if [ -d app/build/outputs ]; then find app/build/outputs -type f \\( -name '*.apk' -o -name '*.aab' \\) -exec cp -f {} /workspace/out/ \\; ; fi`,
      `find . -path '*/build/outputs/*' -type f \\( -name '*.apk' -o -name '*.aab' \\) -exec cp -f {} /workspace/out/ \\; 2>/dev/null || true`,
    ].join(' && ');
    const cidfile=join(work,'container.id');
    const args=['run','--rm','--init','--cidfile',cidfile,'--network','bridge','--cpus',process.env.ANDRO_JOB_CPUS||'2','--memory',process.env.ANDRO_JOB_MEMORY||'6g','--pids-limit',process.env.ANDRO_JOB_PIDS||'512','--security-opt','no-new-privileges','--cap-drop','ALL','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=2g','--tmpfs','/home/andro:rw,nosuid,nodev,size=512m,uid=10001,gid=10001','--user','10001:10001','--workdir','/workspace','--mount',`type=bind,src=${work},dst=/workspace`,'--env','HOME=/home/andro','--env','GRADLE_USER_HOME=/home/andro/.gradle','--env','TMPDIR=/tmp',runnerImage,'bash','-lc',command];
    const child=spawn('docker',args,{stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH||'/usr/bin:/bin'}});
    let timedOut=false;
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGTERM');void readFile(cidfile,'utf8').then(cid=>new Promise<void>(resolve=>{const killer=spawn('docker',['kill',cid.trim()],{stdio:'ignore'});killer.on('close',()=>resolve());killer.on('error',()=>resolve());})).catch(()=>undefined);setTimeout(()=>child.kill('SIGKILL'),5000).unref();},timeoutMs);
    child.stdout.on('data',chunk=>{for(const line of String(chunk).split(/\r?\n/).filter(Boolean)) void log(job.id,line);});
    child.stderr.on('data',chunk=>{for(const line of String(chunk).split(/\r?\n/).filter(Boolean)) void log(job.id,line);});
    child.on('error',err=>{clearTimeout(timer);reject(err);});
    child.on('close',code=>{clearTimeout(timer);if(timedOut) reject(new Error(`Build exceeded timeout of ${timeoutMs}ms`));else resolve(code??1);});
  });
}
async function uploadArtifacts(job:BuildJob,work:string):Promise<string|undefined>{
  const out=join(work,'out');
  const files=await readdir(out).catch(()=>[]);
  const artifact=files.find(f=>/\.(apk|aab)$/i.test(f));
  if(!artifact) return undefined;
  if(!storage) throw new Error('Build succeeded but artifact storage is not configured (SUPABASE_URL and SUPABASE_SECRET_KEY are required).');
  const path=`${job.id}/${basename(artifact)}`;
  const bytes=await readFile(join(out,artifact));
  const info=await stat(join(out,artifact));
  if(info.size>Number(process.env.ANDRO_MAX_ARTIFACT_BYTES||536870912)) throw new Error('Artifact exceeds configured size limit.');
  const {error}=await storage.storage.from(artifactBucket).upload(path,bytes,{contentType:artifact.toLowerCase().endsWith('.aab')?'application/octet-stream':'application/vnd.android.package-archive',upsert:true});
  if(error) throw new Error(`Artifact upload failed: ${error.message}`);
  await log(job.id,`Uploaded artifact ${artifact} (${info.size} bytes) to private storage.`);
  return path;
}
async function execute(job:BuildJob){
  const work=await mkdtemp(join(workRoot,'andro-job-'));
  try {
    await chmod(work,0o777);
    await log(job.id,`Worker starting job ${job.id} in an ephemeral resource-limited Docker container.`);
    const code=await dockerBuild(job,work);
    if(code!==0) throw new Error(`Isolated Gradle container exited with code ${code}`);
    const artifactPath=await uploadArtifacts(job,work);
    await api(`/internal/jobs/${job.id}/status`,{status:'succeeded',...(artifactPath?{artifactPath}:{}),log:artifactPath?'Gradle completed and the APK/AAB was stored privately.':'Gradle task completed; no APK/AAB artifact was produced.'});
  } catch(e) {
    const message=e instanceof Error?e.message:'Unknown worker failure';
    await log(job.id,`Build failed: ${message}`);
    try { await api(`/internal/jobs/${job.id}/status`,{status:'failed',error:message.slice(0,2000),log:'Worker marked this build failed.'}); } catch(reportError) { console.error('Failed to report job failure',reportError); }
  } finally { await rm(work,{recursive:true,force:true}).catch(()=>undefined); }
}
const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
console.log(`Andro worker polling ${serverUrl}; isolated runner image ${runnerImage}`);
while(true){
  try { const result=await api('/internal/worker/claim'); if(result.job) await execute(result.job as BuildJob); else await sleep(pollMs); }
  catch(e){ console.error('Worker poll failed:',e); await sleep(Math.max(pollMs,5000)); }
}