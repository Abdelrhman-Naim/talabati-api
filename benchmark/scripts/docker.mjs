import {spawnSync,execFileSync} from 'node:child_process';import {resolve} from 'node:path';import {mkdirSync,writeFileSync,existsSync} from 'node:fs';
const root=resolve(import.meta.dirname,'../..');
if(process.env.NODE_ENV==='production'){console.error('Benchmark Docker refuses production');process.exit(1);}
const docker=spawnSync('docker',['version','--format','{{.Server.Version}}'],{encoding:'utf8',timeout:5000});
if(docker.error||docker.status!==0){console.error('NOT RUN: Docker binary/server unavailable. No containers started or benchmark results invented.');process.exit(2);}
const run=(cmd,args)=>{const r=spawnSync(cmd,args,{cwd:root,stdio:'inherit'});if(r.error||r.status!==0)throw new Error(cmd+' failed');};
const compose=['compose','-f','docker-compose.benchmark.yml'];
try{
 if(process.argv.includes('--down')){run('docker',[...compose,'down','-v']);process.exit(0);}
 // Reviewed official release v1.4. The published release commit prefix is pinned in docker-pins.json.
 const pins=JSON.parse(await (await import('node:fs/promises')).readFile(resolve(root,'benchmark/docker-pins.json'),'utf8'));
 const dir=resolve(root,'benchmark/external/NodeGoat');mkdirSync(resolve(root,'benchmark/external'),{recursive:true});
 if(!existsSync(dir))run('git',['clone','--no-checkout','https://github.com/OWASP/NodeGoat.git',dir]);
 if(execFileSync('git',['-C',dir,'status','--porcelain'],{encoding:'utf8'}).trim())throw new Error('NodeGoat checkout has local changes; refusing to overwrite');
 run('git',['-C',dir,'checkout','--detach',pins.nodegoat.tag]);
 const revision=execFileSync('git',['-C',dir,'rev-parse','HEAD'],{encoding:'utf8'}).trim();if(!revision.startsWith(pins.nodegoat.commit))throw new Error('NodeGoat source pin mismatch');
 run('docker',[...compose,'build','nodegoat']);run('docker',[...compose,'up','-d']);
 mkdirSync(resolve(root,'benchmark/runs'),{recursive:true});
 const metadata=execFileSync('docker',[...compose,'images','--format','json'],{encoding:'utf8'});writeFileSync(resolve(root,'benchmark/runs/docker-images.json'),JSON.stringify({nodegoatCommit:revision,images:metadata},null,2));
 console.log('Started isolated local targets. Initialize DVWA at http://127.0.0.1:3003/setup.php if needed.');
 console.log('Run BENCHMARK_MODE=1 NODE_ENV=test npm run benchmark -- --target all --osv-offline; use --final only for final measurement.');
}catch(error){console.error(error.message);process.exitCode=1;}
