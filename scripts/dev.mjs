import {spawn} from 'node:child_process';
const args=process.argv.slice(2),get=(key,fallback)=>{const i=args.indexOf(key);return i<0?fallback:args[i+1];};
if(process.env.AUTO_SCAN_WORKER!=='false')await new Promise(resolve=>{const reset=spawn(process.execPath,['--env-file-if-exists=.env.local','--import','tsx','scripts/restart-worker.ts'],{stdio:'inherit',env:process.env});reset.on('exit',resolve);});
const worker=process.env.AUTO_SCAN_WORKER==='false'?null:spawn(process.execPath,['--env-file-if-exists=.env.local','--import','tsx','src/worker.ts'],{stdio:'inherit',env:process.env});
const server=spawn(process.execPath,['node_modules/next/dist/bin/next','dev','--hostname',get('--host','0.0.0.0'),'--port',get('--port',process.env.PORT??'3000')],{stdio:'inherit',env:process.env});
let stopping=false;const stop=sig=>{if(stopping)return;stopping=true;worker?.kill(sig);server.kill(sig);};
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>stop(sig));
worker?.on('exit',code=>{if(code&&!stopping)console.error('Scan worker stopped. See its startup message; restart npm run dev.');});
server.on('exit',code=>{worker?.kill('SIGTERM');process.exitCode=code??1;});
