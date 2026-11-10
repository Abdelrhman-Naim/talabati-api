import {spawn} from 'node:child_process';
const worker=spawn(process.execPath,['--env-file-if-exists=.env.local','--import','tsx','src/worker.ts'],{stdio:'inherit',env:process.env});
const server=spawn(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','0.0.0.0','--port',process.env.PORT??'3000'],{stdio:'inherit',env:process.env});
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{worker.kill(sig);server.kill(sig);});
server.on('exit',code=>{worker.kill('SIGTERM');process.exitCode=code??1;});
