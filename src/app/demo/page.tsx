import Workspace from '@/components/workspace';
import {demoReport,demoRepositoryReport} from '@/lib/demo';
import type {Project,Scan} from '@/lib/types';
export default async function Demo(){
 const project:Project={id:'preview-project',owner_id:'preview',name:'أكاديمية المعرفة',url:'https://academy.example/',token:'not-a-real-verification-token',verified_until:0,created_at:1793970000000};
 const scan:Scan={id:'preview-scan',project_id:project.id,owner_id:'preview',status:'completed',stage:'تقرير توضيحي',created_at:1793970000000,updated_at:1793970000000,lease_until:0,error:null,is_demo:1,result:demoReport()};
 const repository={id:'preview-link',project_id:project.id,owner:'aegis-demo',name:'academy-fixture',branch:'demo',private:false,hasToken:false,updated_at:1793970000000};
 const repoScan:Scan={...scan,id:'preview-repository',kind:'repository',repository,stage:'تحليل مستودع توضيحي',result:await demoRepositoryReport()};
 return <Workspace preview initial={{user:{id:'preview',email:'developer@example.test'},projects:[project],scans:[scan,repoScan],repositories:[repository],workerOnline:false,ai:{provider:'Ollama',model:'qwen2.5:1.5b',vision:false,patch:false}}}/>;
}
