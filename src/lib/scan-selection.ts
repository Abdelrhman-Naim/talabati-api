import type {Scan} from './types';
export function selectedScan(scans:Scan[],project:string,id:string,activity=false){
 const pool=activity||project==='all'?scans:scans.filter(s=>s.project_id===project);
 return pool.find(s=>s.id===id)??pool[0];
}
