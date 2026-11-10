// Detection never contacts providers or tests credentials. Public identifiers are excluded.
export function secretCount(body:string){
 const matches=new Set(body.match(/\b(?:sb_secret_[\w-]{10,}|sk_live_[\w-]{10,}|gh[pousr]_[\w]{20,}|github_pat_[\w]{30,}|xox[baprs]-[\w-]{20,}|sk-proj-[\w-]{20,})\b/g)??[]);
 for(const key of body.match(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g)??[])matches.add(key);
 for(const uri of body.match(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/:"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/g)??[])matches.add(uri);
 for(const jwt of body.match(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g)??[]){try{if(JSON.parse(Buffer.from(jwt.split('.')[1],'base64url').toString()).role==='service_role')matches.add(jwt);}catch{}}
 return matches.size;
}
