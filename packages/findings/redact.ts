import {redact as legacyRedact} from '../../src/lib/redaction';
export function redactSecret(secret:string){return secret.length>8?secret.slice(0,4)+'********'+secret.slice(-4):'[REDACTED]';}
/** Mask known token values before generic key/value redaction. Redact intervening text
 * separately so a second pass cannot erase a safe first4/last4 fingerprint. This is
 * presentation redaction only; it does not add or change any secret detection rule. */
export function redactText(text:string,secrets:readonly string[]=[]){
 // Container credentials must be removed atomically; token-shaped text inside a PEM
 // or database URI must not split it and expose the remaining key/password material.
 text=text.replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,'[REDACTED_PRIVATE_KEY]')
  .replace(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/:"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/g,'[REDACTED_DATABASE_URI]');
 const spans:{start:number;end:number;masked:boolean;replacement?:string}[]=[];
 const recognized=/\b(?:github_pat_[\w]+|xox[baprs]-[\w-]+|sk-proj-[\w-]+|sb_secret_[\w-]+|sk_(?:live|test)_[\w-]+|gh[pousr]_[\w]+|AKIA[A-Z0-9]{16}|eyJ[\w-]+\.[\w-]+\.[\w-]+)\b/g;
 for(const m of text.matchAll(recognized))spans.push({start:m.index!,end:m.index!+m[0].length,masked:false});
 for(const m of text.matchAll(/\b[A-Za-z0-9_-]{4}\*{8}[A-Za-z0-9_-]{4}\b/g))spans.push({start:m.index!,end:m.index!+m[0].length,masked:true});
 for(const secret of new Set(secrets)){if(!secret)continue;let start=0;while((start=text.indexOf(secret,start))!==-1){spans.push({start,end:start+secret.length,masked:false});start+=secret.length;}}
 // A token-shaped substring is not necessarily the whole password/header value.
 // Protect the complete generic credential first, including suffixes such as $...
 // or apparent pre-masked substrings. Unknown opaque values retain full redaction.
 const credential=/((?:api[_-]?key|password|secret|authorization|cookie)["']?\s*[:=]\s*["']?)([^\s"'<>;,]+)/gi;
 const fullToken=/^(?:github_pat_[\w]+|xox[baprs]-[\w-]+|sk-proj-[\w-]+|sb_secret_[\w-]+|sk_(?:live|test)_[\w-]+|gh[pousr]_[\w]+|AKIA[A-Z0-9]{16}|eyJ[\w-]+\.[\w-]+\.[\w-]+)$/;
 const fullMask=/^[A-Za-z0-9_-]{4}\*{8}[A-Za-z0-9_-]{4}$/;
 function addCredential(start:number,value:string){const known=fullToken.test(value)||secrets.includes(value),masked=fullMask.test(value);spans.push({start,end:start+value.length,masked,replacement:masked?value:known?redactSecret(value):'[REDACTED]'});}
 for(const m of text.matchAll(credential))addCredential(m.index!+m[1].length,m[2]);
 for(const m of text.matchAll(/(Bearer\s+)([^\s"'<>;,]+)/gi))addCredential(m.index!+m[1].length,m[2]);
 spans.sort((a,b)=>a.start-b.start||b.end-a.end||Number(b.replacement!==undefined)-Number(a.replacement!==undefined));let out='',offset=0;
 for(const span of spans){if(span.start<offset)continue;out+=legacyRedact(text.slice(offset,span.start));const value=text.slice(span.start,span.end);out+=span.replacement??(span.masked?value:redactSecret(value));offset=span.end;}
 return out+legacyRedact(text.slice(offset));
}
