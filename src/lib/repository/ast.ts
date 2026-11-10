import {createRuleContext} from './rule-context';
import ts from 'typescript';
export function supportsJavaScript(file:string){return /\.(?:[cm]?[jt]sx?|html?|vue|svelte)$/i.test(file);}
export function analyzeJavaScript(file:string,body:string){
 const matches:Record<string,number[]>={},errors:{code:number;line:number;column:number}[]=[];let valid=true,hasCode=false,publicSecretsComplete=true,ambiguousPublicName=false;
 const publicName=(name:string)=>/^(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z\d_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD)[A-Z\d_]*$/.test(name);
 const add=(rule:string,line:number)=>{const list=matches[rule]??=[];if(!list.includes(line))list.push(line);};
 const chunks:{text:string;offset:number;name?:string}[]=[];
 if(/\.(?:html?|vue|svelte)$/i.test(file)){
  for(const m of body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)){
   const attrs=m[1],type=attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i),mime=(type?.[1]??type?.[2]??type?.[3]??'').toLowerCase();
   if(mime&&!['module','text/javascript','application/javascript','text/ecmascript','application/ecmascript'].includes(mime))continue;
   const lang=attrs.match(/\blang\s*=\s*["']?(tsx?|jsx?)/i)?.[1]?.toLowerCase();
   chunks.push({text:m[2],offset:body.slice(0,m.index!+m[0].indexOf('>')+1).split('\n').length-1,name:'inline.'+(lang??'js')});
  }
 }else chunks.push({text:body,offset:0,name:file});
 for(const chunk of chunks){
  if(!chunk.text.trim())continue;hasCode=true;
  const name=chunk.name??file;
  const tokens:{kind:ts.SyntaxKind;value:string;pos:number}[]=[];
  const scanner=ts.createScanner(ts.ScriptTarget.Latest,true,ts.LanguageVariant.Standard,chunk.text,()=>{publicSecretsComplete=false;});
  let token:ts.SyntaxKind;while((token=scanner.scan())!==ts.SyntaxKind.EndOfFileToken)tokens.push({kind:token,value:scanner.getTokenValue()||scanner.getTokenText(),pos:scanner.getTokenPos()});
  if(tokens.some(t=>[ts.SyntaxKind.Identifier,ts.SyntaxKind.StringLiteral].includes(t.kind)&&publicName(t.value)))ambiguousPublicName=true;
  const kind=/\.(?:jsx?|[cm]js|tsx)$/i.test(name)?ts.ScriptKind.TSX:ts.ScriptKind.TS;
  const source=ts.createSourceFile(name,chunk.text,ts.ScriptTarget.Latest,true,kind);
  // Parser diagnostics belong to the installed compiler SourceFile; never emit or execute repository code.
  const diagnostics=(source as ts.SourceFile&{parseDiagnostics?:readonly ts.Diagnostic[]}).parseDiagnostics;
  if(!Array.isArray(diagnostics)){valid=false;errors.push({code:0,line:chunk.offset+1,column:1});continue;}
  if(diagnostics.some(d=>d.category===ts.DiagnosticCategory.Error)){valid=false;for(const d of diagnostics.slice(0,5)){const pos=source.getLineAndCharacterOfPosition(d.start??0);errors.push({code:d.code,line:chunk.offset+pos.line+1,column:pos.character+1});}}
  const line=(node:ts.Node)=>chunk.offset+source.getLineAndCharacterOfPosition(node.getStart(source)).line+1;
  const text=(node:ts.Node)=>node.getText(source);
  const context=createRuleContext(source);
  const member=(node:ts.Node)=>ts.isPropertyAccessExpression(node)?node.name.text:ts.isIdentifier(node)?node.text:'';
  function visit(node:ts.Node){
   if(ts.isCallExpression(node)||ts.isNewExpression(node)){
    const method=member(node.expression),args=node.arguments??[];
    const props=(arg:ts.Node|undefined)=>arg&&ts.isObjectLiteralExpression(arg)?arg.properties.filter(ts.isPropertyAssignment):[];
    const key=(p:ts.PropertyAssignment)=>ts.isIdentifier(p.name)||ts.isStringLiteral(p.name)?p.name.text:'';
    if(method==='verify')for(const p of props(args[2])){if(key(p)==='ignoreExpiration'&&p.initializer.kind===ts.SyntaxKind.TrueKeyword)add('repo.jwt-expiry',line(p));if(key(p)==='algorithms'&&ts.isArrayLiteralExpression(p.initializer)&&p.initializer.elements.some(e=>ts.isStringLiteral(e)&&e.text.toLowerCase()==='none'))add('repo.jwt-none',line(p));}
    if(method==='cors'){const fields=props(args[0]);if(fields.some(p=>key(p)==='origin'&&p.initializer.kind===ts.SyntaxKind.TrueKeyword)&&fields.some(p=>key(p)==='credentials'&&p.initializer.kind===ts.SyntaxKind.TrueKeyword))add('repo.cors-reflection',line(node));}
    if(['createHash','createHmac'].includes(method)&&args[0]&&ts.isStringLiteral(args[0])&&['md5','sha1'].includes(args[0].text.toLowerCase())&&context.securityHash(node))add('repo.weak-hash',line(node));
    if(['eval','Function'].includes(method))add('repo.eval',line(node));
    if(method==='insertAdjacentHTML'&&!context.safeHtml(args[1]))add('repo.html-sink',line(node));
    const arg=args[0],dynamic=arg&&(ts.isTemplateExpression(arg)||(ts.isBinaryExpression(arg)&&arg.operatorToken.kind===ts.SyntaxKind.PlusToken));
    if(dynamic&&['query','execute','raw'].includes(method)&&/\b(?:SELECT|UPDATE|DELETE|INSERT)\b/i.test(text(arg)))add('repo.sql-concat',line(node));
    if(dynamic&&['exec','execSync'].includes(method))add('repo.shell',line(node));
   }
   if(ts.isJsxAttribute(node)&&node.name.getText(source)==='dangerouslySetInnerHTML'&&!context.htmlPropertyIsSafe(node.initializer))add('repo.html-sink',line(node));
   if(ts.isVariableDeclaration(node)&&ts.isIdentifier(node.name)&&publicName(node.name.text)&&node.initializer&&node.initializer.getText(source)!=='undefined'&&node.initializer.getText(source)!=="''"&&node.initializer.getText(source)!=='""')add('repo.public-secret',line(node));
   if(ts.isBinaryExpression(node)&&node.operatorToken.kind===ts.SyntaxKind.EqualsToken&&publicName(member(node.left)))add('repo.public-secret',line(node));
   if(ts.isPropertyAssignment(node)){const key=node.name.getText(source).replace(/^["']|["']$/g,'');if(publicName(key))add('repo.public-secret',line(node));if((context.propertyName(node.name)??key)==='dangerouslySetInnerHTML'&&!context.htmlPropertyIsSafe(node.initializer))add('repo.html-sink',line(node));if(key==='rejectUnauthorized'&&node.initializer.kind===ts.SyntaxKind.FalseKeyword)add('repo.tls-bypass',line(node));}
   if(ts.isBinaryExpression(node)&&node.operatorToken.kind===ts.SyntaxKind.EqualsToken){if(['innerHTML','outerHTML'].includes(context.property(node.left)??'')&&!context.safeHtml(node.right))add('repo.html-sink',line(node));if(/NODE_TLS_REJECT_UNAUTHORIZED/.test(text(node.left))&&ts.isStringLiteral(node.right)&&node.right.text==='0')add('repo.tls-bypass',line(node));}
   ts.forEachChild(node,visit);
  }
  visit(source);
 }
 return {matches,valid,hasCode,errors:errors.slice(0,10),publicSecrets:{lines:matches['repo.public-secret']??[],complete:valid||(publicSecretsComplete&&!ambiguousPublicName)}};
}
