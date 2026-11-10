import ts from 'typescript';

/** Local binding analysis only: no import resolution, execution, or filesystem reads. */
export function createRuleContext(source:ts.SourceFile){
 let checker:ts.TypeChecker|undefined;
 const symbol=(node:ts.Node)=>{
  if(!checker){const host:ts.CompilerHost={getSourceFile:()=>source,getDefaultLibFileName:()=>'',writeFile:()=>{},getCurrentDirectory:()=>'',getDirectories:()=>[],fileExists:()=>false,readFile:()=>undefined,getCanonicalFileName:n=>n,useCaseSensitiveFileNames:()=>true,getNewLine:()=> '\n'};checker=ts.createProgram([source.fileName],{noResolve:true,noLib:true,noEmit:true,allowJs:true,jsx:ts.JsxEmit.Preserve},host).getTypeChecker();}
  if(ts.isIdentifier(node)&&ts.isShorthandPropertyAssignment(node.parent)&&node.parent.name===node)return checker.getShorthandAssignmentValueSymbol(node.parent)??checker.getSymbolAtLocation(node);
  return checker.getSymbolAtLocation(node);
 };
 const unwrap=(node:ts.Node):ts.Node=>ts.isParenthesizedExpression(node)||ts.isAsExpression(node)||ts.isTypeAssertionExpression(node)||ts.isNonNullExpression(node)?unwrap(node.expression):node;
 const declaration=(id:ts.Identifier)=>symbol(id)?.declarations?.find(d=>ts.isVariableDeclaration(d)||ts.isParameter(d)||ts.isImportClause(d)||ts.isImportSpecifier(d)||ts.isNamespaceImport(d));
 const constInitializer=(node:ts.Node)=>{if(!ts.isIdentifier(node))return undefined;const d=declaration(node);return d&&ts.isVariableDeclaration(d)&&ts.isVariableDeclarationList(d.parent)&&(d.parent.flags&ts.NodeFlags.Const)?d.initializer:undefined;};
 const refsCache=new Map<ts.Symbol,ts.Identifier[]>();
 function references(id:ts.Identifier){const s=symbol(id);if(!s)return [];if(!refsCache.has(s)){const refs:ts.Identifier[]=[];function visit(n:ts.Node){if(ts.isIdentifier(n)&&symbol(n)===s)refs.push(n);ts.forEachChild(n,visit);}visit(source);refsCache.set(s,refs);}return refsCache.get(s)!;}
 const property=(node:ts.Node)=>ts.isPropertyAccessExpression(node)?node.name.text:ts.isElementAccessExpression(node)&&node.argumentExpression&&ts.isStringLiteral(node.argumentExpression)?node.argumentExpression.text:undefined;
 const receiver=(node:ts.Node)=>ts.isPropertyAccessExpression(node)||ts.isElementAccessExpression(node)?node.expression:undefined;
 function objectNotMutated(id:ts.Identifier,sanitizer=false){return references(id).every(ref=>{
  const d=declaration(ref);if(d&&ref===d.name)return true;
  let node:ts.Node=ref;while((ts.isPropertyAccessExpression(node.parent)||ts.isElementAccessExpression(node.parent))&&node.parent.expression===node)node=node.parent;
  const p=node.parent;
  if(ts.isBinaryExpression(p)&&p.left===node&&p.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&p.operatorToken.kind<=ts.SyntaxKind.LastAssignment)return false;
  if(ts.isPrefixUnaryExpression(p)||ts.isPostfixUnaryExpression(p)||ts.isDeleteExpression(p))return false;
  if(node!==ref){return sanitizer?property(node)==='sanitize':property(node)==='__html'&&!(ts.isCallExpression(p)&&p.expression===node);}
  // Objects are mutable even when their binding is const. Only a direct JSX read is
  // proven here; passing/returning/assigning/spreading/wrapping the object may escape it.
  return ts.isJsxExpression(p)&&ts.isJsxAttribute(p.parent)&&p.parent.name.getText(source)==='dangerouslySetInnerHTML';
 });}
 const moduleName=(d:ts.Declaration)=>{let n:ts.Node=d;while(!ts.isImportDeclaration(n)&&n.parent)n=n.parent;return ts.isImportDeclaration(n)&&ts.isStringLiteral(n.moduleSpecifier)?n.moduleSpecifier.text:undefined;};
 function imported(id:ts.Identifier){const d=declaration(id);if(!d)return undefined;if(ts.isImportClause(d)&&!d.isTypeOnly)return {module:moduleName(d),member:'default'};if(ts.isImportSpecifier(d)&&!d.isTypeOnly&&!(d.parent.parent as ts.ImportClause).isTypeOnly)return {module:moduleName(d),member:(d.propertyName??d.name).text};if(ts.isNamespaceImport(d)&&!(d.parent as ts.ImportClause).isTypeOnly)return {module:moduleName(d),member:'namespace'};const init=constInitializer(id);if(init&&ts.isCallExpression(init)&&ts.isIdentifier(init.expression)&&init.expression.text==='require'&&!symbol(init.expression)?.declarations?.length&&init.arguments.length===1&&ts.isStringLiteral(init.arguments[0]))return {module:init.arguments[0].text,member:'default'};return undefined;}
 const purifier=(id:ts.Identifier)=>{const imp=imported(id);return imp&&['dompurify','isomorphic-dompurify'].includes(imp.module??'')&&['default','namespace'].includes(imp.member);};
 function unmodifiedPurifier(id:ts.Identifier){return objectNotMutated(id,true)&&references(id).every(ref=>{const d=declaration(ref);if(d&&ref===d.name)return true;return (ts.isPropertyAccessExpression(ref.parent)||ts.isElementAccessExpression(ref.parent))&&property(ref.parent)==='sanitize';});}
 function sanitizerCall(node:ts.Node){if(!ts.isCallExpression(node)||node.arguments.length!==1)return false;const callee=unwrap(node.expression),obj=receiver(callee);if(property(callee)==='sanitize'&&obj&&ts.isIdentifier(obj))return !!purifier(obj)&&unmodifiedPurifier(obj);if(ts.isIdentifier(callee)){const imp=imported(callee);return !!imp&&((['dompurify','isomorphic-dompurify'].includes(imp.module??'')&&imp.member==='sanitize')||(imp.module==='sanitize-html'&&imp.member==='default'));}return false;}
 function constant(node:ts.Node,seen=new Set<ts.Node>(),depth=0):boolean{node=unwrap(node);if(depth>12||seen.has(node))return false;const next=new Set(seen).add(node);if(ts.isStringLiteral(node)||ts.isNoSubstitutionTemplateLiteral(node)||ts.isNumericLiteral(node)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(node.kind))return true;if(ts.isIdentifier(node)){const init=constInitializer(node);return !!init&&constant(init,next,depth+1);}if(ts.isBinaryExpression(node)&&node.operatorToken.kind===ts.SyntaxKind.PlusToken)return constant(node.left,next,depth+1)&&constant(node.right,next,depth+1);if(ts.isTemplateExpression(node))return node.templateSpans.every(s=>constant(s.expression,next,depth+1));return false;}
 function safeHtml(node:ts.Node|undefined,seen=new Set<ts.Node>(),depth=0):boolean{
  if(!node||depth>12)return false;node=unwrap(node);if(seen.has(node))return false;
  if(constant(node)||sanitizerCall(node))return true;
  // A sanitized *fragment* is not proof that a larger concatenation is safe in a
  // newly constructed attribute/URL/script context. Sanitize the complete value.
  if(ts.isIdentifier(node)){const init=constInitializer(node);return !!init&&safeHtml(init,new Set(seen).add(node),depth+1);}return false;
 }
 function propertyName(name:ts.PropertyName){if(ts.isIdentifier(name)||ts.isStringLiteral(name)||ts.isNumericLiteral(name))return name.text;if(ts.isComputedPropertyName(name)){const value=unwrap(name.expression);if(ts.isStringLiteral(value)||ts.isNoSubstitutionTemplateLiteral(value))return value.text;}return undefined;}
 function htmlPropertyValue(node:ts.Node|undefined,seen=new Set<ts.Node>(),depth=0):ts.Node|undefined{
  if(!node||depth>12)return;node=unwrap(node);if(seen.has(node))return;const next=new Set(seen).add(node);
  if(ts.isJsxExpression(node))return htmlPropertyValue(node.expression,next,depth+1);
  if(ts.isIdentifier(node)){const init=constInitializer(node);return init&&objectNotMutated(node)?htmlPropertyValue(init,next,depth+1):undefined;}
  if(!ts.isObjectLiteralExpression(node))return;let value:ts.Node|undefined;
  for(const p of node.properties){
   if(ts.isSpreadAssignment(p)){value=undefined;continue;}
   const key=propertyName(p.name);
   if(key===undefined){value=undefined;continue;}
   if(key!=='__html')continue;
   value=ts.isPropertyAssignment(p)?p.initializer:ts.isShorthandPropertyAssignment(p)?p.name:undefined;
  }return value;
 }
 const words=(name:string)=>name.replace(/([a-z\d])([A-Z])/g,'$1 $2').replace(/[^a-z\d]+/gi,' ').toLowerCase();
 const securityName=(name:string)=>/(?:^| )(?:passwords?|passwd|pwd|tokens?|signatures?|hmac|sessions?|auth|authenticate|authorize|authentication|authorization|secrets?|credentials?)(?: |$)/.test(words(name));
 const benignName=(name:string)=>/(?:^| )(?:checksums?|cache|etag|etags|entity tag)(?: |$)/.test(words(name));
 function containsSecurityName(node:ts.Node,seen=new Set<ts.Node>(),depth=0){if(depth>12||seen.has(node))return false;const next=new Set(seen).add(node);let found=false;function visit(n:ts.Node){if(ts.isIdentifier(n)){if(securityName(n.text))found=true;else{const init=constInitializer(n);if(init&&containsSecurityName(init,next,depth+1))found=true;}}if(ts.isElementAccessExpression(n)&&n.argumentExpression&&ts.isStringLiteral(n.argumentExpression)&&securityName(n.argumentExpression.text))found=true;ts.forEachChild(n,visit);}visit(node);return found;}
 function expressionRoot(node:ts.Node){let current=node;while(current.parent&&!ts.isStatement(current.parent)&&!ts.isVariableDeclaration(current.parent)&&!ts.isArrowFunction(current.parent)&&!ts.isFunctionLike(current.parent))current=current.parent;return current;}
 /**
  * A weak algorithm alone is NOT a security finding. Require a security-named input,
  * output binding, enclosing function, or use in a secret comparison. We follow the
  * immediate fluent chain and local references of a hash/result binding only, never
  * filenames, comments, or unrelated identifiers elsewhere in a function. Explicit
  * security input wins over a checksum/cache/ETag name; a benign-purpose name prevents
  * enclosing-function-name inference. This is bounded lexical context, not full taint analysis.
  */
 function fluentRoot(node:ts.Node){let root=node;while((ts.isPropertyAccessExpression(root.parent)||ts.isElementAccessExpression(root.parent))&&root.parent.expression===root&&ts.isCallExpression(root.parent.parent)&&root.parent.parent.expression===root.parent)root=root.parent.parent;return root;}
 function securityUse(node:ts.Node){let current=node;while(ts.isParenthesizedExpression(current.parent)||ts.isAsExpression(current.parent)||ts.isNonNullExpression(current.parent))current=current.parent;const p=current.parent;
  if(ts.isBinaryExpression(p)&&['===','==','!==','!='].includes(p.operatorToken.getText(source)))return containsSecurityName(p.left===current?p.right:p.left);
  if(ts.isBinaryExpression(p)&&p.operatorToken.kind===ts.SyntaxKind.EqualsToken&&p.right===current)return containsSecurityName(p.left)&&!benignName(p.left.getText(source));
  if(ts.isVariableDeclaration(p))return securityName(p.name.getText(source))&&!benignName(p.name.getText(source));
  if(ts.isCallExpression(p)&&p.arguments.includes(current as ts.Expression)){const method=property(p.expression)??(ts.isIdentifier(p.expression)?p.expression.text:'');return method==='timingSafeEqual'||securityName(method)&&!benignName(method);}return false;
 }
 function securityHash(call:ts.CallExpression|ts.NewExpression){
  const root=fluentRoot(call);if(containsSecurityName(root)||securityUse(root))return true;
  const seen=new Set<ts.Symbol>();
  function trace(id:ts.Identifier,handle:boolean,depth=0):boolean{
   const sym=symbol(id);if(!sym||seen.has(sym)||depth>12)return false;seen.add(sym);
   for(const ref of references(id)){if(ref===id)continue;const use=fluentRoot(ref);
    if(securityUse(use))return true;
    if(handle&&ts.isCallExpression(use)){
     // Only update's own input is hash input, never unrelated surrounding-call args.
     let secure=false;function walk(n:ts.Node){if(ts.isCallExpression(n)&&property(n.expression)==='update'&&n.arguments[0]&&containsSecurityName(n.arguments[0]))secure=true;ts.forEachChild(n,walk);}walk(use);if(secure)return true;
    }
    const owner=use.parent;if(ts.isVariableDeclaration(owner)&&ts.isIdentifier(owner.name)){
     const digest=ts.isCallExpression(use)&&property(use.expression)==='digest';if(trace(owner.name,handle&&!digest,depth+1))return true;
    }
   }return false;
  }
  const owner=root.parent;
  if(ts.isVariableDeclaration(owner)&&ts.isIdentifier(owner.name)){const digest=ts.isCallExpression(root)&&property(root.expression)==='digest';if(trace(owner.name,!digest))return true;}
  let fn:ts.Node|undefined=call.parent;while(fn&&!ts.isFunctionLike(fn))fn=fn.parent;
  if(fn&&ts.isFunctionLike(fn)){let name=fn.name?.getText(source)??'';if(!name&&ts.isArrowFunction(fn)&&ts.isVariableDeclaration(fn.parent))name=fn.parent.name.getText(source);const output=ts.isVariableDeclaration(owner)?owner.name.getText(source):'';if(!benignName(output)&&!benignName(name)&&securityName(name))return true;}return false;
 }
 return {securityHash,safeHtml,propertyName,htmlPropertyIsSafe:(node:ts.Node|undefined)=>safeHtml(htmlPropertyValue(node)),property};
}
