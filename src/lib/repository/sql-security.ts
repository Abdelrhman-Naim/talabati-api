// Bounded lexical SQL inspection; never executes SQL or claims full PostgreSQL parsing.
export type SqlToken={value:string;kind:'word'|'identifier'|'literal'|'symbol';line:number};
export function tokenizeSql(body:string){
 const statements:SqlToken[][]=[];let tokens:SqlToken[]=[],i=0,line=1,depth=0,complete=true;
 const wordPattern=/[A-Za-z_][A-Za-z_0-9$]*/y,dollarPattern=/\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$/y;let tokenCount=0;
 const advance=(end:number)=>{for(;i<end;i++)if(body[i]==='\n')line++;};
 while(i<body.length){if(++tokenCount>60000){complete=false;break;}const ch=body[i],start=i,at=line;
  if(/\s/.test(ch)){advance(i+1);continue;}
  if(body.startsWith('--',i)){const end=body.indexOf('\n',i+2);advance(end<0?body.length:end);continue;}
  if(body.startsWith('/*',i)){let nesting=1;advance(i+2);while(i<body.length&&nesting){if(body.startsWith('/*',i)){nesting++;advance(i+2);}else if(body.startsWith('*/',i)){nesting--;advance(i+2);}else advance(i+1);}if(nesting)complete=false;continue;}
  dollarPattern.lastIndex=i;const dollar=ch==='$'?dollarPattern.exec(body)?.[0]:undefined;
  if(dollar){const end=body.indexOf(dollar,i+dollar.length);if(end<0){complete=false;advance(body.length);}else advance(end+dollar.length);tokens.push({value:'[body]',kind:'literal',line:at});continue;}
  if(ch==="'"||ch==='"'){const quote=ch;let value='',closed=false;advance(i+1);while(i<body.length){if(body[i]===quote){if(body[i+1]===quote){value+=quote;advance(i+2);continue;}advance(i+1);closed=true;break;}if(body[i]==='\\'&&quote==="'"){if(body[i+1]==="'")complete=false;value+='[escape]';advance(Math.min(body.length,i+2));continue;}value+=body[i];advance(i+1);}if(!closed)complete=false;tokens.push({value:quote==='"'?value:['off','false','0'].includes(value.toLowerCase())?value.toLowerCase():'[string]',kind:quote==='"'?'identifier':'literal',line:at});continue;}
  wordPattern.lastIndex=i;const word=wordPattern.exec(body)?.[0];if(word){advance(i+word.length);tokens.push({value:word.toLowerCase(),kind:'word',line:at});continue;}
  if(ch==='(')depth++;if(ch===')'&&--depth<0){complete=false;depth=0;}
  if(ch===';'){if(depth)complete=false;if(tokens.length)statements.push(tokens);tokens=[];advance(i+1);continue;}
  tokens.push({value:ch,kind:'symbol',line:at});advance(start+1);
 }
 if(depth)complete=false;if(tokens.length)statements.push(tokens);
 return {statements,complete};
}
export type SqlObservation={rule:string;title:string;status:'pass'|'fail'|'unavailable';line:number;resource:string;evidence:string;fix:string;high?:boolean};
const word=(t:SqlToken|undefined,v:string)=>t?.kind==='word'&&t.value===v;
function qualified(tokens:SqlToken[],start:number){let i=start;const parts:string[]=[];while(tokens[i]&&['word','identifier'].includes(tokens[i].kind)){const t=tokens[i++];parts.push(t.kind==='identifier'?'"'+t.value+'"':t.value);if(tokens[i]?.value!=='.')break;i++;}return {name:parts.join('.'),end:i};}
function phrase(t:SqlToken[],values:string[]){return t.findIndex((_,i)=>values.every((v,j)=>word(t[i+j],v)));}
export function sqlSecurity(body:string){const parsed=tokenizeSql(body),observations:SqlObservation[]=[];
 if(!parsed.complete)return {complete:false,observations};
 const created:{name:string;line:number}[]=[],enabled=new Map<string,boolean>();
 for(const t of parsed.statements){if(observations.length>=250)return {complete:false,observations:[]};
  if(word(t[0],'create')&&word(t[1],'table')){let i=2;if(phrase(t.slice(i),['if','not','exists'])===0)i+=3;const table=qualified(t,i);if(table.name)created.push({name:table.name,line:t[0].line});}
  if(word(t[0],'alter')&&word(t[1],'table')){let i=2;if(word(t[i],'if')&&word(t[i+1],'exists'))i+=2;if(word(t[i],'only'))i++;const table=qualified(t,i),rest=t.slice(table.end);const enable=phrase(rest,['enable','row','level','security']),disable=phrase(rest,['disable','row','level','security']);if(enable>=0||disable>=0){enabled.set(table.name,enable>disable);observations.push({rule:'repo.rls-disabled',title:'تعليمة تغيير حالة RLS',status:disable>=0?'fail':'pass',line:t[0].line,resource:table.name,evidence:disable>=0?'تعليمة DISABLE ROW LEVEL SECURITY مرصودة.':'تعليمة ENABLE ROW LEVEL SECURITY مرصودة في هذا الملف.',fix:'راجع الحالة الحية وترتيب migrations واختبر عزل الأدوار على الجدول.',high:true});}}
  if(word(t[0],'create')&&word(t[1],'policy')){
   const on=t.findIndex(x=>word(x,'on')),table=qualified(t,on+1),roleAt=t.findIndex(x=>word(x,'to')),using=t.findIndex(x=>word(x,'using')),check=phrase(t,['with','check']),forAt=t.findIndex(x=>word(x,'for'));
   const command=forAt<0?'all':t[forAt+1]?.value;
   const roleEnd=[using,check].filter(x=>x>roleAt).sort((a,b)=>a-b)[0]??t.length;
   const roles=roleAt<0?['public']:t.slice(roleAt+1,roleEnd).filter(x=>['word','identifier'].includes(x.kind)).map(x=>x.value.toLowerCase());
   const broad=roles.some(r=>['public','anon','authenticated'].includes(r));
   const always=(idx:number,offset=1)=>{
    if(idx<0||t[idx+offset]?.value!=='(')return false;let end=idx+offset,depth=0;
    do{if(t[end]?.value==='(')depth++;if(t[end]?.value===')')depth--;end++;}while(end<t.length&&depth>0);
    let expr=t.slice(idx+offset,end);while(expr[0]?.value==='('&&expr.at(-1)?.value===')'){let d=0,wrap=true;for(let j=0;j<expr.length-1;j++){if(expr[j].value==='(')d++;if(expr[j].value===')')d--;if(d===0){wrap=false;break;}}if(!wrap)break;expr=expr.slice(1,-1);}
    if(expr.length===4&&expr[1].value===':'&&expr[2].value===':'&&['boolean','bool'].some(v=>word(expr[3],v)))expr=expr.slice(0,1);
    return expr.length===1&&word(expr[0],'true');
   };
   if(on<0||!table.name){observations.push({rule:'repo.sql.policy-shape',title:'صيغة سياسة غير محسومة',status:'unavailable',line:t[0].line,resource:'policy',evidence:'تعذر تحديد جدول السياسة من الصيغة المدعومة.',fix:'راجع السياسة بمحلل PostgreSQL واختبار فعلي.'});continue;}
   const usingOpen=using<0||always(using),checkOpen=check<0?command==='insert'||usingOpen:always(check,2);
   if(['select','all'].includes(command??'')&&broad)observations.push({rule:'repo.sql.policy-open-read',title:'سياسة قراءة واسعة — راجع القصد',status:usingOpen?'fail':'pass',line:t[0].line,resource:table.name,evidence:usingOpen?'شرط USING دائم true أو غير محدد لدور واسع؛ الشرط لا يقيد الصفوف. الأثر يعتمد على بقية السياسات وقد تكون البيانات عامة عمدًا.':'لم يرصد USING (true) حرفيًا في هذه السياسة؛ لم يثبت عزل المستخدمين.',fix:'حدد البيانات العامة صراحة، وقيد الموارد الخاصة بهوية المالك أو العضوية.'});
   if(['all','insert','update','delete'].includes(command??'')&&broad){const open=command==='delete'?usingOpen:checkOpen||(['all','update'].includes(command??'')&&usingOpen);observations.push({rule:'repo.sql.policy-open-write',title:'سياسة كتابة واسعة — مراجعة مطلوبة',status:open?'fail':'pass',line:t[0].line,resource:table.name,evidence:open?'شرط كتابة دائم true، صريح أو افتراضي أو موروث من USING، لدور واسع؛ الأثر يعتمد على بقية السياسات.':'لم يرصد شرط كتابة دائم true في السياسة المحددة؛ لا يثبت سلامة بقية الشروط.',fix:'قيد USING وWITH CHECK على المالك والعضوية، واختبر كل عملية كتابة في بيئة اختبار.',high:true});}
  }
  if(word(t[0],'grant')){
   const on=t.findIndex(x=>word(x,'on')),to=t.findIndex(x=>word(x,'to'));
   if(on>0&&to>on&&t.slice(to+1).some(x=>['word','identifier'].includes(x.kind)&&['public','anon'].includes(x.value.toLowerCase()))){
    const operations=t.slice(1,on).filter(x=>x.kind==='word').map(x=>x.value),object=t[on+1],callable=word(object,'function')||word(object,'procedure')||word(object,'routine');
    const explicitClass=['table','sequence','function','procedure','routine','schema','database','language','type'].some(v=>word(object,v)),resource=qualified(t,explicitClass?on+2:on+1).name;
    const write=operations.some(x=>['all','insert','update','delete','truncate','references','trigger'].includes(x));
    if(callable&&(operations.includes('all')||operations.includes('execute')))observations.push({rule:'repo.sql.grant-execute',title:'منح تنفيذ دالة لدور عام أو anon',status:'fail',line:t[0].line,resource,evidence:'GRANT يسمح EXECUTE؛ لا يعني ذلك منح تعديل جدول. راجع جسم الدالة وصلاحيات مالكها وSECURITY DEFINER.',fix:'قيّد تنفيذ الدوال الحساسة بالأدوار اللازمة واختبر التفويض داخلها.'});
    else if(write&&(!explicitClass||word(object,'table')))observations.push({rule:'repo.sql.grant-write',title:'منح كتابة لدور عام أو anon',status:'fail',line:t[0].line,resource,evidence:'GRANT يتضمن صلاحيات تعديل جدول لدور public/anon؛ هذا لا يثبت وحده تجاوز RLS.',fix:'قلص GRANT إلى العمليات اللازمة وراجع RLS وحق المستخدمين المقصودين.',high:true});
   }
  }
  if(word(t[0],'create')&&phrase(t,['security','definer'])>=0){const functionAt=t.findIndex(x=>word(x,'function')||word(x,'procedure'));if(functionAt>=0){const hasPath=t.some((x,i)=>word(x,'search_path')&&word(t[i-1],'set')),rowAt=phrase(t,['set','row_security']),rowValue=t[rowAt+2]?.value==='='?t[rowAt+3]:t[rowAt+2],off=rowAt>=0&&!!rowValue&&['off','false','0'].includes(rowValue.value);observations.push({rule:'repo.sql.definer-search-path',title:'تقييد search_path لدالة SECURITY DEFINER',status:hasPath?'pass':'fail',line:t[0].line,resource:qualified(t,functionAt+1).name,evidence:hasPath?'يوجد SET search_path؛ يجب مراجعة قيمة المسار ومخططاته وصلاحيات تعديلها.':'لم يحدد SET search_path في تعريف الدالة المجموع؛ قد يؤثر مسار البحث في حل أسماء الكائنات.',fix:'ثبت search_path على مسار موثوق أو فارغ مع تأهيل الأسماء، وقيّد EXECUTE؛ راجع جسم الدالة منفصلًا.',high:true});if(off)observations.push({rule:'repo.sql.definer-row-security',title:'تعطيل row_security في تعريف دالة',status:'fail',line:t[0].line,resource:qualified(t,functionAt+1).name,evidence:'SECURITY DEFINER مع SET row_security وإعداد off مرصود؛ راجع أثر الدور الفعلي.',fix:'راجع صلاحيات مالك الدالة وسياسة row_security ومستخدمي EXECUTE.',high:true});}}
 }
 if(observations.length+created.length>250)return {complete:false,observations:[]};
 for(const table of created)observations.push({rule:'repo.sql.rls-declaration',title:'تعريف الجدول وتعليمة تفعيل RLS في الملف',status:enabled.get(table.name)===true?'pass':'unavailable',line:table.line,resource:table.name,evidence:enabled.get(table.name)===true?'CREATE TABLE وتعليمة تفعيل RLS لنفس الاسم في الملف؛ لا يثبت الحالة المنشورة.':'لا توجد حالة تفعيل أخيرة مؤكدة للجدول في هذا الملف؛ قد توجد migrations أخرى ولم يفترض التعطيل.',fix:'تحقق من ترتيب جميع migrations والحالة الحية وسياسات الجدول.'});
 return {complete:true,observations};
}
