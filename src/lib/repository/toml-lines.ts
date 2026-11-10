// Masks comments and string values while retaining line positions; not a full TOML parser.
export function tomlLines(body:string){let i=0,out='',quote='',multi=false,complete=true;
 while(i<body.length){const ch=body[i];
  if(quote){
   if(multi&&body.startsWith(quote.repeat(3),i)){out+='   ';i+=3;quote='';multi=false;continue;}
   if(!multi&&ch===quote){out+=' ';i++;quote='';continue;}
   if(quote==='"'&&ch==='\\'){out+=' ';i++;if(i<body.length){out+=body[i]==='\n'?'\n':' ';i++;}continue;}
   if(ch==='\n'&&!multi){complete=false;quote='';}out+=ch==='\n'?'\n':' ';i++;continue;
  }
  if(ch==='#'){while(i<body.length&&body[i]!=='\n'){out+=' ';i++;}continue;}
  if(ch==='"'||ch==="'"){quote=ch;multi=body.startsWith(ch.repeat(3),i);out+=multi?'   ':' ';i+=multi?3:1;continue;}
  out+=ch;i++;
 }
 if(quote)complete=false;return {lines:out.split('\n'),complete};
}
