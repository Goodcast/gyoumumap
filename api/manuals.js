const { createHmac, timingSafeEqual, randomUUID } = require('node:crypto');
const { Readable } = require('node:stream');
const MAX_PART = 2 * 1024 * 1024;
const MAX_FILE = 25 * 1024 * 1024;
const ID = /^[a-f0-9-]{36}$/;
const TYPES = new Set(['application/pdf','text/html','image/png','image/jpeg','image/webp','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/msword','application/vnd.ms-excel','application/vnd.ms-powerpoint','application/vnd.ms-excel.sheet.macroEnabled.12']);
function createHandler(provided, env = process.env) {
 const sdk = () => provided || require('@vercel/blob');
 const json = (res, status, value) => {res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(value));};
 const fail = (status,message) => {const e=new Error(message);e.status=status;throw e;};
 const equal = (a,b) => {const x=Buffer.from(a||''),y=Buffer.from(b||'');return x.length===y.length&&timingSafeEqual(x,y);};
 const sign = value => createHmac('sha256',env.MANUAL_ADMIN_KEY||'').update(value).digest('hex');
 function authorized(req){if(!env.MANUAL_ADMIN_KEY)return false;const cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('manual_admin='));if(!cookie)return false;const [expiry,sig]=(cookie.slice(13)).split('.');return Number(expiry)>Date.now()&&equal(sig,sign(expiry));}
 async function all(prefix){const result=[];let cursor;do{const r=await sdk().list({prefix,cursor,limit:1000});result.push(...r.blobs);cursor=r.hasMore?r.cursor:null;}while(cursor);return result;}
 async function read(path){const r=await sdk().get(path,{access:'private',useCache:false});if(!r||r.statusCode!==200)fail(404,'資料が見つかりません。');return JSON.parse(await new Response(r.stream).text());}
 async function latest(id){if(!ID.test(id||''))fail(400,'資料IDが正しくありません。');const revisions=await all('manuals/'+id+'/revisions/');if(!revisions.length)fail(404,'資料が見つかりません。');revisions.sort((a,b)=>b.pathname.localeCompare(a.pathname));return read(revisions[0].pathname);}
 async function requested(url){const id=url.searchParams.get('id'),version=url.searchParams.get('v');if(!version)return latest(id);if(!ID.test(id||'')||!/^\d+-[a-f0-9-]{36}$/.test(version))fail(400,'資料の履歴指定が正しくありません。');return read('manuals/'+id+'/revisions/'+version+'.json');}
 async function accessible(req,url){const doc=await requested(url);const head=url.searchParams.has('v')?await latest(doc.id):doc;if(!authorized(req)&&(doc.visibility==='admin'||head.visibility==='admin'||head.archived))fail(404,'資料が見つかりません。');return doc;}
 async function body(req){if(req.body&&typeof req.body==='object'&&!Buffer.isBuffer(req.body))return req.body;const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>3*1024*1024)fail(413,'送信データが大きすぎます。');chunks.push(b);}try{return JSON.parse(Buffer.concat(chunks).toString());}catch{fail(400,'送信形式が正しくありません。');}}
 return async function handler(req,res){
  res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  try{
   const url=new URL(req.url,'https://map.local'),action=url.searchParams.get('action')||'list';
   const ready=Boolean(env.BLOB_STORE_ID||env.BLOB_READ_WRITE_TOKEN);
   if(req.method==='GET'&&action==='status')return json(res,200,{ready,canManage:authorized(req),adminConfigured:Boolean(env.MANUAL_ADMIN_KEY),publicWrite:false});
   if(!ready)fail(503,'マニュアルの保存先を準備中です。');
   if(req.method==='GET'&&action==='feedbacklist'){
    if(!authorized(req))fail(401,'管理者のみ閲覧できます。');
    const paths=await all('feedback/revisions/'),heads=new Map();for(const p of paths){const id=p.pathname.split('/')[2];if(!heads.has(id)||p.pathname>heads.get(id))heads.set(id,p.pathname);}const entries=await Promise.all([...heads.values()].map(read));return json(res,200,{entries:entries.sort((a,b)=>b.createdAt.localeCompare(a.createdAt))});
   }
   if(req.method==='GET'&&action==='mapread'){
    const revisions=await all('business-map/revisions/');revisions.sort((a,b)=>b.pathname.localeCompare(a.pathname));
    return json(res,200,revisions.length?await read(revisions[0].pathname):{version:null,nodes:null});
   }
   if(req.method==='GET'&&action==='list'){
    const heads=new Map();for(const b of await all('manuals/')){const m=b.pathname.match(/^manuals\/([a-f0-9-]{36})\/revisions\/([^/]+)\.json$/);if(m&&(!heads.has(m[1])||b.pathname>heads.get(m[1]).pathname))heads.set(m[1],b);}
    const docs=await Promise.all([...heads.values()].map(b=>read(b.pathname)));
    return json(res,200,{manuals:docs.filter(d=>(!d.archived||(authorized(req)&&url.searchParams.get('archived')==='include'))&&(authorized(req)||d.visibility!=='admin')).map(({id,title,category,summary,updatedAt,version,file,scope,visibility,archived})=>({id,title,category,summary,updatedAt,version,scope,archived:Boolean(archived),visibility:visibility||'public',file:file?{name:file.name,type:file.type,size:file.size}:null}))});
   }
   if(req.method==='GET'&&action==='read')return json(res,200,await accessible(req,url));
   if(req.method==='GET'&&action==='asset'){
    const doc=await accessible(req,url);if(doc.archived||!doc.file)fail(404,'資料が見つかりません。');
    if(doc.file.type==='text/html')res.setHeader('Content-Security-Policy',"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:;");res.setHeader('Content-Type',doc.file.type);res.setHeader('Content-Disposition','inline; filename="manual"');res.setHeader('Content-Length',doc.file.size);
    async function* stream(){for(let i=0;i<doc.file.parts;i++){const path='manuals/'+doc.id+'/files/'+doc.file.uploadId+'/part-'+String(i).padStart(3,'0');const r=await sdk().get(path,{access:'private',useCache:false});if(!r||r.statusCode!==200)throw Error('File missing');const reader=r.stream.getReader();try{while(true){const {done,value}=await reader.read();if(done)break;yield value;}}finally{reader.releaseLock();}}}
    return Readable.from(stream()).pipe(res);
   }
   if(req.method!=='POST')fail(405,'この操作には対応していません。');
   const origin=req.headers.origin;if(origin&&new URL(origin).host!==req.headers.host)fail(403,'別サイトからは操作できません。');
   const b=await body(req);
   if(action==='feedbacksend'){
    if(typeof b.message!=='string'||!b.message.trim()||b.message.length>2000||typeof b.name!=='string'||!b.name.trim()||b.name.length>80)fail(400,'名前と意見を入力してください。');
    const id=randomUUID(),now=new Date().toISOString(),doc={id,name:b.name.trim(),message:b.message.trim(),createdAt:now,replies:[]};await sdk().put('feedback/revisions/'+id+'/'+Date.now()+'-'+randomUUID()+'.json',JSON.stringify(doc),{access:'private',addRandomSuffix:false,allowOverwrite:false,contentType:'application/json'});return json(res,200,{ok:true});
   }
   if(action==='login'){
    if(!env.MANUAL_ADMIN_KEY)fail(503,'管理者設定を準備中です。');if(!equal(b.key,env.MANUAL_ADMIN_KEY))fail(401,'管理用コードが違います。');
    const expiry=String(Date.now()+8*60*60*1000);res.setHeader('Set-Cookie','manual_admin='+expiry+'.'+sign(expiry)+'; Path=/api/manuals; HttpOnly; Secure; SameSite=Strict; Max-Age=28800');return json(res,200,{ok:true});
   }
   if(action==='logout'){res.setHeader('Set-Cookie','manual_admin=; Path=/api/manuals; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return json(res,200,{ok:true});}
   if(!authorized(req))fail(401,'追加・編集には管理用コードが必要です。');
   if(action==='feedbackreply'){
    if(!ID.test(b.id||'')||typeof b.message!=='string'||!b.message.trim()||b.message.length>2000)fail(400,'返信を入力してください。');
    const paths=await all('feedback/revisions/'+b.id+'/');paths.sort((a,b)=>b.pathname.localeCompare(a.pathname));if(!paths.length)fail(404,'投稿が見つかりません。');const doc=await read(paths[0].pathname);doc.replies.push({message:b.message.trim(),createdAt:new Date().toISOString()});await sdk().put('feedback/revisions/'+b.id+'/'+Date.now()+'-'+randomUUID()+'.json',JSON.stringify(doc),{access:'private',addRandomSuffix:false,allowOverwrite:false,contentType:'application/json'});return json(res,200,{ok:true});
   }
   if(action==='mapsave'){
    if(!Array.isArray(b.nodes)||b.nodes.length>3000)fail(400,'項目が多すぎます。');
    const seen=new Map();
    for(const n of b.nodes){
     if(!n||!/^map-[a-zA-Z0-9-]{1,70}$/.test(n.id||'')||seen.has(n.id)||!Number.isInteger(n.level)||n.level<1||n.level>4||typeof n.text!=='string'||!n.text.trim()||n.text.length>10000)fail(400,'項目の形式が正しくありません。');
     if(n.level===1?n.parent!==null:(!seen.has(n.parent)||seen.get(n.parent)!==n.level-1))fail(400,'項目の階層が正しくありません。');
     if(n.scope!==undefined&&!/^business-[a-zA-Z0-9-]{1,60}$/.test(n.scope))fail(400,'格納先が正しくありません。');seen.set(n.id,n.level);
    }
    const revisions=await all('business-map/revisions/');revisions.sort((a,b)=>b.pathname.localeCompare(a.pathname));
    const previous=revisions.length?await read(revisions[0].pathname):null;
    if((previous?.version||null)!==(b.baseVersion||null))fail(409,'他の人が更新しました。変更を控えてからページを再読み込みしてください。');
    const version=Date.now().toString().padStart(13,'0')+'-'+randomUUID();
    const doc={version,updatedAt:new Date().toISOString(),nodes:b.nodes.map(n=>({id:n.id,level:n.level,parent:n.parent,text:n.text,...(n.scope?{scope:n.scope}:{})}))};
    await sdk().put('business-map/revisions/'+version+'.json',JSON.stringify(doc),{access:'private',addRandomSuffix:false,allowOverwrite:false,contentType:'application/json'});return json(res,200,doc);
   }
   if(action==='archive'){
    const previous=await latest(b.id);if(previous.version!==b.baseVersion)fail(409,'他の人が更新しました。管理一覧を開き直してください。');if(typeof b.archived!=='boolean')fail(400,'削除状態が正しくありません。');
    const version=Date.now().toString().padStart(13,'0')+'-'+randomUUID(),doc={...previous,version,updatedAt:new Date().toISOString(),archived:b.archived};await sdk().put('manuals/'+b.id+'/revisions/'+version+'.json',JSON.stringify(doc),{access:'private',addRandomSuffix:false,allowOverwrite:false,contentType:'application/json'});return json(res,200,{ok:true});
   }
   if(action==='part'){
    if(!ID.test(b.id||'')||!ID.test(b.uploadId||'')||!Number.isInteger(b.index)||b.index<0||b.index>12)fail(400,'ファイル形式が正しくありません。');
    const bytes=Buffer.from(b.data||'','base64');if(!bytes.length||bytes.length>MAX_PART)fail(413,'ファイルの分割サイズが正しくありません。');
    await sdk().put('manuals/'+b.id+'/files/'+b.uploadId+'/part-'+String(b.index).padStart(3,'0'),bytes,{access:'private',addRandomSuffix:false,allowOverwrite:false,contentType:'application/octet-stream'});return json(res,200,{ok:true});
   }
   if(action==='save'){
    if(!ID.test(b.id||''))fail(400,'資料IDが正しくありません。');
    let previous=null;try{previous=await latest(b.id);}catch(e){if(e.status!==404)throw e;}
    if((previous?.version||null)!==(b.baseVersion||null))fail(409,'他の人が更新しました。一覧を再読み込みしてから編集してください。');
    if(typeof b.title!=='string'||!b.title.trim()||b.title.length>120)fail(400,'タイトルを1〜120文字で入力してください。');
    if(typeof b.content!=='string'||b.content.length>100000)fail(400,'本文は10万文字以内で入力してください。');
    let file=previous?.file||null;
    if(b.file){const f=b.file;if(!ID.test(f.uploadId||'')||!TYPES.has(f.type)||!Number.isInteger(f.size)||f.size<1||f.size>MAX_FILE||f.parts!==Math.ceil(f.size/MAX_PART)||typeof f.name!=='string'||f.name.length>200)fail(400,'ファイルが正しくありません。');
     const blobs=await all('manuals/'+b.id+'/files/'+f.uploadId+'/');const parts=new Map(blobs.map(x=>[x.pathname,x.size]));let total=0;for(let i=0;i<f.parts;i++){const size=parts.get('manuals/'+b.id+'/files/'+f.uploadId+'/part-'+String(i).padStart(3,'0'));if(!size)fail(400,'ファイルの送信が完了していません。');total+=size;}if(total!==f.size)fail(400,'ファイルのサイズが一致しません。');file={name:f.name,type:f.type,size:f.size,parts:f.parts,uploadId:f.uploadId};
    }
    if(!b.content.trim()&&!file)fail(400,'本文かファイルを追加してください。');
    const version=Date.now().toString().padStart(13,'0')+'-'+randomUUID();
    const scope=String(b.scope||previous?.scope||'general');if(!/^(general|business-[a-zA-Z0-9-]{1,90})$/.test(scope))fail(400,'格納先が正しくありません。');
    const visibility=b.visibility??previous?.visibility??(previous?'public':'admin');if(!['admin','public'].includes(visibility))fail(400,'公開範囲が正しくありません。');
    const doc={id:b.id,scope,visibility,title:b.title.trim(),category:String(b.category||'未分類').slice(0,80),summary:String(b.summary||'').slice(0,300),content:b.content,file,version,updatedAt:new Date().toISOString(),archived:Boolean(b.archived)};
    await sdk().put('manuals/'+b.id+'/revisions/'+version+'.json',JSON.stringify(doc),{access:'private',addRandomSuffix:false,contentType:'application/json',allowOverwrite:false});return json(res,200,{ok:true,manual:doc});
   }
   fail(400,'操作が正しくありません。');
  }catch(e){if(res.headersSent){res.destroy();return;}json(res,e.status||500,{error:e.status?e.message:'保存先に接続できませんでした。時間をおいて再度お試しください。'});}
 };
}
module.exports=createHandler();
module.exports.createHandler=createHandler;
