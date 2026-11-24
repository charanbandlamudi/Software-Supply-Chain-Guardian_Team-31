const names=["jsonwebtoken", "lodash"];const out={};
for (const n of names){try{const v=require(n+'/package.json').version;try{require(n);out[n]={version:v,status:'loaded'}}catch(e){out[n]={version:v,status:(e.code==='ERR_PACKAGE_PATH_NOT_EXPORTED'||e.code==='MODULE_NOT_FOUND')?'no importable entry point (CLI or subpath-only package)':'load_failed',error:String(e.message).slice(0,200)}}}catch(e){out[n]={status:'not_installed',error:String(e.message).slice(0,200)}}}
console.log(JSON.stringify(out));
