// deno-lint-ignore-file
// deno-fmt-ignore-file
// @ts-nocheck
// @ts-self-types="./redirect.d.ts"
async function setHref(target){return location.href=target,block()}function block(){
// deno-lint-ignore no-explicit-any
let e=resolve=>{setTimeout(()=>e(resolve),400)};return new Promise(e)}export{setHref};