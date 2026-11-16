import {ready,b64,unb64} from './crypto.mjs';
const utf8=new TextEncoder();
export async function protect(binding,password){
 const sodium=await ready();
 if(typeof password!=='string'||password.length<16||password.length>256)throw Error('Enter the encryption password (at least 16 characters)');
 const parts=binding.split('.'),salt=unb64(parts.at(-1));if(salt.length!==16)throw Error('Invalid encryption salt');
 const root=sodium.crypto_pwhash(32,utf8.encode(password),salt,3,64*1024*1024,sodium.crypto_pwhash_ALG_ARGON2ID13);
 const authorization=b64(sodium.crypto_generichash(32,utf8.encode('NextShuttle/v2/authorization\0'+binding),root));
 return {binding,root,authorization};
}
export async function protectedKey(protection,seed=null){
 const sodium=await ready(),prefix=utf8.encode('NextShuttle/v2/'+(seed?'upload':'file')+'\0'+protection.binding);
 const data=seed?new Uint8Array([...prefix,...seed]):prefix;
 return sodium.crypto_generichash(32,data,protection.root);
}
