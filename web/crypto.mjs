import sodium from 'libsodium-wrappers-sumo';
export const MAX_PLAIN=32*1024*1024, MAX_CIPHER=34*1024*1024, CHUNK=65536;
const encoder=new TextEncoder(), decoder=new TextDecoder('utf-8',{fatal:true});
export async function ready(){await sodium.ready;return sodium;}
export function b64(bytes){return sodium.to_base64(bytes,sodium.base64_variants.URLSAFE_NO_PADDING);}
export function unb64(value){if(!/^[A-Za-z0-9_-]+$/.test(value))throw Error('Invalid code');return sodium.from_base64(value,sodium.base64_variants.URLSAFE_NO_PADDING);}
export function safeName(name){
 if(typeof name!=='string'||!name||encoder.encode(name).length>240||/[\x00-\x1f\x7f/\\:]/.test(name)||name.startsWith('.')||/[. ]$/.test(name)||/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(name))throw Error('Unsafe filename');
 return name;
}
function manifest(file){safeName(file.name);if(!Number.isSafeInteger(file.size)||file.size<1||file.size>MAX_PLAIN)throw Error('File exceeds the 32 MiB limit');return encoder.encode(JSON.stringify({name:file.name,size:file.size}));}
function u32(n){return new Uint8Array([(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255]);}
export function cipherSize(file,upload=false){const m=manifest(file);return 5+(upload?80:0)+24+4+m.length+17+file.size+Math.ceil(file.size/CHUNK)*21+21;}
export async function encrypt(file,publicKey=null){
 await ready(); const meta=manifest(file), key=sodium.crypto_secretstream_xchacha20poly1305_keygen();
 const upload=publicKey!==null, prefix=encoder.encode(upload?'NSH1U':'NSH1D');
 const stream=sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
 const chunks=[prefix];
 if(upload){if(publicKey.length!==32)throw Error('Invalid inbox key');chunks.push(sodium.crypto_box_seal(key,publicKey));}
 chunks.push(stream.header);
 const frame=(data,tag)=>{const c=sodium.crypto_secretstream_xchacha20poly1305_push(stream.state,data,prefix,tag);chunks.push(u32(c.length),c);};
 frame(meta,sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
 for(let offset=0;offset<file.size;offset+=CHUNK)frame(new Uint8Array(await file.slice(offset,offset+CHUNK).arrayBuffer()),sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
 frame(new Uint8Array(),sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
 const blob=new Blob(chunks,{type:'application/octet-stream'});
 if(blob.size!==cipherSize(file,upload)||blob.size>MAX_CIPHER)throw Error('Invalid encrypted size');
 return {blob,key};
}
export async function decrypt(bytes,key,box=null){
 await ready();if(!(bytes instanceof Uint8Array)||bytes.length>MAX_CIPHER||bytes.length<50)throw Error('Invalid encrypted file');
 let pos=0; const take=n=>{if(n<0||pos+n>bytes.length)throw Error('Truncated encrypted file');const v=bytes.subarray(pos,pos+n);pos+=n;return v;};
 const prefix=take(5), kind=decoder.decode(prefix);
 if(!['NSH1D','NSH1U'].includes(kind))throw Error('Unsupported encrypted format');
 if(kind==='NSH1U'){if(!box)throw Error('Inbox key required');key=sodium.crypto_box_seal_open(take(80),box.publicKey,box.privateKey);}
 if(!key||key.length!==32)throw Error('Invalid file key');
 const state=sodium.crypto_secretstream_xchacha20poly1305_init_pull(take(24),key);
 const pull=()=>{const length=take(4),n=new DataView(length.buffer,length.byteOffset,4).getUint32(0);if(n<17||n>CHUNK+17)throw Error('Invalid chunk');const r=sodium.crypto_secretstream_xchacha20poly1305_pull(state,take(n),prefix);if(!r)throw Error('Authentication failed');return r;};
 const first=pull();if(first.tag!==0||first.message.length>4096)throw Error('Invalid encrypted manifest');
 const meta=JSON.parse(decoder.decode(first.message));safeName(meta.name);
 if(!Number.isSafeInteger(meta.size)||meta.size<1||meta.size>MAX_PLAIN)throw Error('Invalid plaintext size');
 const chunks=[];let size=0, final=false;
 while(pos<bytes.length){const r=pull();if(r.tag===3){if(r.message.length!==0||pos!==bytes.length)throw Error('Invalid stream ending');final=true;break;}if(r.tag!==0||r.message.length<1)throw Error('Invalid data frame');size+=r.message.length;if(size>meta.size)throw Error('Plaintext limit exceeded');chunks.push(r.message);}
 if(!final||size!==meta.size)throw Error('Incomplete encrypted file');
 return {name:meta.name,blob:new Blob(chunks,{type:'application/octet-stream'})};
}
