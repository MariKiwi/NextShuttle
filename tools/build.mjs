import {build} from 'esbuild';
import {mkdir} from 'node:fs/promises';
await mkdir('relay/static',{recursive:true});
await mkdir('nextcloud/nextshuttle/js',{recursive:true});
for(const [entry,out] of [
  ['web/public.mjs','relay/static/public.js'],
  ['web/nextcloud.mjs','nextcloud/nextshuttle/js/main.js'],
  ['web/files.mjs','nextcloud/nextshuttle/js/files.js'],
]) await build({entryPoints:[entry],outfile:out,bundle:true,minify:true,format:'iife',target:'es2022',legalComments:'eof'});
