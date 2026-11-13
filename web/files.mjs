import {registerFileAction} from '@nextcloud/files';
import {registerSidebarAction} from '@nextcloud/sharing/ui';
import {openTransfer} from './api.mjs';
const icon='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="currentColor" d="M3 6h13l-3-3 2-2 7 7-7 7-2-2 3-3H3zm18 12H8l3 3-2 2-7-7 7-7 2 2-3 3h13z"/></svg>';
registerFileAction({id:'nextshuttle',displayName:({nodes})=>nodes[0]?.type==='folder'?'Receive with NextShuttle':'Share with NextShuttle',iconSvgInline:()=>icon,
 enabled:({nodes})=>nodes.length===1&&Boolean(nodes[0].permissions&16),order:45,
 exec:async({nodes})=>{await openTransfer(nodes[0]);return null;}});
class ShuttleAction extends HTMLElement{
 set node(value){this._node=value;this.render();}get node(){return this._node;}
 set share(value){}onSave(callback){}
 connectedCallback(){this.render();}
 render(){this.replaceChildren();if(!this._node)return;const b=document.createElement('button');b.type='button';b.textContent=this._node.type==='folder'?'Receive with NextShuttle':'Share with NextShuttle';b.addEventListener('click',()=>openTransfer(this._node));this.append(b);}
}
if(!customElements.get('oca_nextshuttle-sharing_action'))customElements.define('oca_nextshuttle-sharing_action',ShuttleAction);
registerSidebarAction({id:'nextshuttle',element:'oca_nextshuttle-sharing_action',order:40,enabled:(_share,node)=>Boolean(node?.permissions&16)});
