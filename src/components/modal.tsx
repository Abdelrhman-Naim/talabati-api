'use client';
import React,{useRef} from 'react';
import {X} from 'lucide-react';
export default function Modal({title,subtitle,children,onClose,wide=false,error}:{title:string;subtitle?:string;children:React.ReactNode;onClose:()=>void;wide?:boolean;error?:string}){
  const ref=useRef<HTMLElement>(null);
  return <div className="modal-backdrop" onClick={onClose}><section ref={ref} className={'modal '+(wide?'wide-modal':'')} role="dialog" aria-modal="true" aria-labelledby="dialog-title" onClick={e=>e.stopPropagation()} onKeyDown={e=>{
    if(e.key!=='Tab')return;const els=ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href]');if(!els?.length)return;const first=els[0],last=els[els.length-1];if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  }}><header><div><h2 id="dialog-title">{title}</h2><p>{subtitle}</p></div><button autoFocus className="icon-button" onClick={onClose} aria-label="إغلاق النافذة"><X size={20}/></button></header><div className="modal-body">{error&&<div className="alert error" role="alert">{error}</div>}{children}</div></section></div>;
}
