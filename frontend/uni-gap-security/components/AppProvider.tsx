'use client';
import { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { useApp } from '@/store/app';
import { Guard } from '@/lib/guard';
import { AuthService, WebSocketService } from '@/lib/services';
export function AppProvider({children}:{children:React.ReactNode}){
  const theme=useApp(s=>s.theme), add=useApp(s=>s.addAlert), path=usePathname();
  const user=useApp(s=>s.user), setUser=useApp(s=>s.setUser), setConnection=useApp(s=>s.setConnection);
  const socketRef=useRef<WebSocketService|null>(null);
  useEffect(()=>{document.body.classList.toggle('dark',theme==='dark'||(theme==='system'&&matchMedia('(prefers-color-scheme:dark)').matches))},[theme]);
  useEffect(()=>{let active=true; AuthService.restore().then(u=>{if(active && u && !useApp.getState().user) setUser(u)}); return()=>{active=false}},[setUser]);
  useEffect(()=>{
    if(!user) return;
    const svc=new WebSocketService(); socketRef.current=svc;
    svc.connect(process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/alerts', add, s=>setConnection(s==='LIVE'?'LIVE':(s as any)));
    return()=>{svc.close(); socketRef.current=null};
  },[user,add,setConnection]);
  useEffect(()=>{if(path!=='/login')localStorage.setItem('lastPath',path)},[path]);
  return <>{path!=='/login'&&<Guard/>}{children}</>;
}
