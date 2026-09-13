'use client';
import { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { useApp } from '@/store/app';
import { Guard } from '@/lib/guard';
import { AuthService, loadLabDataset, WebSocketService } from '@/lib/services';
export function AppProvider({children}:{children:React.ReactNode}){
  const theme=useApp(s=>s.theme), add=useApp(s=>s.addAlert), path=usePathname();
  const user=useApp(s=>s.user), setUser=useApp(s=>s.setUser), setAuthReady=useApp(s=>s.setAuthReady), setConnection=useApp(s=>s.setConnection), setLabData=useApp(s=>s.setLabData);
  const socketRef=useRef<WebSocketService|null>(null);
  useEffect(()=>{document.body.classList.toggle('dark',theme==='dark'||(theme==='system'&&matchMedia('(prefers-color-scheme:dark)').matches))},[theme]);
  useEffect(()=>{
    let active=true;
    AuthService.restore()
      .then(u=>{if(active && u && !useApp.getState().user) setUser(u)})
      .finally(()=>{if(active) setAuthReady(true)});
    return()=>{active=false};
  },[setUser,setAuthReady]);
  useEffect(()=>{
    if(!user) return;
    let active=true;
    const loadFallback=async()=>{
      try {
        const data=await loadLabDataset('/uni-gap-security');
        if(active && useApp.getState().connection!=='LIVE') setLabData(data.alerts,data.telemetry);
      } catch {
        try {
          const data=await loadLabDataset('');
          if(active && useApp.getState().connection!=='LIVE') setLabData(data.alerts,data.telemetry);
        } catch { /* The backend may provide data instead. */ }
      }
    };
    loadFallback();
    const svc=new WebSocketService(); socketRef.current=svc;
    svc.connect(process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/alerts', add, s=>{
      const state=s==='LIVE'?'LIVE':(s as 'RECONNECTING'|'DISCONNECTED');
      setConnection(state);
      if(state!=='LIVE') loadFallback();
    });
    return()=>{active=false;svc.close(); socketRef.current=null};
  },[user,add,setConnection,setLabData]);
  useEffect(()=>{if(path!=='/login')localStorage.setItem('lastPath',path)},[path]);
  return <>{path!=='/login'&&<Guard/>}{children}</>;
}
