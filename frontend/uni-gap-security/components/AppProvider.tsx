'use client';
import { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { useApp } from '@/store/app';
import { Guard } from '@/lib/guard';
import { AuthService, loadLabDataset, loadLabFlowRows, WebSocketService } from '@/lib/services';

export function AppProvider({children}:{children:React.ReactNode}){
  const theme=useApp(s=>s.theme), add=useApp(s=>s.addAlert), path=usePathname();
  const user=useApp(s=>s.user), setUser=useApp(s=>s.setUser), setAuthReady=useApp(s=>s.setAuthReady), setConnection=useApp(s=>s.setConnection);
  const setLabData=useApp(s=>s.setLabData), setLabReplayData=useApp(s=>s.setLabReplayData), startLabReplay=useApp(s=>s.startLabReplay), pauseLabReplay=useApp(s=>s.pauseLabReplay), advanceLabReplay=useApp(s=>s.advanceLabReplay), labReplay=useApp(s=>s.labReplay);
  const socketRef=useRef<WebSocketService|null>(null);

  useEffect(()=>{document.body.classList.toggle('dark',theme==='dark'||(theme==='system'&&matchMedia('(prefers-color-scheme:dark)').matches))},[theme]);
  useEffect(()=>{
    let active=true;
    AuthService.restore().then(u=>{if(active && u && !useApp.getState().user) setUser(u)}).finally(()=>{if(active) setAuthReady(true)});
    return()=>{active=false};
  },[setUser,setAuthReady]);

  useEffect(()=>{
    if(!user) return;
    let active=true;

    const loadFallback=async()=>{
      try {
        const rows = await loadLabFlowRows(process.env.NEXT_PUBLIC_BASE_PATH || '');
        if(active && useApp.getState().connection !== 'LIVE') {
          setLabReplayData(rows);
          setConnection('LAB');
          startLabReplay();
        }
      } catch {
        try {
          const rows = await loadLabFlowRows('');
          if(active && useApp.getState().connection !== 'LIVE') {
            setLabReplayData(rows);
            setConnection('LAB');
            startLabReplay();
          }
        } catch { /* The backend may provide data instead. */ }
      }
    };

    loadFallback();
    const svc=new WebSocketService(); socketRef.current=svc;
    svc.connect(process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/alerts', add, s=>{
      const state=s==='LIVE'?'LIVE':(s as 'RECONNECTING'|'DISCONNECTED');
      setConnection(state);
      if(state==='LIVE') {
        pauseLabReplay();
        return;
      }
      startLabReplay();
      if(state!=='RECONNECTING') loadFallback();
    });
    return()=>{active=false;svc.close(); socketRef.current=null};
  },[user,add,setConnection,setLabData,setLabReplayData,startLabReplay,pauseLabReplay]);

  useEffect(()=>{
    if(!user || useApp.getState().connection === 'LIVE' || !labReplay.datasetRows.length || !labReplay.running) return;
    const delay = {1:2000,2:1000,5:400,10:200}[labReplay.speed] ?? 2000;
    const timer = window.setInterval(() => {
      if (useApp.getState().connection === 'LIVE') {
        useApp.getState().pauseLabReplay();
        return;
      }
      useApp.getState().advanceLabReplay();
    }, delay);
    return ()=> window.clearInterval(timer);
  }, [user, labReplay.running, labReplay.speed, labReplay.datasetRows.length, labReplay.cursor, labReplay.windowSize]);

  useEffect(()=>{if(path!=='/login')localStorage.setItem('lastPath',path)},[path]);
  return <>{path!=='/login'&&<Guard/>}{children}</>;
}
