'use client';
import { create } from 'zustand';
import { Alert, AuditEvent, Notification, Telemetry } from '@/types';

interface UserSession {
  name: string;
  role: string;
  session: string;
  source: 'backend'|'demo';
  token?: string;
}

interface S {
  user: UserSession|null;
  theme: 'light'|'dark'|'system';
  alerts: Alert[];
  telemetry: Telemetry[];
  monitoring: boolean;
  notifications: Notification[];
  audit: AuditEvent[];
  threshold: number;
  density: 'comfortable'|'compact';
  animations: boolean;
  connection: 'LIVE'|'RECONNECTING'|'DISCONNECTED'|'DEMO';
  setUser:(u:UserSession|null)=>void;
  logout:()=>void;
  toggleMonitoring:()=>void;
  addAlert:(a:Alert)=>void;
  markRead:()=>void;
  addAudit:(e:string)=>void;
  setTheme:(t:any)=>void;
  setThreshold:(n:number)=>void;
  setDensity:(d:any)=>void;
  setAnimations:(b:boolean)=>void;
  addNotification:(n:Notification)=>void;
  setConnection:(s:S['connection'])=>void;
}

export const useApp=create<S>((set)=>({
  user:null,
  theme:'light',
  alerts:[],
  telemetry:[],
  monitoring:true,
  notifications:[],
  audit:[],
  threshold:80,
  density:'comfortable',
  animations:true,
  connection:'DEMO',
  setUser:u=>set({user:u}),
  logout:()=>set({user:null,monitoring:false}),
  toggleMonitoring:()=>set(s=>({monitoring:!s.monitoring})),
  addAlert:a=>set(s=>({alerts:[a,...s.alerts].slice(0,120),notifications:[{id:crypto.randomUUID(),time:new Date().toISOString(),title:`New ${a.severity.toLowerCase()} threat detected`,detail:`${a.threat_class} · ${Math.round(a.confidence*100)}% confidence`,read:false,type:(a.severity==='Critical'?'critical':'info') as Notification['type']},...s.notifications].slice(0,40)})),
  markRead:()=>set(s=>({notifications:s.notifications.map(n=>({...n,read:true}))})),
  addAudit:e=>set(s=>({audit:[{timestamp:new Date().toISOString(),analyst:s.user?.name||'Analyst',role:s.user?.role||'Security Analyst',event:e,status:'Success',session:s.user?.session||'SES-DEMO'},...s.audit]})),
  setTheme:t=>set({theme:t}),
  setThreshold:n=>set({threshold:n}),
  setDensity:d=>set({density:d}),
  setAnimations:b=>set({animations:b}),
  addNotification:n=>set(s=>({notifications:[n,...s.notifications]})),
  setConnection:s=>set({connection:s}),
}));
