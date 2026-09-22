'use client';
import { create } from 'zustand';
import { buildAlertsFromRows, buildLabReplayWindow, buildTelemetryFromRows, LabFlowRow } from '@/lib/labReplay';
import { Alert, AuditEvent, Notification, Telemetry } from '@/types';

interface UserSession {
  name: string;
  role: string;
  session: string;
  source: 'backend'|'demo';
  token?: string;
}

interface LabReplayState {
  running: boolean;
  cursor: number;
  windowSize: number;
  speed: 1 | 2 | 5 | 10;
  processedRows: number;
  loopCount: number;
  startedAt: string | null;
  currentRows: LabFlowRow[];
  datasetRows: LabFlowRow[];
  sessionRows: LabFlowRow[];
  lastTickAt: string | null;
}

interface S {
  user: UserSession|null;
  authReady: boolean;
  theme: 'light'|'dark'|'system';
  alerts: Alert[];
  telemetry: Telemetry[];
  monitoring: boolean;
  notifications: Notification[];
  audit: AuditEvent[];
  threshold: number;
  density: 'comfortable'|'compact';
  animations: boolean;
  connection: 'LIVE'|'RECONNECTING'|'DISCONNECTED'|'DEMO'|'LAB';
  labReplay: LabReplayState;
  setUser:(u:UserSession|null)=>void;
  setAuthReady:(ready:boolean)=>void;
  logout:()=>void;
  toggleMonitoring:()=>void;
  addAlert:(a:Alert)=>void;
  setLabData:(alerts:Alert[],telemetry:Telemetry[])=>void;
  setLabReplayData:(rows:LabFlowRow[])=>void;
  startLabReplay:()=>void;
  pauseLabReplay:()=>void;
  restartLabReplay:()=>void;
  setLabReplaySpeed:(speed:1|2|5|10)=>void;
  advanceLabReplay:()=>void;
  markRead:()=>void;
  addAudit:(e:string)=>void;
  setTheme:(t:any)=>void;
  setThreshold:(n:number)=>void;
  setDensity:(d:any)=>void;
  setAnimations:(b:boolean)=>void;
  addNotification:(n:Notification)=>void;
  setConnection:(s:S['connection'])=>void;
}

const initialReplayState = (): LabReplayState => ({
  running: false,
  cursor: 0,
  windowSize: 220,
  speed: 1,
  processedRows: 0,
  loopCount: 0,
  startedAt: null,
  currentRows: [],
  datasetRows: [],
  sessionRows: [],
  lastTickAt: null,
});

export const useApp=create<S>((set)=>({
  user:null,
  authReady:false,
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
  labReplay: initialReplayState(),
  setUser:u=>set({user:u}),
  setAuthReady:ready=>set({authReady:ready}),
  logout:()=>set({user:null,monitoring:false,connection:'DEMO',labReplay:initialReplayState()}),
  toggleMonitoring:()=>set(s=>({monitoring:!s.monitoring})),
  addAlert:a=>set(s=>({alerts:[a,...s.alerts].slice(0,120),notifications:[{id:crypto.randomUUID(),time:new Date().toISOString(),title:`New ${a.severity.toLowerCase()} threat detected`,detail:`${a.threat_class} · ${Math.round(a.confidence*100)}% confidence`,read:false,type:(a.severity==='Critical'?'critical':'info') as Notification['type']},...s.notifications].slice(0,40)})),
  setLabData:(alerts,telemetry)=>set(s=>s.connection==='LIVE'?{}:{alerts,telemetry,connection:'LAB'}),
  setLabReplayData:(rows)=>set((state)=>{
    const currentRows = buildLabReplayWindow(rows, 0, state.labReplay.windowSize);
    const alerts = buildAlertsFromRows(currentRows);
    const telemetry = buildTelemetryFromRows(currentRows);
    return {
      alerts,
      telemetry,
      connection: state.connection === 'LIVE' ? 'LIVE' : 'LAB',
      labReplay: {
        ...state.labReplay,
        datasetRows: rows,
        currentRows,
        sessionRows: currentRows,
        cursor: 0,
        processedRows: 0,
        loopCount: 0,
        startedAt: state.labReplay.running ? new Date().toISOString() : null,
        lastTickAt: new Date().toISOString(),
      },
    };
  }),
  startLabReplay:()=>set((state)=>{
    if (state.connection === 'LIVE' || !state.labReplay.datasetRows.length) return state;
    return {
      ...state,
      connection: 'LAB',
      labReplay: {
        ...state.labReplay,
        running: true,
        startedAt: state.labReplay.startedAt || new Date().toISOString(),
      },
    };
  }),
  pauseLabReplay:()=>set((state)=>({
    ...state,
    labReplay: {
      ...state.labReplay,
      running: false,
    },
  })),
  restartLabReplay:()=>set((state)=>{
    const rows = state.labReplay.datasetRows;
    if (!rows.length) return state;
    const currentRows = buildLabReplayWindow(rows, 0, state.labReplay.windowSize);
    return {
      ...state,
      alarms: state.alerts,
      alerts: buildAlertsFromRows(currentRows),
      telemetry: buildTelemetryFromRows(currentRows),
      connection: 'LAB',
      labReplay: {
        ...state.labReplay,
        running: true,
        cursor: 0,
        processedRows: 0,
        loopCount: 0,
        startedAt: new Date().toISOString(),
        currentRows,
        sessionRows: currentRows,
        lastTickAt: new Date().toISOString(),
      },
    };
  }),
  setLabReplaySpeed:(speed)=>set((state)=>({
    ...state,
    labReplay: {
      ...state.labReplay,
      speed,
    },
  })),
  advanceLabReplay:()=>set((state)=>{
    const rows = state.labReplay.datasetRows;
    if (!rows.length || state.connection === 'LIVE') return state;

    const nextCursor = (state.labReplay.cursor + Math.max(1, Math.min(30, Math.ceil(state.labReplay.windowSize / 12)))) % rows.length;
    const currentRows = buildLabReplayWindow(rows, nextCursor, state.labReplay.windowSize);
    const nextLoopCount = state.labReplay.cursor + Math.max(1, Math.min(30, Math.ceil(state.labReplay.windowSize / 12))) >= rows.length ? state.labReplay.loopCount + 1 : state.labReplay.loopCount;
    const sessionRows = [...state.labReplay.sessionRows, ...currentRows].slice(-2000);
    const alerts = buildAlertsFromRows(currentRows);
    const telemetry = buildTelemetryFromRows(currentRows);

    return {
      ...state,
      alerts,
      telemetry,
      connection: 'LAB',
      labReplay: {
        ...state.labReplay,
        cursor: nextCursor,
        currentRows,
        sessionRows,
        processedRows: state.labReplay.processedRows + currentRows.length,
        loopCount: nextLoopCount,
        lastTickAt: new Date().toISOString(),
      },
    };
  }),
  markRead:()=>set(s=>({notifications:s.notifications.map(n=>({...n,read:true}))})),
  addAudit:e=>set(s=>({audit:[{timestamp:new Date().toISOString(),analyst:s.user?.name||'Analyst',role:s.user?.role||'Security Analyst',event:e,status:'Success',session:s.user?.session||'SES-DEMO'},...s.audit]})),
  setTheme:t=>set({theme:t}),
  setThreshold:n=>set({threshold:n}),
  setDensity:d=>set({density:d}),
  setAnimations:b=>set({animations:b}),
  addNotification:n=>set(s=>({notifications:[n,...s.notifications]})),
  setConnection:s=>set((state)=>{
    if (s === 'LIVE') {
      return { ...state, connection: s, alerts: [], telemetry: [], labReplay: { ...state.labReplay, running: false } };
    }
    return { ...state, connection: s };
  }),
}));
