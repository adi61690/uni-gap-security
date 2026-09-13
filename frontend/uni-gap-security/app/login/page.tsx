'use client';
import {FormEvent, useState} from 'react';
import {useRouter} from 'next/navigation';
import {ShieldCheck, Eye, EyeOff, Loader2, LockKeyhole} from 'lucide-react';
import {AuthService} from '@/lib/services';
import {useApp} from '@/store/app';

export default function LoginPage(){
  const router=useRouter();
  const setUser=useApp(s=>s.setUser);
  const [username,setUsername]=useState('analyst');
  const [password,setPassword]=useState('analyst123');
  const [show,setShow]=useState(false);
  const [remember,setRemember]=useState(true);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  async function submit(e:FormEvent){
    e.preventDefault(); setBusy(true); setError('');
    try{
      const u=await AuthService.login(username.trim(),password,remember);
      if(!u){setError('Invalid username or password.');return;}
      setUser(u); router.replace('/');
    }finally{setBusy(false);}
  }
  return <main className="min-h-screen grid lg:grid-cols-2" style={{background:'var(--bg)'}}>
    <section className="hidden lg:flex p-10 xl:p-16 items-end" style={{background:'linear-gradient(135deg,var(--soft),var(--bg2))'}}>
      <div className="max-w-xl">
        <div className="flex items-center gap-3"><div className="w-12 h-12 rounded-2xl grid place-items-center text-white" style={{background:'linear-gradient(135deg,var(--iris),var(--mint))'}}><ShieldCheck/></div><div><div className="text-2xl font-extrabold">Uni-Gap Security</div><div className="text-xs mono" style={{color:'var(--muted)'}}>UNIDIRECTIONAL THREAT INTELLIGENCE</div></div></div>
        <h1 className="text-5xl font-extrabold tracking-tight mt-10 leading-tight">Passive visibility for one-way critical networks.</h1>
        <p className="mt-5 text-lg leading-8" style={{color:'var(--muted)'}}>Observe packet and flow metadata, enrich with ML detections, and present explainable evidence without creating a return path.</p>
        <div className="flex flex-wrap gap-2 mt-7">{['Read-only ingest','No active probing','TLS/QUIC metadata only','Live WebSocket alerts'].map(x=><span key={x} className="soft rounded-full px-3 py-2 text-xs">{x}</span>)}</div>
      </div>
    </section>
    <section className="grid place-items-center p-6">
      <form onSubmit={submit} className="surface rounded-3xl p-7 w-full max-w-md shadow-xl">
        <div className="flex items-center gap-2 text-xs mono" style={{color:'var(--muted)'}}><LockKeyhole size={15}/> SECURE ANALYST LOGIN</div>
        <h2 className="text-2xl font-extrabold mt-2">Welcome back</h2>
        <p className="text-sm mt-1" style={{color:'var(--muted)'}}>Sign in to the monitoring workspace.</p>
        <label className="block text-sm mt-6">Username<input value={username} onChange={e=>setUsername(e.target.value)} className="soft w-full mt-1 p-3 rounded-xl bg-transparent outline-none" autoComplete="username"/></label>
        <label className="block text-sm mt-4">Password<div className="soft mt-1 rounded-xl flex items-center"><input value={password} onChange={e=>setPassword(e.target.value)} type={show?'text':'password'} className="w-full p-3 bg-transparent outline-none" autoComplete="current-password"/><button type="button" onClick={()=>setShow(v=>!v)} className="p-3" aria-label="Toggle password visibility">{show?<EyeOff size={17}/>:<Eye size={17}/>}</button></div></label>
        <label className="flex items-center gap-2 text-sm mt-4"><input type="checkbox" checked={remember} onChange={e=>setRemember(e.target.checked)}/> Remember session</label>
        {error&&<div className="mt-4 p-3 rounded-xl text-sm" style={{background:'color-mix(in srgb,var(--coral) 10%,transparent)',color:'var(--coral)'}}>{error}</div>}
        <button disabled={busy} className="w-full mt-5 px-4 py-3 rounded-xl text-white font-semibold disabled:opacity-60" style={{background:'var(--iris)'}}>{busy?<><Loader2 size={16} className="inline mr-2 animate-spin"/>Signing in…</>:'Sign in'}</button>
        <div className="mt-4 text-xs text-center" style={{color:'var(--muted)'}}>Local development credential: <span className="mono">analyst / analyst123</span></div>
      </form>
    </section>
  </main>;
}
