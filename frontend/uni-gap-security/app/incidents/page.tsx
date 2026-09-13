'use client';
import {useEffect} from 'react';
import {useRouter} from 'next/navigation';
import {useApp} from '@/store/app';
import {Shell} from '@/components/Shell';
import {DatasetIncidents} from '@/components/Pages';
export default function Page(){const u=useApp(s=>s.user),authReady=useApp(s=>s.authReady),r=useRouter(); useEffect(()=>{if(authReady&&!u)r.replace('/login')},[authReady,u,r]); if(!authReady)return <main className="min-h-screen grid place-items-center" style={{background:'var(--bg)',color:'var(--muted)'}}>Restoring session...</main>; if(!u)return null; return <Shell><DatasetIncidents/></Shell>}
