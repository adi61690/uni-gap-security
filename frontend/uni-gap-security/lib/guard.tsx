'use client';
import {useEffect} from 'react';import {useRouter} from 'next/navigation';import {useApp} from '@/store/app';
export function Guard(){const u=useApp(s=>s.user),authReady=useApp(s=>s.authReady),r=useRouter();useEffect(()=>{if(authReady&&!u)r.replace('/login')},[authReady,u,r]);return null}
