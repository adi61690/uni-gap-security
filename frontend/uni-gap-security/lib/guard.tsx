'use client';
import {useEffect} from 'react';import {useRouter} from 'next/navigation';import {useApp} from '@/store/app';
export function Guard(){const u=useApp(s=>s.user),r=useRouter();useEffect(()=>{if(!u)r.replace('/login')},[u,r]);return null}
