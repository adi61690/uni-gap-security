'use client';
import {useEffect} from 'react';
import {useRouter} from 'next/navigation';
import {useApp} from '@/store/app';
import {Shell} from '@/components/Shell';
import {Settings} from '@/components/Pages';
export default function Page(){const u=useApp(s=>s.user),r=useRouter(); useEffect(()=>{if(!u)r.replace('/login')},[u,r]); if(!u)return null; return <Shell><Settings/></Shell>}
