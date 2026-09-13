'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Activity,
  Bell,
  BrainCircuit,
  ChartNoAxesCombined,
  ClipboardList,
  Crosshair,
  FileBarChart,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  Microscope,
  Moon,
  Network,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sun,
  TriangleAlert,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { useApp } from '@/store/app';
import { AuthService } from '@/lib/services';
import type { Notification } from '@/types';
import { Badge } from './ui';

type NavItem = {
  name: string;
  href: string;
  icon: LucideIcon;
  badge?: number;
};

type CommandItem = {
  name: string;
  href: string;
};

const nav: NavItem[] = [
  { href: '/', name: 'Overview', icon: LayoutDashboard },
  { href: '/traffic', name: 'Traffic', icon: Activity },
  { href: '/threats', name: 'Threats', icon: ShieldAlert },
  { href: '/ai-lab', name: 'AI Lab', icon: BrainCircuit },
  { href: '/evidence', name: 'Evidence', icon: Microscope },
  { href: '/network', name: 'Network', icon: Network },
  { href: '/data-diode', name: 'Data Diode', icon: ShieldCheck },
  { href: '/pcap-replay', name: 'PCAP Replay', icon: FileSearch },
  { href: '/incidents', name: 'Incidents', icon: TriangleAlert },
  { href: '/threat-hunt', name: 'Threat Hunt', icon: Crosshair },
  { href: '/analytics', name: 'Analytics', icon: ChartNoAxesCombined },
  { href: '/reports', name: 'Reports', icon: FileBarChart },
  { href: '/audit', name: 'Audit', icon: ClipboardList },
  { href: '/settings', name: 'Settings', icon: Settings2 },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [mobile, setMobile] = useState(false);
  const [profile, setProfile] = useState(false);
  const [notes, setNotes] = useState(false);
  const user = useApp((state) => state.user);
  const theme = useApp((state) => state.theme);
  const setTheme = useApp((state) => state.setTheme);
  const logout = useApp((state) => state.logout);
  const notesArr = useApp((state) => state.notifications);
  const mark = useApp((state) => state.markRead);
  const alerts = useApp((state) => state.alerts);
  const connection = useApp((state) => state.connection);
  const audit = useApp((state) => state.addAudit);
  const [cmd, setCmd] = useState(false);
  const initials = (user?.name || 'Analyst')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((initial: string) => initial[0])
    .join('')
    .toUpperCase();
  const connectionLabel = connection === 'LAB' ? 'LAB DATA — STATIC DATASET' : connection === 'LIVE' ? 'LIVE BACKEND' : connection === 'RECONNECTING' ? 'RECONNECTING' : 'BACKEND OFFLINE';

  return (
    <div className="min-h-screen" style={{ background: 'var(--bg)' }}>
      <aside className={`fixed z-40 top-0 bottom-0 left-0 w-64 p-4 border-r transition-transform ${mobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`} style={{ background: 'var(--surface)', borderColor: 'var(--border)' }}>
        <div className="flex items-center justify-between px-2 mb-5">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 rounded-xl grid place-items-center text-white font-extrabold" style={{ background: 'linear-gradient(135deg,var(--iris),var(--mint))' }}>U</div>
            <div><div className="font-extrabold">Uni-Gap</div><div className="text-[10px] mono" style={{ color: 'var(--muted)' }}>SECURITY</div></div>
          </div>
          <button className="lg:hidden" onClick={() => setMobile(false)}><X /></button>
        </div>
        <div className="text-[10px] font-bold uppercase tracking-[.15em] px-2 mb-2" style={{ color: 'var(--muted)' }}>Command Center</div>
        <nav className="space-y-1 overflow-y-auto max-h-[calc(100vh-180px)] scrollbar">
          {nav.map((item: NavItem) => {
            const Icon = item.icon;
            const badge = item.name === 'Threats' ? alerts.length : item.badge;
            return <Link onClick={() => setMobile(false)} href={item.href} key={item.href} className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium" style={{ background: path === item.href ? 'color-mix(in srgb,var(--iris) 11%,transparent)' : 'transparent', color: path === item.href ? 'var(--iris)' : 'var(--muted)' }}><Icon size={17} /><span>{item.name}</span>{badge !== undefined && badge > 0 && <Badge tone="critical">{badge}</Badge>}</Link>;
          })}
        </nav>
        <div className="absolute bottom-4 left-4 right-4 soft rounded-xl p-3 text-xs"><div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full" style={{ background: connection === 'LAB' ? 'var(--gold)' : 'var(--mint)' }} /><span>One-way ingest active</span></div><div className="mono mt-1" style={{ color: 'var(--muted)' }}>{connectionLabel}</div></div>
      </aside>
      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 h-16 px-4 md:px-6 flex items-center justify-between border-b backdrop-blur-xl" style={{ background: 'color-mix(in srgb,var(--bg) 88%,transparent)', borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-3"><button className="lg:hidden p-2 rounded-xl soft" onClick={() => setMobile(true)}><Menu size={18} /></button><div><div className="text-xs" style={{ color: 'var(--muted)' }}>Passive security monitoring</div><div className="font-bold">{nav.find((item: NavItem) => item.href === path)?.name || 'Overview'}</div></div></div>
          <button onClick={() => setCmd(true)} className="hidden md:flex items-center gap-2 px-3 py-2 rounded-xl soft text-sm" style={{ color: 'var(--muted)' }}><Search size={16} /> Search <kbd className="mono text-[10px] px-1.5 py-0.5 rounded border" style={{ borderColor: 'var(--border)' }}>Ctrl K</kbd></button>
          <div className="flex items-center gap-1"><div className="hidden sm:flex items-center gap-2 text-xs px-2.5 py-2 rounded-xl" style={{ color: connection === 'LIVE' ? 'var(--mint)' : connection === 'RECONNECTING' || connection === 'LAB' ? 'var(--gold)' : 'var(--muted)' }}><span className="w-2 h-2 rounded-full" style={{ background: connection === 'LIVE' ? 'var(--mint)' : connection === 'RECONNECTING' || connection === 'LAB' ? 'var(--gold)' : 'var(--muted)' }} />{connectionLabel}</div><button onClick={() => { setNotes(!notes); mark(); }} className="relative p-2 rounded-xl hover:bg-[var(--bg2)]"><Bell size={18} />{notesArr.some((notification: Notification) => !notification.read) && <span className="absolute top-1 right-1 w-2 h-2 rounded-full" style={{ background: 'var(--coral)' }} />}</button><button onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} className="p-2 rounded-xl hover:bg-[var(--bg2)]">{theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}</button><div className="relative"><button onClick={() => setProfile(!profile)} className="flex items-center gap-2 p-1 rounded-xl"><span className="w-8 h-8 rounded-full grid place-items-center text-white text-xs font-bold overflow-hidden" style={{ background: 'var(--iris)' }}>{initials || 'A'}</span></button>{profile && <div className="absolute right-0 mt-2 w-56 surface rounded-2xl p-2 shadow-xl"><div className="p-3"><div className="font-semibold">{user?.name || 'Analyst'}</div><div className="text-xs" style={{ color: 'var(--muted)' }}>{user?.role || 'Security Analyst'}</div></div><button className="w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-[var(--bg2)]">Session details</button><button className="w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-[var(--bg2)]">Audit activity</button><button onClick={async () => { await AuthService.logout(); audit('Logout'); logout(); router.push('/login'); }} className="w-full text-left px-3 py-2 rounded-lg text-sm text-[var(--coral)] hover:bg-[var(--bg2)]"><LogOut size={15} className="inline mr-2" />Logout</button></div>}</div></div>
        </header>
        {notes && <div className="fixed right-4 top-16 z-40 w-[min(380px,calc(100vw-2rem))] surface rounded-2xl shadow-xl p-3"><div className="flex justify-between p-2"><b>Notifications</b><span className="text-xs" style={{ color: 'var(--muted)' }}>{notesArr.length} total</span></div>{notesArr.slice(0, 6).map((notification: Notification) => <div key={notification.id} className="p-3 rounded-xl hover:bg-[var(--bg2)]"><div className="text-sm font-semibold">{notification.title}</div><div className="text-xs" style={{ color: 'var(--muted)' }}>{notification.detail}</div></div>)}</div>}
        {children}
      </div>
      {cmd && <Command onClose={() => setCmd(false)} />}
    </div>
  );
}

function Command({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const items: CommandItem[] = [...nav.map((item: NavItem): CommandItem => ({ name: item.name, href: item.href })), { name: 'Show critical threats', href: '/threats' }, { name: 'Open PCAP replay', href: '/pcap-replay' }, { name: 'Show DGA detections', href: '/threats' }, { name: 'Show C2 detections', href: '/threats' }];
  const filteredItems: CommandItem[] = items.filter((item: CommandItem) => item.name.toLowerCase().includes(q.toLowerCase()));

  return <div className="fixed inset-0 z-50 grid place-items-start pt-[15vh] bg-black/30" onClick={onClose}><div className="w-[min(650px,calc(100vw-2rem))] surface rounded-2xl shadow-2xl overflow-hidden" onClick={(event: React.MouseEvent<HTMLDivElement>) => event.stopPropagation()}><div className="p-4 flex gap-3 border-b" style={{ borderColor: 'var(--border)' }}><Search /><input autoFocus value={q} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setQ(event.target.value)} onKeyDown={(event: React.KeyboardEvent<HTMLInputElement>) => event.key === 'Escape' && onClose()} placeholder="Search pages and actions..." className="flex-1 outline-none bg-transparent" /></div><div className="max-h-96 overflow-auto p-2">{filteredItems.map((item: CommandItem) => <button key={item.name} onClick={() => { router.push(item.href); onClose(); }} className="w-full text-left px-3 py-3 rounded-xl hover:bg-[var(--bg2)] text-sm">{item.name}</button>)}</div></div></div>;
}
