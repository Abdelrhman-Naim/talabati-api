import type {Metadata} from 'next';
import './globals.css';
import './workspace.css';
import './auth.css';
export const metadata:Metadata={title:'Aegis Audit — مساحة جودة مشروعك',description:'فحوص ويب بأدلة واضحة وبرومبتات تساعدك على الإصلاح. نسخة تجريبية للمبرمجين.'};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="ar" dir="rtl" suppressHydrationWarning><head><script dangerouslySetInnerHTML={{__html:`try{var t=localStorage.getItem('aegis-theme');document.documentElement.dataset.theme=t==='dark'||t==='light'?t:matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}catch(e){document.documentElement.dataset.theme='light';}`}}/></head><body>{children}</body></html>;}
