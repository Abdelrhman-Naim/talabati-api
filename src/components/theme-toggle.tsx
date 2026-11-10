'use client';
import {useEffect,useState} from 'react';
import {Moon,Sun} from 'lucide-react';
export default function ThemeToggle(){
 const [theme,setTheme]=useState('light');
 useEffect(()=>{setTheme(document.documentElement.dataset.theme??'light');},[]);
 function change(){const next=theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;setTheme(next);try{localStorage.setItem('aegis-theme',next);}catch{}}
 return <button className="theme-toggle" onClick={change} aria-label={theme==='dark'?'تفعيل الوضع الفاتح':'تفعيل الوضع الداكن'} title="تغيير المظهر">{theme==='dark'?<Sun size={17}/>:<Moon size={17}/>}<span>{theme==='dark'?'فاتح':'داكن'}</span></button>;
}
