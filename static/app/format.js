// format.js — pure, DOM-free formatting helpers: Markdown → safe HTML plus
// message-time helpers. Ported from gianna's static/app/format.js (the
// hand-written escape-first renderer — no vendored lib, nothing the CSP's
// script-src 'self' objects to), minus everything household-specific
// (liturgy, cron phrasing, push key decoding, image fitting).

import { escapeHtml } from './api.js';

/* The destination host of a model-authored link, for display next to its label
   (markdown-link-exfiltration defence — see renderMarkdown). http(s) -> the
   hostname; mailto -> the address's domain. '' when nothing sensible. */
export function linkHost(url){
  url=String(url==null?'':url);
  const mail=url.match(/^mailto:[^@\s]+@([^?\s)]+)/i);
  if(mail)return mail[1].toLowerCase();
  try{return new URL(url).hostname.toLowerCase();}
  catch(_){
    const m=url.match(/^https?:\/\/([^/?#\s]+)/i);
    return m?m[1].toLowerCase():'';
  }
}

/* Render the agent's Markdown (**bold**, *italic*, `code`, ``` blocks ```,
   # headings, - bullets, [text](url)) to a small, safe HTML subset. XSS-safe by
   construction: the raw text is HTML-escaped FIRST, so the only special chars
   left are entities; we then insert a fixed allowlist of tags and never echo raw
   user/model markup. Newlines are preserved by the bubble's white-space:pre-wrap. */
export function renderMarkdown(src){
  src=String(src==null?'':src);
  // Pull fenced code blocks out before escaping so their contents are shown
  // verbatim (and never parsed as markup). Placeholders, restored last.
  const blocks=[];
  let s=src.replace(/```[^\n]*\n?([\s\S]*?)```/g,(_,code)=>{
    blocks.push(code.replace(/\n$/,''));
    return ' B'+(blocks.length-1)+' ';
  });
  s=escapeHtml(s);
  // Inline code first (its contents must not be parsed for bold/italic).
  const inline=[];
  s=s.replace(/`([^`]+)`/g,(_,c)=>{inline.push(c);return ' I'+(inline.length-1)+' ';});
  s=s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
     .replace(/__([^_]+)__/g,'<strong>$1</strong>')
     .replace(/(^|[^*])\*([^*\n]+)\*/g,'$1<em>$2</em>')
     .replace(/(^|[^_\w])_([^_\n]+)_/g,'$1<em>$2</em>');
  // Links [text](url) — only http(s)/mailto, so javascript: can't sneak
  // through. The destination host is surfaced after the label when the label
  // doesn't already show it (markdown-link exfiltration defence: a mismatched
  // destination is visible before anyone clicks). Never auto-loaded.
  s=s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+|mailto:[^\s)]+)\)/g,
    (_,label,url)=>{
      const host=linkHost(url);
      const showHost=host && label.toLowerCase().indexOf(host.toLowerCase())===-1;
      const suffix=showHost?' ('+host+')':'';
      return `<a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>${suffix}`;
    });
  // Block pass: markdown tables (a header row of |cells|, a |---|:---|
  // separator row, then body rows) become a real <table>. Runs before the
  // per-line pass so table lines never get bullet/heading treatment, and
  // the rows are joined WITHOUT newlines — the bubble's white-space:
  // pre-wrap would otherwise render each inter-row newline as a blank line.
  const lines=s.split('\n');
  const out=[];
  const isRow=(l)=>/^\s*\|.*\|\s*$/.test(l);
  const isSep=(l)=>/^\s*\|(\s*:?-+:?\s*\|)+\s*$/.test(l);
  const cells=(l)=>l.trim().replace(/^\|/,'').replace(/\|$/,'').split('|').map(c=>c.trim());
  for(let i=0;i<lines.length;i++){
    if(isRow(lines[i])&&i+1<lines.length&&isSep(lines[i+1])){
      let html='<table><thead><tr>'+cells(lines[i]).map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>';
      i+=1; // skip the separator row
      while(i+1<lines.length&&isRow(lines[i+1])&&!isSep(lines[i+1])){
        i+=1;
        html+='<tr>'+cells(lines[i]).map(c=>'<td>'+c+'</td>').join('')+'</tr>';
      }
      out.push(html+'</tbody></table>');
      continue;
    }
    out.push(lines[i]);
  }
  // Per-line: headings -> bold line; -/* bullets -> • marker.
  s=out.map(line=>{
    if(line.startsWith('<table>'))return line;
    const h=line.match(/^\s*#{1,6}\s+(.*)$/);
    if(h)return '<strong>'+h[1]+'</strong>';
    const b=line.match(/^(\s*)[-*]\s+(.*)$/);
    if(b)return b[1]+'• '+b[2];
    return line;
  }).join('\n');
  // Restore code. Inline spans were captured AFTER escaping (already safe);
  // fenced blocks were pulled out BEFORE escaping, so escape them now.
  s=s.replace(/ I(\d+) /g,(_,i)=>'<code>'+inline[+i]+'</code>');
  s=s.replace(/ B(\d+) /g,(_,i)=>'<pre><code>'+escapeHtml(blocks[+i])+'</code></pre>');
  return s;
}

// Coerce an `at` (ISO string, Date, or null for a live message) to a Date.
export function asDate(at){
  if(at instanceof Date)return at;
  if(at){const d=new Date(at);if(!isNaN(d))return d;}
  return new Date();
}

// HH:MM in the viewer's locale/timezone (the server sends UTC).
export function fmtTime(d){
  try{return d.toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});}
  catch(_){return '';}
}
