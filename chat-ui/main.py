"""Chat UI — proxies questions (and pasted images / attached files) to siem-agent /query."""

import os
import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()

AGENT_HOST = os.getenv("AGENT_HOST", "siem-agent")
AGENT_PORT = os.getenv("AGENT_PORT", "8080")
AGENT_URL  = f"http://{AGENT_HOST}:{AGENT_PORT}"

_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SIEM Chat</title>
<style>
  *{box-sizing:border-box}
  body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
  h1{color:#58a6ff;font-size:1.4rem;margin-bottom:16px}
  #chat{height:380px;overflow-y:auto;border:1px solid #30363d;border-radius:8px;
        padding:14px;background:#161b22;margin-bottom:10px}
  .u{color:#58a6ff;margin:8px 0 2px}.b{color:#7ee787;margin:2px 0 10px;white-space:pre-wrap}
  .err{color:#f85149}
  .msgimg{max-width:140px;max-height:140px;border-radius:6px;margin:4px 6px 4px 0;border:1px solid #30363d}
  #attachments{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}
  .chip{display:flex;align-items:center;gap:6px;background:#21262d;border:1px solid #30363d;
        border-radius:6px;padding:4px 8px;font-size:0.8rem}
  .chip img{width:34px;height:34px;object-fit:cover;border-radius:4px}
  .chip .x{cursor:pointer;color:#f85149;font-weight:bold}
  #row{display:flex;gap:8px;align-items:center}
  #q{flex:1;padding:10px;background:#21262d;color:#c9d1d9;
     border:1px solid #30363d;border-radius:6px;font-size:0.95rem}
  button{padding:10px 16px;background:#238636;color:#fff;border:none;
         border-radius:6px;cursor:pointer;font-size:0.95rem}
  button:hover{background:#2ea043}
  #attachBtn{background:#30363d}#attachBtn:hover{background:#3c444d}
  .hint{color:#6e7681;font-size:0.75rem;margin-top:6px}
</style></head>
<body>
<h1>SIEM+RAG Security Assistant</h1>
<div id="chat"><div class="b">Ready. Ask a question, paste a screenshot, or attach a file.</div></div>
<div id="attachments"></div>
<div id="row">
  <button id="attachBtn" onclick="document.getElementById('file').click()">+ File</button>
  <input id="file" type="file" multiple style="display:none"
         accept="image/*,.txt,.log,.csv,.json,.md,.yaml,.yml,.conf,.ini,.xml"
         onchange="handleFiles(this.files); this.value=''"/>
  <input id="q" placeholder="Ask, or paste an image (Ctrl/Cmd+V)..."
         onkeydown="if(event.key==='Enter')send()"/>
  <button onclick="send()">Send</button>
</div>
<div class="hint">Paste images directly into the box. Attach .txt/.log/.csv/.json files. Other files attach by name only.</div>
<script>
// pending attachments
let pendImages = [];   // {name, dataUrl, b64}
let pendFiles  = [];   // {name, content}

const TEXT_EXT = ['txt','log','csv','json','md','yaml','yml','conf','ini','xml'];

function isImage(f){ return f.type && f.type.indexOf('image/') === 0; }
function isText(f){
  if(f.type && f.type.indexOf('text/') === 0) return true;
  const ext = (f.name.split('.').pop()||'').toLowerCase();
  return TEXT_EXT.indexOf(ext) !== -1;
}

function handleFiles(files){
  for(const f of files){
    if(isImage(f)){
      const r = new FileReader();
      r.onload = e => {
        const dataUrl = e.target.result;
        const b64 = dataUrl.split(',')[1];
        pendImages.push({name: f.name||'pasted-image', dataUrl, b64});
        render();
      };
      r.readAsDataURL(f);
    } else if(isText(f)){
      const r = new FileReader();
      r.onload = e => { pendFiles.push({name: f.name, content: e.target.result}); render(); };
      r.readAsText(f);
    } else {
      // unsupported/binary: attach name only, no content
      pendFiles.push({name: f.name, content: ''});
      render();
    }
  }
}

function render(){
  const box = document.getElementById('attachments');
  box.innerHTML = '';
  pendImages.forEach((im,i)=>{
    const c = document.createElement('div'); c.className='chip';
    c.innerHTML = `<img src="${im.dataUrl}"/><span>${im.name}</span><span class="x" onclick="delImg(${i})">x</span>`;
    box.appendChild(c);
  });
  pendFiles.forEach((fl,i)=>{
    const tag = fl.content ? '' : ' (not readable)';
    const c = document.createElement('div'); c.className='chip';
    c.innerHTML = `<span>📄 ${fl.name}${tag}</span><span class="x" onclick="delFile(${i})">x</span>`;
    box.appendChild(c);
  });
}
function delImg(i){ pendImages.splice(i,1); render(); }
function delFile(i){ pendFiles.splice(i,1); render(); }

// paste images straight into the box
document.getElementById('q').addEventListener('paste', e=>{
  const items = (e.clipboardData||window.clipboardData).items;
  for(const it of items){
    if(it.type && it.type.indexOf('image') === 0){
      const f = it.getAsFile();
      if(f) handleFiles([f]);
    }
  }
});

async function send(){
  const inp = document.getElementById('q');
  const q = inp.value.trim();
  if(!q && pendImages.length===0 && pendFiles.length===0) return;

  const chat = document.getElementById('chat');
  const thumbs = pendImages.map(im=>`<img class="msgimg" src="${im.dataUrl}"/>`).join('');
  const fnames = pendFiles.map(f=>`📄 ${f.name}`).join(' ');
  chat.innerHTML += `<div class="u">You: ${q||''} ${fnames}</div>${thumbs}<div class="b" id="pending">Thinking…</div>`;

  const payload = {
    question: q,
    images: pendImages.map(im=>im.b64),
    files: pendFiles.map(f=>({name:f.name, content:f.content}))
  };
  inp.value=''; pendImages=[]; pendFiles=[]; render();
  chat.scrollTop = chat.scrollHeight;

  try{
    const r = await fetch('/ask',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)});
    const d = await r.json();
    document.getElementById('pending').textContent = 'Agent: '+(d.answer||d.error||'No response');
  }catch(e){
    document.getElementById('pending').innerHTML = `<span class="err">Error: ${e}</span>`;
  }
  chat.scrollTop = chat.scrollHeight;
}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return _HTML


class FileAttachment(BaseModel):
    name: str
    content: str = ""


class Q(BaseModel):
    question: str = ""
    images: list[str] = []
    files: list[FileAttachment] = []


@app.post("/ask")
async def ask(q: Q):
    try:
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(
                f"{AGENT_URL}/query",
                json={
                    "question": q.question,
                    "images": q.images,
                    "files": [f.model_dump() for f in q.files],
                },
            )
            return r.json()
    except Exception as e:
        return {"error": str(e)}


@app.get("/health")
def health():
    return {"status": "ok"}
