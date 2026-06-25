"""Chat UI — proxies questions to siem-agent /query."""

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
  #chat{height:420px;overflow-y:auto;border:1px solid #30363d;border-radius:8px;
        padding:14px;background:#161b22;margin-bottom:12px}
  .u{color:#58a6ff;margin:8px 0 2px}.b{color:#7ee787;margin:2px 0 10px;white-space:pre-wrap}
  .err{color:#f85149}
  #row{display:flex;gap:8px}
  #q{flex:1;padding:10px;background:#21262d;color:#c9d1d9;
     border:1px solid #30363d;border-radius:6px;font-size:0.95rem}
  button{padding:10px 18px;background:#238636;color:#fff;border:none;
         border-radius:6px;cursor:pointer;font-size:0.95rem}
  button:hover{background:#2ea043}
</style></head>
<body>
<h1>SIEM+RAG Security Assistant</h1>
<div id="chat"><div class="b">Ready. Ask a security question.</div></div>
<div id="row">
  <input id="q" placeholder="e.g. How do I respond to a brute force attack?"
         onkeydown="if(event.key==='Enter')send()"/>
  <button onclick="send()">Send</button>
</div>
<script>
async function send(){
  const inp=document.getElementById('q');
  const q=inp.value.trim();
  if(!q)return;
  const chat=document.getElementById('chat');
  chat.innerHTML+=`<div class="u">You: ${q}</div><div class="b" id="pending">Thinking…</div>`;
  inp.value='';chat.scrollTop=chat.scrollHeight;
  try{
    const r=await fetch('/ask',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({question:q})});
    const d=await r.json();
    document.getElementById('pending').textContent=
      'Agent: '+(d.answer||d.error||'No response');
  }catch(e){
    document.getElementById('pending').innerHTML=
      `<span class="err">Error: ${e}</span>`;
  }
  chat.scrollTop=chat.scrollHeight;
}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return _HTML


class Q(BaseModel):
    question: str


@app.post("/ask")
async def ask(q: Q):
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(f"{AGENT_URL}/query",
                                  json={"question": q.question})
            return r.json()
    except Exception as e:
        return {"error": str(e)}


@app.get("/health")
def health():
    return {"status": "ok"}
