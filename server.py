"""
server.py - SecureFile 고급 로컬 서버

풀 엔진(securepack: 파일별 최적 압축 zstd/bz2/lzma/brotli + 속도 모드 + AES 암호화)을
브라우저 UI로 제공한다. localhost에서만 돌기 때문에 파일이 기기 밖으로 나가지 않는다.

실행:
  python server.py        # http://127.0.0.1:8770 열기
"""

import io
import json
import base64
import zipfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import autopack
import securepack

PORT = 8770

PAGE = r"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureFile — 고급(로컬 풀 엔진)</title>
<style>
:root{--bg:#0b0e1a;--card:#161b33;--line:#262d4d;--accent:#6c8cff;--ok:#37d39b;--err:#ff6b6b;--muted:#8a93b2;--txt:#eef1ff;}
*{box-sizing:border-box;}body{margin:0;min-height:100vh;font-family:"Segoe UI",system-ui,sans-serif;color:var(--txt);
background:radial-gradient(900px 500px at 50% -10%,#23294a,var(--bg));display:flex;align-items:center;justify-content:center;padding:24px;}
.card{width:100%;max-width:560px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px;box-shadow:0 20px 60px rgba(0,0,0,.45);}
h1{margin:0 0 4px;font-size:22px;}.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:20px;background:#203a2c;color:var(--ok);margin-left:6px;}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px;}
.drop{border:2px dashed #3a4275;border-radius:14px;padding:20px;text-align:center;cursor:pointer;background:#0c1124;}
.drop:hover,.drop.over{border-color:var(--accent);background:#1b2240;}.drop .big{font-size:28px;}
.name{margin-top:6px;font-size:13px;color:#cdd5ff;word-break:break-all;}
.picks{display:flex;gap:8px;margin-top:10px;}.picks button{flex:1;padding:8px;font-size:12px;background:#222a4d;color:#cdd5ff;border:1px solid #38406b;border-radius:9px;cursor:pointer;}
.field{margin-top:14px;}.field label{font-size:12px;color:var(--muted);display:block;margin-bottom:6px;}
select,input[type=password]{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #38406b;background:#0c1124;color:#fff;font-size:14px;}
.togg{display:flex;align-items:center;gap:10px;margin-top:14px;}
.row{display:flex;gap:10px;margin-top:16px;}.row button{flex:1;padding:13px;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;}
.go{background:var(--accent);color:#fff;}.open{background:#2a3157;color:#dfe4ff;}button:disabled{opacity:.5;}
.status{margin-top:12px;font-size:13px;min-height:18px;}.status.ok{color:var(--ok);}.status.err{color:var(--err);}.status.info{color:var(--muted);}
table{width:100%;margin-top:12px;border-collapse:collapse;font-size:12px;}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);color:#cdd5ff;}
th{color:var(--muted);}.foot{margin-top:14px;font-size:11px;color:var(--muted);border-top:1px solid var(--line);padding-top:10px;line-height:1.6;}
</style></head><body><div class="card">
<h1>🔐 SecureFile <span class="tag" id="eng">로컬 풀 엔진</span></h1>
<div class="sub">파일별 최적 압축(zstd·bz2·lzma·brotli) + 선택적 암호화. 모든 처리는 내 컴퓨터(localhost)에서만.</div>
<div class="drop" id="drop"><div class="big">📁</div><div>파일·폴더를 끌어다 놓거나 클릭</div>
<div class="name" id="fname"></div>
<input type="file" id="file" hidden multiple><input type="file" id="dir" hidden webkitdirectory></div>
<div class="picks"><button id="pf">📄 파일</button><button id="pd">📁 폴더</button></div>
<div class="field"><label>압축 모드</label>
<select id="mode"><option value="max">최대압축 (느림, 제일 작음)</option>
<option value="balanced" selected>균형 (zstd 고압축)</option>
<option value="fast">빠르게 (zstd 빠름)</option></select></div>
<div class="togg"><input type="checkbox" id="enc" checked><label for="enc" style="margin:0;font-size:14px;">🔒 암호화</label></div>
<div class="field" id="pwf"><input type="password" id="pw" placeholder="비밀번호"></div>
<div class="row"><button class="go" id="go">압축 + 암호화</button><button class="open" id="op">📂 열기(.spk/.spkx)</button></div>
<input type="file" id="arc" hidden>
<div class="status info" id="st"></div>
<div id="rep"></div>
<div class="foot">엔진: securepack · 압축: 파일별 자동선택 · 암호화: AES-256-GCM(PBKDF2)<br>
localhost 전용 — 파일이 인터넷으로 전송되지 않습니다.<br>만든 사람: knox9014</div>
</div>
<script>
const $=id=>document.getElementById(id);let files=[];
function b64(buf){let s='',b=new Uint8Array(buf);for(let i=0;i<b.length;i+=0x8000)s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));return btoa(s);}
function deb64(str){const s=atob(str),a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a;}
function setSt(m,c){$("st").textContent=m;$("st").className="status "+(c||"info");}
function dl(bytes,name){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([bytes]));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),4000);}
function pick(list,label){files=[...list];if(!files.length)return;const tot=files.reduce((s,f)=>s+f.size,0);
 $("fname").textContent="📦 "+label+": "+files.length+"개 ("+tot.toLocaleString()+" bytes)";setSt("");}
$("drop").onclick=()=>$("file").click();
$("file").onchange=e=>pick(e.target.files,"파일");
$("dir").onchange=e=>pick(e.target.files,"폴더");
$("pf").onclick=()=>$("file").click();$("pd").onclick=()=>$("dir").click();
["dragover","dragenter"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.add("over");}));
["dragleave","drop"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.remove("over");}));
$("drop").addEventListener("drop",e=>pick(e.dataTransfer.files,"파일"));
$("enc").onchange=()=>{$("pwf").style.display=$("enc").checked?"block":"none";$("go").textContent=$("enc").checked?"압축 + 암호화":"압축만";};
async function pack(){
 if(!files.length)return setSt("파일/폴더를 선택하세요.","err");
 const enc=$("enc").checked,pw=$("pw").value;
 if(enc&&!pw)return setSt("비밀번호를 입력하세요.","err");
 $("go").disabled=true;setSt("처리 중… (큰 파일은 시간이 걸릴 수 있어요)","info");
 try{
  const payload={mode:$("mode").value,password:enc?pw:"",files:[]};
  for(const f of files){const buf=await f.arrayBuffer();payload.files.push({name:f.webkitRelativePath||f.name,data:b64(buf)});}
  const r=await fetch("/api/pack",{method:"POST",body:JSON.stringify(payload)});
  const j=await r.json();if(!j.ok)throw new Error(j.error||"실패");
  dl(deb64(j.archive),j.name);
  let html="<table><tr><th>파일</th><th>방식</th><th>압축률</th></tr>";
  for(const x of j.report)html+=`<tr><td>${x[0]}</td><td>${x[1]}</td><td>${x[2]?(x[3]/x[2]*100).toFixed(1):0}%</td></tr>`;
  html+="</table>";$("rep").innerHTML=html;
  setSt(`완료! ${j.report.length}개 파일 → ${j.total.toLocaleString()} bytes${enc?" (암호화)":""}`,"ok");
 }catch(e){setSt(e.message,"err");}finally{$("go").disabled=false;}
}
async function open_(){
 $("arc").click();
}
$("arc").onchange=async e=>{
 const f=e.target.files[0];if(!f)return;
 const buf=await f.arrayBuffer();const isEnc=new TextDecoder().decode(new Uint8Array(buf.slice(0,4)))==="SPKE";
 const pw=isEnc?prompt("비밀번호:")||"":"";
 $("op").disabled=true;setSt("여는 중…","info");
 try{
  const r=await fetch("/api/unpack",{method:"POST",body:JSON.stringify({password:pw,data:b64(buf)})});
  const j=await r.json();if(!j.ok)throw new Error(j.error||"실패");
  dl(deb64(j.zip),"restored.zip");setSt(`복원 완료! ${j.count}개 파일 → restored.zip`,"ok");
 }catch(err){setSt(err.message,"err");}finally{$("op").disabled=false;}
};
$("go").onclick=pack;$("op").onclick=open_;
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/health":
            self._json({"ok": True, "engine": "securepack"})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        try:
            if self.path == "/api/pack":
                b = self._body()
                items = [(f["name"], base64.b64decode(f["data"])) for f in b["files"]]
                spk, report = autopack.pack_entries(items, b.get("mode", "max"))
                pw = b.get("password", "")
                blob = securepack.encrypt_bytes(spk, pw) if pw else spk
                self._json({"ok": True, "archive": base64.b64encode(blob).decode(),
                            "report": report, "total": len(blob),
                            "name": "archive.spkx" if pw else "archive.spk"})
            elif self.path == "/api/unpack":
                b = self._body()
                blob = base64.b64decode(b["data"])
                if blob[:4] == securepack.ENC_MAGIC:
                    blob = securepack.decrypt_bytes(blob, b.get("password", ""))
                items = autopack.unpack_entries(blob)
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
                    for name, data in items:
                        z.writestr(name, data)
                self._json({"ok": True, "zip": base64.b64encode(buf.getvalue()).decode(),
                            "count": len(items)})
            else:
                self._json({"ok": False, "error": "unknown endpoint"}, 404)
        except Exception as e:
            self._json({"ok": False, "error": str(e)}, 400)


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"SecureFile 고급 서버: {url}  (Ctrl+C로 종료)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    srv.serve_forever()


if __name__ == "__main__":
    main()
