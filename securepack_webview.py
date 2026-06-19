"""
securepack_webview.py - SecureFile 데스크탑 앱 (모던 UI)

웹사이트와 같은 디자인을 네이티브 창(pywebview)에 띄운다. 브라우저 없음.
파일은 네이티브 대화상자로 디스크에서 직접 읽어 처리 → base64 없이 RAM 절약.

실행:  python securepack_webview.py    (또는 패키징한 .exe)
"""

import os
import webview

import autopack
import securepack

HTML = r"""<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>SecureFile</title>
<style>
:root{--bg:#0b0e1a;--bg2:#10142a;--card:#161b33;--line:#262d4d;--accent:#6c8cff;--ok:#37d39b;--err:#ff6b6b;--muted:#8a93b2;--txt:#eef1ff;}
*{box-sizing:border-box;}html,body{margin:0;height:100%;}
body{font-family:"Segoe UI",system-ui,sans-serif;color:var(--txt);
background:radial-gradient(800px 500px at 50% -10%,#23294a,var(--bg));
display:flex;align-items:center;justify-content:center;padding:22px;user-select:none;}
.card{width:100%;max-width:480px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.45);}
h1{margin:0 0 4px;font-size:21px;}.tag{font-size:11px;padding:2px 8px;border-radius:20px;background:#203a2c;color:var(--ok);margin-left:6px;vertical-align:middle;}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px;}
.drop{border:2px dashed #3a4275;border-radius:14px;padding:24px 16px;text-align:center;background:#0c1124;}
.drop .big{font-size:30px;}.drop .t{margin-top:6px;color:#cdd5ff;font-size:13px;}
.name{margin-top:8px;font-size:13px;color:#9fb0ff;word-break:break-all;}
.picks{display:flex;gap:8px;margin-top:10px;}
button{font-family:inherit;cursor:pointer;}
.picks button{flex:1;padding:9px;font-size:12px;background:#222a4d;color:#cdd5ff;border:1px solid #38406b;border-radius:9px;}
.picks button:hover{border-color:var(--accent);}
.field{margin-top:14px;}.field label{font-size:12px;color:var(--muted);display:block;margin-bottom:6px;}
select,input[type=password]{width:100%;padding:11px 12px;border-radius:10px;border:1px solid #38406b;background:#0c1124;color:#fff;font-size:14px;}
.togg{display:flex;align-items:center;gap:9px;margin-top:14px;}.togg input{width:18px;height:18px;}
.row{display:flex;gap:10px;margin-top:16px;}
.row button{flex:1;padding:13px;border:none;border-radius:10px;font-size:15px;font-weight:600;color:#fff;}
.go{background:var(--accent);}.open{background:#2a3157;color:#dfe4ff;}
button:disabled{opacity:.5;cursor:default;}
.status{margin-top:12px;font-size:13px;min-height:18px;}.status.ok{color:var(--ok);}.status.err{color:var(--err);}.status.info{color:var(--muted);}
table{width:100%;margin-top:10px;border-collapse:collapse;font-size:12px;}
td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);color:#cdd5ff;}th{color:var(--muted);}
.foot{margin-top:14px;font-size:11px;color:var(--muted);border-top:1px solid var(--line);padding-top:10px;line-height:1.6;}
.spin{display:inline-block;width:13px;height:13px;border:2px solid #45507f;border-top-color:var(--accent);border-radius:50%;animation:r .7s linear infinite;vertical-align:-2px;margin-right:6px;}
@keyframes r{to{transform:rotate(360deg);}}
</style></head><body><div class="card">
<h1>🔐 SecureFile <span class="tag">데스크탑</span></h1>
<div class="sub">파일별 최적 압축 + 선택적 암호화 · 모든 처리는 내 컴퓨터에서만.</div>
<div class="drop"><div class="big">📁</div><div class="t">아래 버튼으로 파일·폴더를 선택하세요</div>
<div class="name" id="sel">선택된 항목 없음</div></div>
<div class="picks"><button id="pf">📄 파일 선택</button><button id="pd">📁 폴더 선택</button></div>
<div class="field"><label>압축 모드</label>
<select id="mode"><option value="max">최대압축 (느림, 제일 작음)</option>
<option value="balanced" selected>균형 (zstd 고압축)</option>
<option value="fast">빠르게 (zstd 빠름)</option></select></div>
<div class="togg"><input type="checkbox" id="enc" checked><label for="enc" style="font-size:14px;">🔒 암호화</label></div>
<div class="field" id="pwf"><input type="password" id="pw" placeholder="비밀번호"></div>
<div class="row"><button class="go" id="go">압축 + 암호화</button><button class="open" id="op">📂 열기 / 복원</button></div>
<div class="status info" id="st"></div><div id="rep"></div>
<div class="foot">엔진: 파일별 자동선택(zstd·bz2·lzma·brotli) · 암호화: AES-256-GCM<br>파일이 인터넷으로 전송되지 않습니다.<br><span style="color:#9fb0ff;">만든 사람: knox9014 · MIT 라이선스</span></div>
</div>
<script>
const $=id=>document.getElementById(id);let paths=[];
function busy(b,m){$("go").disabled=$("op").disabled=b;$("st").className="status info";$("st").innerHTML=(b?'<span class="spin"></span>':'')+(m||"");}
function ok(m){$("st").className="status ok";$("st").textContent=m;}
function err(m){$("st").className="status err";$("st").textContent=m;}
function api(){return window.pywebview.api;}
$("enc").onchange=()=>{$("pwf").style.display=$("enc").checked?"block":"none";$("go").textContent=$("enc").checked?"압축 + 암호화":"압축만";};
$("pf").onclick=async()=>{const p=await api().select_files();if(p&&p.length){paths=p;$("sel").textContent="📄 "+p.length+"개 파일 선택됨";}};
$("pd").onclick=async()=>{const p=await api().select_folder();if(p&&p.length){paths=p;$("sel").textContent="📁 "+p[0];}};
$("go").onclick=async()=>{
 if(!paths.length)return err("먼저 파일/폴더를 선택하세요.");
 const enc=$("enc").checked,pw=$("pw").value;
 if(enc&&!pw)return err("비밀번호를 입력하세요.");
 busy(true,"압축 중… (큰 파일은 시간이 걸릴 수 있어요)");$("rep").innerHTML="";
 const j=await api().pack(paths,$("mode").value,enc?pw:"");
 busy(false);
 if(!j.ok)return err(j.error);
 let h="<table><tr><th>파일</th><th>방식</th><th>압축률</th></tr>";
 for(const x of j.report)h+=`<tr><td>${x[0]}</td><td>${x[1]}</td><td>${x[2]?(x[3]/x[2]*100).toFixed(1):0}%</td></tr>`;
 h+="</table>";$("rep").innerHTML=h;
 ok(`완료! ${j.report.length}개 → ${j.total.toLocaleString()} bytes · 저장: ${j.path}`);
};
$("op").onclick=async()=>{
 busy(true,"여는 중…");
 const j=await api().unpack($("pw").value);busy(false);
 if(!j.ok)return err(j.error);
 ok(`복원 완료! ${j.count}개 파일 → ${j.path}`);
};
</script></body></html>"""


class Api:
    def _win(self):
        return webview.windows[0]

    def select_files(self):
        r = self._win().create_file_dialog(webview.OPEN_DIALOG, allow_multiple=True)
        return list(r) if r else []

    def select_folder(self):
        r = self._win().create_file_dialog(webview.FOLDER_DIALOG)
        return list(r) if r else []

    def pack(self, paths, mode, password):
        try:
            if not paths:
                return {"ok": False, "error": "선택된 항목이 없습니다."}
            if len(paths) == 1 and os.path.isdir(paths[0]):
                spk, report = autopack.pack_folder(paths[0], mode)
                base = os.path.basename(paths[0].rstrip("/\\")) or "archive"
            else:
                items = [(os.path.basename(p), open(p, "rb").read()) for p in paths]
                spk, report = autopack.pack_entries(items, mode)
                base = "archive"
            blob = securepack.encrypt_bytes(spk, password) if password else spk
            ext = ".spkx" if password else ".spk"
            save = self._win().create_file_dialog(webview.SAVE_DIALOG, save_filename=base + ext)
            if not save:
                return {"ok": False, "error": "저장이 취소되었습니다."}
            save = save if isinstance(save, str) else save[0]
            with open(save, "wb") as f:
                f.write(blob)
            return {"ok": True, "report": report, "total": len(blob), "path": save}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def unpack(self, password):
        try:
            r = self._win().create_file_dialog(
                webview.OPEN_DIALOG,
                file_types=("SecureFile (*.spk;*.spkx)", "All files (*.*)"))
            if not r:
                return {"ok": False, "error": "파일이 선택되지 않았습니다."}
            src = r[0]
            blob = open(src, "rb").read()
            if blob[:4] == securepack.ENC_MAGIC:
                if not password:
                    return {"ok": False, "error": "암호화 파일입니다. 비밀번호 입력 후 다시 누르세요."}
                blob = securepack.decrypt_bytes(blob, password)
            out = self._win().create_file_dialog(webview.FOLDER_DIALOG)
            if not out:
                return {"ok": False, "error": "복원할 폴더가 선택되지 않았습니다."}
            names = autopack.unpack_archive(blob, out[0])
            return {"ok": True, "count": len(names), "path": out[0]}
        except Exception as e:
            return {"ok": False, "error": str(e)}


def main():
    webview.create_window("SecureFile", html=HTML, js_api=Api(),
                          width=540, height=680, background_color="#0b0e1a")
    webview.start()


if __name__ == "__main__":
    main()
