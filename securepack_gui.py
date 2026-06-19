"""
securepack_gui.py - KnoxSecureZip 데스크탑 GUI (브라우저/서버 없음)

디스크에서 파일을 직접 읽고 써서 base64 오버헤드 없이 RAM을 절약한다.
풀 엔진(파일별 최적 압축 + 속도 모드 + AES 암호화)을 네이티브 창에서 사용.

실행:  python securepack_gui.py    (또는 패키징한 .exe 더블클릭)
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import autopack
import securepack


class App:
    def __init__(self, root):
        self.root = root
        self.paths = []          # 선택된 파일/폴더 경로들
        root.title("KnoxSecureZip — 압축 & 암호화")
        root.geometry("480x420")
        root.resizable(False, False)

        tk.Label(root, text="🔐 KnoxSecureZip", font=("Segoe UI", 16, "bold")).pack(pady=(16, 2))
        tk.Label(root, text="파일별 최적 압축 + 선택적 암호화 · 모두 내 컴퓨터에서",
                 fg="#666").pack()

        self.sel = tk.StringVar(value="선택된 항목 없음")
        tk.Label(root, textvariable=self.sel, wraplength=440, fg="#333").pack(pady=8)

        pick = tk.Frame(root); pick.pack()
        tk.Button(pick, text="📄 파일 선택", width=16, command=self.pick_files).grid(row=0, column=0, padx=4)
        tk.Button(pick, text="📁 폴더 선택", width=16, command=self.pick_dir).grid(row=0, column=1, padx=4)

        opt = tk.Frame(root); opt.pack(pady=12)
        tk.Label(opt, text="압축 모드:").grid(row=0, column=0, sticky="e", padx=4)
        self.mode = tk.StringVar(value="balanced")
        ttk.Combobox(opt, textvariable=self.mode, width=24, state="readonly",
                     values=["fast (빠르게)", "balanced (균형)", "max (최대압축)"]).grid(row=0, column=1, padx=4)
        self.mode.set("balanced (균형)")

        self.enc = tk.BooleanVar(value=True)
        tk.Checkbutton(opt, text="🔒 암호화", variable=self.enc, command=self._toggle_pw).grid(row=1, column=0, pady=8)
        self.pw_entry = tk.Entry(opt, show="*", width=26)
        self.pw_entry.grid(row=1, column=1, padx=4)

        act = tk.Frame(root); act.pack(pady=6)
        tk.Button(act, text="🗜️ 압축하기", width=16, command=lambda: self.run("pack")).grid(row=0, column=0, padx=4)
        tk.Button(act, text="📂 열기/복원", width=16, command=lambda: self.run("unpack")).grid(row=0, column=1, padx=4)

        self.bar = ttk.Progressbar(root, mode="indeterminate", length=440)
        self.status = tk.Label(root, text="", fg="#0a7")
        self.status.pack(pady=10)

    def _toggle_pw(self):
        self.pw_entry.config(state="normal" if self.enc.get() else "disabled")

    def pick_files(self):
        ps = filedialog.askopenfilenames()
        if ps:
            self.paths = list(ps)
            self.sel.set(f"파일 {len(ps)}개 선택됨")

    def pick_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.paths = [p]
            self.sel.set(f"폴더: {p}")

    def _mode(self):
        return self.mode.get().split()[0]

    def run(self, action):
        pw = self.pw_entry.get() if self.enc.get() else ""
        if self.enc.get() and action == "pack" and not pw:
            return messagebox.showwarning("알림", "비밀번호를 입력하세요.")
        self.bar.pack(pady=4); self.bar.start(12)
        self.status.config(text="처리 중…", fg="#0a7")
        for b in self.root.winfo_children():
            pass
        threading.Thread(target=self._work, args=(action, pw), daemon=True).start()

    def _work(self, action, pw):
        try:
            if action == "pack":
                out = self._do_pack(pw)
                msg = f"압축 완료 → {out}"
            else:
                out = self._do_unpack(pw)
                msg = f"복원 완료 → {out}"
            self.root.after(0, lambda: self._done(msg))
        except Exception as e:
            m = str(e)
            self.root.after(0, lambda: self._fail(m))

    def _do_pack(self, pw):
        if not self.paths:
            raise ValueError("먼저 파일이나 폴더를 선택하세요.")
        # 파일 목록(경로만) → 스트리밍으로 한 개씩 처리 (저RAM)
        if len(self.paths) == 1 and os.path.isdir(self.paths[0]):
            root = self.paths[0].rstrip("/\\")
            files = [(os.path.relpath(os.path.join(dp, fn), root).replace("\\", "/"),
                      os.path.join(dp, fn))
                     for dp, _, fns in os.walk(root) for fn in sorted(fns)]
            base = os.path.basename(root) or "archive"
        else:
            files = [(os.path.basename(p), p) for p in self.paths]
            base = "archive"
        ext = ".spkx" if pw else ".spk"
        out = filedialog.asksaveasfilename(defaultextension=ext, initialfile=base + ext)
        if not out:
            raise ValueError("저장이 취소되었습니다.")
        securepack.pack_stream(out, files, pw, self._mode())
        return out

    def _do_unpack(self, pw):
        src = filedialog.askopenfilename(filetypes=[("KnoxSecureZip", "*.spk *.spkx"), ("모든 파일", "*.*")])
        if not src:
            raise ValueError("파일이 선택되지 않았습니다.")
        with open(src, "rb") as fh:
            enc = fh.read(4) == securepack.ENC_MAGIC
        if enc and not pw:
            pw = self.pw_entry.get()
            if not pw:
                raise ValueError("암호화 파일입니다. 비밀번호를 입력하세요.")
        outdir = filedialog.askdirectory(title="복원할 폴더 선택")
        if not outdir:
            raise ValueError("폴더가 선택되지 않았습니다.")
        names = securepack.unpack_stream(src, outdir, pw)
        return f"{outdir} ({len(names)}개 파일)"

    def _done(self, msg):
        self.bar.stop(); self.bar.pack_forget()
        self.status.config(text=msg, fg="#0a7")
        messagebox.showinfo("완료", msg)

    def _fail(self, msg):
        self.bar.stop(); self.bar.pack_forget()
        self.status.config(text="실패: " + msg, fg="#c00")
        messagebox.showerror("오류", msg)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
