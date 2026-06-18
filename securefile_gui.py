"""
securefile_gui.py - SecureFile 그래픽 인터페이스 (tkinter, 파이썬 기본 내장)

실행:
    python securefile_gui.py

CLI가 익숙하지 않아도 버튼으로 파일/폴더를 잠그고 풀 수 있다.
무거운 작업은 별도 스레드에서 처리해 창이 멈추지 않는다.
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import securefile


class App:
    def __init__(self, root):
        self.root = root
        self.selected = None
        root.title("SecureFile - 파일 암호화/압축")
        root.geometry("460x300")
        root.resizable(False, False)

        tk.Label(root, text="🔐 SecureFile", font=("Segoe UI", 16, "bold")).pack(pady=(16, 4))
        tk.Label(root, text="파일 또는 폴더를 압축 + 암호화합니다", fg="#666").pack()

        # 선택 표시
        self.path_var = tk.StringVar(value="선택된 항목 없음")
        tk.Label(root, textvariable=self.path_var, wraplength=420, fg="#333").pack(pady=10)

        pick = tk.Frame(root)
        pick.pack()
        tk.Button(pick, text="📄 파일 선택", width=14, command=self.pick_file).grid(row=0, column=0, padx=4)
        tk.Button(pick, text="📁 폴더 선택", width=14, command=self.pick_dir).grid(row=0, column=1, padx=4)

        # 비밀번호
        pw = tk.Frame(root)
        pw.pack(pady=10)
        tk.Label(pw, text="비밀번호:").grid(row=0, column=0, padx=4)
        self.pw_entry = tk.Entry(pw, show="*", width=24)
        self.pw_entry.grid(row=0, column=1, padx=4)

        # 동작 버튼
        act = tk.Frame(root)
        act.pack(pady=6)
        tk.Button(act, text="🔒 암호화", width=14, command=lambda: self.run("encrypt")).grid(row=0, column=0, padx=4)
        tk.Button(act, text="🔓 복호화", width=14, command=lambda: self.run("decrypt")).grid(row=0, column=1, padx=4)

        self.status = tk.Label(root, text="", fg="#0a7")
        self.status.pack(pady=6)

    def pick_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.selected = p
            self.path_var.set(p)

    def pick_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.selected = p
            self.path_var.set(p)

    def run(self, mode):
        if not self.selected:
            messagebox.showwarning("알림", "먼저 파일이나 폴더를 선택하세요.")
            return
        password = self.pw_entry.get()
        if not password:
            messagebox.showwarning("알림", "비밀번호를 입력하세요.")
            return
        self.status.config(text="처리 중...", fg="#0a7")
        # 무거운 작업은 스레드로 -> 창이 안 멈춤
        threading.Thread(target=self._work, args=(mode, password), daemon=True).start()

    def _work(self, mode, password):
        try:
            if mode == "encrypt":
                out = securefile.encrypt_path(self.selected, password)
            else:
                out = securefile.decrypt_path(self.selected, password)
            self.root.after(0, lambda: self._done(out))
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda: self._fail(msg))

    def _done(self, out):
        self.status.config(text=f"완료 → {os.path.basename(out)}", fg="#0a7")
        messagebox.showinfo("완료", f"작업이 완료되었습니다.\n\n결과: {out}")

    def _fail(self, msg):
        self.status.config(text="실패", fg="#c00")
        messagebox.showerror("오류", msg)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
