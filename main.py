import os
import tarfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ============ 常量 ============
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
CHUNK = 32 * 1024 * 1024  # 32MB

# ============ 密钥 / nonce ============
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        iterations=3,
        memory_cost=64 * 1024,
        lanes=4,
        length=KEY_LEN,
    )
    return kdf.derive(password.encode("utf-8"))

def derive_nonce(base_nonce: bytes, counter: int) -> bytes:
    return base_nonce[:8] + counter.to_bytes(4, "big")

# ============ 加密：tar → 临时文件 → 流式加密写盘 ============
def encrypt_streaming(source_path: Path, output_path: Path, password: str,
                      progress_cb=None):
    """
    1. tar 打包到磁盘临时文件（tarfile 拿到真实文件，seek 正常）
    2. 读临时 tar 文件 → GCM 加密 → 写 .enc 输出
    内存中同时只有 CHUNK 大小
    """
    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 临时 tar 文件
    temp_tar = output_path.parent / "_temp_pack.tar"
    try:
        # Step 1: tar 到磁盘
        with tarfile.open(temp_tar, mode="w") as tar:
            if source_path.is_file():
                tar.add(source_path, arcname=source_path.name)
            else:
                tar.add(source_path, arcname=source_path.name)

        # Step 2: 流式加密
        tar_size = temp_tar.stat().st_size
        with temp_tar.open("rb") as tf:
            with output_path.open("wb") as fout:
                fout.write(salt)
                fout.write(base_nonce)

                offset = 0
                chunk_index = 0
                while offset < tar_size:
                    nonce = derive_nonce(base_nonce, chunk_index)
                    remaining = tar_size - offset
                    block_size = min(CHUNK, remaining)
                    plaintext = tf.read(block_size)
                    if not plaintext:
                        break

                    ct = aes.encrypt(
                        nonce, plaintext,
                        chunk_index.to_bytes(4, "big")
                    )
                    fout.write(ct)
                    offset += len(plaintext)
                    chunk_index += 1

                    if progress_cb:
                        progress_cb(offset, tar_size)

    finally:
        temp_tar.unlink(missing_ok=True)

    if progress_cb:
        progress_cb(1, 1)

# ============ 解密：密文 → 临时 tar → 解包 ============
def decrypt_streaming(input_path: Path, output_dir: Path, password: str,
                      progress_cb=None):
    """
    读密文 → 解密 → 临时 tar 文件 → tarfile 从磁盘解包
    """
    with input_path.open("rb") as fin:
        salt = fin.read(SALT_LEN)
        base_nonce = fin.read(NONCE_LEN)

        fin.seek(0, 2)
        total_ct = fin.tell() - SALT_LEN - NONCE_LEN
        fin.seek(SALT_LEN + NONCE_LEN)

        key = derive_key(password, salt)
        aes = AESGCM(key)

        output_dir.mkdir(parents=True, exist_ok=True)
        temp_tar = output_dir / "_temp_decrypted.tar"

        try:
            # Step 1: 解密到临时 tar
            with temp_tar.open("wb") as tf:
                offset = 0
                chunk_index = 0
                while offset < total_ct:
                    nonce = derive_nonce(base_nonce, chunk_index)
                    remaining = total_ct - offset
                    block_size = min(CHUNK + 16, remaining)
                    ct = fin.read(block_size)
                    if not ct:
                        break

                    try:
                        pt = aes.decrypt(
                            nonce, ct,
                            chunk_index.to_bytes(4, "big")
                        )
                    except InvalidTag:
                        raise ValueError("解密失败：密码错误或数据损坏")

                    tf.write(pt)
                    offset += block_size
                    chunk_index += 1

                    if progress_cb:
                        progress_cb(offset, total_ct)

            # Step 2: tarfile 从磁盘读（支持 seek）
            with tarfile.open(temp_tar, mode="r") as tar:
                file_members = [m for m in tar.getmembers() if m.isfile()]

                if len(file_members) == 1:
                    member = file_members[0]
                    member.name = os.path.basename(member.name)
                    tar.extract(member, path=output_dir)
                else:
                    for member in tar.getmembers():
                        if member.isfile():
                            member.name = os.path.basename(member.name)
                    tar.extractall(path=output_dir)

        finally:
            temp_tar.unlink(missing_ok=True)

        if progress_cb:
            progress_cb(total_ct, total_ct)

# ============ GUI ============
class AESFolderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-256-GCM 加密工具（流式）")
        self.resizable(False, False)

        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")

        self._build_widgets()

    def _build_widgets(self):
        pad = {"padx": 10, "pady": 6}

        mode_frame = ttk.LabelFrame(self, text="模式", padding=10)
        mode_frame.pack(fill="x", **pad)
        ttk.Radiobutton(mode_frame, text="加密", variable=self.mode,
                        value="encrypt", command=self._on_mode_change)\
            .pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="解密", variable=self.mode,
                        value="decrypt", command=self._on_mode_change)\
            .pack(side="left", padx=10)

        in_frame = ttk.LabelFrame(self, text="输入（文件或文件夹）", padding=10)
        in_frame.pack(fill="x", **pad)
        ttk.Entry(in_frame, textvariable=self.input_path, width=45,
                  state="readonly").pack(side="left", padx=(0, 6))
        ttk.Button(in_frame, text="选择", command=self._select_input)\
            .pack(side="left")

        out_frame = ttk.LabelFrame(self, text="输出", padding=10)
        out_frame.pack(fill="x", **pad)
        self.output_entry = ttk.Entry(out_frame, textvariable=self.output_path,
                                      width=45, state="readonly")
        self.output_entry.pack(side="left", padx=(0, 6))
        ttk.Button(out_frame, text="选择", command=self._select_output)\
            .pack(side="left")

        pw_frame = ttk.LabelFrame(self, text="密码", padding=10)
        pw_frame.pack(fill="x", **pad)
        ttk.Entry(pw_frame, textvariable=self.password, show="*", width=45)\
            .pack(side="left")

        ttk.Label(self, text="流式处理：内存占用恒定 ~100MB",
                  foreground="green", font=("Arial", 9)).pack(pady=(4, 0))

        prog_frame = tk.Frame(self)
        prog_frame.pack(fill="x", **pad)
        self.progress = ttk.Progressbar(prog_frame, mode="determinate", maximum=100)
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 8))
        self.progress_label = ttk.Label(prog_frame, text="0%", width=6)
        self.progress_label.pack(side="left")

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="开始执行", command=self._start).pack()

        self._on_mode_change()

    def _auto_output_name(self):
        in_path = self.input_path.get().strip()
        if not in_path:
            return
        p = Path(in_path)
        if self.mode.get() == "encrypt":
            self.output_path.set(str(p) + ".enc")
        else:
            if p.suffix == ".enc":
                self.output_path.set(str(p.with_suffix("")))
            else:
                self.output_path.set(str(p) + ".decrypted")

    def _on_mode_change(self):
        self.input_path.set("")
        self.output_path.set("")
        self.progress["value"] = 0
        self.progress_label.config(text="0%")

    def _select_input(self):
        if self.mode.get() == "encrypt":
            choice = messagebox.askyesnocancel(
                "选择类型",
                "选「是」选择文件夹\n选「否」选择单个文件\n选「取消」取消")
            if choice is None:
                return
            elif choice:
                path = filedialog.askdirectory(title="选择要加密的文件夹")
            else:
                path = filedialog.askopenfilename(title="选择要加密的文件")
        else:
            path = filedialog.askopenfilename(
                title="选择加密文件 (.enc)",
                filetypes=[("加密文件", "*.enc"), ("所有文件", "*.*")])
        if path:
            self.input_path.set(path)
            self._auto_output_name()

    def _select_output(self):
        if self.mode.get() == "encrypt":
            path = filedialog.asksaveasfilename(
                title="保存加密文件", defaultextension=".enc",
                initialfile=Path(self.output_path.get()).name or "output.enc",
                filetypes=[("加密文件", "*.enc")])
        else:
            path = filedialog.askdirectory(title="选择解密输出目录")
        if path:
            self.output_path.set(path)

    def _start(self):
        in_path = self.input_path.get().strip()
        out_path = self.output_path.get().strip()
        password = self.password.get()

        if not in_path or not out_path or not password:
            messagebox.showerror("错误", "请填写所有字段")
            return
        if self.mode.get() == "encrypt" and not os.path.exists(in_path):
            messagebox.showerror("错误", f"输入路径不存在:\n{in_path}")
            return

        self.progress["value"] = 0
        self.progress_label.config(text="0%")
        threading.Thread(target=self._worker, args=(in_path, out_path, password),
                         daemon=True).start()

    def _update_progress(self, current, total):
        pct = int(current / total * 100) if total > 0 else 0
        self.after(0, lambda v=pct: [
            self.progress.config(value=v),
            self.progress_label.config(text=f"{v}%")
        ])

    def _worker(self, in_path, out_path, password):
        try:
            if self.mode.get() == "encrypt":
                src = Path(in_path)
                if not src.exists():
                    raise FileNotFoundError(f"路径不存在: {in_path}")
                encrypt_streaming(src, Path(out_path), password,
                                  progress_cb=self._update_progress)
                msg = f"加密完成：\n{out_path}"
            else:
                decrypt_streaming(Path(in_path), Path(out_path), password,
                                  progress_cb=self._update_progress)
                msg = f"解密完成：\n{out_path}"

            self.after(0, lambda m=msg: [
                self.progress.config(value=100),
                self.progress_label.config(text="100%"),
                messagebox.showinfo("成功", m)
            ])

        except Exception as exc:
            import traceback
            full_tb = traceback.format_exc()  # ← 拿完整 traceback 字符串
            err_msg = str(exc)
            self.after(0, lambda em=err_msg, ftb=full_tb: [
                self.progress.config(value=0),
                self.progress_label.config(text="失败"),
                messagebox.showerror("失败", ftb)  # ← 弹完整 traceback
            ])


if __name__ == "__main__":
    AESFolderApp().mainloop()