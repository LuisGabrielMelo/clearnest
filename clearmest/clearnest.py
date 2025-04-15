import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import psutil
import subprocess
from datetime import datetime

class ClearNest:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ ClearNest – Protección contra adware")
        self.center_window(1000, 700)
        self.root.minsize(900, 600)

        self.suspect_paths = [
            os.path.expandvars(r"%APPDATA%\\SearchProtect"),
            os.path.expandvars(r"%APPDATA%\\Babylon"),
            os.path.expandvars(r"%APPDATA%\\Delta"),
            os.path.expandvars(r"%PROGRAMFILES%\\SearchProtect"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\\SearchProtect"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Temp"),
        ]
        self.custom_paths = []
        self.virus_names = []
        self.detected = []

        self.build_ui()
        self.update_system_info()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def build_ui(self):
        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Treeview", font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        title = tk.Label(self.root, text="🧹 ClearNest – Limpieza inteligente de adware",
                         font=("Segoe UI", 18, "bold"))
        title.pack(pady=(15, 5))

        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=5, fill=tk.X)
        button_frame.columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        ttk.Button(button_frame, text="📂 Agregar carpeta", command=self.add_folder).grid(row=0, column=0, sticky="ew", padx=3)
        ttk.Button(button_frame, text="📄 Cargar virus.txt", command=self.load_virus_names).grid(row=0, column=1, sticky="ew", padx=3)
        ttk.Button(button_frame, text="🔍 Escanear", command=self.scan).grid(row=0, column=2, sticky="ew", padx=3)
        self.clean_button = ttk.Button(button_frame, text="🗑️ Eliminar seleccionados", command=self.clean_selected, state=tk.DISABLED)
        self.clean_button.grid(row=0, column=3, sticky="ew", padx=3)
        self.clean_all_button = ttk.Button(button_frame, text="💣 Eliminar todo", command=self.clean_all, state=tk.DISABLED)
        self.clean_all_button.grid(row=0, column=4, sticky="ew", padx=3)
        ttk.Button(button_frame, text="⛔ Detener virus activos", command=self.kill_virus_processes).grid(row=0, column=5, sticky="ew", padx=3)
        ttk.Button(button_frame, text="🚫 Eliminar procesos maliciosos", command=self.remove_virus_processes).grid(row=0, column=6, sticky="ew", padx=3)

        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(10, 5))

        self.tree = ttk.Treeview(tree_frame, columns=("path",), show="headings", selectmode="extended")
        self.tree.heading("path", text="🦠 Rutas sospechosas encontradas")
        self.tree.column("path", anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        open_btn = ttk.Button(self.root, text="🗂️ Ver en carpeta", command=self.open_in_explorer)
        open_btn.pack(pady=5)

        tk.Label(self.root, text="📝 Log del análisis", font=("Segoe UI", 11, "bold")).pack()
        self.log_area = scrolledtext.ScrolledText(self.root, height=6, state="disabled", font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=False, padx=15, pady=5)

        self.system_info_label = tk.Label(self.root, text="", font=("Segoe UI", 10))
        self.system_info_label.pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Button(self.root, text="🔄 Actualizar sistema", command=self.update_system_info).pack(side=tk.RIGHT, padx=10)

    def log(self, msg):
        now = datetime.now().strftime("%H:%M:%S")
        full_msg = f"[{now}] {msg}"
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, full_msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")
        with open("clearnest_log.txt", "a", encoding="utf-8") as f:
            f.write(full_msg + "\n")

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.custom_paths.append(folder)
            self.log(f"[+] Carpeta agregada: {folder}")

    def load_virus_names(self):
        filepath = filedialog.askopenfilename(filetypes=[("Archivo de texto", "*.txt")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                self.virus_names = [line.strip().lower() for line in f if line.strip()]
            self.log(f"[✔] Lista de virus cargada: {len(self.virus_names)} entradas")

    def scan(self):
        self.tree.delete(*self.tree.get_children())
        self.detected.clear()
        self.clean_button.config(state=tk.DISABLED)
        self.clean_all_button.config(state=tk.DISABLED)
        all_paths = self.suspect_paths + self.custom_paths
        self.log("🔎 Escaneando carpetas sospechosas...")

        for path in all_paths:
            if not os.path.exists(path):
                continue
            for root_dir, dirs, files in os.walk(path):
                for item in dirs + files:
                    full_path = os.path.join(root_dir, item)
                    if item.lower() in self.virus_names or any(v in full_path.lower() for v in self.virus_names):
                        self.tree.insert("", "end", values=(full_path,))
                        self.detected.append(full_path)
                        self.log(f"[!] Detectado: {full_path}")

        if not self.detected:
            self.log("✅ Todo limpio.")
            messagebox.showinfo("ClearNest", "No se detectaron amenazas.")
        else:
            self.clean_button.config(state=tk.NORMAL)
            self.clean_all_button.config(state=tk.NORMAL)
            messagebox.showwarning("ClearNest", f"Se detectaron {len(self.detected)} amenazas.")
            self.log(f"⚠️ Total amenazas: {len(self.detected)}")

    def clean_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("ClearNest", "Selecciona elementos para eliminar.")
            return
        if not messagebox.askyesno("Confirmar", f"¿Eliminar {len(selected_items)} elementos seleccionados?"):
            return

        eliminados = 0
        for item in selected_items:
            path = self.tree.item(item, "values")[0]
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)
                eliminados += 1
                self.log(f"[✔] Eliminado: {path}")
                self.tree.delete(item)
            except Exception as e:
                self.log(f"[X] Error al eliminar {path}: {e}")

        messagebox.showinfo("ClearNest", f"{eliminados} elementos eliminados.")
        if not self.tree.get_children():
            self.clean_button.config(state=tk.DISABLED)
            self.clean_all_button.config(state=tk.DISABLED)

    def clean_all(self):
        for item in self.tree.get_children():
            self.tree.selection_add(item)
        self.clean_selected()

    def open_in_explorer(self):
        selected = self.tree.selection()
        if selected:
            path = self.tree.item(selected[0], "values")[0]
            if os.path.exists(path):
                subprocess.run(f'explorer /select,"{path}"')
            else:
                messagebox.showerror("ClearNest", "Ruta no encontrada.")

    def update_system_info(self):
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            info = f"🖥️ CPU: {cpu}% | RAM libre: {ram.available // (1024**2)} MB | Disco: {disk.free // (1024**3)} GB libres"
            self.system_info_label.config(text=info)
        except Exception as e:
            self.system_info_label.config(text=f"Error al obtener info: {e}")

    def kill_virus_processes(self):
        count = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(v in name for v in self.virus_names):
                    proc.kill()
                    count += 1
                    self.log(f"[✖] Proceso detenido: {name}")
            except Exception as e:
                self.log(f"[X] Error al detener: {e}")
        messagebox.showinfo("ClearNest", f"{count} procesos detenidos.")

    def remove_virus_processes(self):
        if not messagebox.askyesno("Confirmar", "¿Eliminar archivos de procesos maliciosos?"):
            return
        count = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info['name'].lower()
                path = proc.info.get('exe', '')
                if path and any(v in name for v in self.virus_names):
                    proc.kill()
                    os.remove(path)
                    count += 1
                    self.log(f"[✔] Proceso eliminado: {path}")
            except Exception as e:
                self.log(f"[X] Error: {e}")
        messagebox.showinfo("ClearNest", f"{count} archivos eliminados.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClearNest(root)
    root.mainloop()
