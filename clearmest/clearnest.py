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
        self.root.title("🛡️ ClearNest – Limpieza avanzada del sistema")
        self.root.geometry("950x760")
        self.root.resizable(False, False)

        self.suspect_paths = [
            os.path.expandvars(r"%APPDATA%\SearchProtect"),
            os.path.expandvars(r"%APPDATA%\Babylon"),
            os.path.expandvars(r"%APPDATA%\Delta"),
            os.path.expandvars(r"%PROGRAMFILES%\SearchProtect"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\SearchProtect"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
        ]

        self.custom_paths = []
        self.virus_names = []
        self.detected = []

        self.build_ui()
        self.update_system_info()

    def build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=8, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))

        title = tk.Label(self.root, text="🛡️ ClearNest", font=("Segoe UI", 22, "bold"), fg="#2d3436")
        subtitle = tk.Label(self.root, text="Protección contra adware y procesos sospechosos", font=("Segoe UI", 11), fg="#636e72")
        title.pack(pady=(15, 0))
        subtitle.pack(pady=(0, 15))

        self.build_buttons()
        self.build_tree()
        self.build_log_area()
        self.build_footer()

    def build_buttons(self):
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        buttons = [
            ("📂 Agregar carpeta", self.add_folder),
            ("📄 Cargar virus.txt", self.load_virus_names),
            ("🔍 Escanear", self.scan),
            ("🗑️ Eliminar seleccionados", self.clean_selected),
            ("💣 Eliminar todo", self.clean_all),
            ("⛔ Detener procesos", self.kill_virus_processes),
            ("🔥 Eliminar procesos maliciosos", self.remove_virus_processes)
        ]

        for i, (label, command) in enumerate(buttons):
            btn = ttk.Button(frame, text=label, command=command)
            btn.grid(row=0, column=i, padx=4)

        self.clean_button = frame.winfo_children()[3]
        self.clean_all_button = frame.winfo_children()[4]
        self.clean_button.config(state=tk.DISABLED)
        self.clean_all_button.config(state=tk.DISABLED)

    def build_tree(self):
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tree_frame, columns=("path",), show="headings", height=18)
        self.tree.heading("path", text="Ruta detectada")
        self.tree.column("path", width=880)

        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(self.root, text="🗂️ Ver archivo en carpeta", command=self.open_in_explorer).pack(pady=5)

    def build_log_area(self):
        tk.Label(self.root, text="Registro de actividad:", font=("Segoe UI", 10, "bold")).pack(pady=(5, 0))
        self.log_area = scrolledtext.ScrolledText(self.root, height=6, state="disabled", font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, padx=15, pady=5)

    def build_footer(self):
        footer = tk.Frame(self.root)
        footer.pack(fill=tk.X, pady=10)
        self.system_info_label = tk.Label(footer, text="", font=("Segoe UI", 9))
        self.system_info_label.pack(side=tk.LEFT, padx=15)
        ttk.Button(footer, text="🔄 Actualizar sistema", command=self.update_system_info).pack(side=tk.RIGHT, padx=15)

    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {msg}"
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, log_msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

        with open("clearnest_log.txt", "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.custom_paths.append(folder)
            self.log(f"🗂️ Carpeta agregada: {folder}")

    def load_virus_names(self):
        file = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
        if file:
            with open(file, "r", encoding="utf-8") as f:
                self.virus_names = [line.strip().lower() for line in f if line.strip()]
            self.log(f"📄 Lista de virus cargada ({len(self.virus_names)} nombres)")

    def scan(self):
        self.tree.delete(*self.tree.get_children())
        self.detected.clear()
        self.clean_button.config(state=tk.DISABLED)
        self.clean_all_button.config(state=tk.DISABLED)

        all_paths = self.suspect_paths + self.custom_paths
        self.log("🔍 Escaneando rutas...")

        for path in all_paths:
            if not os.path.exists(path):
                continue
            for root_dir, dirs, files in os.walk(path):
                for item in dirs + files:
                    full_path = os.path.join(root_dir, item)
                    if item.lower() in self.virus_names or any(v in full_path.lower() for v in self.virus_names):
                        self.tree.insert("", "end", values=(full_path,))
                        self.detected.append(full_path)
                        self.log(f"⚠️ Detectado: {full_path}")

        if not self.detected:
            self.log("✅ No se detectaron amenazas.")
            messagebox.showinfo("ClearNest", "Todo limpio.")
        else:
            self.clean_button.config(state=tk.NORMAL)
            self.clean_all_button.config(state=tk.NORMAL)
            messagebox.showwarning("ClearNest", f"Se encontraron {len(self.detected)} amenazas.")
            self.log(f"🛑 Total: {len(self.detected)} elementos sospechosos")

    def clean_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("ClearNest", "Selecciona al menos un elemento.")
            return

        if not messagebox.askyesno("Confirmación", f"¿Eliminar {len(selected)} elementos seleccionados?"):
            return

        eliminados = 0
        for item in selected:
            path = self.tree.item(item, "values")[0]
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)
                self.tree.delete(item)
                eliminados += 1
                self.log(f"🗑️ Eliminado: {path}")
            except Exception as e:
                self.log(f"❌ Error al eliminar {path}: {e}")

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
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            info = f"CPU: {cpu}% | RAM: {mem.available // (1024**2)} MB libres / {mem.total // (1024**2)} MB | Disco: {disk.free // (1024**3)} GB libres"
            self.system_info_label.config(text=info)
        except Exception as e:
            self.system_info_label.config(text=f"Error obteniendo datos: {e}")

    def kill_virus_processes(self):
        killed = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(v in name for v in self.virus_names):
                    proc.kill()
                    self.log(f"⛔ Proceso detenido: {name}")
                    killed += 1
            except Exception as e:
                self.log(f"❌ Error: {e}")
        messagebox.showinfo("ClearNest", f"Se detuvieron {killed} procesos.")

    def remove_virus_processes(self):
        if not messagebox.askyesno("Confirmar", "¿Eliminar procesos maliciosos detectados?"):
            return

        removed = 0
        for proc in psutil.process_iter(['exe']):
            try:
                exe = proc.info['exe']
                if exe and any(v in exe.lower() for v in self.virus_names):
                    proc.kill()
                    os.remove(exe)
                    self.log(f"🔥 Proceso y archivo eliminado: {exe}")
                    removed += 1
            except Exception as e:
                self.log(f"❌ No se pudo eliminar: {e}")
        messagebox.showinfo("ClearNest", f"🔥 {removed} procesos eliminados.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClearNest(root)
    root.mainloop()
