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
        self.root.title("ClearNest – Escaneo y limpieza avanzada")

        # Tamaño fijo o adaptable según pantalla
        self.root.geometry("900x750")  # Tamaño fijo recomendado
        # O para tamaño adaptable:
        # screen_width = self.root.winfo_screenwidth()
        # screen_height = self.root.winfo_screenheight()
        # self.root.geometry(f"{int(screen_width * 0.8)}x{int(screen_height * 0.85)}")

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
        ttk.Style().configure("TButton", padding=6, font=("Segoe UI", 10))
        ttk.Style().configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        title = tk.Label(self.root, text="🛡️ ClearNest – Protección contra adware", font=("Segoe UI", 18, "bold"))
        title.pack(pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="📂 Agregar carpeta", command=self.add_folder).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="📄 Cargar virus.txt", command=self.load_virus_names).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="🔍 Escanear", command=self.scan).grid(row=0, column=2, padx=5)
        self.clean_button = ttk.Button(button_frame, text="🗑️ Eliminar seleccionados", command=self.clean_selected, state=tk.DISABLED)
        self.clean_button.grid(row=0, column=3, padx=5)
        self.clean_all_button = ttk.Button(button_frame, text="💣 Eliminar todo", command=self.clean_all, state=tk.DISABLED)
        self.clean_all_button.grid(row=0, column=4, padx=5)
        ttk.Button(button_frame, text="⛔ Detener virus activos", command=self.kill_virus_processes).grid(row=0, column=5, padx=5)
        ttk.Button(button_frame, text="🚫 Eliminar procesos maliciosos", command=self.remove_virus_processes).grid(row=0, column=6, padx=5)

        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tree = ttk.Treeview(tree_frame, columns=("path",), show="headings", height=18)
        self.tree.heading("path", text="Ruta sospechosa")
        self.tree.column("path", width=750)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = tk.Frame(self.root)
        action_frame.pack()

        ttk.Button(action_frame, text="🗂️ Ver en carpeta", command=self.open_in_explorer).pack(side=tk.LEFT, padx=5)

        tk.Label(self.root, text="Estado del análisis:", font=("Segoe UI", 11, "bold")).pack()
        self.log_area = scrolledtext.ScrolledText(self.root, height=6, state="disabled", font=("Consolas", 9))
        self.log_area.pack(fill=tk.X, padx=10, pady=5)

        self.system_info_frame = tk.Frame(self.root)
        self.system_info_frame.pack(pady=5, fill=tk.X)
        self.system_info_label = tk.Label(self.system_info_frame, text="", font=("Segoe UI", 10))
        self.system_info_label.pack(side=tk.LEFT, padx=10)
        ttk.Button(self.system_info_frame, text="🔄 Actualizar", command=self.update_system_info).pack(side=tk.RIGHT, padx=10)

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
            self.log(f"[✔] Lista de virus cargada: {len(self.virus_names)} nombres")

    def scan(self):
        self.tree.delete(*self.tree.get_children())
        self.detected.clear()
        self.clean_button.config(state=tk.DISABLED)
        self.clean_all_button.config(state=tk.DISABLED)

        all_paths = self.suspect_paths + self.custom_paths
        self.log("🔎 Iniciando escaneo...")

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
            self.log("✅ No se encontraron amenazas.")
            messagebox.showinfo("ClearNest", "Todo limpio.")
        else:
            self.clean_button.config(state=tk.NORMAL)
            self.clean_all_button.config(state=tk.NORMAL)
            messagebox.showwarning("ClearNest", f"Se encontraron {len(self.detected)} elementos sospechosos.")
            self.log(f"⚠️ Total amenazas: {len(self.detected)}")

    def clean_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("ClearNest", "Selecciona al menos una ruta.")
            return

        if not messagebox.askyesno("Confirmar", f"¿Eliminar {len(selected_items)} elementos?"):
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

        messagebox.showinfo("ClearNest", f"🧹 {eliminados} elementos eliminados.")
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
                messagebox.showerror("ClearNest", "La ruta no existe.")

    def update_system_info(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            info = (
                f"CPU: {cpu_percent}% | RAM: {memory.available // (1024**2)} MB libres de {memory.total // (1024**2)} MB | "
                f"Disco: {disk.free // (1024**3)} GB libres"
            )
            self.system_info_label.config(text=info)
        except Exception as e:
            self.system_info_label.config(text=f"Error al obtener info: {e}")

    def kill_virus_processes(self):
        killed = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(v in name for v in self.virus_names):
                    proc.kill()
                    killed += 1
                    self.log(f"[✖] Proceso detenido: {name}")
            except Exception as e:
                self.log(f"[X] Error al detener proceso: {e}")
        messagebox.showinfo("ClearNest", f"⛔ Se detuvieron {killed} procesos.")

    def remove_virus_processes(self):
        confirm = messagebox.askyesno("Confirmar", "¿Eliminar archivos de procesos maliciosos encontrados?")
        if not confirm:
            return
        removed = 0
        for proc in psutil.process_iter(['exe']):
            try:
                exe = proc.info['exe']
                if exe and any(v in exe.lower() for v in self.virus_names):
                    proc.kill()
                    os.remove(exe)
                    removed += 1
                    self.log(f"[🔥] Eliminado proceso y archivo: {exe}")
            except Exception as e:
                self.log(f"[X] No se pudo eliminar: {e}")
        messagebox.showinfo("ClearNest", f"🔥 Se eliminaron {removed} procesos maliciosos.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClearNest(root)
    root.mainloop()

