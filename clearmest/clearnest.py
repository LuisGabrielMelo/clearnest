import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext

class ClearNest:
    def __init__(self, root):
        self.root = root
        self.root.title("ClearNest – Escaneo y limpieza avanzada")
        self.root.geometry("700x550")
        self.root.resizable(False, False)

        self.suspect_paths = [
            os.path.expandvars(r"%APPDATA%\SearchProtect"),
            os.path.expandvars(r"%APPDATA%\Babylon"),
            os.path.expandvars(r"%APPDATA%\Delta"),
            os.path.expandvars(r"%PROGRAMFILES%\SearchProtect"),
            os.path.expandvars(r"%PROGRAMFILES(X86)%\SearchProtect"),
            os.path.expandvars(r"%TEMP%"),
        ]

        self.custom_paths = []
        self.virus_names = []

        self.detected = []
        self.build_ui()

    def build_ui(self):
        title = tk.Label(self.root, text="🛡️ ClearNest – Protección contra adware", font=("Segoe UI", 16, "bold"))
        title.pack(pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=5)

        tk.Button(button_frame, text="📂 Agregar carpeta", command=self.add_folder).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="📄 Cargar virus.txt", command=self.load_virus_names).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="🔍 Escanear", command=self.scan).grid(row=0, column=2, padx=5)
        self.clean_button = tk.Button(button_frame, text="🗑️ Eliminar seleccionados", command=self.clean_selected, state=tk.DISABLED)
        self.clean_button.grid(row=0, column=3, padx=5)

        # Tabla de resultados
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tree = ttk.Treeview(tree_frame, columns=("path",), show="headings", height=12)
        self.tree.heading("path", text="Ruta sospechosa")
        self.tree.column("path", width=650)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Log/status
        tk.Label(self.root, text="Estado:", font=("Segoe UI", 11, "bold")).pack()
        self.log_area = scrolledtext.ScrolledText(self.root, height=6, state="disabled", font=("Consolas", 9))
        self.log_area.pack(fill=tk.X, padx=10, pady=5)

    def log(self, msg):
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.custom_paths.append(folder)
            self.log(f"[+] Carpeta agregada para escanear: {folder}")

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

        all_paths = self.suspect_paths + self.custom_paths
        self.log("🔎 Escaneando...")

        for path in all_paths:
            if not os.path.exists(path):
                continue

            for root_dir, dirs, files in os.walk(path):
                items = dirs + files
                for item in items:
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
            messagebox.showwarning("ClearNest", f"Se encontraron {len(self.detected)} elementos sospechosos.")
            self.log(f"⚠️ Amenazas detectadas: {len(self.detected)}")

    def clean_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("ClearNest", "Selecciona al menos una ruta para eliminar.")
            return

        confirm = messagebox.askyesno("Confirmar", f"¿Eliminar {len(selected_items)} elementos seleccionados?")
        if not confirm:
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
                self.log(f"[X] Error eliminando {path}: {str(e)}")

        messagebox.showinfo("ClearNest", f"🧹 Limpieza completa. {eliminados} elementos eliminados.")
        if self.tree.get_children():
            self.clean_button.config(state=tk.NORMAL)
        else:
            self.clean_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = ClearNest(root)
    root.mainloop()
