import os
import shutil
import psutil
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
    QWidget, QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QTextEdit,
    QScrollArea
)
from PyQt5.QtCore import Qt, QTimer


class ClearNest(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ ClearNest – Protección contra adware")
        self.setMinimumSize(1000, 700)
        self.center()

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

        self.setup_ui()
        self.update_system_info()

    def center(self):
        screen = QApplication.primaryScreen().availableGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) // 2,
                  (screen.height() - size.height()) // 2)

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("🧹 ClearNest – Limpieza inteligente de adware")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold")
        layout.addWidget(title)

        button_layout = QHBoxLayout()
        buttons = [
            ("📂 Agregar carpeta", self.add_folder),
            ("📄 Cargar virus.txt", self.load_virus_names),
            ("🔍 Escanear", self.scan),
            ("🗑️ Eliminar seleccionados", self.clean_selected),
            ("💣 Eliminar todo", self.clean_all),
            ("⛔ Detener virus activos", self.kill_virus_processes),
            ("🚫 Eliminar procesos maliciosos", self.remove_virus_processes),
        ]

        self.clean_selected_btn = None
        self.clean_all_btn = None

        for text, handler in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            btn.setMinimumHeight(32)
            button_layout.addWidget(btn)
            if "seleccionados" in text:
                self.clean_selected_btn = btn
                btn.setEnabled(False)
            elif "todo" in text:
                self.clean_all_btn = btn
                btn.setEnabled(False)

        layout.addLayout(button_layout)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["🦠 Rutas sospechosas encontradas"])
        layout.addWidget(self.tree)

        open_btn = QPushButton("🗂️ Ver en carpeta")
        open_btn.clicked.connect(self.open_in_explorer)
        layout.addWidget(open_btn)

        log_label = QLabel("📝 Log del análisis")
        log_label.setStyleSheet("font-weight: bold; margin-top: 10px")
        layout.addWidget(log_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        bottom_layout = QHBoxLayout()
        self.system_info_label = QLabel()
        bottom_layout.addWidget(self.system_info_label)
        update_btn = QPushButton("🔄 Actualizar sistema")
        update_btn.clicked.connect(self.update_system_info)
        bottom_layout.addWidget(update_btn)
        layout.addLayout(bottom_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def log(self, msg):
        now = datetime.now().strftime("%H:%M:%S")
        full_msg = f"[{now}] {msg}"
        self.log_area.append(full_msg)
        with open("clearnest_log.txt", "a", encoding="utf-8") as f:
            f.write(full_msg + "\n")

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if folder:
            self.custom_paths.append(folder)
            self.log(f"[+] Carpeta agregada: {folder}")

    def load_virus_names(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar archivo", "", "Archivo de texto (*.txt)")
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.virus_names = [line.strip().lower() for line in f if line.strip()]
            self.log(f"[✔] Lista de virus cargada: {len(self.virus_names)} entradas")

    def scan(self):
        self.tree.clear()
        self.detected.clear()
        self.clean_selected_btn.setEnabled(False)
        self.clean_all_btn.setEnabled(False)

        all_paths = self.suspect_paths + self.custom_paths
        self.log("🔎 Escaneando carpetas sospechosas...")

        for path in all_paths:
            if not os.path.exists(path):
                continue
            for root_dir, dirs, files in os.walk(path):
                for item in dirs + files:
                    full_path = os.path.join(root_dir, item)
                    if item.lower() in self.virus_names or any(v in full_path.lower() for v in self.virus_names):
                        QTreeWidgetItem(self.tree, [full_path])
                        self.detected.append(full_path)
                        self.log(f"[!] Detectado: {full_path}")

        if not self.detected:
            self.log("✅ Todo limpio.")
            QMessageBox.information(self, "ClearNest", "No se detectaron amenazas.")
        else:
            self.clean_selected_btn.setEnabled(True)
            self.clean_all_btn.setEnabled(True)
            QMessageBox.warning(self, "ClearNest", f"Se detectaron {len(self.detected)} amenazas.")
            self.log(f"⚠️ Total amenazas: {len(self.detected)}")

    def clean_selected(self):
        selected_items = self.tree.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "ClearNest", "Selecciona elementos para eliminar.")
            return
        if not QMessageBox.question(self, "Confirmar", f"¿Eliminar {len(selected_items)} elementos seleccionados?",
                                    QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            return

        eliminados = 0
        for item in selected_items:
            path = item.text(0)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)
                eliminados += 1
                self.log(f"[✔] Eliminado: {path}")
                idx = self.tree.indexOfTopLevelItem(item)
                self.tree.takeTopLevelItem(idx)
            except Exception as e:
                self.log(f"[X] Error al eliminar {path}: {e}")

        QMessageBox.information(self, "ClearNest", f"{eliminados} elementos eliminados.")
        if self.tree.topLevelItemCount() == 0:
            self.clean_selected_btn.setEnabled(False)
            self.clean_all_btn.setEnabled(False)

    def clean_all(self):
        self.tree.selectAll()
        self.clean_selected()

    def open_in_explorer(self):
        selected = self.tree.selectedItems()
        if selected:
            path = selected[0].text(0)
            if os.path.exists(path):
                subprocess.run(f'explorer /select,"{path}"')
            else:
                QMessageBox.critical(self, "ClearNest", "Ruta no encontrada.")

    def update_system_info(self):
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            info = f"🖥️ CPU: {cpu}% | RAM libre: {ram.available // (1024**2)} MB | Disco: {disk.free // (1024**3)} GB libres"
            self.system_info_label.setText(info)
        except Exception as e:
            self.system_info_label.setText(f"Error: {e}")

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
        QMessageBox.information(self, "ClearNest", f"{count} procesos detenidos.")

    def remove_virus_processes(self):
        if QMessageBox.question(self, "Confirmar", "¿Eliminar archivos de procesos maliciosos?",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
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
        QMessageBox.information(self, "ClearNest", f"{count} archivos eliminados.")


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = ClearNest()
    window.show()
    sys.exit(app.exec_())
