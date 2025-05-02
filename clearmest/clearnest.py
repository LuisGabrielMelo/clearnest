import os
import shutil
import psutil
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
    QWidget, QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QTextEdit
)
from PyQt5.QtCore import Qt

class ClearNest(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ ClearNest – Protección contra adware")
        self.setMinimumSize(1000, 700)
        self.center_window()

        self.suspect_paths = [
            os.path.expandvars(p) for p in [
                r"%APPDATA%\\SearchProtect",
                r"%APPDATA%\\Babylon",
                r"%APPDATA%\\Delta",
                r"%PROGRAMFILES%\\SearchProtect",
                r"%PROGRAMFILES(X86)%\\SearchProtect",
                r"%TEMP%",
                r"%USERPROFILE%\\AppData\\Local\\Temp"
            ]
        ]
        self.custom_paths = []
        self.virus_names = set()

        self.setup_ui()
        self.update_system_info()

    def center_window(self):
        screen = QApplication.primaryScreen().availableGeometry()
        self.move((screen.width() - self.width()) // 2,
                  (screen.height() - self.height()) // 2)

    def setup_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🧹 ClearNest – Limpieza inteligente de adware")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold")
        layout.addWidget(title)

        buttons_layout = QHBoxLayout()
        actions = [
            ("📂 Agregar carpeta", self.add_folder),
            ("📄 Cargar virus.txt", self.load_virus_names),
            ("🔍 Escanear", self.scan_system),
            ("🗑️ Eliminar seleccionados", self.delete_selected),
            ("💣 Eliminar todo", self.delete_all),
            ("⛔ Detener virus activos", self.kill_malicious_processes),
            ("🚫 Eliminar procesos maliciosos", self.remove_malicious_executables)
        ]

        self.btn_delete_selected = QPushButton("🗑️ Eliminar seleccionados")
        self.btn_delete_all = QPushButton("💣 Eliminar todo")
        self.btn_delete_selected.setEnabled(False)
        self.btn_delete_all.setEnabled(False)

        for text, action in actions:
            btn = QPushButton(text)
            btn.clicked.connect(action)
            btn.setMinimumHeight(32)
            buttons_layout.addWidget(btn)

        layout.addLayout(buttons_layout)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["🦠 Amenazas Detectadas"])
        layout.addWidget(self.tree)

        open_btn = QPushButton("🗂️ Ver en carpeta")
        open_btn.clicked.connect(self.open_in_explorer)
        layout.addWidget(open_btn)

        self.log_area = QTextEdit(readOnly=True)
        layout.addWidget(self.log_area)

        info_layout = QHBoxLayout()
        self.system_info_label = QLabel()
        info_layout.addWidget(self.system_info_label)
        update_btn = QPushButton("🔄 Actualizar")
        update_btn.clicked.connect(self.update_system_info)
        info_layout.addWidget(update_btn)

        layout.addLayout(info_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.log_area.append(log_entry)
        with open('clearnest_log.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(log_entry + '\n')

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if folder:
            self.custom_paths.append(folder)
            self.log(f"Carpeta añadida: {folder}")

    def load_virus_names(self):
        path, _ = QFileDialog.getOpenFileName(self, "Cargar virus.txt", "", "Texto (*.txt)")
        if path:
            with open(path, 'r', encoding='utf-8') as file:
                self.virus_names = {line.strip().lower() for line in file if line.strip()}
            self.log(f"Lista cargada: {len(self.virus_names)} virus")

    def scan_system(self):
        self.tree.clear()
        found = []
        search_paths = self.suspect_paths + self.custom_paths

        for path in search_paths:
            for root, dirs, files in os.walk(path, topdown=True, onerror=lambda e: None):
                for name in files + dirs:
                    if name.lower() in self.virus_names:
                        full_path = os.path.join(root, name)
                        found.append(full_path)
                        QTreeWidgetItem(self.tree, [full_path])
                        self.log(f"Amenaza detectada: {full_path}")

        self.btn_delete_selected.setEnabled(bool(found))
        self.btn_delete_all.setEnabled(bool(found))

        if not found:
            QMessageBox.information(self, "Resultado del escaneo", "No se encontraron amenazas.")
            self.log("Sistema limpio.")

    def delete_selected(self):
        for item in self.tree.selectedItems():
            path = item.text(0)
            self.secure_delete(path)

    def delete_all(self):
        for index in range(self.tree.topLevelItemCount()):
            path = self.tree.topLevelItem(index).text(0)
            self.secure_delete(path)

    def secure_delete(self, path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            self.log(f"Eliminado: {path}")
        except Exception as e:
            self.log(f"Error al eliminar {path}: {e}")

    def kill_malicious_processes(self):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() in self.virus_names:
                proc.kill()
                self.log(f"Proceso detenido: {proc.info['name']}")

    def remove_malicious_executables(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.info['name'].lower() in self.virus_names and proc.info['exe']:
                try:
                    proc.kill()
                    os.remove(proc.info['exe'])
                    self.log(f"Ejecutable eliminado: {proc.info['exe']}")
                except Exception as e:
                    self.log(f"Error eliminando ejecutable {proc.info['exe']}: {e}")

    def open_in_explorer(self):
        item = self.tree.currentItem()
        if item:
            path = item.text(0)
            subprocess.run(['explorer', '/select,', path])

    def update_system_info(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().available / (1024**2)
        disk = psutil.disk_usage('/').free / (1024**3)
        self.system_info_label.setText(f"CPU: {cpu}% | RAM disponible: {ram:.0f} MB | Disco libre: {disk:.1f} GB")

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    window = ClearNest()
    window.show()
    sys.exit(app.exec())
