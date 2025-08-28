from pyQt5.QtWidgets import QMainWindow, QAction, QMenuBar, QStatusBar,QApplication
import sys

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Web Forensics")
        self.setGeometry(200,200,900,600)

        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("Archivo")
        exit_action = QAction("Salir", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        options_menu = menubar.addMenu("Opciones")

        help_menu = menubar.addMenu("Ayuda")
        about_action = QAction("Acerca de", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Listo")
    
    def show_about(self):
        self.status_bar.showMessage("Herramienta Forense para Navegedaores v1.0")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())