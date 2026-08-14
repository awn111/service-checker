#!/usr/bin/env python3
"""
Port Checker R1 GUI
Version: 0.1

GUI front-end for:
    port_checker_r1_v1_2_2.py

Requirements:
    pip install PySide6

Future Features:
    - Charts
    - Historical trend viewer
    - Scheduled testing
    - Interface selection
"""

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QObject, Signal, QThread
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)


###############################################################################
# Worker Thread
###############################################################################

class ScanWorker(QObject):

    completed = Signal()
    log = Signal(str)
    result = Signal(dict)
    region = Signal(dict)
    progress = Signal(int)

    def __init__(self, host_file, threads):
        super().__init__()
        self.host_file = host_file
        self.threads = threads
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        """
        Placeholder.

        This is where we import and call
        port_checker_r1_v1_2_2.py
        """

        self.log.emit("Starting scan...")
        self.progress.emit(0)

        #
        # EXAMPLE DATA
        #
        demo_results = [
            {
                "status": "PASS",
                "host": "api.ruckus.cloud",
                "port": 443,
                "dns": "OK",
                "tcp": "OK",
                "tls": "OK",
                "cert": "Valid",
                "latency": "44"
            },
            {
                "status": "WARN",
                "host": "eu1.ruckus.cloud",
                "port": 443,
                "dns": "OK",
                "tcp": "OK",
                "tls": "OK",
                "cert": "14 days",
                "latency": "62"
            }
        ]

        for idx, item in enumerate(demo_results):

            if not self.running:
                self.log.emit("Scan stopped.")
                break

            self.result.emit(item)
            self.progress.emit((idx + 1) * 50)

        #
        # Demo Region Summary
        #

        self.region.emit(
            {
                "region": "US",
                "status": "PASS",
                "success": "100%",
                "latency": "44 ms"
            }
        )

        self.region.emit(
            {
                "region": "EU",
                "status": "WARN",
                "success": "98%",
                "latency": "62 ms"
            }
        )

        self.region.emit(
            {
                "region": "APAC",
                "status": "PASS",
                "success": "100%",
                "latency": "31 ms"
            }
        )

        self.log.emit("Scan complete.")
        self.progress.emit(100)
        self.completed.emit()


###############################################################################
# Main Window
###############################################################################

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("RUCKUS R1 Port Checker")
        self.resize(1400, 900)

        self.worker = None
        self.thread = None

        self.build_ui()

    ###########################################################################
    # UI
    ###########################################################################

    def build_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)

        #
        # Configuration
        #

        config_group = QGroupBox("Configuration")
        config_layout = QGridLayout(config_group)

        self.file_edit = QLineEdit("hosts_r1.csv")

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.select_file)

        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 500)
        self.thread_spin.setValue(50)

        self.start_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")

        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)

        config_layout.addWidget(QLabel("Host File"), 0, 0)
        config_layout.addWidget(self.file_edit, 0, 1)
        config_layout.addWidget(browse_btn, 0, 2)

        config_layout.addWidget(QLabel("Threads"), 1, 0)
        config_layout.addWidget(self.thread_spin, 1, 1)

        config_layout.addWidget(self.start_btn, 2, 1)
        config_layout.addWidget(self.stop_btn, 2, 2)

        layout.addWidget(config_group)

        #
        # Regional Summary
        #

        region_group = QGroupBox("R1 Regional Readiness")
        region_layout = QVBoxLayout(region_group)

        self.region_table = QTableWidget()
        self.region_table.setColumnCount(4)
        self.region_table.setHorizontalHeaderLabels(
            [
                "Region",
                "Status",
                "Success %",
                "Median Latency"
            ]
        )

        self.region_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        region_layout.addWidget(self.region_table)

        layout.addWidget(region_group)

        #
        # Results
        #

        result_group = QGroupBox("Detailed Results")
        result_layout = QVBoxLayout(result_group)

        self.results_table = QTableWidget()

        self.results_table.setColumnCount(8)

        self.results_table.setHorizontalHeaderLabels(
            [
                "Status",
                "Host",
                "Port",
                "DNS",
                "TCP",
                "TLS",
                "Certificate",
                "Latency (ms)"
            ]
        )

        self.results_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        result_layout.addWidget(self.results_table)

        layout.addWidget(result_group)

        #
        # Progress
        #

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        #
        # Log Window
        #

        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)

        log_layout.addWidget(self.log_text)

        layout.addWidget(log_group)

    ###########################################################################
    # File Selection
    ###########################################################################

    def select_file(self):

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Host File",
            ".",
            "CSV Files (*.csv)"
        )

        if filename:
            self.file_edit.setText(filename)

    ###########################################################################
    # Scan Control
    ###########################################################################

    def start_scan(self):

        host_file = self.file_edit.text().strip()

        if not Path(host_file).exists():

            QMessageBox.warning(
                self,
                "Missing File",
                f"Cannot find:\n{host_file}"
            )
            return

        self.results_table.setRowCount(0)
        self.region_table.setRowCount(0)

        self.thread = QThread()

        self.worker = ScanWorker(
            host_file=host_file,
            threads=self.thread_spin.value()
        )

        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)

        self.worker.result.connect(self.add_result)
        self.worker.region.connect(self.add_region)
        self.worker.log.connect(self.log_message)
        self.worker.progress.connect(self.progress.setValue)

        self.worker.completed.connect(self.thread.quit)

        self.thread.start()

    def stop_scan(self):

        if self.worker:
            self.worker.stop()

    ###########################################################################
    # Updates
    ###########################################################################

    def add_result(self, data):

        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        values = [
            data["status"],
            data["host"],
            str(data["port"]),
            data["dns"],
            data["tcp"],
            data["tls"],
            data["cert"],
            data["latency"]
        ]

        for col, value in enumerate(values):
            self.results_table.setItem(
                row,
                col,
                QTableWidgetItem(value)
            )

    def add_region(self, data):

        row = self.region_table.rowCount()
        self.region_table.insertRow(row)

        values = [
            data["region"],
            data["status"],
            data["success"],
            data["latency"]
        ]

        for col, value in enumerate(values):
            self.region_table.setItem(
                row,
                col,
                QTableWidgetItem(value)
            )

    def log_message(self, message):

        self.log_text.appendPlainText(message)


###############################################################################
# Main
###############################################################################

def main():

    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()