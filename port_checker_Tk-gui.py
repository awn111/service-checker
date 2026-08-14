#!/usr/bin/env python3
"""
RUCKUS R1 Port Checker GUI
Version: 0.1

Tkinter GUI Front-End

Features:
- Sortable columns
- PASS/WARN/FAIL filtering
- Status bar statistics
- Regional readiness table
- Detailed results table
- Activity log
"""

import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

import threading
from pathlib import Path


class PortCheckerGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("RUCKUS R1 Port Checker")
        self.root.geometry("1400x900")

        self.results_data = []

        self.build_ui()

    ###########################################################################
    # UI
    ###########################################################################

    def build_ui(self):

        self.build_configuration()

        self.build_region_table()

        self.build_results_table()

        self.build_log_window()

        self.build_status_bar()

    ###########################################################################
    # Configuration
    ###########################################################################

    def build_configuration(self):

        frame = ttk.LabelFrame(
            self.root,
            text="Configuration"
        )

        frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        ttk.Label(
            frame,
            text="Host File:"
        ).grid(
            row=0,
            column=0,
            padx=5,
            pady=5,
            sticky="w"
        )

        self.host_file = tk.StringVar(
            value="hosts_r1.csv"
        )

        ttk.Entry(
            frame,
            textvariable=self.host_file,
            width=80
        ).grid(
            row=0,
            column=1,
            padx=5,
            pady=5
        )

        ttk.Button(
            frame,
            text="Browse",
            command=self.select_file
        ).grid(
            row=0,
            column=2,
            padx=5
        )

        ttk.Button(
            frame,
            text="Start Scan",
            command=self.start_scan
        ).grid(
            row=0,
            column=3,
            padx=5
        )

        ttk.Button(
            frame,
            text="Stop",
            command=self.stop_scan
        ).grid(
            row=0,
            column=4,
            padx=5
        )

    ###########################################################################
    # Region Table
    ###########################################################################

    def build_region_table(self):

        frame = ttk.LabelFrame(
            self.root,
            text="Regional Readiness"
        )

        frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        columns = (
            "Region",
            "Status",
            "Success %",
            "Median Latency"
        )

        self.region_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            height=4
        )

        for col in columns:

            self.region_tree.heading(
                col,
                text=col
            )

            self.region_tree.column(
                col,
                width=150,
                anchor="center"
            )

        self.region_tree.pack(
            fill="x"
        )

        self.region_tree.tag_configure(
            "PASS",
            background="#c6efce"
        )

        self.region_tree.tag_configure(
            "WARN",
            background="#ffeb9c"
        )

        self.region_tree.tag_configure(
            "FAIL",
            background="#ffc7ce"
        )

    ###########################################################################
    # Results Table
    ###########################################################################

    def build_results_table(self):

        frame = ttk.LabelFrame(
            self.root,
            text="Detailed Results"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        filter_frame = ttk.Frame(frame)
        filter_frame.pack(fill="x", pady=5)

        ttk.Button(
            filter_frame,
            text="ALL",
            command=lambda: self.apply_filter("ALL")
        ).pack(side="left", padx=2)

        ttk.Button(
            filter_frame,
            text="PASS",
            command=lambda: self.apply_filter("PASS")
        ).pack(side="left", padx=2)

        ttk.Button(
            filter_frame,
            text="WARN",
            command=lambda: self.apply_filter("WARN")
        ).pack(side="left", padx=2)

        ttk.Button(
            filter_frame,
            text="FAIL",
            command=lambda: self.apply_filter("FAIL")
        ).pack(side="left", padx=2)

        columns = (
            "Status",
            "Host",
            "Port",
            "DNS",
            "TCP",
            "TLS",
            "Certificate",
            "Latency"
        )

        self.tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        for col in columns:

            self.tree.heading(
                col,
                text=col,
                command=lambda c=col: self.sort_column(c, False)
            )

            self.tree.column(
                col,
                width=120
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.tree.tag_configure(
            "PASS",
            background="#c6efce"
        )

        self.tree.tag_configure(
            "WARN",
            background="#ffeb9c"
        )

        self.tree.tag_configure(
            "FAIL",
            background="#ffc7ce"
        )

    ###########################################################################
    # Log Window
    ###########################################################################

    def build_log_window(self):

        frame = ttk.LabelFrame(
            self.root,
            text="Activity Log"
        )

        frame.pack(
            fill="both",
            padx=10,
            pady=5
        )

        self.log_text = tk.Text(
            frame,
            height=8
        )

        self.log_text.pack(
            fill="both"
        )

    ###########################################################################
    # Status Bar
    ###########################################################################

    def build_status_bar(self):

        self.status_var = tk.StringVar()

        self.status_var.set("Ready")

        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            anchor="w"
        )

        status_bar.pack(
            fill="x",
            side="bottom"
        )

    ###########################################################################
    # File Selection
    ###########################################################################

    def select_file(self):

        filename = filedialog.askopenfilename(
            filetypes=[("CSV Files", "*.csv")]
        )

        if filename:
            self.host_file.set(filename)

    ###########################################################################
    # Sorting
    ###########################################################################

    def sort_column(self, col, reverse):

        items = []

        for child in self.tree.get_children(""):

            value = self.tree.set(child, col)

            items.append(
                (value, child)
            )

        if col == "Status":

            priority = {
                "FAIL": 0,
                "WARN": 1,
                "PASS": 2
            }

            items.sort(
                key=lambda x: priority.get(
                    x[0],
                    99
                ),
                reverse=reverse
            )

        else:

            items.sort(
                key=lambda x: str(
                    x[0]
                ).lower(),
                reverse=reverse
            )

        for index, (_, child) in enumerate(items):

            self.tree.move(
                child,
                "",
                index
            )

        self.tree.heading(
            col,
            command=lambda: self.sort_column(
                col,
                not reverse
            )
        )

    ###########################################################################
    # Filtering
    ###########################################################################

    def apply_filter(self, status_filter):

        self.tree.delete(
            *self.tree.get_children()
        )

        for result in self.results_data:

            if (
                status_filter == "ALL"
                or result["status"] == status_filter
            ):
                self.display_result(result)

    ###########################################################################
    # Results
    ###########################################################################

    def add_result(self, result):

        self.results_data.append(result)

        self.display_result(result)

        self.update_statistics()

    def display_result(self, result):

        status = result["status"]

        self.tree.insert(
            "",
            "end",
            values=(
                status,
                result["host"],
                result["port"],
                result["dns"],
                result["tcp"],
                result["tls"],
                result["cert"],
                result["latency"]
            ),
            tags=(status,)
        )

    ###########################################################################
    # Region Summary
    ###########################################################################

    def add_region(
        self,
        region,
        status,
        success,
        latency
    ):

        self.region_tree.insert(
            "",
            "end",
            values=(
                region,
                status,
                success,
                latency
            ),
            tags=(status,)
        )

    ###########################################################################
    # Statistics
    ###########################################################################

    def update_statistics(self):

        total = len(self.results_data)

        passes = sum(
            1 for r in self.results_data
            if r["status"] == "PASS"
        )

        warns = sum(
            1 for r in self.results_data
            if r["status"] == "WARN"
        )

        fails = sum(
            1 for r in self.results_data
            if r["status"] == "FAIL"
        )

        latencies = []

        for r in self.results_data:

            try:

                value = str(
                    r["latency"]
                )

                value = value.replace(
                    " ms",
                    ""
                )

                value = value.replace(
                    "ms",
                    ""
                )

                latencies.append(
                    float(value)
                )

            except Exception:
                pass

        median_latency = 0

        if latencies:

            latencies.sort()

            median_latency = latencies[
                len(latencies) // 2
            ]

        self.status_var.set(
            f"Checks: {total}    "
            f"PASS: {passes}    "
            f"WARN: {warns}    "
            f"FAIL: {fails}    "
            f"Median Latency: {median_latency:.1f} ms"
        )

    ###########################################################################
    # Logging
    ###########################################################################

    def log(self, message):

        self.log_text.insert(
            "end",
            message + "\n"
        )

        self.log_text.see("end")

    ###########################################################################
    # Scan Functions
    ###########################################################################

    def start_scan(self):

        if not Path(
            self.host_file.get()
        ).exists():

            messagebox.showerror(
                "Error",
                "Host file not found"
            )

            return

        self.results_data.clear()

        self.tree.delete(
            *self.tree.get_children()
        )

        self.region_tree.delete(
            *self.region_tree.get_children()
        )

        t = threading.Thread(
            target=self.run_scan,
            daemon=True
        )

        t.start()

    def stop_scan(self):

        self.log(
            "Stop requested"
        )

    def run_scan(self):

        self.log(
            "Starting scan..."
        )

        #
        # DEMO DATA
        #

        sample = [

            {
                "status": "PASS",
                "host": "us.ruckus.cloud",
                "port": 443,
                "dns": "OK",
                "tcp": "OK",
                "tls": "OK",
                "cert": "Valid",
                "latency": "42"
            },

            {
                "status": "WARN",
                "host": "eu.ruckus.cloud",
                "port": 443,
                "dns": "OK",
                "tcp": "OK",
                "tls": "OK",
                "cert": "14 days",
                "latency": "65"
            },

            {
                "status": "FAIL",
                "host": "bad.example.com",
                "port": 443,
                "dns": "FAIL",
                "tcp": "-",
                "tls": "-",
                "cert": "-",
                "latency": "-"
            }
        ]

        for row in sample:

            self.root.after(
                0,
                lambda r=row: self.add_result(r)
            )

        self.root.after(
            0,
            lambda: self.add_region(
                "US",
                "PASS",
                "100%",
                "42 ms"
            )
        )

        self.root.after(
            0,
            lambda: self.add_region(
                "EU",
                "WARN",
                "98%",
                "65 ms"
            )
        )

        self.root.after(
            0,
            lambda: self.add_region(
                "APAC",
                "FAIL",
                "75%",
                "51 ms"
            )
        )

        self.log(
            "Scan complete"
        )


if __name__ == "__main__":

    root = tk.Tk()

    app = PortCheckerGUI(root)

    root.mainloop()