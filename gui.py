import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
import json
from cybersecurity_system import CybersecuritySystem
from rich.console import Console
from rich.text import Text
import sys
import io

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.update()

    def flush(self):
        pass

class CybersecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Driven Cybersecurity System")
        self.root.geometry("800x600")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # System Information Frame
        info_frame = ttk.LabelFrame(main_frame, text="System Information", padding="5")
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # OS Name
        ttk.Label(info_frame, text="OS Name:").grid(row=0, column=0, sticky=tk.W)
        self.os_name = ttk.Entry(info_frame, width=30)
        self.os_name.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.os_name.insert(0, "Ubuntu")
        
        # OS Version
        ttk.Label(info_frame, text="OS Version:").grid(row=1, column=0, sticky=tk.W)
        self.os_version = ttk.Entry(info_frame, width=30)
        self.os_version.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        self.os_version.insert(0, "22.04 LTS")
        
        # Kernel Version
        ttk.Label(info_frame, text="Kernel Version:").grid(row=2, column=0, sticky=tk.W)
        self.kernel_version = ttk.Entry(info_frame, width=30)
        self.kernel_version.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5)
        self.kernel_version.insert(0, "5.15.0-91-generic")
        
        # Installed Packages
        ttk.Label(info_frame, text="Installed Packages:").grid(row=3, column=0, sticky=tk.W)
        self.packages = scrolledtext.ScrolledText(info_frame, width=30, height=4)
        self.packages.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=5)
        self.packages.insert(tk.END, "nginx\npostgresql\npython3\ndocker")
        
        # Network Services
        ttk.Label(info_frame, text="Network Services:").grid(row=4, column=0, sticky=tk.W)
        self.services = scrolledtext.ScrolledText(info_frame, width=30, height=4)
        self.services.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5)
        self.services.insert(tk.END, "ssh\nhttp\nhttps\npostgresql")
        
        # Output Frame
        output_frame = ttk.LabelFrame(main_frame, text="Analysis Output", padding="5")
        output_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Output Text
        self.output_text = scrolledtext.ScrolledText(output_frame, width=80, height=20)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Redirect stdout to the text widget
        sys.stdout = RedirectText(self.output_text)
        
        # Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        # Analyze Button
        self.analyze_button = ttk.Button(button_frame, text="Analyze System", command=self.start_analysis)
        self.analyze_button.grid(row=0, column=0, padx=5)
        
        # Clear Button
        self.clear_button = ttk.Button(button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=1, padx=5)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
    def get_system_info(self):
        """Get system information from the GUI inputs."""
        return {
            "os_name": self.os_name.get(),
            "os_version": self.os_version.get(),
            "kernel_version": self.kernel_version.get(),
            "installed_packages": [pkg.strip() for pkg in self.packages.get("1.0", tk.END).split("\n") if pkg.strip()],
            "network_services": [svc.strip() for svc in self.services.get("1.0", tk.END).split("\n") if svc.strip()]
        }
        
    def start_analysis(self):
        """Start the system analysis."""
        self.analyze_button.state(['disabled'])
        self.status_var.set("Analyzing system...")
        self.output_text.delete("1.0", tk.END)
        
        # Create and run the analysis in a separate thread
        def run_analysis():
            try:
                system = CybersecuritySystem()
                system_info = self.get_system_info()
                results = asyncio.run(system.analyze_system(system_info))
                
                # Update GUI in the main thread
                self.root.after(0, self.analysis_complete, results)
            except Exception as e:
                self.root.after(0, self.analysis_error, str(e))
                
        import threading
        thread = threading.Thread(target=run_analysis)
        thread.daemon = True
        thread.start()
        
    def analysis_complete(self, results):
        """Handle completion of the analysis."""
        self.analyze_button.state(['!disabled'])
        self.status_var.set("Analysis complete")
        
        # Display the formatted report
        console = Console()
        console.print(results["formatted_report"])
        
    def analysis_error(self, error_message):
        """Handle analysis errors."""
        self.analyze_button.state(['!disabled'])
        self.status_var.set("Error during analysis")
        messagebox.showerror("Error", f"An error occurred during analysis:\n{error_message}")
        
    def clear_output(self):
        """Clear the output text area."""
        self.output_text.delete("1.0", tk.END)
        self.status_var.set("Ready")

def main():
    root = tk.Tk()
    app = CybersecurityGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 