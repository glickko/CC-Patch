

import ctypes
import hashlib
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
import tkinter as tk
from pathlib import Path
from tkinter import font, messagebox

# Third-party library for real-time file system monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    messagebox.showerror(
        "Missing Library",
        "The 'watchdog' library is required. Please install it by running:\n\npip install watchdog"
    )
    sys.exit(1)


class Config:
    """Holds all static configuration and paths for the patcher."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        EMBEDDED_FILES_DIR = Path(sys._MEIPASS)
    else:
        EMBEDDED_FILES_DIR = Path(__file__).resolve().parent

    if getattr(sys, 'frozen', False):
        BASE_APP_DIR = Path(sys.executable).parent
    else:
        BASE_APP_DIR = EMBEDDED_FILES_DIR

    CAPCUT_DIR = BASE_APP_DIR / "3.8.0.1400"
    PATCH_DIR = EMBEDDED_FILES_DIR / "Patch"

    PATHS = {
        "loader1": PATCH_DIR / "patched" / "DLLLoader64_6E8D.exe",
        "loader2": PATCH_DIR / "patched" / "DLLLoader64_D057.exe",
        "target_dll": CAPCUT_DIR / "VECreator.dll",
        "target_dll_backup": CAPCUT_DIR / "VECreator.dll.bak",
        "target_loader1": CAPCUT_DIR / "DLLLoader64_6E8D.exe",
        "target_loader2": CAPCUT_DIR / "DLLLoader64_D057.exe",
        "capcut_exe": CAPCUT_DIR / "CapCut.exe",
    }
    
    SECRET_KEY = b"your-super-secret-key-glickko-123"
    
    # --- CORRECTED HEX PATCH DATA ---
    HEX_PATCHES = [
        {'name': 'Patch 1', 'offset': 0x9ebcde, 'original': b'\x0f\x84\x59\x03', 'modified': b'\xe9\x5a\x03\x00'},
        {'name': 'Patch 2', 'offset': 0x9ebce3, 'original': b'\x00', 'modified': b'\x90'},
        {'name': 'Patch 3', 'offset': 0xb738cc, 'original': b'\x0f\x85\x74\x06', 'modified': b'\xe9\x75\x06\x00'},
        {'name': 'Patch 4', 'offset': 0xb738d1, 'original': b'\x00', 'modified': b'\x90'},
        {'name': 'Patch 5', 'offset': 0x268a41a, 'original': b'\x0f\x85\x3a\x0a', 'modified': b'\xe9\x3b\x0a\x00'},
        {'name': 'Patch 6', 'offset': 0x28cc03c, 'original': b'\x00', 'modified': b'\x01'},
        {'name': 'Patch 7', 'offset': 0x28cc097, 'original': b'\x00', 'modified': b'\x01'},
        {'name': 'Patch 8', 'offset': 0x28cc1b5, 'original': b'\x00', 'modified': b'\x01'}
    ]

    CAPCUT_PROCESS_NAME = "CapCut.exe"
    GLICKKO_URL = "https://glickko.github.io"
    KOFI_URL = "https://ko-fi.com/glickko"

    @staticmethod
    def get_required_files():
        """Returns a list of files and directories that must exist externally."""
        return [
            Config.CAPCUT_DIR,
            Config.PATHS["target_dll"],
            Config.PATHS["capcut_exe"],
        ]

class FileIntegrityChecker:
    """Handles state detection."""

    @staticmethod
    def get_status() -> str:
        """Determines the patch status based on the existence of the backup file."""
        if Config.PATHS["target_dll_backup"].exists():
            return "PATCHED"
        else:
            return "UNPATCHED"

class Patcher:
    """Handles all core logic for the CapCut patcher."""

    def __init__(self):
        self._startup_info = subprocess.STARTUPINFO()
        self._startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self._startup_info.wShowWindow = subprocess.SW_HIDE

    def is_capcut_running(self):
        """Checks if the CapCut process is currently running."""
        try:
            cmd = ['tasklist', '/FI', f'IMAGENAME eq {Config.CAPCUT_PROCESS_NAME}']
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True,
                startupinfo=self._startup_info, encoding='utf-8'
            )
            return Config.CAPCUT_PROCESS_NAME.lower() in result.stdout.lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def force_close_capcut(self):
        """Forcefully terminates the CapCut process and waits for it to exit."""
        if not self.is_capcut_running():
            return True, "CapCut is already closed."
        
        try:
            cmd = ['taskkill', '/F', '/IM', Config.CAPCUT_PROCESS_NAME]
            subprocess.run(cmd, check=True, capture_output=True, startupinfo=self._startup_info)
            
            for _ in range(15):
                if not self.is_capcut_running():
                    time.sleep(0.5) 
                    return True, "CapCut closed successfully."
                time.sleep(0.2)
                
            return False, "Failed to close CapCut (timeout)."

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            return False, f"Error closing CapCut: {e}"

    def _set_file_attributes(self, file_path: Path, hide: bool):
        """Applies or removes hidden and system attributes from a file."""
        try:
            op = "+" if hide else "-"
            command = ['attrib', f'{op}h', f'{op}s', str(file_path)]
            subprocess.run(command, check=True, capture_output=True, startupinfo=self._startup_info)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass # Fail silently, as this is a non-critical enhancement

    def _unscramble_and_deploy(self, source_scrambled: Path, destination: Path):
        """Securely unscrambles a source file and writes it to the destination."""
        try:
            with open(source_scrambled, 'rb') as f_in, open(destination, 'wb') as f_out:
                i = 0
                key = Config.SECRET_KEY
                while True:
                    byte = f_in.read(1)
                    if not byte:
                        break
                    unscrambled_byte = bytes([byte[0] ^ key[i % len(key)]])
                    f_out.write(unscrambled_byte)
                    i += 1
        except Exception as e:
            messagebox.showerror("Security Error", f"Could not deploy secure file '{destination.name}': {e}")
            return False
        return True

    def _apply_hex_patch_and_deploy(self):
        """
        Reads the user's DLL, verifies original bytes at each offset, and patches in memory.
        """
        target_dll = Config.PATHS["target_dll"]
        backup_dll = Config.PATHS["target_dll_backup"]
        
        try:
            if not backup_dll.exists():
                shutil.copy2(target_dll, backup_dll)
                self._set_file_attributes(backup_dll, hide=True)

            with open(backup_dll, 'rb') as f:
                dll_data = bytearray(f.read())

            for patch in Config.HEX_PATCHES:
                offset = patch['offset']
                original = patch['original']
                modified = patch['modified']
                
                if dll_data[offset : offset + len(original)] != original:
                    messagebox.showerror("Patch Error", f"Byte mismatch for '{patch['name']}'. The DLL is not the expected version.")
                    return False
                
                dll_data[offset : offset + len(modified)] = modified

            with open(target_dll, 'wb') as f_out:
                f_out.write(dll_data)
        
        except Exception as e:
            messagebox.showerror("Hex Patch Error", f"Failed during in-memory patching: {e}")
            return False
        return True

    def apply_patch(self):
        """Sets the state to PATCHED by backing up, hex-patching, and deploying."""
        success, _ = self.force_close_capcut()
        if not success:
            return False
        
        if not self._apply_hex_patch_and_deploy():
            self.remove_patch()
            return False
        
        if self._unscramble_and_deploy(Config.PATHS["loader1"], Config.PATHS["target_loader1"]):
            self._set_file_attributes(Config.PATHS["target_loader1"], hide=True)
        else:
            return False
            
        if self._unscramble_and_deploy(Config.PATHS["loader2"], Config.PATHS["target_loader2"]):
            self._set_file_attributes(Config.PATHS["target_loader2"], hide=True)
        else:
            return False
            
        return True

    def remove_patch(self):
        """Sets the state to UNPATCHED by restoring the backup and cleaning up."""
        success, _ = self.force_close_capcut()
        if not success:
            return False
        
        backup_dll = Config.PATHS["target_dll_backup"]
        target_dll = Config.PATHS["target_dll"]

        if backup_dll.exists():
            try:
                self._set_file_attributes(backup_dll, hide=False)
                shutil.copy2(backup_dll, target_dll)
                backup_dll.unlink()
            except Exception as e:
                messagebox.showerror("Restore Error", f"Could not restore from backup: {e}")
                return False

        loader1 = Config.PATHS["target_loader1"]
        loader2 = Config.PATHS["target_loader2"]
        if loader1.exists():
            self._set_file_attributes(loader1, hide=False)
            loader1.unlink()
        if loader2.exists():
            self._set_file_attributes(loader2, hide=False)
            loader2.unlink()
            
        return True

    def launch_capcut(self):
        """Launches the CapCut executable."""
        if not Config.PATHS["capcut_exe"].exists():
            return False, "CapCut.exe not found."
        try:
            subprocess.Popen(f'"{Config.PATHS["capcut_exe"]}"', shell=False, cwd=str(Config.CAPCUT_DIR))
            return True, "CapCut launched."
        except Exception as e:
            return False, f"Failed to launch CapCut: {e}"

class StatusUpdateHandler(FileSystemEventHandler):
    """Handles file system events to trigger real-time UI updates."""
    def __init__(self, app_instance):
        self.app = app_instance
        self.watched_files = {
            str(Config.PATHS["target_dll"].resolve()),
            str(Config.PATHS["target_dll_backup"].resolve())
        }

    def on_any_event(self, event):
        """Triggers on file creation, deletion, or modification."""
        try:
            if event.src_path in self.watched_files:
                self.app.after(100, self.app._update_patch_status)
        except Exception:
            pass

class PatcherApp(tk.Tk):
    """The main GUI window for the launcher application."""

    def __init__(self, patcher: Patcher):
        super().__init__()
        self.patcher = patcher
        
        self.colors = {
            "background": "#1A1A2E",
            "primary": "#16213E",
            "secondary": "#0F3460",
            "accent": "#E94560",
            "text": "#FFFFFF",
            "text_muted": "#A9A9A9",
            "success": "#50C878",
            "error": "#E94560",
            "unknown": "#F4A261",
        }

        self._configure_window()
        self._create_widgets()
        self._start_monitoring()
        self._start_periodic_updates()

    def _configure_window(self):
        """Sets up window properties, fonts, and styles."""
        self.title("CC-Launcher by Glickko")
        
        try:
            icon_path = Config.EMBEDDED_FILES_DIR / "icon.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception:
            pass
        
        self.geometry("360x480")
        self.resizable(False, False)
        self.configure(bg=self.colors["background"])
        self.protocol("WM_DELETE_WINDOW", self._on_exit)

        self.bind("<Map>", self._force_redraw)
        self.bind("<Configure>", self._force_redraw)

        self.fonts = {
            "title": font.Font(family="Segoe UI", size=12, weight="bold"),
            "proc_status": font.Font(family="Segoe UI", size=8),
            "feedback": font.Font(family="Segoe UI", size=9, weight="bold"),
            "guide_header": font.Font(family="Segoe UI", size=9, weight="bold"),
            "guide_body": font.Font(family="Segoe UI", size=8),
            "warning_header": font.Font(family="Segoe UI", size=8, weight="bold"),
            "warning_body": font.Font(family="Segoe UI", size=7),
            "link": font.Font(family="Segoe UI", size=8, underline=True)
        }

    def _create_widgets(self):
        """Creates and places all GUI elements in the window."""
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self, textvariable=self.status_var, font=self.fonts["title"], bg=self.colors["background"], fg=self.colors["text"])
        self.status_label.pack(pady=(10, 2))

        self.process_status_var = tk.StringVar()
        process_status_label = tk.Label(self, textvariable=self.process_status_var, font=self.fonts["proc_status"], bg=self.colors["background"], fg=self.colors["text_muted"])
        process_status_label.pack(pady=(0, 2))
        
        self.feedback_var = tk.StringVar()
        self.feedback_label = tk.Label(self, textvariable=self.feedback_var, font=self.fonts["feedback"], bg=self.colors["background"])
        self.feedback_label.pack(pady=(0, 5))

        button_frame = tk.Frame(self, bg=self.colors["background"])
        button_frame.pack(pady=2, padx=15, fill="x")
        
        self._create_button(button_frame, "UNPATCHED (Online Features)", self.handle_unpatch, self.colors["secondary"]).pack(fill="x", pady=2)
        self._create_button(button_frame, "PATCHED (Offline Export)", self.handle_patch, self.colors["success"]).pack(fill="x", pady=2)
        self._create_button(button_frame, "Force Close CapCut", self.handle_force_close, self.colors["accent"]).pack(fill="x", pady=2)
        
        guide_frame = tk.Frame(self, bg=self.colors["primary"], bd=1, relief="solid")
        guide_frame.pack(pady=8, padx=15, fill="x")
        
        guide_header_label = tk.Label(guide_frame, text="GUIDE", font=self.fonts["guide_header"], bg=self.colors["primary"], fg=self.colors["text"])
        guide_header_label.pack(anchor="w", padx=8, pady=(5,0))

        guide_text = (
            "- PATCHED: Edit & export without login or Pro Member. Online features disabled.\n"
            "- UNPATCHED: Restores all online features. Use for normal editing, after done just Patch again for export."
        )
        guide_label = tk.Label(guide_frame, text=guide_text, font=self.fonts["guide_body"], bg=self.colors["primary"], fg=self.colors["text"], justify="left", wraplength=310)
        guide_label.pack(anchor="w", padx=8, pady=(0,8))

        warning_frame = tk.Frame(self, bg=self.colors["background"], bd=1, relief="solid", highlightbackground=self.colors["accent"], highlightthickness=1)
        warning_frame.pack(pady=8, padx=15, fill="x")

        warning_header = tk.Label(warning_frame, text="*****WARNING******", font=self.fonts["warning_header"], bg=self.colors["background"], fg=self.colors["accent"])
        warning_header.pack(pady=(4, 0))

        warning_text = (
            "Disclaimer: For education and informing CapCut about loopholes in\n"
            "VESafeGuard.dll and VECreator.dll.\n\n"
            "Note: Only works for CapCut version 3.8.0.1400"
        )
        warning_body = tk.Label(warning_frame, text=warning_text, font=self.fonts["warning_body"], bg=self.colors["background"], fg=self.colors["text_muted"], justify="center")
        warning_body.pack(padx=4, pady=4)

        footer_frame = tk.Frame(self, bg=self.colors["background"])
        footer_frame.pack(pady=(4, 8))

        link_label_gk = tk.Label(footer_frame, text="Visit GK", font=self.fonts["link"], bg=self.colors["background"], fg=self.colors["accent"], cursor="hand2")
        link_label_gk.pack(side="left", padx=10)
        link_label_gk.bind("<Button-1>", lambda e: webbrowser.open_new(Config.GLICKKO_URL))

        link_label_kofi = tk.Label(footer_frame, text="Give GK Coffee", font=self.fonts["link"], bg=self.colors["background"], fg=self.colors["accent"], cursor="hand2")
        link_label_kofi.pack(side="left", padx=10)
        link_label_kofi.bind("<Button-1>", lambda e: webbrowser.open_new(Config.KOFI_URL))
    
    def _create_button(self, parent, text, command, bg_color):
        """Helper function to create consistently styled buttons."""
        return tk.Button(
            parent, text=text, command=lambda: self._run_in_thread(command),
            bg=bg_color, fg=self.colors["text"], relief="flat", height=2,
            activebackground=self.colors["primary"], activeforeground=self.colors["text"],
            font=("Segoe UI", 9, "bold"), borderwidth=0
        )

    def _force_redraw(self, event=None):
        """Forces the window to redraw its widgets to prevent UI bugs."""
        self.update_idletasks()

    def _run_in_thread(self, target_func):
        """Runs a function in a separate thread to keep the GUI responsive."""
        thread = threading.Thread(target=target_func, daemon=True)
        thread.start()

    def show_feedback(self, message, is_error=False, duration=4000):
        """Displays a temporary feedback message to the user. This MUST be called from the main thread."""
        self.feedback_var.set(message)
        color = self.colors["error"] if is_error else self.colors["success"]
        self.feedback_label.config(fg=color)
        
        if hasattr(self, "_feedback_job"):
            self.after_cancel(self._feedback_job)
        self._feedback_job = self.after(duration, lambda: self.feedback_var.set(""))

    def _update_patch_status(self):
        """Updates the patch status label and its color using the backup file."""
        current_status = FileIntegrityChecker.get_status()
        self.status_var.set(f"Current State: {current_status}")
        
        color_map = {
            "PATCHED": self.colors["success"],
            "UNPATCHED": self.colors["text"],
        }
        self.status_label.config(fg=color_map.get(current_status, self.colors["error"]))

    def _update_process_status(self):
        """Updates the CapCut process status label."""
        status_text = "Process: Running" if self.patcher.is_capcut_running() else "Process: Not Running"
        self.process_status_var.set(status_text)
            
    def _start_monitoring(self):
        """Initializes and starts the file system observer."""
        if not Config.CAPCUT_DIR.exists():
            return
        event_handler = StatusUpdateHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, path=str(Config.CAPCUT_DIR), recursive=False)
        self.observer.daemon = True
        self.observer.start()

    def _start_periodic_updates(self):
        """Initiates periodic checks for statuses not covered by watchdog."""
        def update_loop():
            self._update_process_status()
            self.after(2000, update_loop)
        
        self._update_ui_states()
        update_loop()

    def _update_ui_states(self):
        """Forces an immediate update of all status labels."""
        self._update_patch_status()
        self._update_process_status()

    def handle_unpatch(self):
        """THREAD-SAFE: Handles the 'Set to UNPATCHED' button click."""
        self.after(0, lambda: self.show_feedback("Setting state to UNPATCHED...", duration=10000))
        
        action_success = self.patcher.remove_patch()
        
        def final_ui_update():
            if action_success:
                self.show_feedback("State set to UNPATCHED. Launching...")
                launch_success, msg = self.patcher.launch_capcut()
                if launch_success:
                    self.iconify()
                self.show_feedback(msg, is_error=not launch_success)
            else:
                self.show_feedback("Operation failed. Check permissions.", is_error=True)
            self._update_ui_states()
        
        self.after(0, final_ui_update)

    def handle_patch(self):
        """THREAD-SAFE: Handles the 'Set to PATCHED' button click."""
        self.after(0, lambda: self.show_feedback("Setting state to PATCHED...", duration=10000))
        
        action_success = self.patcher.apply_patch()
        
        def final_ui_update():
            if action_success:
                self.show_feedback("State set to PATCHED. Launching...")
                launch_success, msg = self.patcher.launch_capcut()
                if launch_success:
                    self.iconify()
                self.show_feedback(msg, is_error=not launch_success)
            else:
                self.show_feedback("Operation failed. Check permissions.", is_error=True)
            self._update_ui_states()
        
        self.after(0, final_ui_update)
        
    def handle_force_close(self):
        """THREAD-SAFE: Handles the 'Force Close' button click."""
        self.after(0, lambda: self.show_feedback("Attempting to force close CapCut...", duration=10000))
        
        success, message = self.patcher.force_close_capcut()
        
        def final_ui_update():
            self.show_feedback(message, is_error=not success)
            self._update_process_status()
            
        self.after(0, final_ui_update)

    def _on_exit(self):
        """Handles the application exit gracefully and ensures CapCut is closed."""
        if hasattr(self, 'observer'):
            self.observer.stop()
            try:
                self.observer.join()
            except RuntimeError:
                pass

        # Always try to restore the original state on exit
        if FileIntegrityChecker.get_status() == "PATCHED":
            self.patcher.remove_patch()

        if self.patcher.is_capcut_running():
            self.patcher.force_close_capcut()

        self.destroy()

def main():
    """
    Main entry point of the script. Handles administrator checks
    and file verification before launching the application.
    """
    
    def is_admin():
        """Checks for administrator privileges on Windows."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def run_as_admin():
        """Re-runs the script with administrator privileges."""
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            messagebox.showerror("Elevation Failed", f"Could not restart as administrator: {e}")

    if not is_admin():
        run_as_admin()
        return

    missing = [f for f in Config.get_required_files() if not f.exists()]
    if missing:
        error_message = "Initialization Failed!\n\nThe following required file(s) or folder(s) are missing:\n\n" + "\n".join(f" - {Path(f).name}" for f in missing) + "\n\nPlease ensure they are next to the launcher."
        messagebox.showerror("File Verification Failed", error_message)
        return

    try:
        patcher = Patcher()
        app = PatcherApp(patcher)
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

