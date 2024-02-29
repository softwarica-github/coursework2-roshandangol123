import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import hashlib
import os
from PIL import Image, ImageTk

class FileIntegrityChecker:
    def __init__(self):
        self.imported_files = {}
        self.load_imported_files()

    def load_imported_files(self):
        if os.path.exists("hashes.txt"):
            with open("hashes.txt", "r") as f:
                for line in f:
                    filename, hash_value = line.strip().split(": ")
                    self.imported_files[filename] = hash_value

    def save_imported_files(self):
        with open("hashes.txt", "w") as f:
            for filename, hash_value in self.imported_files.items():
                f.write(f"{filename}: {hash_value}\n")

    def import_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            filename = os.path.basename(file_path)
            hash_value = self.calculate_hash(file_path)
            self.store_hash(filename, hash_value)
            self.check_hash(filename, hash_value)

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return None

    def store_hash(self, filename, hash_value):
        self.imported_files[filename] = hash_value
        self.save_imported_files()

    def check_hash(self, filename, hash_value):
        if filename in self.imported_files and self.imported_files[filename] == hash_value:
            return True
        else:
            return False

    def remove_file(self, filename):
        if filename in self.imported_files:
            del self.imported_files[filename]
            self.save_imported_files()

    def remove_malware(self):
        for filename, hash_value in self.imported_files.items():
           
            if "malware" in hash_value:
                self.remove_file(filename)

class MalwareDetectorApp:
    def __init__(self, root, file_checker):
        self.root = root
        self.root.title("Malware Detector")
        self.root.geometry("800x400")
        
        self.background_image = Image.open("malware.jpg")
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.background_label = tk.Label(root, image=self.background_photo)
        self.background_label.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.file_checker = file_checker

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.title_label = tk.Label(root, text="Malware Detector", font=("Arial", 32), bg="#F0F0F0", fg="#333")
        self.title_label.pack(pady=(20, 0))

        self.content_frame = ttk.Frame(root, padding=20, style="Custom.TFrame")
        self.content_frame.pack(fill="both", expand=True)

        self.buttons_frame = ttk.Frame(self.content_frame, style="Custom.TFrame")
        self.buttons_frame.pack(fill="both", expand=True)

        self.import_button = ttk.Button(self.buttons_frame, text="Import File", command=self.import_file, style="Import.TButton")
        self.import_button.pack(pady=(0, 10))

        self.remove_malware_button = ttk.Button(self.buttons_frame, text="Remove File", command=self.remove_file, state=tk.DISABLED, style="Remove.TButton")
        self.remove_malware_button.pack()

        self.result_label = ttk.Label(root, text="", font=("Arial", 18), background="#F0F0F0", foreground="#333")
        self.result_label.pack(pady=(20, 0))

        self.style.configure("Custom.TFrame", background="#F0F0F0")
        self.style.configure("Import.TButton", background="#4CAF50", foreground="white", font=("Arial", 14), borderwidth=0)
        self.style.configure("Remove.TButton", background="#FF5733", foreground="white", font=("Arial", 14), borderwidth=0)

        self.style.map("Import.TButton",
            foreground=[("active", "black"), ("pressed", "black")],
            background=[("active", "#45A049"), ("pressed", "#3E9143")]
        )

        self.style.map("Remove.TButton",
            foreground=[("active", "black"), ("pressed", "black")],
            background=[("active", "#FF5733"), ("pressed", "#D4452A")]
        )

    def import_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            filename = os.path.basename(file_path)
            hash_value = self.file_checker.calculate_hash(file_path)
            if hash_value:
                self.file_checker.store_hash(filename, hash_value)
                self.check_hash(filename, hash_value)
            else:
                self.result_label.config(text="Error calculating hash.", foreground="red")
                self.remove_malware_button.config(state=tk.DISABLED)

    def check_hash(self, filename, hash_value):
        if self.file_checker.check_hash(filename, hash_value):
            self.result_label.config(text=f"File '{filename}' is safe.", foreground="green")
            self.remove_malware_button.config(state=tk.NORMAL)
        else:
            self.result_label.config(text=f"File '{filename}' may be corrupted or tampered!", foreground="red")
            self.remove_malware_button.config(state=tk.NORMAL)

    def remove_file(self):
        detected_filename = self.result_label.cget("text").split("'")[1]
        self.file_checker.remove_file(detected_filename)
        self.result_label.config(text=f"File '{detected_filename}' removed.", foreground="blue")
        self.remove_malware_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg="#F0F0F0")
    file_checker = FileIntegrityChecker()
    app = MalwareDetectorApp(root, file_checker)
    root.mainloop()
