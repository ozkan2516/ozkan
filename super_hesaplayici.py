
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import hashlib

class SuperHesaplayiciApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Süper Hesaplayıcı")
        self.geometry("800x600")

        # Ana Notebook (Sekme Yöneticisi)
        notebook = ttk.Notebook(self)
        notebook.pack(pady=10, padx=10, fill="both", expand=True)

        # Sekmeleri oluştur
        tab1 = ttk.Frame(notebook)
        tab2 = ttk.Frame(notebook)
        tab3 = ttk.Frame(notebook)

        notebook.add(tab1, text='Kriptografik Hash Hesaplayıcı')
        notebook.add(tab2, text='Evrensel Taban Dönüştürücü')
        notebook.add(tab3, text='Bayt <-> Hex Detay Aracı')

        # Her sekmeyi doldur
        self.create_tab1_hash_calculator(tab1)
        self.create_tab2_base_converter(tab2)
        self.create_tab3_byte_tool(tab3)

    # --- SEKME 1: HASH HESAPLAYICI --- #
    def create_tab1_hash_calculator(self, parent):
        # Metin Hashing
        text_frame = ttk.LabelFrame(parent, text="Metin Hash'leme", padding=10)
        text_frame.pack(fill="x", padx=10, pady=10)

        self.hash_input_text = scrolledtext.ScrolledText(text_frame, height=4, wrap=tk.WORD)
        self.hash_input_text.pack(fill="x", expand=True)

        # Dosya Hashing
        file_frame = ttk.LabelFrame(parent, text="Dosya Hash'leme", padding=10)
        file_frame.pack(fill="x", padx=10)
        
        self.file_path_var = tk.StringVar()
        self.file_path_var.set("Henüz dosya seçilmedi.")
        file_label = ttk.Label(file_frame, textvariable=self.file_path_var, foreground="gray")
        file_label.pack(side="left", fill="x", expand=True)
        file_button = ttk.Button(file_frame, text="Dosya Seç...", command=self.select_file_for_hashing)
        file_button.pack(side="right")

        # Kontrol ve Sonuç
        controls_frame = ttk.Frame(parent, padding=10)
        controls_frame.pack(fill="x")

        self.hash_algorithm_var = tk.StringVar(value="sha256")
        supported_algorithms = sorted(['md5', 'sha1', 'sha256', 'sha384', 'sha512'])
        algorithm_menu = ttk.OptionMenu(controls_frame, self.hash_algorithm_var, self.hash_algorithm_var.get(), *supported_algorithms)
        algorithm_menu.pack(side="left")

        calculate_button = ttk.Button(controls_frame, text="HESAPLA", command=self.calculate_hash)
        calculate_button.pack(side="right", padx=10)

        self.hash_result_text = scrolledtext.ScrolledText(parent, height=5, wrap=tk.WORD, state='disabled')
        self.hash_result_text.pack(fill="both", expand=True, padx=10, pady=10)

    def select_file_for_hashing(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path_var.set(filepath)
            self.hash_input_text.delete('1.0', tk.END) # Metin alanını temizle

    def calculate_hash(self):
        algorithm = self.hash_algorithm_var.get()
        hasher = hashlib.new(algorithm)
        
        filepath = self.file_path_var.get()
        input_text = self.hash_input_text.get("1.0", tk.END).strip()

        try:
            if filepath != "Henüz dosya seçilmedi.":
                with open(filepath, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
            elif input_text:
                hasher.update(input_text.encode('utf-8'))
            else:
                self.display_output(self.hash_result_text, "HATA: Hash'lenecek bir metin girin veya bir dosya seçin.")
                return
            
            hex_digest = hasher.hexdigest()
            self.display_output(self.hash_result_text, hex_digest)

        except Exception as e:
            self.display_output(self.hash_result_text, f"HATA: {e}")
        finally:
            self.file_path_var.set("Henüz dosya seçilmedi.") # İşlem sonrası sıfırla

    # --- SEKME 2: EVRENSEL DÖNÜŞTÜRÜCÜ --- #
    def create_tab2_base_converter(self, parent):
        int_frame = ttk.LabelFrame(parent, text="Tam Sayıdan Diğer Tabanlara", padding=10)
        int_frame.pack(fill="x", expand=True, padx=10, pady=10)

        ttk.Label(int_frame, text="Ondalık Tam Sayı:").pack(anchor="w")
        self.int_input_tab2 = ttk.Entry(int_frame)
        self.int_input_tab2.pack(fill="x", expand=True, pady=5)

        btn_frame = ttk.Frame(int_frame)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Hex'e Çevir", command=lambda: self.convert_integer('hex')).pack(side="left", expand=True)
        ttk.Button(btn_frame, text="Binary'e Çevir", command=lambda: self.convert_integer('bin')).pack(side="left", expand=True, padx=5)
        ttk.Button(btn_frame, text="Octal'a Çevir", command=lambda: self.convert_integer('oct')).pack(side="left", expand=True)

        self.int_output_tab2 = scrolledtext.ScrolledText(int_frame, height=3, wrap=tk.WORD, state='disabled')
        self.int_output_tab2.pack(fill="x", expand=True, pady=5)

        text_frame = ttk.LabelFrame(parent, text="Metinden Hex'e", padding=10)
        text_frame.pack(fill="both", expand=True, padx=10)
        self.text_input_tab2 = scrolledtext.ScrolledText(text_frame, height=4, wrap=tk.WORD)
        self.text_input_tab2.pack(fill="x", expand=True, pady=5)
        ttk.Button(text_frame, text="Metni Hex'e Çevir", command=self.convert_text_to_hex).pack(anchor="e")
        self.text_output_tab2 = scrolledtext.ScrolledText(text_frame, height=4, wrap=tk.WORD, state='disabled')
        self.text_output_tab2.pack(fill="x", expand=True, pady=5)

    def convert_integer(self, base):
        try:
            num = int(self.int_input_tab2.get().strip())
            if base == 'hex': result = hex(num)[2:]
            elif base == 'bin': result = bin(num)[2:]
            elif base == 'oct': result = oct(num)[2:]
            self.display_output(self.int_output_tab2, result)
        except ValueError:
            self.display_output(self.int_output_tab2, "HATA: Geçerli bir tam sayı girin.")

    def convert_text_to_hex(self):
        text = self.text_input_tab2.get("1.0", tk.END).strip()
        hex_val = text.encode('utf-8').hex()
        self.display_output(self.text_output_tab2, hex_val)

    # --- SEKME 3: BAYT ARACI --- #
    def create_tab3_byte_tool(self, parent):
        b2h_frame = ttk.LabelFrame(parent, text="Bayt → Hex", padding=20)
        b2h_frame.pack(pady=20, padx=20, fill="x")
        ttk.Label(b2h_frame, text="Bayt Değeri (0-255):").grid(row=0, column=0, sticky="w")
        self.byte_input_tab3 = ttk.Entry(b2h_frame, width=10)
        self.byte_input_tab3.grid(row=0, column=1, padx=5)
        ttk.Button(b2h_frame, text="Çevir →", command=self.t3_byte_to_hex).grid(row=0, column=2, padx=5)
        self.hex_result_label_tab3 = ttk.Label(b2h_frame, text="", font=("Courier", 12, "bold"))
        self.hex_result_label_tab3.grid(row=0, column=3, padx=10)

        h2b_frame = ttk.LabelFrame(parent, text="Hex → Bayt", padding=20)
        h2b_frame.pack(pady=10, padx=20, fill="x")
        ttk.Label(h2b_frame, text="Hex Kodu (örn: ff):").grid(row=0, column=0, sticky="w")
        self.hex_input_tab3 = ttk.Entry(h2b_frame, width=10)
        self.hex_input_tab3.grid(row=0, column=1, padx=5)
        ttk.Button(h2b_frame, text="Çevir →", command=self.t3_hex_to_byte).grid(row=0, column=2, padx=5)
        self.byte_result_label_tab3 = ttk.Label(h2b_frame, text="", font=("Courier", 12, "bold"))
        self.byte_result_label_tab3.grid(row=0, column=3, padx=10)

    def t3_byte_to_hex(self):
        try:
            b = int(self.byte_input_tab3.get())
            if not (0 <= b <= 255): raise ValueError("Değer 0-255 arası olmalı")
            self.hex_result_label_tab3.config(text=f'"{b:02x}"', foreground="#007acc")
        except Exception as e:
            self.hex_result_label_tab3.config(text=str(e), foreground="red")

    def t3_hex_to_byte(self):
        try:
            hex_str = self.hex_input_tab3.get().strip()
            if len(hex_str) != 2: raise ValueError("Kod 2 karakter olmalı")
            byte_val = int(hex_str, 16)
            self.byte_result_label_tab3.config(text=str(byte_val), foreground="#007acc")
        except Exception as e:
            self.byte_result_label_tab3.config(text=str(e), foreground="red")

    # --- Genel Yardımcı Fonksiyon --- #
    def display_output(self, widget, content):
        widget.configure(state='normal')
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, content)
        widget.configure(state='disabled')

if __name__ == "__main__":
    app = SuperHesaplayiciApp()
    app.mainloop()
