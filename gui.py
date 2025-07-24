import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image
import os

# Caesar Cipher enc & dec
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c for c in text)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Binary Conversion
def text_to_binary(text):
    return ''.join(f'{ord(c):08b}' for c in text)

def binary_to_text(binary):
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

# LSB enc & dec
def encode_image(image_path, message, output_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    bits = text_to_binary(message) + '1111111111111110'
    out_pixels, bit_index, total_bits = [], 0, len(bits)

    for pixel in pixels:
        if bit_index < total_bits:
            pixel_list = list(pixel)
            for i in range(3):
                if bit_index < total_bits:
                    pixel_list[i] = (pixel_list[i] & ~1) | int(bits[bit_index])
                    bit_index += 1
            out_pixels.append(tuple(pixel_list))
        else:
            out_pixels.append(pixel)

    img.putdata(out_pixels)
    img.save(output_path)

def decode_image(image_path):
    img = Image.open(image_path)
    bits = ''
    for pixel in img.getdata():
        for color in pixel[:3]:
            bits += str(color & 1)
            if bits.endswith('1111111111111110'):
                return binary_to_text(bits[:-16])
    return ""

class StegoApp:
    def __init__(self, root):
        self.root = root
        root.title("StegoApp")
        root.geometry("650x600")

        # Color and font configuration
        self.bg_color = "#f5f7fa"
        self.accent_color = "#4f46e5"
        self.text_color = "#1e293b"
        self.font = ("Segoe UI", 10)
        self.header_font = ("Segoe UI", 14, "bold")

        root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=self.font)
        self.style.configure("Header.TLabel", background=self.bg_color, foreground=self.accent_color, font=self.header_font)
        self.style.configure("TButton", background=self.accent_color, foreground="white", padding=5, font=self.font)
        self.style.configure("TRadiobutton", background=self.bg_color)
        self.style.map("TButton", background=[("active", "#3730a3")])
        self.style.map("TRadiobutton", background=[('active', self.bg_color)], foreground=[('active', self.text_color)])

        main_frame = ttk.Frame(root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        mode_frame = ttk.Frame(main_frame)
        mode_frame.pack(fill=tk.X, pady=(0, 15))

        self.mode_var = tk.StringVar(value="encode")
        ttk.Radiobutton(mode_frame, text="Encode Message", variable=self.mode_var, value="encode", command=self.toggle_mode).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Decode Message", variable=self.mode_var, value="decode", command=self.toggle_mode).pack(side=tk.LEFT)

        ttk.Separator(main_frame, orient="horizontal").pack(fill=tk.X, pady=10)

        image_frame = ttk.Frame(main_frame)
        image_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(image_frame, text="Image:").pack(side=tk.LEFT, padx=(0, 5))
        self.image_path_var = tk.StringVar()
        image_entry = ttk.Entry(image_frame, textvariable=self.image_path_var, width=50)
        image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(image_frame, text="Browse", command=self.browse_image).pack(side=tk.LEFT)

        self.image_info = ttk.Label(main_frame, text="", foreground="#64748b")
        self.image_info.pack(anchor="w", pady=(0, 15))

        self.message_frame = ttk.Frame(main_frame)
        ttk.Label(self.message_frame, text="Secret Message:").pack(anchor="w", pady=(0, 5))
        self.message_text = self.create_scrolled_text(self.message_frame, 5)
        self.message_text.pack(fill=tk.BOTH, expand=True)

        self.char_count = ttk.Label(self.message_frame, text="0 characters", foreground="#64748b")
        self.char_count.pack(anchor="e", pady=(5, 0))
        self.message_text.bind("<KeyRelease>", self.update_char_count)

        self.status = ttk.Label(main_frame, text="Ready", background=self.bg_color, foreground="#64748b", font=self.font)
        self.status.pack(fill=tk.X, pady=(0, 10))

        cipher_frame = ttk.Frame(main_frame)
        cipher_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(cipher_frame, text="Caesar Shift:").pack(side=tk.LEFT, padx=(0, 5))
        self.shift_var = tk.IntVar(value=3)
        ttk.Spinbox(cipher_frame, from_=1, to=25, textvariable=self.shift_var, width=5).pack(side=tk.LEFT)

        self.output_frame = ttk.Frame(main_frame)
        ttk.Label(self.output_frame, text="Output File:").pack(side=tk.LEFT, padx=(0, 5))
        self.output_path_var = tk.StringVar(value="output.png")
        ttk.Entry(self.output_frame, textvariable=self.output_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(self.output_frame, text="Save As", command=self.save_as).pack(side=tk.LEFT)

        self.result_frame = ttk.Frame(main_frame)
        ttk.Label(self.result_frame, text="Decoded Message:").pack(anchor="w", pady=(0, 5))
        self.result_text = self.create_scrolled_text(self.result_frame, 6, disabled=True)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        ttk.Button(self.result_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side=tk.RIGHT)

        self.action_button = ttk.Button(main_frame, text="Encode Message", command=self.run)
        self.action_button.pack(pady=(0, 10))

        self.toggle_mode()

    def create_scrolled_text(self, parent, height, disabled=False):
        text = scrolledtext.ScrolledText(parent, height=height, wrap=tk.WORD, font=self.font, padx=8, pady=8, background="white", foreground=self.text_color)
        if disabled:
            text.config(state=tk.DISABLED)
        return text

    def show_error(self, message, reset_status="Ready"):
        messagebox.showerror("Error", message)
        self.status.config(text=reset_status)

    def update_char_count(self, event=None):
        count = len(self.message_text.get("1.0", tk.END).strip())
        self.char_count.config(text=f"{count} characters")

    def toggle_mode(self):
        if self.mode_var.get() == "encode":
            self.message_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            self.output_frame.pack(fill=tk.X, pady=(0, 15))
            self.result_frame.pack_forget()
            self.action_button.config(text="Encode Message")
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete("1.0", tk.END)
            self.result_text.config(state=tk.DISABLED)
        else:
            self.message_frame.pack_forget()
            self.output_frame.pack_forget()
            self.result_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            self.action_button.config(text="Decode Message")

    def browse_image(self):
        file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG Images", "*.png")])
        if file_path:
            self.image_path_var.set(file_path)
            self.update_image_info(file_path)

    def update_image_info(self, path):
        try:
            img = Image.open(path)
            width, height = img.size
            format_name = img.format
            file_size = os.path.getsize(path) / 1024
            info_text = f"Image: {os.path.basename(path)} | {width}x{height} | {format_name} | {file_size:.1f} KB"
            self.image_info.config(text=info_text)
        except Exception as e:
            self.image_info.config(text=f"Error loading image: {str(e)}")

    def save_as(self):
        file_path = filedialog.asksaveasfilename(title="Save Encoded Image As", defaultextension=".png", filetypes=[("PNG Images", "*.png")])
        if file_path:
            if not file_path.lower().endswith('.png'):
                file_path += '.png'
            self.output_path_var.set(file_path)

    def copy_to_clipboard(self):
        message = self.result_text.get("1.0", tk.END).strip()
        if message:
            self.root.clipboard_clear()
            self.root.clipboard_append(message)
            self.status.config(text="Message copied to clipboard")

    def run(self):
        mode = self.mode_var.get()
        image_path = self.image_path_var.get()
        shift = self.shift_var.get()

        if not image_path:
            self.show_error("Please select an image file.")
            return

        try:
            self.status.config(text="Processing...")
            self.root.update_idletasks()

            if mode == "encode":
                message = self.message_text.get("1.0", tk.END).strip()
                if not message:
                    self.show_error("Please enter a message to encode.")
                    return

                encrypted = caesar_encrypt(message, shift)
                output_path = self.output_path_var.get()
                encode_image(image_path, encrypted, output_path)

                messagebox.showinfo("Success", f"Message encoded and saved to:\n{output_path}")
                self.status.config(text=f"Message encoded to {os.path.basename(output_path)}")
            else:
                encrypted_message = decode_image(image_path)
                decrypted_message = caesar_decrypt(encrypted_message, shift)

                self.result_text.config(state=tk.NORMAL)
                self.result_text.delete("1.0", tk.END)
                self.result_text.insert(tk.END, decrypted_message)
                self.result_text.config(state=tk.DISABLED)
                self.status.config(text="Message successfully decoded")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")
            self.status.config(text=f"Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()