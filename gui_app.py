"""
Secure Image Steganography - Tkinter GUI
Simple desktop application that works on all systems
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
from steganography_core import SecureSteganography
import threading


class SteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Secure Image Steganography")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.stego = SecureSteganography()
        
        # Variables
        self.cover_image_path = tk.StringVar()
        self.stego_image_path = tk.StringVar()
        self.output_path = tk.StringVar(value="stego_output.png")
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.embed_tab = ttk.Frame(self.notebook)
        self.extract_tab = ttk.Frame(self.notebook)
        self.compare_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.embed_tab, text="📝 Embed Message")
        self.notebook.add(self.extract_tab, text="🔍 Extract Message")
        self.notebook.add(self.compare_tab, text="📊 Compare Images")
        
        # Setup each tab
        self.setup_embed_tab()
        self.setup_extract_tab()
        self.setup_compare_tab()
        
    def setup_embed_tab(self):
        # Title
        title = tk.Label(self.embed_tab, text="Embed Secret Message in Image", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Info about automatic features
        info_frame = ttk.Frame(self.embed_tab)
        info_frame.pack(fill='x', padx=20, pady=5)
        info_text = "✨ Supports PNG & JPEG | Uses LSB Method | 🚀 Optimized Processing"
        tk.Label(info_frame, text=info_text, font=("Arial", 9), fg="blue").pack()
        
        warning_frame = ttk.Frame(self.embed_tab)
        warning_frame.pack(fill='x', padx=20, pady=2)
        warning_text = "⚠️ JPEG inputs will be converted to PNG to preserve hidden data"
        tk.Label(warning_frame, text=warning_text, font=("Arial", 8), fg="red").pack()
        
        # Cover Image Section
        cover_frame = ttk.LabelFrame(self.embed_tab, text="1. Select Cover Image", padding=10)
        cover_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Entry(cover_frame, textvariable=self.cover_image_path, width=60).pack(side='left', padx=5)
        ttk.Button(cover_frame, text="Browse", command=self.browse_cover_image).pack(side='left')
        
        # Message Section
        msg_frame = ttk.LabelFrame(self.embed_tab, text="2. Enter Secret Message", padding=10)
        msg_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.message_text = scrolledtext.ScrolledText(msg_frame, height=8, width=80)
        self.message_text.pack(fill='both', expand=True)
        
        # Password Section
        pass_frame = ttk.LabelFrame(self.embed_tab, text="3. Set Password", padding=10)
        pass_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(pass_frame, text="Password:").pack(side='left', padx=5)
        self.embed_password = ttk.Entry(pass_frame, show="*", width=30)
        self.embed_password.pack(side='left', padx=5)
        
        tk.Label(pass_frame, text="Confirm:").pack(side='left', padx=5)
        self.embed_password_confirm = ttk.Entry(pass_frame, show="*", width=30)
        self.embed_password_confirm.pack(side='left', padx=5)
        
        # Output Section
        out_frame = ttk.LabelFrame(self.embed_tab, text="4. Output File", padding=10)
        out_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Entry(out_frame, textvariable=self.output_path, width=60).pack(side='left', padx=5)
        ttk.Button(out_frame, text="Save As", command=self.browse_output).pack(side='left')
        
        # Embed Button
        btn_frame = ttk.Frame(self.embed_tab)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔒 Embed Message", 
                  command=self.embed_message).pack()
        
        # Result Section
        self.embed_result = scrolledtext.ScrolledText(self.embed_tab, height=6, width=80)
        self.embed_result.pack(fill='x', padx=20, pady=10)
        
    def setup_extract_tab(self):
        # Title
        title = tk.Label(self.extract_tab, text="Extract Hidden Message", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Stego Image Section
        stego_frame = ttk.LabelFrame(self.extract_tab, text="1. Select Stego Image", padding=10)
        stego_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Entry(stego_frame, textvariable=self.stego_image_path, width=60).pack(side='left', padx=5)
        ttk.Button(stego_frame, text="Browse", command=self.browse_stego_image).pack(side='left')
        
        # Password Section
        pass_frame = ttk.LabelFrame(self.extract_tab, text="2. Enter Password", padding=10)
        pass_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(pass_frame, text="Password:").pack(side='left', padx=5)
        self.extract_password = ttk.Entry(pass_frame, show="*", width=40)
        self.extract_password.pack(side='left', padx=5)
        
        # Extract Button
        btn_frame = ttk.Frame(self.extract_tab)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔓 Extract & Decrypt", 
                  command=self.extract_message).pack()
        
        # Result Section
        result_frame = ttk.LabelFrame(self.extract_tab, text="Extracted Message", padding=10)
        result_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.extract_result = scrolledtext.ScrolledText(result_frame, height=15, width=80)
        self.extract_result.pack(fill='both', expand=True)
        
        # Save button
        ttk.Button(self.extract_tab, text="💾 Save Message to File", 
                  command=self.save_extracted_message).pack(pady=5)
        
    def setup_compare_tab(self):
        # Title
        title = tk.Label(self.compare_tab, text="Compare Original and Stego Images", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Images Selection
        img_frame = ttk.Frame(self.compare_tab)
        img_frame.pack(fill='x', padx=20, pady=10)
        
        # Original Image
        orig_frame = ttk.LabelFrame(img_frame, text="Original Image", padding=10)
        orig_frame.pack(side='left', fill='x', expand=True, padx=5)
        
        self.compare_orig_path = tk.StringVar()
        ttk.Entry(orig_frame, textvariable=self.compare_orig_path, width=35).pack()
        ttk.Button(orig_frame, text="Browse", command=self.browse_compare_orig).pack(pady=5)
        
        # Stego Image
        stego_frame = ttk.LabelFrame(img_frame, text="Stego Image", padding=10)
        stego_frame.pack(side='left', fill='x', expand=True, padx=5)
        
        self.compare_stego_path = tk.StringVar()
        ttk.Entry(stego_frame, textvariable=self.compare_stego_path, width=35).pack()
        ttk.Button(stego_frame, text="Browse", command=self.browse_compare_stego).pack(pady=5)
        
        # Compare Button
        btn_frame = ttk.Frame(self.compare_tab)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔬 Compare Images", 
                  command=self.compare_images).pack()
        
        # Results
        self.compare_result = scrolledtext.ScrolledText(self.compare_tab, height=20, width=80)
        self.compare_result.pack(fill='both', expand=True, padx=20, pady=10)
    
    # Browse methods
    def browse_cover_image(self):
        path = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("PNG Images", "*.png"), ("JPEG Images", "*.jpg *.jpeg"), ("All Files", "*.*")]
        )
        if path:
            self.cover_image_path.set(path)
            
    def browse_stego_image(self):
        path = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")]
        )
        if path:
            self.stego_image_path.set(path)
            
    def browse_output(self):
        path = filedialog.asksaveasfilename(
            title="Save Stego Image As",
            defaultextension=".png",
            filetypes=[("PNG Images", "*.png")]
        )
        if path:
            self.output_path.set(path)
            
    def browse_compare_orig(self):
        path = filedialog.askopenfilename(title="Select Original Image")
        if path:
            self.compare_orig_path.set(path)
            
    def browse_compare_stego(self):
        path = filedialog.askopenfilename(title="Select Stego Image")
        if path:
            self.compare_stego_path.set(path)
    
    # Action methods
    def embed_message(self):
        # Validate inputs
        if not self.cover_image_path.get():
            messagebox.showerror("Error", "Please select a cover image!")
            return
            
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a secret message!")
            return
            
        password = self.embed_password.get()
        password_confirm = self.embed_password_confirm.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
            
        if password != password_confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
            
        # Perform embedding
        self.embed_result.delete("1.0", tk.END)
        self.embed_result.insert(tk.END, "🔐 Encrypting and embedding message...\n\n")
        self.root.update()
        
        result = self.stego.embed_message(
            cover_image_path=self.cover_image_path.get(),
            secret_message=message,
            password=password,
            output_path=self.output_path.get()
        )
        
        if result['status'] == 'success':
            self.embed_result.insert(tk.END, f"✅ {result['message']}\n\n")
            
            if result.get('original_format') == 'JPEG':
                self.embed_result.insert(tk.END, f"⚠️ WARNING: JPEG input detected\n")
                self.embed_result.insert(tk.END, f"   Converted to PNG format to preserve hidden data\n\n")
            
            self.embed_result.insert(tk.END, f"🔧 Original Format: {result.get('original_format', 'PNG')}\n")
            self.embed_result.insert(tk.END, f"🔧 Method Used: {result['method']} (LSB Steganography)\n")
            self.embed_result.insert(tk.END, f"⚡ {result['processing']}\n\n")
            self.embed_result.insert(tk.END, f"📊 Quality Metrics:\n")
            self.embed_result.insert(tk.END, f"   MSE: {result['mse']}\n")
            self.embed_result.insert(tk.END, f"   PSNR: {result['psnr']} dB\n")
            self.embed_result.insert(tk.END, f"   Capacity Used: {result['capacity_used']}\n\n")
            self.embed_result.insert(tk.END, f"💾 Stego image saved to: {result['output_path']}\n")
            self.embed_result.insert(tk.END, f"🔑 Image Hash: {result['image_hash'][:32]}...\n")
            
            if result.get('warning'):
                self.embed_result.insert(tk.END, f"\n{result['warning']}\n")
            
            messagebox.showinfo("Success", "Message embedded successfully!\n\nIMPORTANT: Use the PNG output file for extraction.")
        else:
            self.embed_result.insert(tk.END, f"❌ Error: {result['message']}\n")
            messagebox.showerror("Error", result['message'])
            
    def extract_message(self):
        # Validate inputs
        if not self.stego_image_path.get():
            messagebox.showerror("Error", "Please select a stego image!")
            return
            
        password = self.extract_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter the decryption password!")
            return
            
        # Perform extraction
        self.extract_result.delete("1.0", tk.END)
        self.extract_result.insert(tk.END, "🔍 Extracting and decrypting message...\n\n")
        self.root.update()
        
        result = self.stego.extract_message(
            stego_image_path=self.stego_image_path.get(),
            password=password
        )
        
        if result['status'] == 'success':
            self.extract_result.delete("1.0", tk.END)
            self.extract_result.insert(tk.END, "✅ Message extracted successfully!\n\n")
            self.extract_result.insert(tk.END, f"🔧 Method: {result['method']} (LSB Steganography)\n")
            self.extract_result.insert(tk.END, f"⚡ {result['parallel_processing']}\n\n")
            self.extract_result.insert(tk.END, "📄 Decrypted Message:\n")
            self.extract_result.insert(tk.END, "="*70 + "\n")
            self.extract_result.insert(tk.END, result['message'])
            self.extract_result.insert(tk.END, "\n" + "="*70 + "\n")
            
            messagebox.showinfo("Success", "Message extracted successfully!")
        else:
            self.extract_result.insert(tk.END, f"❌ Error: {result['message']}\n")
            messagebox.showerror("Error", result['message'])
            
    def save_extracted_message(self):
        message = self.extract_result.get("1.0", tk.END)
        if not message.strip():
            messagebox.showwarning("Warning", "No message to save!")
            return
            
        path = filedialog.asksaveasfilename(
            title="Save Message As",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(message)
            messagebox.showinfo("Saved", f"Message saved to {path}")
            
    def compare_images(self):
        if not self.compare_orig_path.get() or not self.compare_stego_path.get():
            messagebox.showerror("Error", "Please select both images!")
            return
            
        self.compare_result.delete("1.0", tk.END)
        self.compare_result.insert(tk.END, "🔬 Comparing images...\n\n")
        self.root.update()
        
        result = self.stego.compare_images(
            original_path=self.compare_orig_path.get(),
            stego_path=self.compare_stego_path.get()
        )
        
        if result['status'] == 'success':
            self.compare_result.delete("1.0", tk.END)
            self.compare_result.insert(tk.END, "✅ Comparison Complete!\n\n")
            self.compare_result.insert(tk.END, f"📊 Quality Metrics:\n")
            self.compare_result.insert(tk.END, f"   PSNR: {result['psnr']} dB\n")
            self.compare_result.insert(tk.END, f"   MSE: {result['mse']}\n")
            self.compare_result.insert(tk.END, f"   Identical: {result['identical']}\n")
            self.compare_result.insert(tk.END, f"   Tampered: {result['tampered']}\n\n")
            
            self.compare_result.insert(tk.END, f"🔑 Image Hashes:\n")
            self.compare_result.insert(tk.END, f"   Original: {result['original_hash'][:48]}...\n")
            self.compare_result.insert(tk.END, f"   Stego:    {result['stego_hash'][:48]}...\n\n")
            
            self.compare_result.insert(tk.END, f"📋 Quality Assessment:\n")
            if result['psnr'] > 40:
                self.compare_result.insert(tk.END, "   🌟 EXCELLENT: Changes are imperceptible\n")
            elif result['psnr'] > 30:
                self.compare_result.insert(tk.END, "   ✅ GOOD: Minor changes\n")
            else:
                self.compare_result.insert(tk.END, "   ⚠️ POOR: Visible changes\n")
        else:
            self.compare_result.insert(tk.END, f"❌ Error: {result['message']}\n")
            messagebox.showerror("Error", result['message'])


def main():
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()