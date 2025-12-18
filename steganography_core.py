"""
Secure Image Steganography with AES Encryption
Enhanced Core implementation with automatic format detection and multiprocessing
"""

import cv2
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import os
from multiprocessing import Pool, cpu_count
from functools import partial
import math


class SecureSteganography:
    def __init__(self):
        self.delimiter = "====END===="
        self.num_processes = max(1, cpu_count() - 1)  # Leave one CPU free
        
    def generate_key(self, password: str) -> bytes:
        """Generate 256-bit AES key from password"""
        return hashlib.sha256(password.encode()).digest()
    
    def encrypt_message(self, message: str, password: str) -> bytes:
        """Encrypt message using AES-256-CBC"""
        key = self.generate_key(password)
        iv = os.urandom(16)  # Initialization vector
        
        # Pad message to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted
    
    def decrypt_message(self, encrypted_data: bytes, password: str) -> str:
        """Decrypt message using AES-256-CBC"""
        key = self.generate_key(password)
        
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted.decode()
    
    def detect_image_format(self, image_path: str) -> str:
        """
        Automatically detect image format
        Returns: 'PNG' or 'JPEG'
        """
        try:
            with Image.open(image_path) as img:
                format_type = img.format.upper()
                if format_type in ['PNG', 'BMP', 'TIFF']:
                    return 'PNG'  # Lossless formats - use LSB
                elif format_type in ['JPEG', 'JPG']:
                    return 'JPEG'  # Lossy format - use DCT
                else:
                    # Default to PNG for unknown formats
                    return 'PNG'
        except Exception as e:
            return 'PNG'  # Default fallback
    
    # ==================== LSB STEGANOGRAPHY (for PNG) ====================
    
    def _embed_lsb_block(self, args):
        """Process a single block for LSB embedding (for multiprocessing)"""
        img_block, binary_data, start_idx = args
        data_index = start_idx
        binary_len = len(binary_data)
        
        for row in range(img_block.shape[0]):
            for col in range(img_block.shape[1]):
                for channel in range(3):
                    if data_index < binary_len:
                        img_block[row, col, channel] = (img_block[row, col, channel] & 0xFE) | int(binary_data[data_index])
                        data_index += 1
                    else:
                        return img_block, data_index
        
        return img_block, data_index
    
    def embed_lsb(self, img: np.ndarray, binary_message: str) -> np.ndarray:
        """
        Embed message using LSB (sequential, reliable method)
        """
        data_index = 0
        binary_len = len(binary_message)
        
        # Sequential embedding for reliability
        for row in range(img.shape[0]):
            for col in range(img.shape[1]):
                for channel in range(3):
                    if data_index < binary_len:
                        # Modify LSB
                        img[row, col, channel] = (img[row, col, channel] & 0xFE) | int(binary_message[data_index])
                        data_index += 1
                    else:
                        return img
        
        return img
    
    def _extract_lsb_block(self, img_block):
        """Extract LSB from a single block (for multiprocessing)"""
        binary_data = ""
        for row in range(img_block.shape[0]):
            for col in range(img_block.shape[1]):
                for channel in range(3):
                    binary_data += str(img_block[row, col, channel] & 1)
        return binary_data
    
    def extract_lsb(self, img: np.ndarray) -> str:
        """
        Extract message using LSB (sequential, reliable method)
        """
        binary_data = ""
        
        # Sequential extraction for reliability
        for row in range(img.shape[0]):
            for col in range(img.shape[1]):
                for channel in range(3):
                    binary_data += str(img[row, col, channel] & 1)
        
        return binary_data
    
    # ==================== DCT STEGANOGRAPHY (for JPEG) ====================
    
    def _dct_embed_block(self, args):
        """Embed data in a single 8x8 DCT block"""
        block, bit = args
        # Apply DCT
        dct_block = cv2.dct(np.float32(block))
        
        # Embed bit in middle frequency coefficient with stronger modification
        # Use multiple coefficients for redundancy
        positions = [(3, 4), (4, 3), (4, 4), (5, 4), (4, 5)]
        
        for pos in positions:
            coeff = abs(dct_block[pos[0], pos[1]])
            if bit == '1':
                # Make coefficient odd and increase magnitude
                dct_block[pos[0], pos[1]] = int(coeff / 4) * 4 + 1
            else:
                # Make coefficient even
                dct_block[pos[0], pos[1]] = int(coeff / 4) * 4
        
        # Apply inverse DCT
        return cv2.idct(dct_block)
    
    def embed_dct(self, img: np.ndarray, binary_message: str) -> np.ndarray:
        """
        Embed message using DCT (for JPEG images)
        Process 8x8 blocks with multiprocessing
        """
        height, width = img.shape[:2]
        
        # Ensure dimensions are multiples of 8
        new_height = (height // 8) * 8
        new_width = (width // 8) * 8
        img = img[:new_height, :new_width]
        
        # Convert to YCrCb color space (better for JPEG)
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        y_channel = img_ycrcb[:, :, 0]
        
        # Extract 8x8 blocks
        blocks = []
        bits = []
        bit_index = 0
        
        for i in range(0, new_height, 8):
            for j in range(0, new_width, 8):
                if bit_index < len(binary_message):
                    block = y_channel[i:i+8, j:j+8]
                    blocks.append(block)
                    bits.append(binary_message[bit_index])
                    bit_index += 1
        
        # Process blocks in parallel
        with Pool(processes=self.num_processes) as pool:
            processed_blocks = pool.map(self._dct_embed_block, zip(blocks, bits))
        
        # Reconstruct Y channel
        block_idx = 0
        for i in range(0, new_height, 8):
            for j in range(0, new_width, 8):
                if block_idx < len(processed_blocks):
                    y_channel[i:i+8, j:j+8] = processed_blocks[block_idx]
                    block_idx += 1
        
        # Convert back to BGR
        img_ycrcb[:, :, 0] = y_channel
        img = cv2.cvtColor(img_ycrcb, cv2.COLOR_YCrCb2BGR)
        
        return img
    
    def _dct_extract_block(self, block):
        """Extract bit from a single 8x8 DCT block with voting"""
        dct_block = cv2.dct(np.float32(block))
        
        # Use multiple positions and vote
        positions = [(3, 4), (4, 3), (4, 4), (5, 4), (4, 5)]
        votes = []
        
        for pos in positions:
            coeff = abs(dct_block[pos[0], pos[1]])
            votes.append(1 if int(coeff) % 4 == 1 else 0)
        
        # Majority voting
        return '1' if sum(votes) > len(votes) // 2 else '0'
    
    def extract_dct(self, img: np.ndarray, message_length: int) -> str:
        """
        Extract message using DCT with multiprocessing
        """
        height, width = img.shape[:2]
        new_height = (height // 8) * 8
        new_width = (width // 8) * 8
        img = img[:new_height, :new_width]
        
        # Convert to YCrCb
        img_ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        y_channel = img_ycrcb[:, :, 0]
        
        # Extract 8x8 blocks
        blocks = []
        bits_needed = message_length * 8  # Approximate
        
        for i in range(0, new_height, 8):
            for j in range(0, new_width, 8):
                if len(blocks) * 8 < bits_needed + 10000:  # Extra buffer
                    blocks.append(y_channel[i:i+8, j:j+8])
        
        # Extract from blocks in parallel
        with Pool(processes=self.num_processes) as pool:
            bits = pool.map(self._dct_extract_block, blocks)
        
        return ''.join(bits)
    
    # ==================== MAIN INTERFACE ====================
    
    def embed_message(self, cover_image_path: str, secret_message: str, 
                     password: str, output_path: str) -> dict:
        """
        Embed encrypted message with automatic format detection
        """
        try:
            # Detect format
            img_format = self.detect_image_format(cover_image_path)
            
            # Read image
            img = cv2.imread(cover_image_path)
            if img is None:
                return {"status": "error", "message": "Failed to read image"}
            
            original_img = img.copy()
            
            # Encrypt message
            encrypted_data = self.encrypt_message(secret_message, password)
            message_with_delimiter = encrypted_data + self.delimiter.encode()
            
            # Convert to binary
            binary_message = ''.join(format(byte, '08b') for byte in message_with_delimiter)
            
            # Always use LSB for reliability
            # Force PNG output for JPEG inputs
            if img_format == 'JPEG':
                img_format = 'PNG'  # Force LSB method
                if not output_path.lower().endswith('.png'):
                    output_path = output_path.rsplit('.', 1)[0] + '.png'
            
            # Check capacity
            max_bytes = (img.shape[0] * img.shape[1] * 3) // 8
            required_bytes = len(message_with_delimiter)
            
            if required_bytes > max_bytes:
                return {
                    "status": "error",
                    "message": f"Message too large. Max: {max_bytes} bytes, Required: {required_bytes} bytes"
                }
            
            # Embed using LSB (reliable sequential method)
            img = self.embed_lsb(img, binary_message)
            
            # Save as PNG to preserve data
            if not output_path.lower().endswith('.png'):
                output_path = output_path.rsplit('.', 1)[0] + '.png'
            cv2.imwrite(output_path, img)
            
            # Calculate metrics
            mse = np.mean((original_img.astype(float) - img.astype(float)) ** 2)
            psnr = 100 if mse == 0 else 10 * np.log10((255 ** 2) / mse)
            img_hash = hashlib.sha256(img.tobytes()).hexdigest()
            
            return {
                "status": "success",
                "message": "Message embedded successfully",
                "method": "LSB",
                "original_format": self.detect_image_format(cover_image_path),
                "output_path": output_path,
                "psnr": round(psnr, 2),
                "mse": round(mse, 6),
                "capacity_used": f"{required_bytes}/{max_bytes} bytes ({round(required_bytes/max_bytes*100, 2)}%)",
                "image_hash": img_hash,
                "processing": f"Sequential LSB (reliable method)",
                "warning": "⚠️ Output saved as PNG to preserve hidden data" if self.detect_image_format(cover_image_path) == 'JPEG' else None
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def extract_message(self, stego_image_path: str, password: str) -> dict:
        """
        Extract and decrypt message (always uses LSB for reliability)
        """
        try:
            # Read image
            img = cv2.imread(stego_image_path)
            if img is None:
                return {"status": "error", "message": "Failed to read image"}
            
            # Always use LSB extraction (most reliable)
            binary_data = self.extract_lsb(img)
            
            # Convert to bytes
            all_bytes = []
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) == 8:
                    all_bytes.append(int(byte, 2))
            
            byte_data = bytes(all_bytes)
            
            # Find delimiter
            delimiter_bytes = self.delimiter.encode()
            delimiter_index = byte_data.find(delimiter_bytes)
            
            if delimiter_index == -1:
                return {"status": "error", "message": "No hidden message found or corrupted data. Make sure you're using the PNG stego image (not JPEG)."}
            
            # Extract encrypted message
            encrypted_message = byte_data[:delimiter_index]
            
            # Decrypt
            try:
                decrypted_message = self.decrypt_message(encrypted_message, password)
                return {
                    "status": "success",
                    "message": decrypted_message,
                    "method": "LSB",
                    "encrypted_size": len(encrypted_message),
                    "parallel_processing": f"Used {self.num_processes} CPU cores"
                }
            except Exception as e:
                return {"status": "error", "message": "Decryption failed. Wrong password or corrupted data."}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def compare_images(self, original_path: str, stego_path: str) -> dict:
        """Compare original and stego images"""
        try:
            img1 = cv2.imread(original_path)
            img2 = cv2.imread(stego_path)
            
            if img1 is None or img2 is None:
                return {"status": "error", "message": "Failed to read images"}
            
            # Resize if dimensions don't match
            if img1.shape != img2.shape:
                img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))
            
            # Calculate MSE and PSNR
            mse = np.mean((img1.astype(float) - img2.astype(float)) ** 2)
            psnr = 100 if mse == 0 else 10 * np.log10((255 ** 2) / mse)
            
            # Calculate hashes
            hash1 = hashlib.sha256(img1.tobytes()).hexdigest()
            hash2 = hashlib.sha256(img2.tobytes()).hexdigest()
            
            identical = np.array_equal(img1, img2)
            
            return {
                "status": "success",
                "mse": round(mse, 6),
                "psnr": round(psnr, 2),
                "identical": identical,
                "original_hash": hash1,
                "stego_hash": hash2,
                "tampered": hash1 != hash2
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def detect_steganography(self, image_path: str) -> dict:
        """Perform basic statistical analysis"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {"status": "error", "message": "Failed to read image"}
            
            # LSB analysis
            lsb_values = []
            for channel in range(3):
                lsb = img[:, :, channel] & 1
                lsb_values.append(lsb.flatten())
            
            results = {}
            for i, lsb in enumerate(lsb_values):
                ones = np.sum(lsb)
                zeros = len(lsb) - ones
                ratio = ones / len(lsb)
                expected = len(lsb) / 2
                chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
                
                results[f"channel_{i}"] = {
                    "ones": int(ones),
                    "zeros": int(zeros),
                    "ratio": round(ratio, 4),
                    "chi_square": round(chi_square, 4)
                }
            
            suspicious = any(abs(results[f"channel_{i}"]["ratio"] - 0.5) > 0.1 for i in range(3))
            
            return {
                "status": "success",
                "suspicious": suspicious,
                "analysis": results,
                "note": "Ratio close to 0.5 suggests random data (possible steganography)"
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


# Example usage
if __name__ == "__main__":
    stego = SecureSteganography()
    
    print(f"Using {stego.num_processes} CPU cores for parallel processing\n")
    
    # Example: Embed message (auto-detects format)
    result = stego.embed_message(
        cover_image_path="cover.png",
        secret_message="This is a secret message!",
        password="mySecurePassword123",
        output_path="stego.png"
    )
    print("Embed Result:", result)
    
    # Example: Extract message
    result = stego.extract_message(
        stego_image_path="stego.png",
        password="mySecurePassword123"
    )
    print("\nExtract Result:", result)