# 🔒 Secure Image Steganography

A powerful Python-based steganography tool that hides encrypted messages within images using AES-256 encryption and advanced embedding techniques.



## ✨ Features

### Core Capabilities
- **🔐 Military-Grade Encryption**: AES-256-CBC encryption for message security
- **🖼️ Multiple Image Formats**: Automatic detection and handling of PNG and JPEG
- **🎯 LSB Steganography**: Reliable Least Significant Bit embedding for lossless formats
- **📊 DCT Steganography**: Discrete Cosine Transform embedding for JPEG images
- **⚡ Parallel Processing**: Multi-core CPU utilization for faster operations
- **🔍 Steganalysis Tools**: Built-in detection and analysis capabilities

### User Interfaces
- **🖥️ Desktop GUI**: User-friendly Tkinter application
- **⌨️ Command Line**: Powerful CLI for automation and scripting
- **🐍 Python API**: Easy integration into other projects

### Quality & Analysis
- **📈 PSNR/MSE Metrics**: Quality assessment of stego images
- **🔬 Image Comparison**: Detailed comparison between original and stego images
- **🕵️ Steganography Detection**: Statistical analysis for hidden data detection
- **#️⃣ Image Hashing**: SHA-256 hashing for integrity verification

## 🔬 How It Works

### Embedding Process

```
Original Message → AES-256 Encryption → Binary Conversion → LSB/DCT Embedding → Stego Image
     ↓                    ↓                    ↓                  ↓               ↓
"Hello World"    [encrypted bytes]      10110101...      Modified pixels    output.png
```

1. **Encryption**: Your message is encrypted using AES-256-CBC with a password-derived key
2. **Binary Conversion**: Encrypted data is converted to binary format
3. **Embedding**: Binary data is hidden in image pixels using LSB or DCT method
4. **Output**: Modified image is saved (always as PNG to preserve data)

### Extraction Process

```
Stego Image → LSB/DCT Extraction → Binary to Bytes → AES-256 Decryption → Original Message
     ↓                ↓                   ↓                  ↓                    ↓
  input.png     10110101...      [encrypted bytes]     [decrypted]         "Hello World"
```

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/secure-steganography.git
cd secure-steganography
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation

```bash
python cli.py --help
```

## 🚀 Quick Start

### Embed a Message (GUI)

```bash
python gui_app.py
```

1. Select the "📝 Embed Message" tab
2. Browse for a cover image
3. Type your secret message
4. Set a password
5. Click "🔒 Embed Message"

### Embed a Message (CLI)

```bash
python cli.py embed -i cover.png -o stego.png -m "Secret message" -p password123
```

### Extract a Message (CLI)

```bash
python cli.py extract -i stego.png -p password123
```

## 📖 Usage

### GUI Application

#### Starting the GUI

```bash
python gui_app.py
```

#### Tab 1: Embed Message

1. **Select Cover Image**: Browse for PNG or JPEG image (will be converted to PNG)
2. **Enter Secret Message**: Type or paste your message (any length up to capacity)
3. **Set Password**: Enter and confirm your encryption password
4. **Choose Output**: Select where to save the stego image
5. **Embed**: Click the embed button to process

**Output Information:**
- PSNR (Peak Signal-to-Noise Ratio): Higher is better (>40 dB = excellent)
- MSE (Mean Squared Error): Lower is better
- Capacity Used: Percentage of image capacity utilized
- Image Hash: SHA-256 hash for verification

#### Tab 2: Extract Message

1. **Select Stego Image**: Browse for the PNG image containing hidden data
2. **Enter Password**: Must match the password used during embedding
3. **Extract**: Click to decrypt and extract the message
4. **Save (Optional)**: Save extracted message to a text file

#### Tab 3: Compare Images

1. **Select Images**: Choose original and stego images
2. **Compare**: View quality metrics and analysis
3. **Assess Quality**: Review PSNR, MSE, and hash comparison

### Command Line Interface

#### Embed Message

**From text:**
```bash
python cli.py embed -i cover.png -o stego.png -m "Your secret message" -p password123
```

**From file:**
```bash
python cli.py embed -i cover.png -o stego.png -f message.txt -p password123
```

**Parameters:**
- `-i, --input`: Cover image path (PNG or JPEG)
- `-o, --output`: Output stego image path (will be PNG)
- `-m, --message`: Secret message text
- `-f, --file`: Path to file containing message
- `-p, --password`: Encryption password

#### Extract Message

**To console:**
```bash
python cli.py extract -i stego.png -p password123
```

**To file:**
```bash
python cli.py extract -i stego.png -p password123 -o extracted.txt
```

**Parameters:**
- `-i, --input`: Stego image path
- `-p, --password`: Decryption password
- `-o, --output`: (Optional) Output file for message

#### Compare Images

```bash
python cli.py compare -i1 original.png -i2 stego.png
```

**Output includes:**
- PSNR and MSE values
- Image hashes
- Tampering detection
- Quality assessment

#### Detect Steganography

```bash
python cli.py detect -i suspicious.png
```

**Analysis includes:**
- LSB bit distribution per channel
- Chi-square statistics
- Anomaly detection
- Suspicion indicators

### Python API

#### Basic Usage

```python
from steganography_core import SecureSteganography

# Initialize
stego = SecureSteganography()

# Embed message
result = stego.embed_message(
    cover_image_path="cover.png",
    secret_message="This is secret!",
    password="myPassword123",
    output_path="stego.png"
)

if result['status'] == 'success':
    print(f"PSNR: {result['psnr']} dB")
    print(f"Hash: {result['image_hash']}")

# Extract message
result = stego.extract_message(
    stego_image_path="stego.png",
    password="myPassword123"
)

if result['status'] == 'success':
    print(f"Message: {result['message']}")
```

#### Advanced Usage

```python
# Compare images
result = stego.compare_images(
    original_path="original.png",
    stego_path="stego.png"
)

print(f"PSNR: {result['psnr']} dB")
print(f"Tampered: {result['tampered']}")

# Detect steganography
result = stego.detect_steganography("suspicious.png")

if result['suspicious']:
    print("Warning: Image may contain hidden data")
    print(f"Analysis: {result['analysis']}")
```

#### Error Handling

```python
result = stego.embed_message(
    cover_image_path="cover.png",
    secret_message="Secret",
    password="pass",
    output_path="out.png"
)

if result['status'] == 'error':
    print(f"Error: {result['message']}")
else:
    print("Success!")
```

##  Technical Details

### Encryption

**Algorithm**: AES-256-CBC (Advanced Encryption Standard)
- **Key Derivation**: SHA-256 hash of password
- **Block Size**: 128 bits
- **Padding**: PKCS7
- **IV**: Random 16-byte initialization vector (prepended to ciphertext)

**Security Features:**
- Each encryption uses a unique random IV
- No key reuse across different messages
- Cryptographically secure password hashing

### LSB Steganography (PNG)

**Method**: Least Significant Bit embedding
- Modifies the least significant bit of each color channel
- Sequential embedding for reliability
- Capacity: (width × height × 3) / 8 bytes
- Quality: Very high PSNR (>40 dB typical)

**Process:**
1. Convert encrypted message to binary
2. Iterate through pixels sequentially (row by row, channel by channel)
3. Replace LSB of each byte with one bit of message
4. Save as PNG (lossless format)

**Example:**
```
Original pixel: [10110110, 11001011, 10101010] = [182, 203, 170]
Message bit:     1         0         1
Modified pixel: [10110111, 11001010, 10101011] = [183, 202, 171]
Difference:      +1        -1        +1         (imperceptible)
```

### DCT Steganography (JPEG)

**Method**: Discrete Cosine Transform coefficient modification
- Embeds data in frequency domain
- Uses YCrCb color space (luminance channel)
- Processes 8×8 pixel blocks
- Redundant embedding with majority voting

**Process:**
1. Convert image to YCrCb color space
2. Divide luminance channel into 8×8 blocks
3. Apply DCT to each block
4. Modify middle-frequency coefficients
5. Apply inverse DCT
6. Reconstruct image

**Note**: JPEG inputs are automatically converted to PNG output to prevent data loss from re-compression.

### Multiprocessing

- Utilizes `multiprocessing.Pool` for parallel operations
- Automatically detects CPU cores (uses n-1 cores)
- Applies to DCT embedding/extraction
- Significantly speeds up large image processing

### Capacity Calculation

```python
max_capacity = (image_width × image_height × 3 channels) / 8 bits_per_byte
```

**Example:**
- 1920×1080 image = 777,600 bytes capacity (~760 KB)
- 800×600 image = 180,000 bytes capacity (~176 KB)

### Quality Metrics

**PSNR (Peak Signal-to-Noise Ratio):**
```
PSNR = 10 × log₁₀(MAX² / MSE)
```
- Measured in decibels (dB)
- Higher is better
- >40 dB: Excellent (imperceptible changes)
- 30-40 dB: Good (minor changes)
- <30 dB: Poor (visible changes)

**MSE (Mean Squared Error):**
```
MSE = (1 / n) × Σ(original - modified)²
```
- Lower is better
- 0 = identical images

##  Security Considerations

### Strengths

 **Strong Encryption**: AES-256 is military-grade and quantum-resistant (for now)
 **Random IVs**: Each encryption uses unique initialization vector
 **No Pattern Leakage**: Encrypted data appears random in LSB analysis
 **Password-Based**: Only users with password can decrypt

### Limitations

 **Known Container**: If attacker knows image contains hidden data, they can:
- Extract encrypted data (but cannot decrypt without password)
- Attempt password brute-force attacks
- Perform statistical analysis

 **Format Dependency**: 
- Must use PNG output to preserve embedded data
- JPEG compression will destroy hidden information
- Avoid uploading to platforms that re-encode images

 **Capacity Limits**:
- Large messages require large images
- Full capacity usage may be more detectable

### Best Practices

1. **Use Strong Passwords**: Minimum 12 characters, mixed case, numbers, symbols
2. **Don't Reuse Images**: Use unique cover images for each message
3. **Verify Integrity**: Always check output image hash
4. **Secure Distribution**: Use encrypted channels to share stego images
5. **Test Extraction**: Verify message can be extracted before sharing
6. **Keep Originals Private**: Don't share the original cover image
7. **Use PNG Format**: Always extract from PNG, not JPEG

### Password Guidelines

```
❌ Weak:     "password", "12345", "myname"
⚠️  Medium:  "MyPassword123"
✅ Strong:   "Tr0ub4dor&3_SecurePass!"
✅ Best:     "correct-horse-battery-staple-9X2v" (passphrase)
```

## 📊 Examples

### Example 1: Simple Text Message

```bash
# Embed
python cli.py embed -i photo.png -o secret.png -m "Meet at 3pm" -p SecurePass123

# Output:
# ✓ Message embedded successfully
# PSNR: 52.34 dB
# Capacity Used: 256/777600 bytes (0.03%)

# Extract
python cli.py extract -i secret.png -p SecurePass123

# Output:
# ✓ Message extracted successfully
# Decrypted Message:
# ============================================================
# Meet at 3pm
# ============================================================
```

### Example 2: Large File Embedding

```bash
# Create message file
echo "This is a longer secret message with multiple lines.
It can contain any text data.
Line breaks are preserved." > message.txt

# Embed from file
python cli.py embed -i landscape.png -o output.png -f message.txt -p MyPassword

# Extract to file
python cli.py extract -i output.png -p MyPassword -o extracted.txt

# Verify
cat extracted.txt
```

### Example 3: Quality Comparison

```bash
# Embed message
python cli.py embed -i original.png -o stego.png -m "Hidden data" -p pass123

# Compare images
python cli.py compare -i1 original.png -i2 stego.png

# Output:
# ✓ Analysis complete!
# Metrics:
#    PSNR: 51.24 dB
#    MSE: 0.000487
#    Identical: False
#    Tampered: True
# Quality: Excellent (PSNR > 40 dB)
```

### Example 4: Detection Analysis

```bash
python cli.py detect -i suspicious.png

# Output:
# ✓ SUSPICIOUS: This image may contain hidden data!
# 
# Channel Analysis:
#    Blue Channel:
#       Ones: 480234
#       Zeros: 479566
#       Ratio: 0.5004
#       Chi-Square: 0.2341
#       Status: ✓ Very close to 0.5 (potentially random/encrypted data)
```
### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/secure-steganography.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest tests/
```


## 🙏 Acknowledgments

- OpenCV team for image processing capabilities
- Cryptography library maintainers
- Python community
- All contributors

---

Made with ❤️ and Python