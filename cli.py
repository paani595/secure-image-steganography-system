"""
Command Line Interface for Secure Image Steganography
"""

import argparse
import sys
from steganography_core import SecureSteganography
import json


def main():
    parser = argparse.ArgumentParser(
        description='Secure Image Steganography with AES Encryption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Embed a message
  python cli.py embed -i cover.png -o stego.png -m "Secret message" -p password123
  
  # Embed from file
  python cli.py embed -i cover.png -o stego.png -f message.txt -p password123
  
  # Extract message
  python cli.py extract -i stego.png -p password123
  
  # Compare images
  python cli.py compare -i1 original.png -i2 stego.png
  
  # Detect steganography
  python cli.py detect -i suspicious.png
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Embed secret message in image')
    embed_parser.add_argument('-i', '--input', required=True, help='Input cover image path')
    embed_parser.add_argument('-o', '--output', required=True, help='Output stego image path')
    embed_parser.add_argument('-m', '--message', help='Secret message text')
    embed_parser.add_argument('-f', '--file', help='Secret message file path')
    embed_parser.add_argument('-p', '--password', required=True, help='Encryption password')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract secret message from image')
    extract_parser.add_argument('-i', '--input', required=True, help='Input stego image path')
    extract_parser.add_argument('-p', '--password', required=True, help='Decryption password')
    extract_parser.add_argument('-o', '--output', help='Output file for extracted message')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two images')
    compare_parser.add_argument('-i1', '--image1', required=True, help='First image path')
    compare_parser.add_argument('-i2', '--image2', required=True, help='Second image path')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect steganography in image')
    detect_parser.add_argument('-i', '--input', required=True, help='Input image path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    stego = SecureSteganography()
    
    # Execute command
    if args.command == 'embed':
        # Get message
        if args.message:
            message = args.message
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    message = f.read()
            except Exception as e:
                print(f" Error reading file: {e}")
                sys.exit(1)
        else:
            print(" Error: Either -m/--message or -f/--file must be provided")
            sys.exit(1)
        
        print(f"Encrypting and embedding message...")
        print(f"Cover image: {args.input}")
        print(f"Output: {args.output}")
        
        result = stego.embed_message(
            cover_image_path=args.input,
            secret_message=message,
            password=args.password,
            output_path=args.output
        )
        
        if result['status'] == 'success':
            print(f"\n {result['message']}")
            print(f"\nMetrics:")
            print(f"   PSNR: {result['psnr']} dB")
            print(f"   MSE: {result['mse']}")
            print(f"   Capacity Used: {result['capacity_used']}")
            print(f"   Image Hash: {result['image_hash'][:32]}...")
            print(f"\nStego image saved to: {args.output}")
        else:
            print(f"\n Error: {result['message']}")
            sys.exit(1)
    
    elif args.command == 'extract':
        print(f" Extracting and decrypting message...")
        print(f" Stego image: {args.input}")
        
        result = stego.extract_message(
            stego_image_path=args.input,
            password=args.password
        )
        
        if result['status'] == 'success':
            print(f"\n Message extracted successfully!")
            print(f"\n Decrypted Message:")
            print("=" * 60)
            print(result['message'])
            print("=" * 60)
            print(f"\n Encrypted Size: {result['encrypted_size']} bytes")
            
            # Save to file if specified
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        f.write(result['message'])
                    print(f"\n Message saved to: {args.output}")
                except Exception as e:
                    print(f"\n Warning: Could not save to file: {e}")
        else:
            print(f"\n Error: {result['message']}")
            sys.exit(1)
    
    elif args.command == 'compare':
        print(f" Comparing images...")
        print(f" Image 1: {args.image1}")
        print(f" Image 2: {args.image2}")
        
        result = stego.compare_images(
            original_path=args.image1,
            stego_path=args.image2
        )
        
        if result['status'] == 'success':
            print(f"\n Analysis complete!")
            print(f"\n Metrics:")
            print(f"   PSNR: {result['psnr']} dB")
            print(f"   MSE: {result['mse']}")
            print(f"   Identical: {'Yes' if result['identical'] else 'No'}")
            print(f"   Tampered: {'Yes' if result['tampered'] else 'No'}")
            print(f"\n Hashes:")
            print(f"   Image 1: {result['original_hash'][:32]}...")
            print(f"   Image 2: {result['stego_hash'][:32]}...")
            
            # Quality assessment
            if result['psnr'] > 40:
                print(f"\n Quality: Excellent (PSNR > 40 dB)")
            elif result['psnr'] > 30:
                print(f"\n Quality: Good (PSNR > 30 dB)")
            else:
                print(f"\n Quality: Poor (PSNR < 30 dB)")
        else:
            print(f"\n Error: {result['message']}")
            sys.exit(1)
    
    elif args.command == 'detect':
        print(f" Analyzing image for steganography...")
        print(f" Image: {args.input}")
        
        result = stego.detect_steganography(args.input)
        
        if result['status'] == 'success':
            if result['suspicious']:
                print(f"\n SUSPICIOUS: This image may contain hidden data!")
            else:
                print(f"\n NORMAL: No obvious signs of steganography detected.")
            
            print(f"\n {result['note']}")
            print(f"\n Channel Analysis:")
            
            for channel in range(3):
                channel_name = ['Blue', 'Green', 'Red'][channel]
                data = result['analysis'][f'channel_{channel}']
                
                print(f"\n   {channel_name} Channel:")
                print(f"      Ones: {data['ones']}")
                print(f"      Zeros: {data['zeros']}")
                print(f"      Ratio: {data['ratio']:.4f}")
                print(f"      Chi-Square: {data['chi_square']:.4f}")
                
                if abs(data['ratio'] - 0.5) < 0.01:
                    print(f"      Status:  Very close to 0.5 (potentially random/encrypted data)")
                elif abs(data['ratio'] - 0.5) > 0.1:
                    print(f"      Status:  Deviates significantly from 0.5")
                else:
                    print(f"      Status:  Normal distribution")
        else:
            print(f"\n Error: {result['message']}")
            sys.exit(1)


if __name__ == "__main__":
    main()