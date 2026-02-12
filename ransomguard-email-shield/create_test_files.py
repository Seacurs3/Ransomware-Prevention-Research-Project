#!/usr/bin/env python3
"""
Create Safe Test Files for RansomGuard Demo
This script creates harmless test files that mimic ransomware characteristics
"""

import os
import random

def create_test_files():
    """Create various test files for demonstration"""
    
    test_dir = "test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    print("Creating safe test files for demonstration...")
    print()
    
    # 1. Benign text file (should ALLOW)
    print("1. Creating benign text file...")
    with open(f"{test_dir}/normal_document.txt", "w") as f:
        f.write("This is a normal text document.\n")
        f.write("It contains regular text content.\n")
        f.write("This should be allowed by the system.\n")
    print("   ✓ Created: normal_document.txt (Expected: ALLOW)")
    
    # 2. Suspicious filename (should WARN/QUARANTINE)
    print("\n2. Creating suspicious filename...")
    with open(f"{test_dir}/invoice.pdf.exe", "w") as f:
        f.write("This file has a suspicious double extension.\n")
    print("   ✓ Created: invoice.pdf.exe (Expected: QUARANTINE/BLOCK)")
    
    # 3. High entropy file (should BLOCK)
    print("\n3. Creating high-entropy file (simulated encryption)...")
    with open(f"{test_dir}/encrypted_data.bin", "wb") as f:
        # Create random bytes (high entropy)
        random_data = bytes([random.randint(0, 255) for _ in range(10240)])  # 10KB
        f.write(random_data)
    print("   ✓ Created: encrypted_data.bin (Expected: BLOCK)")
    
    # 4. EICAR test file (standard antivirus test)
    print("\n4. Creating EICAR test file...")
    eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    with open(f"{test_dir}/eicar.com", "w") as f:
        f.write(eicar_string)
    print("   ✓ Created: eicar.com (Expected: BLOCK)")
    
    # 5. Large file (should be analyzed carefully)
    print("\n5. Creating large file...")
    with open(f"{test_dir}/large_file.bin", "wb") as f:
        # 5MB of zeros (low entropy, but large size)
        f.write(b'\x00' * (5 * 1024 * 1024))
    print("   ✓ Created: large_file.bin (Expected: ALLOW)")
    
    # 6. File with suspicious extension
    print("\n6. Creating VBS script file...")
    with open(f"{test_dir}/script.vbs", "w") as f:
        f.write("' This is a Visual Basic Script\n")
        f.write("MsgBox \"Hello World\"\n")
    print("   ✓ Created: script.vbs (Expected: WARN/QUARANTINE)")
    
    print()
    print("="*60)
    print("✓ All test files created successfully!")
    print("="*60)
    print()
    print(f"Test files location: ./{test_dir}/")
    print()
    print("How to use these files:")
    print("1. Send these files as email attachments to your test account")
    print("2. Use RansomGuard Email Shield to scan them")
    print("3. Observe different detection results")
    print()
    print("⚠️  SAFETY NOTE:")
    print("These are SAFE test files that mimic ransomware characteristics")
    print("They do NOT contain any actual malware")
    print()


if __name__ == "__main__":
    create_test_files()
