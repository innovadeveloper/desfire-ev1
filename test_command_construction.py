#!/usr/bin/env python3
"""
Test script to verify CreateStdDataFile command construction
"""
import struct

def test_create_secure_file_command():
    """Test the CreateStdDataFile command construction"""
    
    file_id = 11
    file_size = 512
    read_key = 1
    write_key = 2
    change_key = 0
    
    # Construir derechos de acceso
    access_word = (read_key << 12) | (write_key << 8) | (read_key << 4) | change_key
    
    # Construir comando CreateStdDataFile manualmente
    command = bytearray([0xCD, file_id])  # Comando CreateStdDataFile + File ID
    command.append(0x03)  # Communication Mode: ENCRYPTED
    command.extend(struct.pack('<H', access_word))  # Access Rights (2 bytes little-endian)
    command.extend(struct.pack('<I', file_size)[:3])  # File Size (3 bytes little-endian)
    
    print("Command construction test:")
    print(f"File ID: {file_id}")
    print(f"File Size: {file_size}")
    print(f"Access Word: 0x{access_word:04X}")
    print(f"Command bytes: {command.hex().upper()}")
    
    # Simulate APDU wrapping (with Le=0x00)
    cmd_byte = command[0]
    data = command[1:]
    apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data) + [0x00]
    
    print(f"APDU: {' '.join(f'{b:02X}' for b in apdu)}")
    
    # Expected: 90 CD 00 00 07 0B 03 10 12 00 02 00 00
    expected_apdu = [0x90, 0xCD, 0x00, 0x00, 0x07, 0x0B, 0x03, 0x10, 0x12, 0x00, 0x02, 0x00, 0x00]
    
    print(f"Expected: {' '.join(f'{b:02X}' for b in expected_apdu)}")
    print(f"Match: {apdu == expected_apdu}")
    
    return apdu == expected_apdu

if __name__ == "__main__":
    success = test_create_secure_file_command()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")