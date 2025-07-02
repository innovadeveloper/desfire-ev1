#!/usr/bin/env python3
"""
Test WriteData command construction
"""
import struct

def test_writedata_command():
    """Test the WriteData command construction"""
    
    file_id = 11
    offset = 100
    data = b"Datos autorizados por clave de escritura"
    
    # Construir comando WriteData
    command = bytearray([0x3D, file_id])
    command.extend(struct.pack('<I', offset)[:3])
    command.extend(struct.pack('<I', len(data))[:3])
    command.extend(data)
    
    print("WriteData command construction test:")
    print(f"File ID: {file_id}")
    print(f"Offset: {offset}")
    print(f"Data length: {len(data)}")
    print(f"Data: {data}")
    print(f"Command bytes: {command.hex().upper()}")
    
    # Simulate APDU wrapping (should now include Le=0x00)
    cmd_byte = command[0]
    data_part = command[1:]
    
    # Check if 0x3D is in no_le_commands
    no_le_commands = [0xC4, 0xDF]  # Updated list
    
    if cmd_byte in no_le_commands:
        apdu = [0x90, cmd_byte, 0x00, 0x00, len(data_part)] + list(data_part)
        print("APDU (without Le):")
    else:
        apdu = [0x90, cmd_byte, 0x00, 0x00, len(data_part)] + list(data_part) + [0x00]
        print("APDU (with Le=0x00):")
    
    print(f"{' '.join(f'{b:02X}' for b in apdu)}")
    
    # The APDU should now end with 0x00
    has_le = apdu[-1] == 0x00 and len(apdu) > 5
    print(f"Has Le=0x00: {has_le}")
    
    return has_le

if __name__ == "__main__":
    success = test_writedata_command()
    print(f"\nWriteData test {'PASSED' if success else 'FAILED'}")