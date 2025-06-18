#!/usr/bin/env python3
"""
Test para demostrar las correcciones en el comando CREATE_STD
"""

import struct

def demonstrate_corrections():
    """Demuestra las correcciones aplicadas al comando WriteData"""
    
    print("=== Demostración de Correcciones en WriteData ===\n")
    
    # Datos de ejemplo
    file_id = 0x02
    offset = 0x000000
    
    # Simular datos cifrados (16 bytes) + CMAC (8 bytes)
    encrypted_data = bytes.fromhex("EABC2CC2BF4E481E7DB46A6977F20CFE")  # 16 bytes
    cmac = bytes.fromhex("79F3B837A5E54746")  # 8 bytes
    
    total_encrypted_length = len(encrypted_data) + len(cmac)  # 24 bytes
    
    print("1. CORRECCIÓN DEL LENGTH:")
    print(f"   - Datos cifrados: {len(encrypted_data)} bytes")
    print(f"   - CMAC: {len(cmac)} bytes") 
    print(f"   - Total: {total_encrypted_length} bytes = 0x{total_encrypted_length:02X}")
    
    # Length correcto en little-endian (3 bytes)
    length_bytes = struct.pack('<L', total_encrypted_length)[0:3]
    print(f"   - Length en little-endian: {length_bytes.hex().upper()} ✅")
    print()
    
    print("2. CORRECCIÓN DEL Lc:")
    # Construir parámetros del comando
    command_params = struct.pack('<B', file_id)  # File ID (1 byte)
    command_params += struct.pack('<L', offset)[0:3]  # Offset (3 bytes)  
    command_params += length_bytes  # Length (3 bytes)
    
    # Calcular Lc correcto
    lc = len(command_params) + len(encrypted_data) + len(cmac)
    print(f"   - File ID: 1 byte")
    print(f"   - Offset: 3 bytes")
    print(f"   - Length: 3 bytes")
    print(f"   - Datos cifrados: {len(encrypted_data)} bytes")
    print(f"   - CMAC: {len(cmac)} bytes")
    print(f"   - Total Lc: {lc} bytes = 0x{lc:02X} ✅")
    print()
    
    print("3. COMANDO CORREGIDO:")
    # Construir comando APDU completo
    command = bytes([0x90, 0x3D, 0x00, 0x00, lc]) + command_params + encrypted_data + cmac + bytes([0x00])
    
    print(f"APDU: {command.hex().upper()}")
    print()
    print("Desglose:")
    print(f"├── 90 3D 00 00: Encabezado APDU")
    print(f"├── {lc:02X}: Lc = {lc} bytes (1+3+3+{len(encrypted_data)}+{len(cmac)})")
    print(f"├── {file_id:02X}: File ID")
    print(f"├── {offset:06X}: Offset = {offset}")  
    print(f"├── {total_encrypted_length:06X}: Length = {total_encrypted_length} bytes ({len(encrypted_data)} datos + {len(cmac)} CMAC)")
    print(f"├── {encrypted_data.hex().upper()}: {len(encrypted_data)} bytes datos cifrados")
    print(f"├── {cmac.hex().upper()}: {len(cmac)} bytes CMAC")
    print(f"└── 00: Le")
    print()
    
    print("4. COMPARACIÓN CON COMANDO ESPERADO:")
    expected = "903D00001F02000000180000EABC2CC2BF4E481E7DB46A6977F20CFE79F3B837A5E5474600"
    actual = command.hex().upper()
    
    # Formatear para comparación
    expected_formatted = ' '.join([expected[i:i+2] for i in range(0, len(expected), 2)])
    actual_formatted = ' '.join([actual[i:i+2] for i in range(0, len(actual), 2)])
    
    print(f"Esperado: {expected_formatted}")
    print(f"Actual:   {actual_formatted}")
    
    if expected == actual:
        print("✅ ¡COMANDO CORREGIDO EXITOSAMENTE!")
    else:
        print("❌ Diferencias encontradas")
        
        # Mostrar diferencias byte por byte
        print("\nAnálisis de diferencias:")
        for i in range(0, min(len(expected), len(actual)), 2):
            exp_byte = expected[i:i+2]
            act_byte = actual[i:i+2]
            if exp_byte != act_byte:
                print(f"  Posición {i//2}: esperado {exp_byte}, actual {act_byte}")

if __name__ == "__main__":
    demonstrate_corrections()