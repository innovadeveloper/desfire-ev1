#!/usr/bin/env python3
"""
Demostración de la corrección del campo Length en el comando WriteData
"""

import struct

def demonstrate_length_correction():
    """Demuestra la corrección del campo Length"""
    
    print("=== Corrección del Campo Length en WriteData ===\n")
    
    # Datos de ejemplo
    original_data = b"Hola DESFire!"  # 13 bytes
    encrypted_data = bytes(16)  # Simulamos 16 bytes cifrados
    cmac = bytes(8)  # 8 bytes de CMAC
    
    print(f"Datos originales: '{original_data.decode()}' ({len(original_data)} bytes)")
    print(f"Datos cifrados: {len(encrypted_data)} bytes (con padding)")
    print(f"CMAC: {len(cmac)} bytes")
    print()
    
    print("PROBLEMA ANTERIOR (INCORRECTO):")
    print("─" * 50)
    # Versión incorrecta: Length = datos cifrados + CMAC
    wrong_length = len(encrypted_data) + len(cmac)  # 24 bytes
    wrong_length_hex = struct.pack('<L', wrong_length)[0:3]
    print(f"Length incorrecto: {wrong_length} bytes = 0x{wrong_length:02X}")
    print(f"Length en little-endian: {wrong_length_hex.hex().upper()}")
    print("❌ PROBLEMA: Length incluye datos cifrados + CMAC")
    print()
    
    print("SOLUCIÓN CORRECTA:")
    print("─" * 50)
    # Versión correcta: Length = datos originales solamente
    correct_length = len(original_data)  # 13 bytes
    correct_length_hex = struct.pack('<L', correct_length)[0:3]
    print(f"Length correcto: {correct_length} bytes = 0x{correct_length:02X}")
    print(f"Length en little-endian: {correct_length_hex.hex().upper()}")
    print("✅ CORRECTO: Length solo incluye datos originales")
    print()
    
    print("COMPARACIÓN DE COMANDOS:")
    print("─" * 50)
    
    # Simular parámetros del comando
    file_id = 0x02
    offset = 0x000000
    
    # Comando incorrecto
    wrong_params = struct.pack('<B', file_id)
    wrong_params += struct.pack('<L', offset)[0:3]
    wrong_params += wrong_length_hex
    wrong_lc = len(wrong_params) + len(encrypted_data) + len(cmac)
    
    print(f"COMANDO INCORRECTO:")
    print(f"├── File ID: {file_id:02X}")
    print(f"├── Offset: {offset:06X}")
    print(f"├── Length: {wrong_length_hex.hex().upper()} ({wrong_length} bytes)")
    print(f"├── Lc: {wrong_lc:02X} ({wrong_lc} bytes)")
    print(f"└── ERROR: Length incluye cifrado + CMAC")
    print()
    
    # Comando correcto
    correct_params = struct.pack('<B', file_id)
    correct_params += struct.pack('<L', offset)[0:3]
    correct_params += correct_length_hex
    correct_lc = len(correct_params) + len(encrypted_data) + len(cmac)
    
    print(f"COMANDO CORRECTO:")
    print(f"├── File ID: {file_id:02X}")
    print(f"├── Offset: {offset:06X}")
    print(f"├── Length: {correct_length_hex.hex().upper()} ({correct_length} bytes)")
    print(f"├── Lc: {correct_lc:02X} ({correct_lc} bytes)")
    print(f"└── ✅ CORRECTO: Length solo datos originales")
    print()
    
    print("EXPLICACIÓN TÉCNICA:")
    print("─" * 50)
    print("El campo Length en DESFire WriteData indica:")
    print("• ✅ Cantidad de bytes de datos ORIGINALES a escribir")
    print("• ❌ NO incluye el padding aplicado al cifrar")  
    print("• ❌ NO incluye el CMAC de autenticación")
    print("• ❌ NO incluye los bytes de cifrado adicionales")
    print()
    print("Esto permite a la tarjeta:")
    print("• Saber cuántos bytes reales contiene el archivo")
    print("• Validar que los datos cifrados son correctos")
    print("• Manejar correctamente el padding ISO")
    print()
    
    print("FORMATO LITTLE-ENDIAN:")
    print("─" * 50)
    examples = [
        (13, "0D 00 00"),
        (24, "18 00 00"), 
        (256, "00 01 00"),
        (1024, "00 04 00")
    ]
    
    for decimal, expected in examples:
        actual = struct.pack('<L', decimal)[0:3].hex().upper()
        formatted = ' '.join([actual[i:i+2] for i in range(0, len(actual), 2)])
        status = "✅" if formatted == expected else "❌"
        print(f"{decimal:4d} bytes → {formatted} {status}")

if __name__ == "__main__":
    demonstrate_length_correction()