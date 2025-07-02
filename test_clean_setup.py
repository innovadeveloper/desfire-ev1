#!/usr/bin/env python3
"""
Test script para verificar la configuración limpia de claves
"""
from desfire_secure_operations import DESFireSecureOperations

def test_setup():
    """Test la configuración de estructura de claves"""
    print("Test: Configuración limpia de claves")
    print("=" * 50)
    
    # Las claves que se deben crear
    expected_keys = {
        'master': bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                        0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80]),
        'read': bytes(16),  # 16 zeros
        'write': bytes([0x01] * 16)  # 16 ones
    }
    
    print("Claves que se van a configurar:")
    print(f"Master (clave #0): {expected_keys['master'].hex().upper()}")
    print(f"Read   (clave #1): {expected_keys['read'].hex().upper()}")
    print(f"Write  (clave #2): {expected_keys['write'].hex().upper()}")
    
    print("\nEsto debería:")
    print("1. Eliminar claves existentes excepto master")
    print("2. Crear clave #1 (lectura)")
    print("3. Crear clave #2 (escritura)")
    print("4. Eliminar archivos existentes")
    print("5. Crear archivo seguro con permisos R=1, W=2, C=0")
    
    return True

if __name__ == "__main__":
    test_setup()