#!/usr/bin/env python3
"""
Script de prueba para verificar que el método _write_encrypted_data funciona correctamente
"""

import sys
import os
from unittest.mock import Mock, MagicMock

# Importar las clases necesarias
from desfire_write_file import DESFireFileWriter, DESFireReaderConnection, DESFireAuthenticateAdvanced, DESFireCryptoUtils

def test_write_encrypted_data():
    """Prueba el método _write_encrypted_data sin conexión real"""
    
    print("=== Test del método _write_encrypted_data ===\n")
    
    # Crear mocks para las dependencias
    mock_connection = Mock(spec=DESFireReaderConnection)
    mock_auth = Mock(spec=DESFireAuthenticateAdvanced)
    
    # Configurar el mock de autenticación
    mock_auth.is_authenticated.return_value = True
    mock_auth.session_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                                   0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])
    mock_auth.session_iv = bytes(16)  # IV de ceros
    mock_auth.crypto_utils = DESFireCryptoUtils()
    
    # Configurar el mock de conexión para simular respuesta exitosa  
    mock_connection.send_apdu.return_value = ([], 0x90, 0x00)  # Respuesta exitosa
    
    # Crear instancia del escritor de archivos
    file_writer = DESFireFileWriter(mock_connection, mock_auth)
    
    # Datos de prueba
    file_id = 2
    offset = 0
    test_data = b"Hola DESFire!"
    
    print(f"Datos de prueba:")
    print(f"  File ID: {file_id}")
    print(f"  Offset: {offset}")
    print(f"  Datos: {test_data}")
    print(f"  Longitud: {len(test_data)} bytes")
    print()
    
    try:
        # Llamar al método que antes fallaba
        result = file_writer._write_encrypted_data(file_id, offset, test_data)
        
        if result:
            print("✅ El método _write_encrypted_data se ejecutó correctamente!")
            
            # Verificar que se llamó al método send_apdu
            if mock_connection.send_apdu.called:
                call_args = mock_connection.send_apdu.call_args[0][0]  # Primer argumento
                print(f"✅ Se generó comando APDU: {len(call_args)} bytes")
                
                # Convertir a hex para mostrar
                command_hex = ''.join(f'{b:02X}' for b in call_args)
                formatted_command = ' '.join([command_hex[i:i+2] for i in range(0, len(command_hex), 2)])
                print(f"   Comando: {formatted_command}")
                
                # Verificar estructura del comando
                if len(call_args) >= 5:
                    header = call_args[0:4]  # 90 3D 00 00
                    lc = call_args[4]        # Lc
                    
                    print(f"✅ Header APDU correcto: {' '.join(f'{b:02X}' for b in header)}")
                    print(f"✅ Lc: {lc:02X} ({lc} bytes)")
                    
                    if len(call_args) == lc + 6:  # Header(4) + Lc(1) + datos(lc) + Le(1)
                        print("✅ Longitud del comando APDU correcta")
                    else:
                        print(f"❌ Longitud del comando incorrecta: esperado {lc + 6}, actual {len(call_args)}")
                        
            else:
                print("❌ No se llamó al método send_apdu")
                
        else:
            print("❌ El método _write_encrypted_data retornó False")
            
    except Exception as e:
        print(f"❌ Error al ejecutar _write_encrypted_data: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    return True

if __name__ == "__main__":
    try:
        success = test_write_encrypted_data()
        if success:
            print("\n✅ ¡Todas las pruebas pasaron correctamente!")
        else:
            print("\n❌ Algunas pruebas fallaron")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(1)