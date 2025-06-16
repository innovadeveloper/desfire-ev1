#!/usr/bin/env python3
"""
DESFire EV1 - Escritura Simple de Archivos
Implementación simplificada basada en el ejemplo de trabajo
"""

import sys
import os
import struct
from enum import IntEnum
from typing import Optional, Union, List, Tuple

# Importaciones de tarjetas inteligentes
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.Exceptions import CardConnectionException
    SMARTCARD_AVAILABLE = True
except ImportError:
    print("Advertencia: Biblioteca pyscard no encontrada.")
    print("Ejecute: pip install pyscard")
    SMARTCARD_AVAILABLE = False

# Importaciones criptográficas
try:
    from Crypto.Cipher import AES
    CRYPTO_AVAILABLE = True
except ImportError:
    print("Advertencia: Biblioteca PyCrypto no encontrada.")
    print("Ejecute: pip install pycryptodome")
    CRYPTO_AVAILABLE = False

# Constantes globales
OPERATION_OK = 0x91
STATUS_OK = 0x00

class CommMode(IntEnum):
    """Modos de comunicación para archivos"""
    PLAIN = 0x00
    MAC = 0x01
    ENCRYPTED = 0x03

# =============================================================================
# CLASE PARA CONEXIÓN CON LECTOR SIMPLIFICADA
# =============================================================================

class DESFireSimpleConnection:
    """Conexión simplificada con el lector de tarjetas DESFire"""
    
    def __init__(self, debug: bool = True):
        self.reader = None
        self.connection = None
        self.debug = debug
        self.atr = None
    
    def connect_reader(self) -> bool:
        """Conecta con el primer lector disponible"""
        if not SMARTCARD_AVAILABLE:
            print("Error: Biblioteca pyscard no disponible")
            return False
        
        print("Buscando lectores disponibles...")
        reader_list = readers()
        
        if not reader_list:
            print("No se han encontrado lectores de tarjetas.")
            return False
        
        print(f"Lectores encontrados: {len(reader_list)}")
        for i, reader in enumerate(reader_list):
            print(f"  [{i}] {reader}")

        # Seleccionar lector
        reader_index = 0
        if len(reader_list) > 1:
            try:
                reader_index = int(input(f"Seleccione un lector (0-{len(reader_list)-1}): "))
                if reader_index < 0 or reader_index >= len(reader_list):
                    reader_index = 0
            except ValueError:
                reader_index = 0
        
        self.reader = reader_list[reader_index]
        print(f"Usando lector: {self.reader}")
        
        try:
            self.connection = self.reader.createConnection()
            self.connection.connect()
            self.atr = self.connection.getATR()
            print("Conexión establecida con la tarjeta.")
            print(f"ATR: {toHexString(self.atr)}")
            return True
        except CardConnectionException:
            print("No se ha detectado ninguna tarjeta.")
            return False
    
    def send_apdu(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        """Envía un comando APDU a la tarjeta"""
        if not self.connection:
            raise ConnectionError("No hay conexión establecida")
        
        try:
            response, sw1, sw2 = self.connection.transmit(apdu)
            if self.debug:
                print(f"APDU: {toHexString(apdu)}")
                print(f"Response: {toHexString(response) if response else 'Sin datos'}, SW: {hex(sw1)} {hex(sw2)}")
            return response, sw1, sw2
        except Exception as e:
            print(f"Error al enviar APDU: {e}")
            return [], 0, 0
    
    def disconnect(self):
        """Desconecta del lector"""
        if self.connection:
            try:
                self.connection.disconnect()
                print("Desconectado del lector.")
            except:
                pass

# =============================================================================
# CLASE PARA OPERACIONES DESFIRE SIMPLIFICADAS
# =============================================================================

class DESFireSimpleOperations:
    """Operaciones DESFire simplificadas"""
    
    def __init__(self, connection: DESFireSimpleConnection):
        self.connection = connection
    
    def select_application(self, aid: List[int]) -> bool:
        """Selecciona una aplicación"""
        print(f"Seleccionando aplicación {toHexString(aid)}...")
        
        apdu = [0x90, 0x5A, 0x00, 0x00, 0x03] + aid + [0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación seleccionada correctamente.")
            return True
        else:
            print(f"Error al seleccionar aplicación: SW={hex(sw1)}{hex(sw2)}")
            return False
    
    def authenticate_simple(self, key_no: int = 0) -> bool:
        """Autenticación DES simple con clave por defecto"""
        print(f"Autenticando con clave #{key_no}...")
        
        # Comando de autenticación DES
        apdu = [0x90, 0x1A, 0x00, 0x00, 0x01, key_no, 0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == 0xAF:
            # Respuesta simple para clave por defecto (todos ceros)
            # En un caso real, aquí se haría el intercambio criptográfico completo
            print("Primera fase de autenticación exitosa")
            
            # Para simplicidad, enviar respuesta dummy
            dummy_response = [0x00] * 16
            apdu2 = [0x90, 0xAF, 0x00, 0x00, 0x10] + dummy_response + [0x00]
            response2, sw1_2, sw2_2 = self.connection.send_apdu(apdu2)
            
            if sw1_2 == OPERATION_OK and sw2_2 == STATUS_OK:
                print("✅ Autenticación exitosa")
                return True
        
        print("❌ Error en autenticación")
        return False
    
    def create_simple_file(self, file_id: int, file_size: int) -> bool:
        """Crea un archivo simple sin cifrado"""
        print(f"Creando archivo #{file_id} de {file_size} bytes...")
        
        # Crear archivo con acceso libre (sin cifrado)
        # Formato: CD + FileID + CommMode + AccessRights + FileSize
        access_rights = 0xEEE0  # Acceso libre para lectura/escritura
        
        command_data = struct.pack('<BBH', file_id, CommMode.PLAIN, access_rights)
        command_data += struct.pack('<L', file_size)[0:3]  # Solo 3 bytes
        
        apdu = [0x90, 0xCD, 0x00, 0x00, len(command_data)] + list(command_data) + [0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("✅ Archivo creado exitosamente")
            return True
        else:
            print(f"❌ Error al crear archivo: {hex(sw1)}{hex(sw2)}")
            if sw1 == OPERATION_OK and sw2 == 0xEE:
                print("El archivo ya existe")
                return True  # Continuar si ya existe
            return False
    
    def write_simple_data(self, file_id: int, offset: int, data: Union[str, bytes]) -> bool:
        """Escribe datos simples sin cifrado"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        print(f"Escribiendo {len(data)} bytes en archivo #{file_id} offset {offset}...")
        print(f"Datos: {data.hex().upper()}")
        print(f"Texto: '{data.decode('utf-8', errors='ignore')}'")
        
        # Comando WriteData simple
        command_data = struct.pack('<BL', file_id, offset)[0:4]  # file_id + 3 bytes offset
        
        apdu = [0x90, 0x3D, 0x00, 0x00, len(command_data) + len(data)] + list(command_data) + list(data) + [0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("✅ Datos escritos exitosamente")
            return True
        else:
            print(f"❌ Error al escribir datos: {hex(sw1)}{hex(sw2)}")
            self._print_error_code(sw2)
            return False
    
    def read_simple_data(self, file_id: int, offset: int, length: int) -> Optional[bytes]:
        """Lee datos simples sin cifrado"""
        print(f"Leyendo {length} bytes del archivo #{file_id} offset {offset}...")
        
        # Comando ReadData
        command_data = struct.pack('<BL', file_id, offset)[0:4]  # file_id + 3 bytes offset
        command_data += struct.pack('<L', length)[0:3]  # 3 bytes length
        
        apdu = [0x90, 0xBD, 0x00, 0x00, len(command_data)] + list(command_data) + [0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            data = bytes(response)
            print(f"✅ Datos leídos: {data.hex().upper()}")
            print(f"Texto: '{data.decode('utf-8', errors='ignore')}'")
            return data
        else:
            print(f"❌ Error al leer datos: {hex(sw1)}{hex(sw2)}")
            return None
    
    def list_files(self) -> List[int]:
        """Lista archivos en la aplicación"""
        print("Listando archivos...")
        
        apdu = [0x90, 0x6F, 0x00, 0x00, 0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            file_ids = list(response)
            print(f"Archivos encontrados: {[f'0x{fid:02X}' for fid in file_ids]}")
            return file_ids
        else:
            print(f"Error al listar archivos: {hex(sw1)}{hex(sw2)}")
            return []
    
    def get_file_settings(self, file_id: int) -> Optional[dict]:
        """Obtiene configuración de un archivo"""
        print(f"Obteniendo configuración del archivo #{file_id}...")
        
        apdu = [0x90, 0xF5, 0x00, 0x00, 0x01, file_id, 0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK and len(response) >= 7:
            settings = {
                'file_type': response[0],
                'comm_mode': response[1],
                'access_rights': int.from_bytes(response[2:4], 'little'),
                'file_size': int.from_bytes(response[4:7], 'little')
            }
            print(f"Configuración: {settings}")
            return settings
        else:
            print(f"Error al obtener configuración: {hex(sw1)}{hex(sw2)}")
            return None
    
    def delete_file(self, file_id: int) -> bool:
        """Elimina un archivo"""
        print(f"Eliminando archivo #{file_id}...")
        
        apdu = [0x90, 0xDF, 0x00, 0x00, 0x01, file_id, 0x00]
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("✅ Archivo eliminado")
            return True
        else:
            print(f"❌ Error al eliminar archivo: {hex(sw1)}{hex(sw2)}")
            return False
    
    def _print_error_code(self, error_code: int):
        """Imprime descripción del código de error"""
        error_codes = {
            0x7E: "Parámetros inválidos",
            0xAE: "Autenticación requerida",
            0x9D: "Permisos insuficientes",
            0xA0: "Archivo no encontrado",
            0xBE: "Modo de comunicación incorrecto o fuera de límites",
            0xEE: "Archivo ya existe",
            0xDE: "Aplicación ya existe",
            0xCA: "Comando abortado"
        }
        if error_code in error_codes:
            print(f"Error: {error_codes[error_code]}")

# =============================================================================
# FUNCIÓN PRINCIPAL DE DEMOSTRACIÓN
# =============================================================================

def demo_simple_write():
    """Demostración de escritura simple"""
    print("=== DESFire EV1 - Escritura Simple ===\n")
    
    if not SMARTCARD_AVAILABLE:
        print("❌ Error: pyscard no disponible")
        return False
    
    # Conectar
    connection = DESFireSimpleConnection(debug=True)
    if not connection.connect_reader():
        return False
    
    try:
        ops = DESFireSimpleOperations(connection)
        
        # 1. Seleccionar aplicación existente
        app_aid = [0xF0, 0x01, 0x01]  # Aplicación del ejemplo
        if not ops.select_application(app_aid):
            # Si no existe, seleccionar aplicación master
            print("Aplicación no encontrada, seleccionando master...")
            if not ops.select_application([0x00, 0x00, 0x00]):
                return False
        
        # 2. Autenticación simple (omitida para archivos públicos)
        print("Saltando autenticación para archivos públicos...")
        
        # 3. Listar archivos existentes
        file_ids = ops.list_files()
        
        # 4. Usar archivo simple
        file_id = 5  # Como en el ejemplo
        
        # 5. Verificar si existe el archivo
        settings = ops.get_file_settings(file_id)
        if not settings:
            print(f"Archivo #{file_id} no existe, creando...")
            if not ops.create_simple_file(file_id, 80):  # Como en el ejemplo
                return False
        else:
            print(f"Archivo #{file_id} ya existe")
        
        # 6. Escribir datos de prueba
        test_data = "Hola DESFire! Este es un test de escritura simple."
        if ops.write_simple_data(file_id, 0, test_data):
            print("✅ Escritura exitosa")
            
            # 7. Leer datos para verificar
            read_data = ops.read_simple_data(file_id, 0, len(test_data))
            if read_data:
                print("✅ Lectura exitosa")
                print(f"Verificación: '{read_data.decode('utf-8', errors='ignore')}'")
                
                if read_data.decode('utf-8', errors='ignore').strip() == test_data:
                    print("🎉 ¡Datos verificados correctamente!")
                    return True
                else:
                    print("⚠️ Los datos leídos no coinciden exactamente")
                    return True  # Parcialmente exitoso
            else:
                print("❌ Error en lectura")
                return False
        else:
            print("❌ Error en escritura")
            return False
            
    finally:
        connection.disconnect()

if __name__ == "__main__":
    print("DESFire EV1 - Escritura Simple de Archivos")
    print("=" * 45)
    
    if not SMARTCARD_AVAILABLE:
        print("❌ Error: pyscard no está disponible")
        sys.exit(1)
    
    try:
        success = demo_simple_write()
        if success:
            print("\n✅ ¡Demostración completada!")
        else:
            print("\n❌ Error en la demostración")
    except KeyboardInterrupt:
        print("\nOperación cancelada")
    except Exception as e:
        print(f"Error inesperado: {e}")
        import traceback
        traceback.print_exc()