#!/usr/bin/env python3
"""
DESFire EV1 - Sistema Unificado Completo
Implementación unificada que incluye todas las funcionalidades desarrolladas:
- Format card y creación/selección de aplicaciones
- Cambio de claves (misma clave y claves diferentes)  
- Creación de archivos STD
- Gestión completa de autenticación AES
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
    from Crypto.Cipher import DES, AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    print("Advertencia: Biblioteca PyCrypto no encontrada.")
    print("Ejecute: pip install pycryptodome")
    CRYPTO_AVAILABLE = False

# Constantes globales
OPERATION_OK = 0x91
ADDITIONAL_FRAME = 0xAF
STATUS_OK = 0x00

class CryptoType(IntEnum):
    """Tipos de criptografía soportados por DESFire"""
    DES = 0x00
    TRIPLE_DES_3K = 0x40
    AES = 0x80

class AuthResult(IntEnum):
    """Resultados de autenticación"""
    SUCCESS = 0
    FAILED = 1
    CRYPTO_ERROR = 2
    INVALID_KEY = 3

class CommMode(IntEnum):
    """Modos de comunicación para archivos"""
    PLAIN = 0x00
    MAC = 0x01
    ENCRYPTED = 0x03

# =============================================================================
# CLASE PARA UTILIDADES CRIPTOGRÁFICAS
# =============================================================================

class DESFireCryptoUtils:
    """Utilidades criptográficas para DESFire EV1"""
    
    CRC32_POLYNOMIAL = 0xEDB88320
    BLOCK_SIZE_AES = 16
    BLOCK_SIZE_DES = 8
    
    @staticmethod
    def calculate_crc32(data: Union[List[int], bytes]) -> int:
        """
        Calcula CRC32 según el polinomio DESFire
        
        Args:
            data: Datos para calcular CRC
            
        Returns:
            int: Valor CRC32
        """
        if isinstance(data, list):
            data = bytes(data)
        
        poly = DESFireCryptoUtils.CRC32_POLYNOMIAL
        crc = 0xFFFFFFFF
        
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
        
        return crc & 0xFFFFFFFF
    
    @staticmethod
    def pad_pkcs7(data: Union[List[int], bytes], block_size: int = 16) -> List[int]:
        """
        Aplica padding PKCS7
        
        Args:
            data: Datos a rellenar
            block_size: Tamaño del bloque
            
        Returns:
            List[int]: Datos con padding aplicado
        """
        if isinstance(data, bytes):
            data = list(data)
        
        pad_len = block_size - (len(data) % block_size)
        return data + [pad_len] * pad_len
    
    @staticmethod
    def pad_data_iso(data: bytes) -> bytes:
        """Aplica padding ISO (0x80 + 0x00s)"""
        padded = bytearray(data)
        padded.append(0x80)
        
        while len(padded) % 16 != 0:
            padded.append(0x00)
            
        return bytes(padded)
    
    @staticmethod
    def aes_encrypt(data: Union[List[int], bytes], key: Union[List[int], bytes], 
                   iv: Union[List[int], bytes] = None) -> List[int]:
        """
        Cifra datos usando AES-CBC
        
        Args:
            data: Datos a cifrar
            key: Clave AES (16 bytes)
            iv: Vector de inicialización (16 bytes)
            
        Returns:
            List[int]: Datos cifrados
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome requerido para cifrado AES")
        
        # Convertir a bytes si es necesario
        if isinstance(data, list):
            data = bytes(data)
        if isinstance(key, list):
            key = bytes(key)
        if iv is None:
            iv = bytes(16)  # IV de ceros
        elif isinstance(iv, list):
            iv = bytes(iv)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return list(encrypted)
    
    @staticmethod
    def aes_decrypt(data: Union[List[int], bytes], key: Union[List[int], bytes], 
                   iv: Union[List[int], bytes] = None) -> List[int]:
        """
        Descifra datos usando AES-CBC
        
        Args:
            data: Datos cifrados
            key: Clave AES (16 bytes)
            iv: Vector de inicialización (16 bytes)
            
        Returns:
            List[int]: Datos descifrados
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome requerido para descifrado AES")
        
        # Convertir a bytes si es necesario
        if isinstance(data, list):
            data = bytes(data)
        if isinstance(key, list):
            key = bytes(key)
        if iv is None:
            iv = bytes(16)  # IV de ceros
        elif isinstance(iv, list):
            iv = bytes(iv)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        return list(decrypted)
    
    @staticmethod
    def rotate_left(data: Union[List[int], bytes], positions: int = 1) -> List[int]:
        """
        Rota bytes hacia la izquierda
        
        Args:
            data: Datos a rotar
            positions: Número de posiciones a rotar
            
        Returns:
            List[int]: Datos rotados
        """
        if isinstance(data, bytes):
            data = list(data)
        
        if len(data) == 0:
            return data
        
        positions = positions % len(data)  # Manejar rotaciones mayores al tamaño
        return data[positions:] + data[:positions]
    
    @staticmethod
    def generate_cmac_subkeys(key: bytes) -> Tuple[bytes, bytes]:
        """Genera subclaves CMAC K1 y K2"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome requerido para CMAC")
        
        # Cifrar 16 ceros con la clave
        cipher = AES.new(key, AES.MODE_ECB)
        l = cipher.encrypt(bytes(16))
        
        # Generar K1
        k1 = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            k1[i] = ((l[i] << 1) | carry) & 0xFF
            carry = (l[i] >> 7) & 1
        
        if l[0] & 0x80:  # MSB de L es 1
            k1[15] ^= 0x87
        
        # Generar K2
        k2 = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            k2[i] = ((k1[i] << 1) | carry) & 0xFF
            carry = (k1[i] >> 7) & 1
        
        if k1[0] & 0x80:  # MSB de K1 es 1
            k2[15] ^= 0x87
        
        return bytes(k1), bytes(k2)

# =============================================================================
# CLASE PARA CONEXIÓN CON LECTOR MEJORADA
# =============================================================================

class DESFireReaderConnection:
    """Maneja la conexión con el lector de tarjetas DESFire"""
    
    def __init__(self, debug: bool = True):
        self.reader = None
        self.connection = None
        self.debug = debug
        self.atr = None
    
    def log(self, message: str):
        """Imprime mensaje de depuración si está habilitado"""
        if self.debug:
            print(message)
    
    def connect_reader(self) -> bool:
        """
        Conecta con el primer lector disponible
        
        Returns:
            bool: True si la conexión fue exitosa
        """
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
        """
        Envía un comando APDU a la tarjeta
        
        Args:
            apdu: Comando APDU como lista de enteros
            
        Returns:
            tuple: (response_data, sw1, sw2)
        """
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
    
    def send_command_unified(self, command: bytes) -> bytes:
        """
        Envía comando DESFire y devuelve respuesta en formato unified
        
        Args:
            command: Comando DESFire nativo
            
        Returns:
            bytes: Respuesta DESFire
        """
        # Envolver comando nativo en ISO APDU
        apdu = self.wrap_native_command(command)
        response, sw1, sw2 = self.send_apdu(apdu)
        
        # Procesar respuesta según códigos de estado
        if sw1 == 0x90 and sw2 == 0x00:
            return bytes([0x00]) + bytes(response) if response else bytes([0x00])
        elif sw1 == 0x91:
            return bytes([sw2]) + bytes(response) if response else bytes([sw2])
        elif sw1 == 0x61:
            # Más datos disponibles
            get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
            response2, sw1_2, sw2_2 = self.send_apdu(get_response)
            if sw1_2 == 0x90 and sw2_2 == 0x00:
                all_response = (response if response else []) + (response2 if response2 else [])
                return bytes([0x00]) + bytes(all_response)
            else:
                return bytes([sw1_2])
        else:
            if self.debug:
                print(f"Error en comunicación: SW1={sw1:02X}, SW2={sw2:02X}")
            return bytes([0x6E])
    
    def wrap_native_command(self, command: bytes) -> List[int]:
        """
        Envuelve comando DESFire nativo en ISO 7816-4 APDU
        
        Args:
            command: Comando DESFire nativo
            
        Returns:
            List[int]: APDU ISO completo
        """
        if len(command) == 1:
            return [0x90, command[0], 0x00, 0x00, 0x00]
        else:
            cmd_byte = command[0]
            data = command[1:]
            lc = len(data)
            return [0x90, cmd_byte, 0x00, 0x00, lc] + list(data) + [0x00]
    
    def disconnect(self):
        """Desconecta del lector"""
        if self.connection:
            try:
                self.connection.disconnect()
                print("Desconectado del lector.")
            except:
                pass
        self.connection = None
        self.reader = None

# =============================================================================
# CLASE PARA COMANDO FORMAT PICC
# =============================================================================

class DESFireFormatPICC:
    """Comando FORMAT PICC para DESFire EV1"""
    
    COMMAND_CODE = 0xFC
    
    @staticmethod
    def create_apdu() -> List[int]:
        """
        Crea el APDU para FORMAT PICC
        
        Returns:
            List[int]: APDU completo
        """
        return [0x90, DESFireFormatPICC.COMMAND_CODE, 0x00, 0x00, 0x00]
    
    @staticmethod
    def execute(connection: DESFireReaderConnection, confirm: bool = False) -> bool:
        """
        Ejecuta el formateo de la tarjeta
        
        Args:
            connection: Conexión con el lector
            confirm: Si True, omite la confirmación del usuario
            
        Returns:
            bool: True si el formateo fue exitoso
        """
        if not confirm:
            print("\n=== FORMATEO DE TARJETA ===")
            print("ADVERTENCIA: Este proceso borrará TODOS los datos de la tarjeta.")
            confirmation = input("¿Está seguro de que desea continuar? (s/n): ")
            
            if confirmation.lower() != 's':
                print("Formateo cancelado.")
                return False
        
        print("Formateando tarjeta...")
        apdu = DESFireFormatPICC.create_apdu()
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("¡Tarjeta formateada exitosamente!")
            return True
        else:
            print(f"Error al formatear la tarjeta: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == 0x91 and sw2 == 0xAE:
                print("Error de autenticación. Debe autenticarse antes de formatear.")
            elif sw1 == 0x91 and sw2 == 0xCA:
                print("Comando abortado. Reinicie la tarjeta e intente de nuevo.")
            
            return False

# =============================================================================
# CLASE PARA SELECCIÓN DE APLICACIONES
# =============================================================================

class DESFireSelectApplication:
    """Comando SELECT APPLICATION para DESFire EV1"""
    
    COMMAND_CODE = 0x5A
    MASTER_APPLICATION_AID = [0x00, 0x00, 0x00]
    
    @staticmethod
    def create_apdu(aid: List[int]) -> List[int]:
        """
        Crea el APDU para SELECT APPLICATION
        
        Args:
            aid: Application ID (3 bytes)
            
        Returns:
            List[int]: APDU completo
        """
        if len(aid) != 3:
            raise ValueError("AID debe ser de 3 bytes")
        
        return [0x90, DESFireSelectApplication.COMMAND_CODE, 0x00, 0x00, 0x03] + aid + [0x00]
    
    @staticmethod
    def select_master_application(connection: DESFireReaderConnection) -> bool:
        """
        Selecciona la aplicación maestra (AID = 000000)
        
        Args:
            connection: Conexión con el lector
            
        Returns:
            bool: True si la selección fue exitosa
        """
        return DESFireSelectApplication.select_application(
            connection, DESFireSelectApplication.MASTER_APPLICATION_AID
        )
    
    @staticmethod
    def select_application(connection: DESFireReaderConnection, aid: List[int]) -> bool:
        """
        Selecciona una aplicación específica
        
        Args:
            connection: Conexión con el lector
            aid: Application ID (3 bytes)
            
        Returns:
            bool: True si la selección fue exitosa
        """
        print(f"Seleccionando aplicación {toHexString(aid)}...")
        
        apdu = DESFireSelectApplication.create_apdu(aid)
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación {toHexString(aid)} seleccionada correctamente.")
            return True
        else:
            print(f"Error al seleccionar aplicación: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == 0x91 and sw2 == 0xA0:
                print("Error: Aplicación no encontrada")
            
            return False

# =============================================================================
# CLASE PARA AUTENTICACIÓN AVANZADA
# =============================================================================

class DESFireAuthenticateAdvanced:
    """Comandos de autenticación avanzados para DESFire EV1"""
    
    COMMAND_AES = 0xAA
    COMMAND_ISO = 0x1A  # DES/3DES
    COMMAND_LEGACY = 0x0A  # DES simple
    
    def __init__(self, connection: DESFireReaderConnection):
        self.connection = connection
        self.authenticated_key = None
        self.session_key = None
        self.session_iv = None
        self.crypto_utils = DESFireCryptoUtils()
    
    def authenticate_aes(self, key_no: int, key_data: Union[List[int], bytes] = None) -> bool:
        """
        Autenticación AES completa mejorada
        
        Args:
            key_no: Número de clave (0-13)
            key_data: Clave AES (16 bytes). Si es None, usa clave por defecto
            
        Returns:
            bool: True si la autenticación fue exitosa
        """
        if not CRYPTO_AVAILABLE:
            print("Error: PyCryptodome requerido para autenticación AES")
            return False
        
        print(f"\n=== Autenticación AES con clave #{key_no} ===")
        
        # Clave por defecto si no se especifica
        if key_data is None:
            key_data = bytes(16)
        elif isinstance(key_data, list):
            key_data = bytes(key_data)
        
        if len(key_data) != 16:
            print(f"Error: Clave AES debe ser de 16 bytes (actual: {len(key_data)})")
            return False
        
        try:
            # 1. Abortar operaciones pendientes
            self._abort_transaction()
            
            # 2. Iniciar autenticación
            command = bytes([self.COMMAND_AES, key_no])
            response = self.connection.send_command_unified(command)
            
            if response[0] != 0xAF or len(response) != 17:
                print(f"Error al iniciar autenticación: {response[0]:02X}")
                return False
            
            # 3. Procesar desafío de la tarjeta
            encrypted_rnd_b = response[1:17]
            print(f"RndB cifrado: {encrypted_rnd_b.hex().upper()}")
            
            # 4. Descifrar desafío (RndB)
            iv_zero = bytes(16)
            rnd_b = bytes(self.crypto_utils.aes_decrypt(encrypted_rnd_b, key_data, iv_zero))
            print(f"RndB descifrado: {rnd_b.hex().upper()}")
            
            # 5. Generar desafío propio (RndA)
            rnd_a = os.urandom(16)
            print(f"RndA generado: {rnd_a.hex().upper()}")
            
            # 6. Rotar RndB
            rnd_b_rotated = bytes(self.crypto_utils.rotate_left(rnd_b, 1))
            print(f"RndB rotado: {rnd_b_rotated.hex().upper()}")
            
            # 7. Concatenar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            print(f"RndAB: {rnd_ab.hex().upper()}")
            
            # 8. Cifrar token
            encrypted_rnd_ab = bytes(self.crypto_utils.aes_encrypt(rnd_ab, key_data, encrypted_rnd_b))
            print(f"RndAB cifrado: {encrypted_rnd_ab.hex().upper()}")
            
            # 9. Enviar token
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.connection.send_command_unified(command)
            
            if response[0] != 0x00 or len(response) != 17:
                print(f"Error en respuesta de token: {response[0]:02X}")
                return False
            
            # 10. Verificar respuesta de la tarjeta
            encrypted_rnd_a = response[1:17]
            
            # 11. Descifrar respuesta
            iv_for_decrypt = encrypted_rnd_ab[-16:]
            decrypted_rnd_a = bytes(self.crypto_utils.aes_decrypt(encrypted_rnd_a, key_data, iv_for_decrypt))
            
            # 12. Verificar RndA rotado
            expected_rnd_a = bytes(self.crypto_utils.rotate_left(rnd_a, 1))
            
            if decrypted_rnd_a == expected_rnd_a:
                print("¡Autenticación AES exitosa!")
                
                # 13. Generar clave de sesión
                self.session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[-4:] + rnd_b[-4:]
                self.authenticated_key = key_no
                self.session_iv = bytes(16)  # IV inicial
                
                print(f"Clave de sesión: {self.session_key.hex()}")
                return True
            else:
                print("Error: Respuesta de la tarjeta no coincide")
                return False
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en autenticación AES: {e}")
            return False
    
    def authenticate_des(self, key_no: int = 0, key_data: Union[List[int], bytes] = None) -> bool:
        """
        Autenticación DES/3DES completa
        
        Args:
            key_no: Número de clave (0-13)
            key_data: Clave DES (8 bytes). Si es None, usa clave por defecto
            
        Returns:
            bool: True si la autenticación fue exitosa
        """
        if not CRYPTO_AVAILABLE:
            print("Error: PyCryptodome requerido para autenticación DES")
            return False
        
        print(f"\n=== Autenticación DES con clave #{key_no} ===")
        
        # Clave por defecto si no se especifica
        if key_data is None:
            key_data = bytes(8)
        elif isinstance(key_data, list):
            key_data = bytes(key_data)
        
        if len(key_data) != 8:
            print(f"Error: Clave DES debe ser de 8 bytes (actual: {len(key_data)})")
            return False
        
        try:
            # 1. Abortar operaciones pendientes
            self._abort_transaction()
            
            # 2. Iniciar autenticación
            command = bytes([self.COMMAND_ISO, key_no])
            response = self.connection.send_command_unified(command)
            
            if response[0] != 0xAF or len(response) != 9:
                print(f"Error al iniciar autenticación: {response[0]:02X}")
                return False
            
            # 3. Procesar desafío de la tarjeta
            encrypted_rnd_b = response[1:9]
            print(f"RndB cifrado: {encrypted_rnd_b.hex().upper()}")
            
            # 4. Descifrar desafío (RndB)
            from Crypto.Cipher import DES
            iv_zero = bytes(8)
            cipher = DES.new(key_data, DES.MODE_CBC, iv_zero)
            rnd_b = cipher.decrypt(encrypted_rnd_b)
            print(f"RndB descifrado: {rnd_b.hex().upper()}")
            
            # 5. Generar desafío propio (RndA)
            rnd_a = os.urandom(8)
            print(f"RndA generado: {rnd_a.hex().upper()}")
            
            # 6. Rotar RndB
            rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
            print(f"RndB rotado: {rnd_b_rotated.hex().upper()}")
            
            # 7. Concatenar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            print(f"RndAB: {rnd_ab.hex().upper()}")
            
            # 8. Cifrar token
            cipher = DES.new(key_data, DES.MODE_CBC, encrypted_rnd_b)
            encrypted_rnd_ab = cipher.encrypt(rnd_ab)
            print(f"RndAB cifrado: {encrypted_rnd_ab.hex().upper()}")
            
            # 9. Enviar token
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.connection.send_command_unified(command)
            
            if response[0] != 0x00 or len(response) != 9:
                print(f"Error en respuesta de token: {response[0]:02X}")
                return False
            
            # 10. Verificar respuesta de la tarjeta
            encrypted_rnd_a = response[1:9]
            
            # 11. Descifrar respuesta
            iv_for_decrypt = encrypted_rnd_ab[-8:]
            cipher = DES.new(key_data, DES.MODE_CBC, iv_for_decrypt)
            decrypted_rnd_a = cipher.decrypt(encrypted_rnd_a)
            
            # 12. Verificar RndA rotado
            expected_rnd_a = rnd_a[1:] + rnd_a[:1]
            
            if decrypted_rnd_a == expected_rnd_a:
                print("¡Autenticación DES exitosa!")
                
                # 13. Generar clave de sesión (para DES es más simple)
                self.session_key = rnd_a[:4] + rnd_b[:4]
                self.authenticated_key = key_no
                self.session_iv = bytes(8)  # IV inicial para DES
                
                print(f"Clave de sesión: {self.session_key.hex()}")
                return True
            else:
                print("Error: Respuesta de la tarjeta no coincide")
                return False
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en autenticación DES: {e}")
            return False
    
    def change_key_same(self, key_number: int, new_key: bytes, new_key_version: int = 0x00) -> bool:
        """
        Cambia la misma clave usada para autenticación
        
        Args:
            key_number: Número de la clave a cambiar
            new_key: Nueva clave (16 bytes para AES)
            new_key_version: Versión de la nueva clave
            
        Returns:
            bool: True si el cambio fue exitoso
        """
        if not self.is_authenticated():
            print("Error: No autenticado")
            return False
        
        print(f"\n=== Cambiando clave #{key_number} (misma clave) ===")
        print(f"Nueva clave: {new_key.hex().upper()}")
        
        try:
            # Calcular CRC del criptograma
            crypto_data = bytes([0xC4, key_number]) + new_key + bytes([new_key_version])
            crc_crypto = self.crypto_utils.calculate_crc32(crypto_data)
            print(f"CRC Crypto: 0x{crc_crypto:08X}")
            
            # Construir criptograma
            cryptogram = new_key + bytes([new_key_version]) + struct.pack('<L', crc_crypto)
            
            # Padding a múltiplo de 16 bytes
            while len(cryptogram) % 16 != 0:
                cryptogram += b'\x00'
            
            print(f"Criptograma: {cryptogram.hex().upper()}")
            
            # Cifrar criptograma
            encrypted_cryptogram = bytes(self.crypto_utils.aes_encrypt(cryptogram, self.session_key, self.session_iv))
            print(f"Criptograma cifrado: {encrypted_cryptogram.hex().upper()}")
            
            # Actualizar IV de sesión
            self.session_iv = encrypted_cryptogram[-16:]
            
            # Enviar comando ChangeKey
            command = bytes([0xC4, key_number]) + encrypted_cryptogram
            response = self.connection.send_command_unified(command)
            
            if response[0] == 0x00:
                print("¡Clave cambiada exitosamente!")
                if len(response) > 1:
                    received_cmac = response[1:9]
                    expected_cmac = self._calculate_cmac(self.session_key, bytes([0x00]))
                    print(f"CMAC recibido: {received_cmac.hex().upper()}")
                    print(f"CMAC esperado: {expected_cmac.hex().upper()}")
                return True
            else:
                print(f"Error al cambiar clave: {response[0]:02X}")
                return False
                
        except Exception as e:
            print(f"Error en cambio de clave: {e}")
            return False
    
    def change_key_different(self, key_number: int, new_key: bytes, current_key: bytes, 
                           new_key_version: int = 0x00) -> bool:
        """
        Cambia una clave diferente a la usada para autenticación
        
        Args:
            key_number: Número de la clave a cambiar
            new_key: Nueva clave (16 bytes para AES)
            current_key: Clave actual a cambiar
            new_key_version: Versión de la nueva clave
            
        Returns:
            bool: True si el cambio fue exitoso
        """
        if not self.is_authenticated():
            print("Error: No autenticado")
            return False
        
        print(f"\n=== Cambiando clave #{key_number} (clave diferente) ===")
        print(f"Nueva clave: {new_key.hex().upper()}")
        print(f"Clave actual: {current_key.hex().upper()}")
        
        try:
            # XOR nueva clave con clave actual
            xored_key = bytes(a ^ b for a, b in zip(new_key, current_key))
            print(f"Nueva XOR Actual: {xored_key.hex().upper()}")
            
            # Calcular CRC de la nueva clave
            crc_new_key = self.crypto_utils.calculate_crc32(new_key)
            print(f"CRC Nueva Clave: 0x{crc_new_key:08X}")
            
            # Calcular CRC del criptograma
            crypto_data = bytes([0xC4, key_number]) + xored_key + bytes([new_key_version])
            crc_crypto = self.crypto_utils.calculate_crc32(crypto_data)
            print(f"CRC Criptograma: 0x{crc_crypto:08X}")
            
            # Construir criptograma
            cryptogram = xored_key + bytes([new_key_version])
            cryptogram += struct.pack('<L', crc_crypto)
            cryptogram += struct.pack('<L', crc_new_key)
            
            # Padding a múltiplo de 16 bytes
            while len(cryptogram) % 16 != 0:
                cryptogram += b'\x00'
            
            print(f"Criptograma: {cryptogram.hex().upper()}")
            
            # Cifrar criptograma
            encrypted_cryptogram = bytes(self.crypto_utils.aes_encrypt(cryptogram, self.session_key, self.session_iv))
            print(f"Criptograma cifrado: {encrypted_cryptogram.hex().upper()}")
            
            # Actualizar IV de sesión
            self.session_iv = encrypted_cryptogram[-16:]
            
            # Enviar comando ChangeKey
            command = bytes([0xC4, key_number]) + encrypted_cryptogram
            response = self.connection.send_command_unified(command)
            
            if response[0] == 0x00:
                print("¡Clave cambiada exitosamente!")
                if len(response) > 1:
                    received_cmac = response[1:9]
                    expected_cmac = self._calculate_cmac(self.session_key, bytes([0x00]))
                    print(f"CMAC recibido: {received_cmac.hex().upper()}")
                    print(f"CMAC esperado: {expected_cmac.hex().upper()}")
                return True
            else:
                print(f"Error al cambiar clave: {response[0]:02X}")
                return False
                
        except Exception as e:
            print(f"Error en cambio de clave: {e}")
            return False
    
    def _calculate_cmac(self, key: bytes, data: bytes) -> bytes:
        """Calcula CMAC para los datos dados"""
        if not data:
            data = bytes()
        
        k1, k2 = self.crypto_utils.generate_cmac_subkeys(key)
        
        # Aplicar padding si es necesario
        if len(data) == 0 or len(data) % 16 != 0:
            padded_data = self.crypto_utils.pad_data_iso(data)
            last_block_key = k2
        else:
            padded_data = data
            last_block_key = k1
        
        # XOR último bloque con subclave apropiada
        last_block = bytearray(padded_data[-16:])
        for i in range(16):
            last_block[i] ^= last_block_key[i]
        
        # Reemplazar último bloque
        cmac_data = padded_data[:-16] + bytes(last_block)
        
        # Cifrar con CBC usando IV cero
        iv = bytes(16)
        encrypted = bytes(self.crypto_utils.aes_encrypt(cmac_data, key, iv))
        
        # Actualizar IV de sesión y retornar primeros 8 bytes como CMAC
        self.session_iv = encrypted[-16:]
        return encrypted[-16:][:8]
    
    def _abort_transaction(self):
        """Aborta transacciones pendientes"""
        abort_command = bytes([0xA7])
        self.connection.send_command_unified(abort_command)
    
    def is_authenticated(self) -> bool:
        """Verifica si hay una autenticación activa"""
        return self.authenticated_key is not None and self.session_key is not None

# =============================================================================
# CLASE PARA CREACIÓN DE APLICACIONES
# =============================================================================

class DESFireCreateApplication:
    """Comando CREATE APPLICATION para DESFire EV1"""
    
    COMMAND_CODE = 0xCA
    
    # Configuraciones predefinidas
    SETTINGS_SECURE = 0x09      # Solo clave maestra puede cambiar configuración
    SETTINGS_OPEN = 0x0F        # Configuración más abierta
    SETTINGS_RESTRICTED = 0x01  # Solo clave maestra, sin acceso libre
    
    @staticmethod
    def create_apdu(aid: List[int], settings: int = 0x0F, num_keys: int = 0x81) -> List[int]:
        """
        Crea el APDU para CREATE APPLICATION
        
        Args:
            aid: Application ID (3 bytes)
            settings: Configuración de la aplicación (1 byte)
            num_keys: Número y tipo de claves (1 byte)
            
        Returns:
            List[int]: APDU completo
        """
        if len(aid) != 3:
            raise ValueError("AID debe ser de 3 bytes")
        
        data = aid + [settings, num_keys]
        return [0x90, DESFireCreateApplication.COMMAND_CODE, 0x00, 0x00, len(data)] + data + [0x00]
    
    @staticmethod
    def create_aes_application(connection: DESFireReaderConnection, aid: List[int], 
                              num_keys: int = 1, settings: int = 0x0F) -> bool:
        """
        Crea una aplicación con claves AES
        
        Args:
            connection: Conexión con el lector
            aid: Application ID (3 bytes)
            num_keys: Número de claves (1-14)
            settings: Configuración de la aplicación
            
        Returns:
            bool: True si la creación fue exitosa
        """
        if not (1 <= num_keys <= 14):
            print(f"Error: Número de claves inválido: {num_keys}")
            return False
        
        # Para AES: 0x80 | num_keys
        key_config = 0x80 | num_keys
        
        return DESFireCreateApplication.create_application(
            connection, aid, settings, key_config, "AES"
        )
    
    @staticmethod
    def create_application(connection: DESFireReaderConnection, aid: List[int], 
                          settings: int, key_config: int, crypto_type: str) -> bool:
        """
        Crea una aplicación genérica
        
        Args:
            connection: Conexión con el lector
            aid: Application ID (3 bytes)
            settings: Configuración de la aplicación
            key_config: Configuración de claves
            crypto_type: Tipo de criptografía (informativo)
            
        Returns:
            bool: True si la creación fue exitosa
        """
        print(f"\n=== Creando aplicación {toHexString(aid)} ===")
        print(f"Tipo de claves: {crypto_type}")
        print(f"Número de claves: {key_config & 0x0F}")
        
        apdu = DESFireCreateApplication.create_apdu(aid, settings, key_config)
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("¡Aplicación creada exitosamente!")
            return True
        else:
            print(f"Error al crear aplicación: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == OPERATION_OK:
                if sw2 == 0xDE:
                    print("Error: La aplicación ya existe")
                elif sw2 == 0xAE:
                    print("Error: Autenticación requerida")
                elif sw2 == 0x9D:
                    print("Error: Permiso denegado")
                elif sw2 == 0xCE:
                    print("Error: Límite de aplicaciones alcanzado (máximo 28)")
            
            return False

# =============================================================================
# CLASE PARA GESTIÓN DE ARCHIVOS STD
# =============================================================================

class DESFireFileOperations:
    """Operaciones de archivos para DESFire EV1"""
    
    @staticmethod
    def create_std_data_file(connection: DESFireReaderConnection, auth: DESFireAuthenticateAdvanced,
                           file_id: int, file_size: int, comm_mode: CommMode = CommMode.PLAIN,
                           read_key: int = 0xE, write_key: int = 0xE, 
                           read_write_key: int = 0xE, change_key: int = 0x0) -> bool:
        """
        Crea un archivo de datos estándar
        
        Args:
            connection: Conexión con el lector
            auth: Instancia de autenticación
            file_id: ID del archivo (0-31)
            file_size: Tamaño del archivo en bytes
            comm_mode: Modo de comunicación
            read_key: Clave para lectura (0-13, 0xE=libre, 0xF=denegado)
            write_key: Clave para escritura
            read_write_key: Clave para lectura/escritura
            change_key: Clave para cambiar configuración
            
        Returns:
            bool: True si la creación fue exitosa
        """
        if not auth.is_authenticated():
            print("Error: Debe estar autenticado para crear archivos")
            return False
        
        print(f"\n=== Creando archivo STD #{file_id} ({file_size} bytes) ===")
        
        try:
            # Construir derechos de acceso (formato correcto DESFire)
            # Bits 15-12: ChangeAccessRights key
            # Bits 11-8:  ReadWrite key  
            # Bits 7-4:   Write key
            # Bits 3-0:   Read key
            access_rights = (change_key << 12) | (read_write_key << 8) | (write_key << 4) | read_key
            
            # Construir comando CreateStdDataFile
            command_data = struct.pack('<BBH', file_id, comm_mode.value, access_rights)
            command_data += struct.pack('<L', file_size)[0:3]  # Solo 3 bytes para file size
            
            command = bytes([0xCD]) + command_data
            print(f"Comando CreateStdDataFile: {command.hex().upper()}")
            print(f"  File ID: {file_id}")
            print(f"  Comm Mode: {comm_mode.value}")
            print(f"  Access Rights: 0x{access_rights:04X}")
            print(f"  File Size: {file_size}")
            
            response = connection.send_command_unified(command)
            
            if response[0] == 0x00:
                print("¡Archivo creado exitosamente!")
                return True
            else:
                print(f"Error al crear archivo: {response[0]:02X}")
                if response[0] == 0x7E:
                    print("Error: Parámetros inválidos o archivo ya existe")
                elif response[0] == 0xAE:
                    print("Error: Autenticación requerida")
                elif response[0] == 0x9D:
                    print("Error: Permisos insuficientes")
                elif response[0] == 0xEE:
                    print("Error: Archivo ya existe")
                return False
                
        except Exception as e:
            print(f"Error en creación de archivo: {e}")
            return False
    
    @staticmethod
    def create_public_file(connection: DESFireReaderConnection, auth: DESFireAuthenticateAdvanced,
                          file_id: int, file_size: int) -> bool:
        """
        Crea un archivo público (acceso libre)
        
        Args:
            connection: Conexión con el lector
            auth: Instancia de autenticación
            file_id: ID del archivo
            file_size: Tamaño del archivo
            
        Returns:
            bool: True si la creación fue exitosa
        """
        return DESFireFileOperations.create_std_data_file(
            connection, auth, file_id, file_size, CommMode.PLAIN,
            read_key=0xE, write_key=0xE, read_write_key=0xE, change_key=0x0
        )
    
    @staticmethod
    def list_files(connection: DESFireReaderConnection) -> List[int]:
        """
        Lista los IDs de archivos en la aplicación actual
        
        Args:
            connection: Conexión con el lector
            
        Returns:
            List[int]: Lista de IDs de archivos
        """
        print("\n=== Listando archivos ===")
        
        try:
            command = bytes([0x6F])  # GetFileIDs
            response = connection.send_command_unified(command)
            
            if response[0] == 0x00:
                file_ids = list(response[1:])
                print(f"Archivos encontrados: {[f'0x{fid:02X}' for fid in file_ids]}")
                return file_ids
            else:
                print(f"Error al listar archivos: {response[0]:02X}")
                return []
                
        except Exception as e:
            print(f"Error en listado de archivos: {e}")
            return []
    
    @staticmethod
    def delete_file(connection: DESFireReaderConnection, auth: DESFireAuthenticateAdvanced,
                   file_id: int) -> bool:
        """
        Elimina un archivo
        
        Args:
            connection: Conexión con el lector
            auth: Instancia de autenticación
            file_id: ID del archivo a eliminar
            
        Returns:
            bool: True si la eliminación fue exitosa
        """
        if not auth.is_authenticated():
            print("Error: Debe estar autenticado para eliminar archivos")
            return False
        
        print(f"\n=== Eliminando archivo #{file_id} ===")
        
        try:
            command = bytes([0xDF, file_id])  # DeleteFile
            response = connection.send_command_unified(command)
            
            if response[0] == 0x00:
                print("¡Archivo eliminado exitosamente!")
                return True
            else:
                print(f"Error al eliminar archivo: {response[0]:02X}")
                return False
                
        except Exception as e:
            print(f"Error en eliminación de archivo: {e}")
            return False

# =============================================================================
# CLASE PRINCIPAL UNIFICADA
# =============================================================================

class DESFireManagerUnified:
    """Clase principal unificada para gestión completa de DESFire EV1"""
    
    def __init__(self, debug: bool = True):
        self.connection = DESFireReaderConnection(debug)
        self.auth = None
        self.debug = debug
    
    def connect(self) -> bool:
        """Establece conexión con el lector"""
        if self.connection.connect_reader():
            self.auth = DESFireAuthenticateAdvanced(self.connection)
            return True
        return False
    
    def disconnect(self):
        """Cierra la conexión"""
        self.connection.disconnect()
    
    def format_card(self, confirm: bool = False) -> bool:
        """
        Formatea la tarjeta (requiere autenticación previa)
        
        Args:
            confirm: Si True, omite confirmación del usuario
            
        Returns:
            bool: True si el formateo fue exitoso
        """
        return DESFireFormatPICC.execute(self.connection, confirm)
    
    def authenticate_master_key_aes(self, key_data: bytes = None) -> bool:
        """
        Autentica con la clave maestra usando AES
        
        Args:
            key_data: Clave AES (16 bytes). Si es None, usa clave por defecto
            
        Returns:
            bool: True si la autenticación fue exitosa
        """
        # Seleccionar aplicación maestra primero
        if not DESFireSelectApplication.select_master_application(self.connection):
            return False
        
        return self.auth.authenticate_aes(0, key_data)
    
    def authenticate_master_key_des(self, key_data: bytes = None) -> bool:
        """
        Autentica con la clave maestra usando DES
        
        Args:
            key_data: Clave DES (8 bytes). Si es None, usa clave por defecto
            
        Returns:
            bool: True si la autenticación fue exitosa
        """
        # Seleccionar aplicación maestra primero
        if not DESFireSelectApplication.select_master_application(self.connection):
            return False
        
        return self.auth.authenticate_des(0, key_data)
    
    def authenticate_master_key_auto(self, aes_key: bytes = None, des_key: bytes = None) -> bool:
        """
        Intenta autenticación automática: primero DES, luego AES
        
        Args:
            aes_key: Clave AES (16 bytes). Si es None, usa clave por defecto
            des_key: Clave DES (8 bytes). Si es None, usa clave por defecto
            
        Returns:
            bool: True si la autenticación fue exitosa
        """
        print("Intentando autenticación automática...")
        
        # Seleccionar aplicación maestra primero
        if not DESFireSelectApplication.select_master_application(self.connection):
            return False
        
        # Intentar DES primero (más común en tarjetas nuevas)
        print("Probando autenticación DES...")
        try:
            if self.auth.authenticate_des(0, des_key):
                print("✅ Autenticación DES exitosa")
                return True
        except Exception as e:
            print(f"DES falló: {e}")
        
        # Si DES falla, intentar AES
        print("Probando autenticación AES...")
        try:
            if self.auth.authenticate_aes(0, aes_key):
                print("✅ Autenticación AES exitosa")
                return True
        except Exception as e:
            print(f"AES falló: {e}")
        
        print("❌ Ambas autenticaciones fallaron")
        return False
    
    def setup_new_card(self, format_first: bool = True) -> bool:
        """
        Configura una tarjeta nueva desde cero
        
        Args:
            format_first: Si True, formatea la tarjeta primero
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        print("=== Configuración de Tarjeta Nueva ===")
        
        # 1. Autenticarse con clave maestra por defecto (automático)
        print("Paso 1: Autenticación con clave maestra...")
        if not self.authenticate_master_key_auto():
            print("Error: No se pudo autenticar con clave maestra")
            return False
        
        # 2. Formatear si se solicita
        if format_first:
            print("Paso 2: Formateando tarjeta...")
            if not self.format_card(confirm=True):
                print("Error: No se pudo formatear la tarjeta")
                return False
            
            # Re-autenticarse después del formateo
            if not self.authenticate_master_key_auto():
                print("Error: No se pudo re-autenticar después del formateo")
                return False
        
        print("✅ Tarjeta configurada y lista para crear aplicaciones")
        return True
    
    def create_wallet_application(self, aid: List[int] = None) -> bool:
        """
        Crea una aplicación de monedero completa
        
        Args:
            aid: Application ID personalizado
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        if aid is None:
            aid = [0xF0, 0x01, 0x01]
        
        print("=== Creando Aplicación de Monedero ===")
        
        # Crear aplicación AES con 3 claves
        if not DESFireCreateApplication.create_aes_application(
            self.connection, aid, num_keys=3, settings=0x09
        ):
            return False
        
        # Seleccionar la aplicación creada
        return DESFireSelectApplication.select_application(self.connection, aid)
    
    def demo_complete_workflow(self) -> bool:
        """
        Demostración del flujo completo de trabajo
        
        Returns:
            bool: True si todo fue exitoso
        """
        print("=== DEMO: Flujo de Trabajo Completo ===")
        
        try:
            # 1. Configurar tarjeta nueva
            if not self.setup_new_card():
                return False
            
            # 2. Crear aplicación de monedero
            wallet_aid = [0xF0, 0x01, 0x01]
            if not self.create_wallet_application(wallet_aid):
                return False
            
            # 3. Autenticarse en la aplicación
            print("\n--- Autenticándose en aplicación de monedero ---")
            if not self.auth.authenticate_aes(0):  # Clave por defecto
                return False
            
            # 4. Cambiar clave maestra de la aplicación
            print("\n--- Cambiando clave maestra de la aplicación ---")
            new_master_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                                   0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])
            
            if not self.auth.change_key_same(0, new_master_key, 0x10):
                return False
            
            # 5. Re-autenticarse con nueva clave
            print("\n--- Re-autenticándose con nueva clave ---")
            if not self.auth.authenticate_aes(0, new_master_key):
                return False
            
            # 6. Cambiar otra clave (clave 1)
            print("\n--- Cambiando clave 1 ---")
            new_key1 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                             0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
            current_key1 = bytes(16)  # Clave por defecto
            
            if not self.auth.change_key_different(1, new_key1, current_key1, 0x20):
                return False
            
            # 7. Crear archivos de datos
            print("\n--- Creando archivos de datos ---")
            
            # Primero listar archivos existentes
            existing_files = DESFireFileOperations.list_files(self.connection)
            
            # Eliminar archivos existentes si los hay
            for file_id in [1, 2]:
                if file_id in existing_files:
                    print(f"Eliminando archivo existente #{file_id}...")
                    DESFireFileOperations.delete_file(self.connection, self.auth, file_id)
            
            # Archivo público para información general
            if not DESFireFileOperations.create_public_file(
                self.connection, self.auth, file_id=1, file_size=1024
            ):
                return False
            
            # Archivo protegido para saldo
            if not DESFireFileOperations.create_std_data_file(
                self.connection, self.auth, file_id=2, file_size=32,
                comm_mode=CommMode.ENCRYPTED, read_key=0, write_key=0
            ):
                return False
            
            # 8. Listar archivos creados
            print("\n--- Listando archivos creados ---")
            files = DESFireFileOperations.list_files(self.connection)
            
            print("\n🎉 ¡Flujo completo ejecutado exitosamente!")
            print(f"✅ Aplicación de monedero: {toHexString(wallet_aid)}")
            print(f"✅ Claves cambiadas: 0 y 1")
            print(f"✅ Archivos creados: {len(files)}")
            
            return True
            
        except Exception as e:
            print(f"Error en flujo completo: {e}")
            import traceback
            traceback.print_exc()
            return False

# =============================================================================
# EJEMPLOS DE USO
# =============================================================================

def ejemplo_uso_completo():
    """Ejemplo de uso completo del sistema unificado"""
    print("=== DESFire EV1 - Sistema Unificado Completo ===\n")
    
    # Verificar dependencias
    if not SMARTCARD_AVAILABLE or not CRYPTO_AVAILABLE:
        print("❌ Error: Dependencias faltantes")
        return False
    
    # Crear manager y conectar
    manager = DESFireManagerUnified(debug=True)
    
    if not manager.connect():
        print("Error: No se pudo conectar al lector")
        return False
    
    try:
        # Ejecutar demostración completa
        success = manager.demo_complete_workflow()
        
        if success:
            print("\n✅ ¡Demostración completada exitosamente!")
        else:
            print("\n❌ Error en la demostración")
        
        return success
        
    finally:
        manager.disconnect()

def ejemplo_cambio_claves():
    """Ejemplo específico de cambio de claves"""
    print("=== Ejemplo: Cambio de Claves ===\n")
    
    manager = DESFireManagerUnified(debug=True)
    
    if not manager.connect():
        return False
    
    try:
        # Seleccionar aplicación existente
        aid = [0xF0, 0x01, 0x01]
        if not DESFireSelectApplication.select_application(manager.connection, aid):
            print("Error: Aplicación no encontrada")
            return False
        
        # Autenticarse con clave conocida
        current_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                            0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])
        
        if not manager.auth.authenticate_aes(0, current_key):
            print("Error: No se pudo autenticar")
            return False
        
        # Cambiar clave diferente
        new_key = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00])
        # old_key = bytes(16)  # Clave por defecto
        old_key = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
        
        success = manager.auth.change_key_different(1, new_key, old_key, 0x30)
        
        if success:
            print("✅ Cambio de clave exitoso")
        else:
            print("❌ Error en cambio de clave")
        
        return success
        
    finally:
        manager.disconnect()

if __name__ == "__main__":
    print("DESFire EV1 - Sistema Unificado Completo")
    print("=" * 50)
    
    # Verificar dependencias
    if not SMARTCARD_AVAILABLE:
        print("❌ Error: pyscard no está disponible")
        print("Instale con: pip install pyscard")
        sys.exit(1)
    
    if not CRYPTO_AVAILABLE:
        print("❌ Error: PyCryptodome no está disponible")  
        print("Instale con: pip install pycryptodome")
        sys.exit(1)
    
    print("✅ Todas las dependencias están disponibles\n")
    
    # Menú de opciones
    print("Seleccione una opción:")
    print("1. Demostración completa")
    print("2. Ejemplo de cambio de claves")
    print("3. Solo configurar tarjeta nueva")
    
    try:
        choice = input("Opción (1-3): ").strip()
        
        if choice == "1":
            ejemplo_uso_completo()
        elif choice == "2":
            ejemplo_cambio_claves()
        elif choice == "3":
            manager = DESFireManagerUnified(debug=True)
            if manager.connect():
                manager.setup_new_card(format_first=True)
                manager.disconnect()
        else:
            print("Opción inválida")
            
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario")
    except Exception as e:
        print(f"Error inesperado: {e}")
        import traceback
        traceback.print_exc()