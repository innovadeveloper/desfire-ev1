#!/usr/bin/env python3
"""
DESFire EV1 - Clases esenciales para formateo con autenticación DES/AES
Implementación simplificada enfocada únicamente en formateo de tarjetas
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
    def pad_pkcs7(data: Union[List[int], bytes, bytearray], block_size: int = 16) -> List[int]:
        """
        Aplica padding PKCS7
        
        Args:
            data: Datos a rellenar
            block_size: Tamaño del bloque
            
        Returns:
            List[int]: Datos con padding aplicado
        """
        if isinstance(data, (bytes, bytearray)):
            data = list(data)
        
        pad_len = block_size - (len(data) % block_size)
        return data + [pad_len] * pad_len
    
    @staticmethod
    def pad_to_block_size(data: Union[List[int], bytes, bytearray], block_size: int) -> bytes:
        """
        Aplica padding con ceros hasta múltiplo del tamaño de bloque (método DESFire)
        
        Args:
            data: Datos a rellenar
            block_size: Tamaño del bloque
            
        Returns:
            bytes: Datos con padding aplicado
        """
        if isinstance(data, list):
            data = bytes(data)
        elif isinstance(data, bytearray):
            data = bytes(data)
        
        pad_len = block_size - (len(data) % block_size)
        if pad_len == block_size:
            pad_len = 0
        
        return data + (b'\x00' * pad_len)
    
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
    def des_encrypt(data: Union[List[int], bytes], key: Union[List[int], bytes], 
                   iv: Union[List[int], bytes] = None) -> List[int]:
        """
        Cifra datos usando DES-CBC
        
        Args:
            data: Datos a cifrar
            key: Clave DES (8 bytes)
            iv: Vector de inicialización (8 bytes)
            
        Returns:
            List[int]: Datos cifrados
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome requerido para cifrado DES")
        
        # Convertir a bytes si es necesario
        if isinstance(data, list):
            data = bytes(data)
        if isinstance(key, list):
            key = bytes(key)
        if iv is None:
            iv = bytes(8)  # IV de ceros
        elif isinstance(iv, list):
            iv = bytes(iv)
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return list(encrypted)
    
    @staticmethod
    def des_decrypt(data: Union[List[int], bytes], key: Union[List[int], bytes], 
                   iv: Union[List[int], bytes] = None) -> List[int]:
        """
        Descifra datos usando DES-CBC
        
        Args:
            data: Datos cifrados
            key: Clave DES (8 bytes)
            iv: Vector de inicialización (8 bytes)
            
        Returns:
            List[int]: Datos descifrados
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome requerido para descifrado DES")
        
        # Convertir a bytes si es necesario
        if isinstance(data, list):
            data = bytes(data)
        if isinstance(key, list):
            key = bytes(key)
        if iv is None:
            iv = bytes(8)  # IV de ceros
        elif isinstance(iv, list):
            iv = bytes(iv)
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
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

# =============================================================================
# CLASE PARA CONEXIÓN CON LECTOR
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
        
        # Seleccionar lector (antes 0)
        reader_index = 2
        # if len(reader_list) > 1:
        #     try:
        #         reader_index = int(input(f"Seleccione un lector (0-{len(reader_list)-1}): "))
        #         if reader_index < 0 or reader_index >= len(reader_list):
        #             reader_index = 0
        #     except ValueError:
        #         reader_index = 0
        
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
                print(f"APDU ====> : {toHexString(apdu)}")
                print(f"Response <=====: {toHexString(response) if response else 'Sin datos'}, SW: {hex(sw1)} {hex(sw2)}")
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
        self.connection = None
        self.reader = None

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
# CLASE PARA AUTENTICACIÓN
# =============================================================================

class DESFireAuthenticate:
    """Comandos de autenticación para DESFire EV1"""
    
    COMMAND_AES = 0xAA
    COMMAND_ISO = 0x1A  # DES/3DES
    COMMAND_LEGACY = 0x0A  # DES simple
    
    def __init__(self, connection: DESFireReaderConnection):
        self.connection = connection
        self.authenticated_key = None
        self.session_key = None
        self.current_iv = None
        self.crypto_utils = DESFireCryptoUtils()
    
    def authenticate_aes(self, key_no: int, key_data: Union[List[int], bytes] = None) -> bool:
        """
        Autenticación AES completa
        
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
        # if key_data is None:
        #     key_data = [0x00] * 16

        if key_data is None:
            key_data = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        if isinstance(key_data, list):
            key_data = bytes(key_data)
        
        if len(key_data) != 16:
            print(f"Error: Clave AES debe ser de 16 bytes (actual: {len(key_data)})")
            return False
        
        try:
            # 1. Abortar operaciones pendientes
            self._abort_transaction()
            
            # 2. Iniciar autenticación
            auth_apdu = [0x90, self.COMMAND_AES, 0x00, 0x00, 0x01, key_no, 0x00]
            response, sw1, sw2 = self.connection.send_apdu(auth_apdu)
            
            if not self._check_additional_frame(sw1, sw2):
                print(f"Error al iniciar autenticación: {hex(sw1)} {hex(sw2)}")
                return False
            
            # 3. Procesar desafío de la tarjeta
            if len(response) != 16:
                print(f"Error: Longitud de desafío incorrecta ({len(response)} bytes)")
                return False
            
            encrypted_challenge = bytes(response)
            print(f"Desafío cifrado: {encrypted_challenge.hex()}")
            
            # 4. Descifrar desafío (RndB)
            iv_zero = bytes(16)
            rnd_b = self.crypto_utils.aes_decrypt(encrypted_challenge, key_data, iv_zero)
            rnd_b_bytes = bytes(rnd_b)
            print(f"Desafío descifrado (RndB): {rnd_b_bytes.hex()}")
            
            # 5. Generar desafío propio (RndA)
            rnd_a = list(os.urandom(16))
            rnd_a_bytes = bytes(rnd_a)
            print(f"Desafío generado (RndA): {rnd_a_bytes.hex()}")
            
            # 6. Rotar RndB
            rnd_b_rotated = self.crypto_utils.rotate_left(rnd_b, 1)
            print(f"RndB rotado: {bytes(rnd_b_rotated).hex()}")
            
            # 7. Concatenar RndA + RndB'
            token = rnd_a + rnd_b_rotated
            token_bytes = bytes(token)
            print(f"Token (RndA + RndB'): {token_bytes.hex()}")
            
            # 8. Cifrar token
            encrypted_token = self.crypto_utils.aes_encrypt(token, key_data, encrypted_challenge)
            print(f"Token cifrado: {bytes(encrypted_token).hex()}")
            
            # 9. Enviar token
            token_apdu = [0x90, 0xAF, 0x00, 0x00, len(encrypted_token)] + encrypted_token + [0x00]
            token_response, token_sw1, token_sw2 = self.connection.send_apdu(token_apdu)
            
            if token_sw1 != OPERATION_OK:
                print(f"Error en respuesta de token: {hex(token_sw1)} {hex(token_sw2)}")
                return False
            
            # 10. Verificar respuesta de la tarjeta
            if len(token_response) != 16:
                print(f"Error: Longitud de respuesta incorrecta ({len(token_response)} bytes)")
                return False
            
            # 11. Descifrar respuesta
            response_iv = bytes(encrypted_token[-16:])
            decrypted_response = self.crypto_utils.aes_decrypt(token_response, key_data, response_iv)
            
            # 12. Verificar RndA rotado
            expected_response = self.crypto_utils.rotate_left(rnd_a, 1)
            
            if decrypted_response == expected_response:
                print("¡Autenticación AES exitosa!")
                
                # 13. Generar clave de sesión
                self.session_key = bytes(rnd_a[:4] + rnd_b[:4] + rnd_a[-4:] + rnd_b[-4:])
                self.authenticated_key = key_no
                self.current_iv = bytes(16)  # IV inicial
                
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
            key_data = [0x00] * 8
        
        if isinstance(key_data, list):
            key_data = bytes(key_data)
        
        if len(key_data) != 8:
            print(f"Error: Clave DES debe ser de 8 bytes (actual: {len(key_data)})")
            return False
        
        try:
            # 1. Abortar operaciones pendientes
            self._abort_transaction()
            
            # 2. Iniciar autenticación
            auth_apdu = [0x90, self.COMMAND_ISO, 0x00, 0x00, 0x01, key_no, 0x00]
            response, sw1, sw2 = self.connection.send_apdu(auth_apdu)
            
            if not self._check_additional_frame(sw1, sw2):
                print(f"Error al iniciar autenticación: {hex(sw1)} {hex(sw2)}")
                return False
            
            # 3. Procesar desafío de la tarjeta
            if len(response) != 8:
                print(f"Error: Longitud de desafío incorrecta ({len(response)} bytes)")
                return False
            
            encrypted_challenge = bytes(response)
            print(f"Desafío cifrado: {encrypted_challenge.hex()}")
            
            # 4. Descifrar desafío (RndB)
            iv_zero = bytes(8)
            rnd_b = self.crypto_utils.des_decrypt(encrypted_challenge, key_data, iv_zero)
            rnd_b_bytes = bytes(rnd_b)
            print(f"Desafío descifrado (RndB): {rnd_b_bytes.hex()}")
            
            # 5. Generar desafío propio (RndA)
            rnd_a = list(os.urandom(8))
            rnd_a_bytes = bytes(rnd_a)
            print(f"Desafío generado (RndA): {rnd_a_bytes.hex()}")
            
            # 6. Rotar RndB
            rnd_b_rotated = self.crypto_utils.rotate_left(rnd_b, 1)
            print(f"RndB rotado: {bytes(rnd_b_rotated).hex()}")
            
            # 7. Concatenar RndA + RndB'
            token = rnd_a + rnd_b_rotated
            token_bytes = bytes(token)
            print(f"Token (RndA + RndB'): {token_bytes.hex()}")
            
            # 8. Cifrar token
            encrypted_token = self.crypto_utils.des_encrypt(token, key_data, encrypted_challenge)
            print(f"Token cifrado: {bytes(encrypted_token).hex()}")
            
            # 9. Enviar token
            token_apdu = [0x90, 0xAF, 0x00, 0x00, len(encrypted_token)] + encrypted_token + [0x00]
            token_response, token_sw1, token_sw2 = self.connection.send_apdu(token_apdu)
            
            if token_sw1 != OPERATION_OK or token_sw2 != STATUS_OK:
                print(f"Error en respuesta de token: {hex(token_sw1)} {hex(token_sw2)}")
                return False
            
            # 10. Verificar respuesta de la tarjeta
            if len(token_response) != 8:
                print(f"Error: Longitud de respuesta incorrecta ({len(token_response)} bytes)")
                return False
            
            # 11. Descifrar respuesta
            response_iv = bytes(encrypted_token[-8:])
            decrypted_response = self.crypto_utils.des_decrypt(token_response, key_data, response_iv)
            
            # 12. Verificar RndA rotado
            expected_response = self.crypto_utils.rotate_left(rnd_a, 1)
            
            if decrypted_response == expected_response:
                print("¡Autenticación DES exitosa!")
                
                # 13. Generar clave de sesión (para DES es más simple)
                self.session_key = bytes(rnd_a[:4] + rnd_b[:4])
                self.authenticated_key = key_no
                self.current_iv = bytes(8)  # IV inicial
                
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
    
    def _abort_transaction(self):
        """Aborta transacciones pendientes"""
        abort_apdu = [0x90, 0xA7, 0x00, 0x00, 0x00]
        self.connection.send_apdu(abort_apdu)
    
    def _check_additional_frame(self, sw1: int, sw2: int) -> bool:
        """Verifica si la respuesta indica frame adicional"""
        return ((sw1 == OPERATION_OK and sw2 == ADDITIONAL_FRAME) or 
                (sw1 == ADDITIONAL_FRAME))
    
    def is_authenticated(self) -> bool:
        """Verifica si hay una autenticación activa"""
        return self.authenticated_key is not None and self.session_key is not None

# =============================================================================
# CLASE PARA COMANDOS DE VERIFICACIÓN
# =============================================================================

class DESFireVerifyCommands:
    """Comandos de verificación para DESFire EV1"""
    
    COMMAND_GET_KEY_SETTINGS = 0x45
    COMMAND_GET_KEY_VERSION = 0x64
    
    @staticmethod
    def get_key_settings(connection: DESFireReaderConnection) -> Tuple[bool, dict]:
        """
        Obtiene la configuración actual de claves del PICC
        
        Args:
            connection: Conexión con el lector
            
        Returns:
            tuple: (success, settings_info)
        """
        print("\n=== GET KEY SETTINGS ===")
        
        apdu = [0x90, DESFireVerifyCommands.COMMAND_GET_KEY_SETTINGS, 0x00, 0x00, 0x00]
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            if len(response) >= 2:
                settings = response[0]
                key_count = response[1]
                
                # En DESFire EV1, el tipo de clave no se refleja directamente en Get Key Settings
                # después de un cambio individual de clave. Se debe determinar mediante otros métodos.
                settings_info = {
                    'settings': settings,
                    'key_count': key_count,
                    'master_key_changeable': bool(settings & 0x01),
                    'list_apps_no_auth': bool(settings & 0x02),
                    'create_delete_no_auth': bool(settings & 0x04),
                    'config_changeable': bool(settings & 0x08),
                    'key_type': 'Indeterminado (verificar por autenticación)'  # Será determinado más adelante
                }
                
                print(f"✅ Configuración obtenida:")
                print(f"   • Settings byte: 0x{settings:02X}")
                print(f"   • Número de claves: {key_count}")
                print(f"   • Tipo de clave: {settings_info['key_type']}")
                print(f"   • Clave maestra modificable: {'Sí' if settings_info['master_key_changeable'] else 'No'}")
                print(f"   • Listar apps sin auth: {'Sí' if settings_info['list_apps_no_auth'] else 'No'}")
                print(f"   • Crear/eliminar sin auth: {'Sí' if settings_info['create_delete_no_auth'] else 'No'}")
                print(f"   • Configuración modificable: {'Sí' if settings_info['config_changeable'] else 'No'}")
                
                return True, settings_info
            else:
                print("❌ Error: Respuesta de longitud incorrecta")
                return False, {}
        else:
            print(f"❌ Error al obtener configuración: SW={hex(sw1)}{hex(sw2)}")
            if sw1 == 0x91 and sw2 == 0xAE:
                print("   • Error de autenticación requerida")
            return False, {}
    
    @staticmethod
    def get_key_version(connection: DESFireReaderConnection, key_no: int = 0) -> Tuple[bool, int]:
        """
        Obtiene la versión de una clave específica
        
        Args:
            connection: Conexión con el lector
            key_no: Número de clave (0-13)
            
        Returns:
            tuple: (success, key_version)
        """
        print(f"\n=== GET KEY VERSION (Clave #{key_no}) ===")
        
        apdu = [0x90, DESFireVerifyCommands.COMMAND_GET_KEY_VERSION, 0x00, 0x00, 0x01, key_no, 0x00]
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            if len(response) >= 1:
                key_version = response[0]
                print(f"✅ Versión de clave #{key_no}: 0x{key_version:02X}")
                
                if key_version == 0x00:
                    print("   • Clave por defecto (no modificada)")
                else:
                    print(f"   • Clave modificada (versión {key_version})")
                
                return True, key_version
            else:
                print("❌ Error: Respuesta de longitud incorrecta")
                return False, 0
        else:
            print(f"❌ Error al obtener versión de clave: SW={hex(sw1)}{hex(sw2)}")
            if sw1 == 0x91 and sw2 == 0xAE:
                print("   • Error de autenticación requerida")
            elif sw1 == 0x91 and sw2 == 0x40:
                print("   • Número de clave inválido")
            return False, 0
    
    @staticmethod
    def detect_key_type(connection: DESFireReaderConnection, key_no: int = 0) -> str:
        """
        Detecta el tipo de clave mediante pruebas de autenticación
        
        Args:
            connection: Conexión con el lector
            key_no: Número de clave a verificar
            
        Returns:
            str: Tipo de clave detectado ('AES', 'DES', 'Desconocido')
        """
        print(f"\n=== DETECCIÓN DE TIPO DE CLAVE #{key_no} ===")
        
        # Crear instancia temporal de autenticación para pruebas
        temp_auth = DESFireAuthenticate(connection)
        
        # Probar con clave AES por defecto modificada (la que usamos en el cambio)
        aes_key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        print("🔍 Probando autenticación AES...")
        if temp_auth.authenticate_aes(key_no, aes_key):
            print("✅ Autenticación AES exitosa")
            return 'AES'
        
        # Si AES falla, probar con DES por defecto
        print("🔍 Probando autenticación DES...")
        des_key = bytes([0x00] * 8)
        if temp_auth.authenticate_des(key_no, des_key):
            print("✅ Autenticación DES exitosa")
            return 'DES'
        
        print("❌ No se pudo determinar el tipo de clave")
        return 'Desconocido'
    
    @staticmethod
    def verify_card_state(connection: DESFireReaderConnection) -> bool:
        """
        Verifica el estado completo de la tarjeta antes del formateo
        
        Args:
            connection: Conexión con el lector
            
        Returns:
            bool: True si la verificación fue exitosa
        """
        print("\n" + "="*50)
        print("VERIFICACIÓN DEL ESTADO ACTUAL DE LA TARJETA")
        print("="*50)
        
        verification_success = True
        
        # 1. Verificar configuración de claves
        settings_success, settings_info = DESFireVerifyCommands.get_key_settings(connection)
        if not settings_success:
            print("⚠️  Advertencia: No se pudo obtener configuración de claves")
            verification_success = False
        
        # 2. Verificar versión de clave maestra
        version_success, key_version = DESFireVerifyCommands.get_key_version(connection, 0)
        if not version_success:
            print("⚠️  Advertencia: No se pudo obtener versión de clave maestra")
            verification_success = False
        
        # 3. Detectar tipo real de clave mediante autenticación
        actual_key_type = DESFireVerifyCommands.detect_key_type(connection, 0)
        
        # 4. Resumen de verificación
        print("\n" + "-"*40)
        print("RESUMEN DE VERIFICACIÓN:")
        print("-"*40)
        
        if settings_success and version_success:
            print("✅ Estado de la tarjeta verificado correctamente")
            print(f"🔑 Tipo de clave real detectado: {actual_key_type}")
            
            # Determinar tipo de autenticación recomendado basado en detección real
            if actual_key_type == 'AES':
                print("📋 Recomendación: Usar autenticación AES para formateo")
            elif actual_key_type == 'DES':
                print("📋 Recomendación: Usar autenticación DES para formateo")
            else:
                print("📋 Recomendación: Probar ambos tipos de autenticación")
            
            if key_version == 0x00:
                print("🔑 La clave maestra está en estado por defecto")
            else:
                print("🔑 La clave maestra ha sido modificada")
                
        else:
            print("⚠️  Verificación parcial o fallida")
            print("💡 Se intentará formateo con clave por defecto")
        
        print("-"*40)
        return verification_success

# =============================================================================
# CLASE PARA CAMBIO DE CLAVES
# =============================================================================

class DESFireChangeKey:
    """Comandos para cambio de claves en DESFire EV1"""
    
    COMMAND_CHANGE_KEY = 0xC4
    AES_KEY_FLAG = 0x80
    
    def __init__(self, connection: DESFireReaderConnection, auth: DESFireAuthenticate):
        self.connection = connection
        self.auth = auth
        self.crypto_utils = DESFireCryptoUtils()
    
    def change_key_des_to_aes(self, key_no: int = 0, new_aes_key: bytes = None, 
                             key_version: int = 0x01) -> bool:
        """
        Cambia una clave DES a AES
        
        Args:
            key_no: Número de clave a cambiar (0-13)
            new_aes_key: Nueva clave AES (16 bytes). Si es None, usa clave por defecto
            key_version: Versión de la nueva clave (0x01 por defecto)
            
        Returns:
            bool: True si el cambio fue exitoso
        """
        if not self.auth.is_authenticated():
            print("Error: Debe autenticarse antes de cambiar claves")
            return False
        
        if not CRYPTO_AVAILABLE:
            print("Error: PyCryptodome requerido para cambio de claves")
            return False
        
        print(f"\n=== CAMBIO DE CLAVE #{key_no} DE DES A AES ===")
        
        # Clave AES por defecto si no se especifica
        if new_aes_key is None:
            new_aes_key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        if len(new_aes_key) != 16:
            print(f"Error: Clave AES debe ser de 16 bytes (actual: {len(new_aes_key)})")
            return False
        
        try:
            print(f"Nueva clave AES: {new_aes_key.hex().upper()}")
            print(f"Versión de clave: 0x{key_version:02X}")
            
            # 1. Preparar criptograma
            cryptogram_data = self._prepare_change_key_cryptogram(
                new_aes_key, key_version, key_no
            )
            
            if not cryptogram_data:
                print("Error: No se pudo preparar el criptograma")
                return False
            
            # 2. Cifrar criptograma con clave de sesión
            encrypted_cryptogram = self._encrypt_cryptogram(cryptogram_data)
            
            if not encrypted_cryptogram:
                print("Error: No se pudo cifrar el criptograma")
                return False
            
            # 3. Enviar comando Change Key
            return self._send_change_key_command(key_no, encrypted_cryptogram)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en cambio de clave: {e}")
            return False
    
    def _prepare_change_key_cryptogram(self, new_key: bytes, version: int, key_no: int) -> bytes:
        """
        Prepara el criptograma para el cambio de clave según protocolo DESFire correcto
        
        Args:
            new_key: Nueva clave AES (16 bytes)
            version: Versión de la clave
            key_no: Número de clave
            
        Returns:
            bytes: Criptograma preparado
        """
        print("Preparando criptograma según protocolo DESFire...")
        
        # ✅ Estructura correcta: [16 bytes nueva clave] + [1 byte versión]
        cryptogram = bytearray(new_key)
        cryptogram.append(version)
        
        print(f"Criptograma base: {cryptogram.hex().upper()}")
        
        # ✅ CORRECCIÓN PRINCIPAL: CRC32 debe incluir comando + key_flag + criptograma
        # Según código C++: Utils::CalcCrc32(u8_Command, 2, i_Cryptogram, i_Cryptogram.GetCount())
        key_flag = key_no | self.AES_KEY_FLAG  # 0x00 | 0x80 = 0x80 para clave 0
        command_bytes = bytes([self.COMMAND_CHANGE_KEY, key_flag])  # C4 80
        
        # Calcular CRC32 sobre comando + key_flag + criptograma
        crc32_data = command_bytes + cryptogram
        crc32_value = self.crypto_utils.calculate_crc32(crc32_data)
        crc_bytes = struct.pack('<I', crc32_value)  # Little endian
        
        print(f"Comando + key_flag: {command_bytes.hex().upper()}")
        print(f"Datos para CRC32: {crc32_data.hex().upper()}")
        print(f"CRC32 calculado: {crc32_value:08X} -> {crc_bytes.hex().upper()}")
        
        # Agregar CRC32 al criptograma (NO al comando)
        cryptogram.extend(crc_bytes)
        
        print(f"Criptograma con CRC32: {cryptogram.hex().upper()}")
        
        # ✅ CORRECCIÓN: Usar padding con ceros (método DESFire) en lugar de PKCS7
        if len(self.auth.session_key) == 8:
            # Sesión DES - padding a múltiplo de 8 bytes con ceros
            padded_cryptogram = self.crypto_utils.pad_to_block_size(cryptogram, 8)
        else:
            # Sesión AES - padding a múltiplo de 16 bytes con ceros
            padded_cryptogram = self.crypto_utils.pad_to_block_size(cryptogram, 16)
        
        print(f"Criptograma final con padding ({len(padded_cryptogram)} bytes): {padded_cryptogram.hex().upper()}")
        
        return padded_cryptogram
    
    def _encrypt_cryptogram(self, cryptogram: bytes) -> bytes:
        """
        Cifra el criptograma con la clave de sesión actual
        
        Args:
            cryptogram: Criptograma a cifrar
            
        Returns:
            bytes: Criptograma cifrado
        """
        if not self.auth.session_key:
            print("Error: No hay clave de sesión disponible")
            return None
        
        print("Cifrando criptograma con clave de sesión...")
        print(f"Clave de sesión: {self.auth.session_key.hex().upper()}")
        print(f"IV actual: {self.auth.current_iv.hex().upper() if self.auth.current_iv else 'None'}")
        
        try:
            if len(self.auth.session_key) == 8:
                # Sesión DES - usar DES para cifrar con IV actual
                iv = self.auth.current_iv if self.auth.current_iv else bytes(8)
                encrypted = self.crypto_utils.des_encrypt(cryptogram, self.auth.session_key, iv)
            else:
                # Sesión AES - usar AES para cifrar con IV actual
                iv = self.auth.current_iv if self.auth.current_iv else bytes(16)
                encrypted = self.crypto_utils.aes_encrypt(cryptogram, self.auth.session_key, iv)
            
            result = bytes(encrypted)
            print(f"Criptograma cifrado ({len(result)} bytes): {result.hex().upper()}")
            
            # Actualizar IV con los últimos bytes del ciphertext (como en Java línea 392)
            if len(self.auth.session_key) == 8:
                # DES: IV de 8 bytes
                self.auth.current_iv = result[-8:]
            else:
                # AES: IV de 16 bytes
                self.auth.current_iv = result[-16:]
            
            print(f"IV actualizado: {self.auth.current_iv.hex().upper()}")
            
            return result
            
        except Exception as e:
            print(f"Error al cifrar criptograma: {e}")
            return None
    
    def _send_change_key_command(self, key_no: int, encrypted_cryptogram: bytes) -> bool:
        """
        Envía el comando Change Key
        
        Args:
            key_no: Número de clave
            encrypted_cryptogram: Criptograma cifrado
            
        Returns:
            bool: True si el comando fue exitoso
        """
        key_flag = key_no | self.AES_KEY_FLAG  # Agregar flag AES
        data_length = 1 + len(encrypted_cryptogram)  # 1 byte flag + criptograma
        
        apdu = [0x90, self.COMMAND_CHANGE_KEY, 0x00, 0x00, data_length, key_flag] + \
               list(encrypted_cryptogram) + [0x00]
        
        print(f"Enviando comando Change Key...")
        print(f"Key flag: 0x{key_flag:02X} (Clave #{key_no} + AES flag)")
        
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("✅ ¡Cambio de clave exitoso!")
            print(f"Respuesta CMAC: {bytes(response).hex().upper() if response else 'Sin datos'}")
            return True
        else:
            print(f"❌ Error en cambio de clave: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == 0x91:
                if sw2 == 0xAE:
                    print("   • Error de autenticación")
                elif sw2 == 0x9D:
                    print("   • Permiso denegado")
                elif sw2 == 0x40:
                    print("   • Parámetro incorrecto")
                elif sw2 == 0x7E:
                    print("   • Longitud incorrecta")
                elif sw2 == 0x1E:
                    print("   • Error de integridad (CMAC/CRC32 inválido)")
                    print("   • Revisar cálculo de CRC32 o estructura del criptograma")
            
            return False
    
    # Método completo actualizado
    def change_key_aes_to_des(self, key_no: int = 0, new_des_key: bytes = None, 
                            key_version: int = 0x01) -> bool:
        """
        Cambia una clave AES a DES usando la misma lógica que funciona para DES→AES
        """
        if not self.auth.is_authenticated():
            print("Error: Debe autenticarse antes de cambiar claves")
            return False
        
        if not CRYPTO_AVAILABLE:
            print("Error: PyCryptodome requerido para cambio de claves")
            return False
        
        print(f"\n=== CAMBIO DE CLAVE #{key_no} DE AES A DES ===")
        
        # Clave DES por defecto si no se especifica
        if new_des_key is None:
            new_des_key = bytes([0x00] * 8)
        
        if len(new_des_key) != 8:
            print(f"Error: Clave DES debe ser de 8 bytes (actual: {len(new_des_key)})")
            return False
        
        try:
            print(f"Nueva clave DES: {new_des_key.hex().upper()}")
            print(f"Versión de clave: 0x{key_version:02X}")
            
            # 1. Preparar criptograma usando lógica probada
            # cryptogram_data = self._prepare_change_key_cryptogram_aes_to_des(
            #     new_des_key, key_version, key_no
            # )

            cryptogram_data = self._prepare_change_key_cryptogram_aes_to_des_correct(
                new_des_key, key_version, key_no
            )

            
            
            if not cryptogram_data:
                print("Error: No se pudo preparar el criptograma")
                return False
            
            # 2. Cifrar criptograma con clave de sesión AES actual
            encrypted_cryptogram = self._encrypt_cryptogram(cryptogram_data)
            
            if not encrypted_cryptogram:
                print("Error: No se pudo cifrar el criptograma")
                return False
            
            # 3. Enviar comando Change Key (SIN flag AES)
            return self._send_change_key_command_to_des(key_no, encrypted_cryptogram)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en cambio de clave: {e}")
            return False
        
    def _prepare_change_key_cryptogram_aes_to_des(self, new_key: bytes, version: int, key_no: int) -> bytes:
        """
        Prepara el criptograma para el cambio de clave AES a DES
        Estructura: new_key(8) + XOR(old[:8], new_key)(8) + version(1) + CRC32(4) = 21 bytes
        
        Args:
            new_key: Nueva clave DES (8 bytes)
            version: Versión de la clave
            key_no: Número de clave
            
        Returns:
            bytes: Criptograma preparado
        """
        print("✅ Preparando criptograma AES→DES siguiendo implementación Java...")
        
        # Clave AES actual 
        current_aes_key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        # 1. Crear plaintext de 32 bytes (como en Java línea 320)
        plaintext = bytearray(32)
        
        # 2. Copiar nueva clave DES (8 bytes) 
        plaintext[0:8] = new_key
        
        # 3. Para DES: duplicar la clave para hacer 16 bytes internamente (Java líneas 331-335)
        plaintext[8:16] = new_key  # Duplicar clave DES
        extended_new_key = bytes(plaintext[0:16])  # 16 bytes total
        
        # 4. XOR con clave antigua si es diferente key number (Java líneas 352-356)
        # Para PICC master key #0, NO se aplica XOR porque (keyNo & 0x0F) == kno (0)
        if (key_no & 0x0F) != 0:  # Si no es la misma clave autenticada  
            for i in range(16):
                plaintext[i] ^= current_aes_key[i % 16]
        else:
            print("PICC master key: NO se aplica XOR (misma clave autenticada)")
        
        print(f"Nueva clave DES extendida: {extended_new_key.hex().upper()}")
        print(f"Plaintext después de XOR: {plaintext[0:16].hex().upper()}")
        
        # 5. Calcular CRC32 sobre Command + KeyNo + newKey (Java líneas 377-382)
        # nklen = 16 para DES extendido, addAesKeyVersionByte = 0 para DES
        crc_data = bytearray()
        crc_data.append(self.COMMAND_CHANGE_KEY)  # 0xC4
        crc_data.append(key_no)  # 0x00 para PICC master key
        crc_data.extend(plaintext[0:16])  # Los 16 bytes de nueva clave
        
        crc32_value = self.crypto_utils.calculate_crc32(crc_data)
        crc_bytes = struct.pack('<I', crc32_value)
        
        print(f"Datos para CRC32 (18 bytes): {crc_data.hex().upper()}")
        print(f"CRC32 calculado: {crc32_value:08X} -> {crc_bytes.hex().upper()}")
        
        # 6. Agregar CRC32 al plaintext en posición 16 (Java línea 382)
        plaintext[16:20] = crc_bytes
        
        # 7. Si es diferente key, agregar CRC32 de newKey también (Java líneas 384-387)
        if (key_no & 0x0F) != 0:
            newkey_crc32 = self.crypto_utils.calculate_crc32(extended_new_key)
            newkey_crc_bytes = struct.pack('<I', newkey_crc32)
            plaintext[20:24] = newkey_crc_bytes
            print(f"CRC32 de newKey: {newkey_crc32:08X} -> {newkey_crc_bytes.hex().upper()}")
        
        print(f"Plaintext completo (32 bytes): {plaintext.hex().upper()}")
        
        return bytes(plaintext)
    

    # ################################################
    # START
    # ################################################



    def downgrade_aes_to_des_via_format(self, aes_key: bytes = None) -> bool:
        """
        Downgrade AES→DES mediante formateo controlado
        Este es el método más confiable cuando el cambio directo falla
        
        Args:
            aes_key: Clave AES actual (si es None, usa la por defecto)
        
        Returns:
            bool: True si el downgrade fue exitoso
        """
        print("=" * 60)
        print("DOWNGRADE AES→DES MEDIANTE FORMATEO CONTROLADO")
        print("=" * 60)
        
        # Clave AES por defecto
        if aes_key is None:
            aes_key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        print("⚠️  ADVERTENCIA: Este proceso formateará la tarjeta")
        print("⚠️  Todos los datos y aplicaciones se perderán")
        print("⚠️  La tarjeta volverá al estado de fábrica con clave DES")
        print()
        
        # Confirmación del usuario
        confirm = input("¿Confirma que desea continuar? Escriba 'CONFIRMO': ")
        if confirm != "CONFIRMO":
            print("❌ Operación cancelada por el usuario")
            return False
        
        try:
            # Paso 1: Seleccionar aplicación maestra
            print("\n📍 Paso 1: Seleccionando aplicación maestra...")
            if not DESFireSelectApplication.select_master_application(self.connection):
                print("❌ Error: No se pudo seleccionar aplicación maestra")
                return False
            
            # Paso 2: Autenticarse con clave AES actual
            print("\n🔐 Paso 2: Autenticando con clave AES actual...")
            if not self.auth.authenticate_aes(0, aes_key):
                print("❌ Error: No se pudo autenticar con clave AES")
                print("💡 Verifique que la clave AES proporcionada sea correcta")
                return False
            
            print("✅ Autenticación AES exitosa")
            
            # Paso 3: Formatear la tarjeta
            print("\n🔄 Paso 3: Formateando tarjeta...")
            if not self._format_picc():
                print("❌ Error: No se pudo formatear la tarjeta")
                return False
            
            print("✅ Formateo exitoso")
            
            # Paso 4: Verificar que ahora usa DES
            print("\n🔍 Paso 4: Verificando downgrade a DES...")
            # self.auth.reset_authentication()
            
            # Intentar autenticación DES con clave por defecto
            default_des_key = bytes([0x00] * 8)
            if self.auth.authenticate_des(0, default_des_key):
                print("✅ ¡DOWNGRADE EXITOSO!")
                print("🎉 La tarjeta ahora usa clave maestra DES por defecto")
                print(f"🔑 Clave maestra actual: {default_des_key.hex().upper()}")
                return True
            else:
                print("❌ Error: La tarjeta no responde con DES después del formateo")
                return False
                
        except Exception as e:
            print(f"❌ Error durante el downgrade: {e}")
            return False

    def _format_picc(self) -> bool:
        """
        Formatea la tarjeta (requiere autenticación previa)
        """
        print("Enviando comando Format PICC...")
        
        # Comando Format PICC: 90 FC 00 00 00
        apdu = [0x90, 0xFC, 0x00, 0x00, 0x00]
        
        try:
            response, sw1, sw2 = self.connection.send_apdu(apdu)
            
            if sw1 == 0x91 and sw2 == 0x00:
                print("✅ Comando Format PICC ejecutado exitosamente")
                
                # Verificar CMAC si hay respuesta
                if response and len(response) >= 8:
                    cmac_received = bytes(response[-8:])
                    print(f"📨 CMAC recibido: {cmac_received.hex().upper()}")
                    
                    # Aquí podrías verificar el CMAC si es necesario
                    # pero para el formateo no es crítico
                
                return True
            else:
                sw = (sw1 << 8) | sw2
                print(f"❌ Error en Format PICC: SW={sw:#06x}")
                
                if sw1 == 0x91:
                    if sw2 == 0x9D:
                        print("   • Permiso denegado - Verificar autenticación")
                    elif sw2 == 0xAE:
                        print("   • Error de autenticación")
                    elif sw2 == 0x1E:
                        print("   • Error de integridad")
                
                return False
                
        except Exception as e:
            print(f"❌ Error al enviar Format PICC: {e}")
            return False

    def verify_downgrade_success(self) -> bool:
        """
        Verifica que el downgrade fue exitoso probando múltiples métodos
        """
        print("\n🔍 VERIFICACIÓN COMPLETA DEL DOWNGRADE")
        print("-" * 40)
        
        # Reset completo
        # self.auth.reset_authentication()
        
        # Verificación 1: Autenticación DES
        print("1️⃣ Probando autenticación DES...")
        default_des_key = bytes([0x00] * 8)
        
        if self.auth.authenticate_des(0, default_des_key):
            print("✅ Autenticación DES exitosa")
            des_success = True
        else:
            print("❌ Autenticación DES falló")
            des_success = False
        
        # Verificación 2: Comprobar que AES ya no funciona
        print("\n2️⃣ Verificando que AES ya no funciona...")
        # self.auth.reset_authentication()
        
        aes_key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        
        if not self.auth.authenticate_aes(0, aes_key):
            print("✅ AES ya no funciona (como esperado)")
            aes_disabled = True
        else:
            print("⚠️ AES todavía funciona (inesperado)")
            aes_disabled = False
        
        # Verificación 3: Obtener configuración de claves
        print("\n3️⃣ Verificando configuración de claves...")
        try:
            # Autenticarse primero con DES
            if self.auth.authenticate_des(0, default_des_key):
                # Obtener configuración
                apdu = [0x90, 0x45, 0x00, 0x00, 0x00]
                response, sw1, sw2 = self.connection.send_apdu(apdu)
                
                if sw1 == 0x91 and sw2 == 0x00 and len(response) >= 2:
                    settings = response[0]
                    key_count = response[1]
                    print(f"✅ Configuración: 0x{settings:02X}")
                    print(f"✅ Número de claves: {key_count}")
                    config_ok = True
                else:
                    print("❌ No se pudo obtener configuración")
                    config_ok = False
            else:
                print("❌ No se pudo autenticar para verificar configuración")
                config_ok = False
        except Exception as e:
            print(f"❌ Error al verificar configuración: {e}")
            config_ok = False
        
        # Resultado final
        print("\n" + "=" * 40)
        print("RESULTADO DE LA VERIFICACIÓN:")
        print("=" * 40)
        
        if des_success and aes_disabled and config_ok:
            print("🎉 ¡DOWNGRADE COMPLETAMENTE EXITOSO!")
            print("✅ DES funciona")
            print("✅ AES deshabilitado")
            print("✅ Configuración correcta")
            return True
        else:
            print("⚠️ Downgrade parcial o con problemas:")
            print(f"   DES funciona: {'✅' if des_success else '❌'}")
            print(f"   AES deshabilitado: {'✅' if aes_disabled else '❌'}")
            print(f"   Configuración OK: {'✅' if config_ok else '❌'}")
            return False

    # Método principal integrado
    def complete_aes_to_des_downgrade(self, aes_key: bytes = None) -> bool:
        """
        Proceso completo de downgrade AES→DES con verificación
        """
        print("🚀 INICIANDO DOWNGRADE COMPLETO AES→DES")
        
        # Realizar downgrade
        if not self.downgrade_aes_to_des_via_format(aes_key):
            print("❌ Downgrade falló")
            return False
        
        # Verificar resultado
        if self.verify_downgrade_success():
            print("\n🎉 ¡PROCESO COMPLETO EXITOSO!")
            print("La tarjeta ha sido convertida exitosamente de AES a DES")
            return True
        else:
            print("\n⚠️ Downgrade realizado pero con advertencias")
            return False





    def _prepare_change_key_cryptogram_aes_to_des_correct(self, new_key: bytes, version: int, key_no: int) -> bytes:
        """
        Preparación CORRECTA del criptograma para cambio AES→DES
        SIN XOR porque estamos cambiando la misma clave con la que nos autenticamos
        
        Args:
            new_key: Nueva clave DES (8 bytes)
            version: Versión de la clave
            key_no: Número de clave
            
        Returns:
            bytes: Criptograma preparado
        """
        print("✅ Preparando criptograma AES→DES CORRECTO (sin XOR para misma clave)...")
        
        # ✅ ESTRUCTURA CORRECTA para cambio de la MISMA clave:
        # Solo: NewKey (8 bytes) + Version (1 byte) + CRC32 (4 bytes) = 13 bytes
        # NO XOR porque es la misma clave
        
        # 1. Nueva clave DES (8 bytes)
        cryptogram = bytearray(new_key)
        
        # 2. Versión (1 byte)
        cryptogram.append(version)
        
        print(f"Nueva clave DES: {new_key.hex().upper()}")
        print(f"Versión: 0x{version:02X}")
        print(f"Criptograma base (9 bytes): {cryptogram.hex().upper()}")
        
        # 3. CRC32 calculado sobre: Comando + KeyNo + Criptograma
        command_bytes = bytes([self.COMMAND_CHANGE_KEY, key_no])  # C4 00
        crc32_data = command_bytes + cryptogram
        crc32_value = self.crypto_utils.calculate_crc32(crc32_data)
        crc_bytes = struct.pack('<I', crc32_value)
        
        print(f"Comando + key_no: {command_bytes.hex().upper()}")
        print(f"Datos para CRC32 (11 bytes): {crc32_data.hex().upper()}")
        print(f"CRC32 calculado: {crc32_value:08X} -> {crc_bytes.hex().upper()}")
        
        # 4. Agregar CRC32 al criptograma
        cryptogram.extend(crc_bytes)
        
        print(f"Criptograma completo (13 bytes): {cryptogram.hex().upper()}")
        
        # 5. Padding para cifrado AES (múltiplo de 16)
        padded_cryptogram = self.crypto_utils.pad_to_block_size(cryptogram, 16)
        
        print(f"Criptograma con padding ({len(padded_cryptogram)} bytes): {padded_cryptogram.hex().upper()}")
        
        return padded_cryptogram


    def _prepare_change_key_cryptogram_aes_to_des_alternative(self, new_key: bytes, version: int, key_no: int) -> bytes:
        """
        Método alternativo basado en los ejemplos de la documentación
        Estructura expandida para DES (similar a los ejemplos que funcionan)
        """
        print("🔄 Probando estructura alternativa expandida...")
        
        # Estructura expandida vista en algunos ejemplos:
        # NewKey (8 bytes) + Padding (8 bytes) + Version (1 byte) + CRC32 (4 bytes) = 21 bytes
        
        # 1. Nueva clave DES (8 bytes)
        cryptogram = bytearray(new_key)
        
        # 2. Padding de 8 bytes (algunos sistemas lo requieren)
        cryptogram.extend([0x00] * 8)
        
        # 3. Versión (1 byte)
        cryptogram.append(version)
        
        print(f"Criptograma expandido (17 bytes): {cryptogram.hex().upper()}")
        
        # 4. CRC32 calculado solo sobre nueva clave + versión (método alternativo)
        crc_data = bytearray(new_key)
        crc_data.append(version)
        crc32_value = self.crypto_utils.calculate_crc32(crc_data)
        crc_bytes = struct.pack('<I', crc32_value)
        
        print(f"CRC32 sobre nueva clave + versión: {crc32_value:08X} -> {crc_bytes.hex().upper()}")
        
        # 5. Agregar CRC32
        cryptogram.extend(crc_bytes)
        
        print(f"Criptograma alternativo (21 bytes): {cryptogram.hex().upper()}")
        
        # 6. Padding para cifrado
        padded_cryptogram = self.crypto_utils.pad_to_block_size(cryptogram, 16)
        
        return padded_cryptogram

    def change_key_aes_to_des_fixed(self, key_no: int = 0, new_des_key: bytes = None, 
                                key_version: int = 0x01) -> bool:
        """
        Cambio de clave AES→DES con múltiples métodos de fallback
        """
        if not self.auth.is_authenticated():
            print("Error: Debe autenticarse antes de cambiar claves")
            return False
        
        print(f"\n=== CAMBIO DE CLAVE #{key_no} AES→DES (MÉTODOS MÚLTIPLES) ===")
        
        if new_des_key is None:
            new_des_key = bytes([0x00] * 8)
        
        if len(new_des_key) != 8:
            print(f"Error: Clave DES debe ser de 8 bytes")
            return False
        
        print(f"Nueva clave DES: {new_des_key.hex().upper()}")
        print(f"Versión de clave: 0x{key_version:02X}")
        
        # Método 1: Implementación Java correcta
        print("\n🔄 Método 1: Implementación Java correcta...")
        try:
            cryptogram_data = self._prepare_change_key_cryptogram_aes_to_des(
                new_des_key, key_version, key_no
            )
            
            encrypted_cryptogram = self._encrypt_cryptogram(cryptogram_data)
            
            if encrypted_cryptogram and self._send_change_key_command_to_des(key_no, encrypted_cryptogram):
                print("✅ ¡Cambio de clave exitoso con implementación Java!")
                return True
            else:
                print("❌ Cambio de clave falló")
        except Exception as e:
            print(f"❌ Error en cambio de clave: {e}")
        
        print("❌ Cambio de clave AES→DES falló")
        return False

    def _try_iso_change_key(self, key_no: int, new_des_key: bytes, key_version: int) -> bool:
        """
        Intenta cambio de clave usando comando ISO 7816 directo
        """
        print("Probando comando ISO 7816 directo...")
        
        # Preparar datos sin cifrar inicialmente
        key_data = bytearray(new_des_key)
        key_data.append(key_version)
        
        # APDU ISO 7816-4 para Change Key
        # CLA=00, INS=24 (Change Reference Data), P1=00, P2=key_no
        apdu = [
            0x00, 0x24, 0x00, key_no,  # CLA INS P1 P2
            len(key_data),             # Lc
            *key_data                  # Data
        ]
        
        print(f"APDU ISO: {' '.join([f'{b:02X}' for b in apdu])}")
        
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == 0x90 and sw2 == 0x00:
            print("✅ Cambio de clave ISO exitoso")
            # self.auth.reset_authentication()
            return True
        else:
            print(f"❌ Error ISO: SW={sw1:02X}{sw2:02X}")
            return False

    # Método para verificar si el cambio funcionó
    def verify_key_change_to_des(self, key_no: int, new_des_key: bytes, key_version: int) -> bool:
        """
        Verifica si el cambio de clave fue exitoso intentando autenticación DES
        """
        print(f"\n🔍 Verificando cambio de clave #{key_no}...")
        
        # Resetear autenticación
        # self.auth.reset_authentication()
        
        # Intentar autenticación DES con la nueva clave
        try:
            if self.auth.authenticate_des(key_no, new_des_key):
                print("✅ ¡Verificación exitosa! La clave ahora es DES")
                return True
            else:
                print("❌ Verificación falló - autenticación DES no funciona")
                return False
        except Exception as e:
            print(f"❌ Error en verificación: {e}")
            return False

    # ################################################
    # ################################################


    def _send_change_key_command_to_des(self, key_no: int, encrypted_cryptogram: bytes) -> bool:
        """
        Envía el comando ChangeKey para cambio a DES con estructura de 32 bytes
        """
        print("Enviando comando Change Key para AES→DES...")
        
        # Key number SIN flag AES (0x00 para clave #0)
        final_key_no = key_no  # Sin flag 0x80
        data_length = 1 + len(encrypted_cryptogram)  # 1 + 32 = 33 bytes
        
        apdu = [0x90, self.COMMAND_CHANGE_KEY, 0x00, 0x00, data_length, final_key_no] + \
               list(encrypted_cryptogram) + [0x00]
        
        print(f"Key number: 0x{final_key_no:02X} (SIN flag AES)")
        print(f"Criptograma cifrado: {len(encrypted_cryptogram)} bytes")
        print(f"Data length: {data_length} (1 + {len(encrypted_cryptogram)})")
        print(f"APDU total: {len(apdu)} bytes")
        
        response, sw1, sw2 = self.connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print("✅ ¡Cambio de clave AES→DES exitoso!")
            print(f"Respuesta CMAC: {bytes(response).hex().upper() if response else 'Sin datos'}")
            
            # Reset autenticación
            self.auth.authenticated_key = None
            self.auth.session_key = None
            self.auth.current_iv = None
            
            return True
        else:
            print(f"❌ Error en cambio de clave: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == 0x91:
                if sw2 == 0x7E:
                    print("   • Longitud incorrecta")
                    print(f"   • Se envió: {data_length} bytes, esperaba diferente")
                elif sw2 == 0x1E:
                    print("   • Error de integridad (CRC32 inválido)")
                elif sw2 == 0x9D:
                    print("   • Permiso denegado")
                elif sw2 == 0xAE:
                    print("   • Error de autenticación")
            
            return False


    def verify_key_change(self, key_no: int = 0, new_aes_key: bytes = None, 
                         expected_version: int = 0x01) -> bool:
        """
        Verifica que el cambio de clave fue exitoso
        
        Args:
            key_no: Número de clave verificar
            new_aes_key: Nueva clave AES para autenticación
            expected_version: Versión esperada de la clave
            
        Returns:
            bool: True si la verificación fue exitosa
        """
        print(f"\n=== VERIFICACIÓN DEL CAMBIO DE CLAVE #{key_no} ===")
        
        # 1. Verificar versión de clave
        print("Paso 1: Verificando versión de clave...")
        version_success, actual_version = DESFireVerifyCommands.get_key_version(
            self.connection, key_no
        )
        
        if not version_success:
            print("❌ Error: No se pudo obtener la versión de clave")
            return False
        
        if actual_version != expected_version:
            print(f"❌ Error: Versión incorrecta (esperada: 0x{expected_version:02X}, actual: 0x{actual_version:02X})")
            return False
        
        print(f"✅ Versión de clave correcta: 0x{actual_version:02X}")
        
        # 2. Verificar autenticación AES
        print("Paso 2: Verificando autenticación AES con nueva clave...")
        
        # Crear nueva instancia de autenticación para prueba
        test_auth = DESFireAuthenticate(self.connection)
        
        if test_auth.authenticate_aes(key_no, new_aes_key):
            print("✅ ¡Autenticación AES exitosa con nueva clave!")
            print("✅ ¡Cambio de clave verificado completamente!")
            return True
        else:
            print("❌ Error: No se pudo autenticar con la nueva clave AES")
            return False
    
    def verify_key_change_to_des(self, key_no: int = 0, new_des_key: bytes = None, 
                                expected_version: int = 0x01) -> bool:
        """
        Verifica que el cambio de clave a DES fue exitoso
        
        Args:
            key_no: Número de clave verificar
            new_des_key: Nueva clave DES para autenticación
            expected_version: Versión esperada de la clave
            
        Returns:
            bool: True si la verificación fue exitosa
        """
        print(f"\n=== VERIFICACIÓN DEL CAMBIO DE CLAVE #{key_no} A DES ===")
        
        # 1. Verificar versión de clave
        print("Paso 1: Verificando versión de clave...")
        version_success, actual_version = DESFireVerifyCommands.get_key_version(
            self.connection, key_no
        )
        
        if not version_success:
            print("❌ Error: No se pudo obtener la versión de clave")
            return False
        
        if actual_version != expected_version:
            print(f"❌ Error: Versión incorrecta (esperada: 0x{expected_version:02X}, actual: 0x{actual_version:02X})")
            return False
        
        print(f"✅ Versión de clave correcta: 0x{actual_version:02X}")
        
        # 2. Verificar autenticación DES
        print("Paso 2: Verificando autenticación DES con nueva clave...")
        
        # Crear nueva instancia de autenticación para prueba
        test_auth = DESFireAuthenticate(self.connection)
        
        if test_auth.authenticate_des(key_no, new_des_key):
            print("✅ ¡Autenticación DES exitosa con nueva clave!")
            print("✅ ¡Cambio de clave a DES verificado completamente!")
            return True
        else:
            print("❌ Error: No se pudo autenticar con la nueva clave DES")
            return False

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
# CLASE PRINCIPAL SIMPLIFICADA PARA FORMATEO
# =============================================================================

class DESFireFormatManager:
    COMMAND_CHANGE_KEY = 0xC4
    """Clase principal simplificada para formateo de DESFire EV1"""
    
    def __init__(self, debug: bool = True):
        self.connection = DESFireReaderConnection(debug)
        self.auth = None
        self.debug = debug
        self.crypto_utils = DESFireCryptoUtils()
    
    def connect(self) -> bool:
        """Establece conexión con el lector"""
        if self.connection.connect_reader():
            self.auth = DESFireAuthenticate(self.connection)
            return True
        return False
    
    def disconnect(self):
        """Cierra la conexión"""
        self.connection.disconnect()
    
    def format_card_with_aes_auth(self, key_data: bytes = None, confirm: bool = True, 
                                  verify_first: bool = True) -> bool:
        """
        Formatea la tarjeta usando autenticación AES
        
        Args:
            key_data: Clave AES (16 bytes). Si es None, usa clave por defecto
            confirm: Si True, omite confirmación del usuario
            verify_first: Si True, verifica el estado antes del formateo
            
        Returns:
            bool: True si el formateo fue exitoso
        """
        print("=== FORMATEO CON AUTENTICACIÓN AES ===")
        
        # 1. Seleccionar aplicación maestra
        if not DESFireSelectApplication.select_master_application(self.connection):
            print("Error: No se pudo seleccionar aplicación maestra")
            return False
        
        # 2. Verificar estado actual (opcional)
        if verify_first:
            print("\nPaso 1: Verificación del estado actual...")
            DESFireVerifyCommands.verify_card_state(self.connection)
        
        # 3. Autenticarse con clave maestra AES
        print("\nPaso 2: Autenticación con clave maestra AES...")
        if not self.auth.authenticate_aes(0, key_data):
            print("Error: No se pudo autenticar con clave maestra AES")
            return False
        
        # 4. Formatear la tarjeta
        print("\nPaso 3: Ejecutando comando FORMAT PICC...")
        return DESFireFormatPICC.execute(self.connection, confirm)
    
    def change_key_des_to_aes_complete(self, old_des_key: bytes = None, 
                                       new_aes_key: bytes = None, key_version: int = 0x01) -> bool:
        """
        Proceso completo de cambio de clave DES a AES con verificación
        
        Args:
            old_des_key: Clave DES actual (8 bytes). Si es None, usa clave por defecto
            new_aes_key: Nueva clave AES (16 bytes). Si es None, usa clave por defecto
            key_version: Versión de la nueva clave
            
        Returns:
            bool: True si el cambio fue exitoso
        """
        print("=== CAMBIO COMPLETO DE CLAVE DES A AES ===")
        
        # 1. Seleccionar aplicación maestra
        if not DESFireSelectApplication.select_master_application(self.connection):
            print("Error: No se pudo seleccionar aplicación maestra")
            return False
        
        # 2. Verificar estado actual
        print("\nPaso 1: Verificación del estado actual...")
        DESFireVerifyCommands.verify_card_state(self.connection)
        
        # 3. Autenticarse con clave DES actual
        print("\nPaso 2: Autenticación con clave DES actual...")
        if not self.auth.authenticate_des(0, old_des_key):
            print("Error: No se pudo autenticar con clave DES actual")
            return False
        
        # 4. Cambiar clave
        print("\nPaso 3: Cambiando clave DES a AES...")
        key_changer = DESFireChangeKey(self.connection, self.auth)
        
        if not key_changer.change_key_des_to_aes(0, new_aes_key, key_version):
            print("Error: No se pudo cambiar la clave")
            return False
        
        # 5. Verificar cambio
        print("\nPaso 4: Verificando cambio de clave...")
        if not key_changer.verify_key_change(0, new_aes_key, key_version):
            print("Error: La verificación del cambio falló")
            return False
        
        print("\n🎉 ¡Cambio de clave DES a AES completado exitosamente!")
        print("La tarjeta ahora usa autenticación AES.")
        
        return True
    
    def change_key_aes_to_des_complete(self, old_aes_key: bytes = None, 
                                       new_des_key: bytes = None, key_version: int = 0x01) -> bool:
        """
        Proceso completo de cambio de clave AES a DES con verificación
        
        Args:
            old_aes_key: Clave AES actual (16 bytes). Si es None, usa clave por defecto
            new_des_key: Nueva clave DES (8 bytes). Si es None, usa clave por defecto
            key_version: Versión de la nueva clave
            
        Returns:
            bool: True si el cambio fue exitoso
        """
        print("=== CAMBIO COMPLETO DE CLAVE AES A DES ===")
        
        # 1. Seleccionar aplicación maestra
        if not DESFireSelectApplication.select_master_application(self.connection):
            print("Error: No se pudo seleccionar aplicación maestra")
            return False
        
        # 2. Verificar estado actual
        print("\nPaso 1: Verificación del estado actual...")
        DESFireVerifyCommands.verify_card_state(self.connection)
        
        # 3. Autenticarse con clave AES actual
        print("\nPaso 2: Autenticación con clave AES actual...")
        if not self.auth.authenticate_aes(0, old_aes_key):
            print("Error: No se pudo autenticar con clave AES actual")
            return False
        
        key_changer = DESFireChangeKey(self.connection, self.auth)

        # Ejecutar downgrade completo
        success = key_changer.complete_aes_to_des_downgrade()

        if success:
            print("¡Downgrade exitoso! Tarjeta ahora usa DES")
        else:
            print("Downgrade falló")

        # 4. Cambiar clave
        print("\nPaso 3: Cambiando clave AES a DES...")
        key_changer = DESFireChangeKey(self.connection, self.auth)
        
        if not key_changer.change_key_aes_to_des_fixed(0, new_des_key, key_version):
            print("Error: No se pudo cambiar la clave")
            return False
        
        
        
        # 5. Verificar cambio
        print("\nPaso 4: Verificando cambio de clave...")
        if not key_changer.verify_key_change_to_des(0, new_des_key, key_version):
            print("Error: La verificación del cambio falló")
            return False
        
        print("\n🎉 ¡Cambio de clave AES a DES completado exitosamente!")
        print("La tarjeta ahora usa autenticación DES.")
        
        return True
    


    def format_card_with_des_auth(self, key_data: bytes = None, confirm: bool = True, 
                                  verify_first: bool = True) -> bool:
        """
        Formatea la tarjeta usando autenticación DES
        
        Args:
            key_data: Clave DES (8 bytes). Si es None, usa clave por defecto
            confirm: Si True, omite confirmación del usuario
            verify_first: Si True, verifica el estado antes del formateo
            
        Returns:
            bool: True si el formateo fue exitoso
        """
        print("=== FORMATEO CON AUTENTICACIÓN DES ===")
        
        # 1. Seleccionar aplicación maestra
        if not DESFireSelectApplication.select_master_application(self.connection):
            print("Error: No se pudo seleccionar aplicación maestra")
            return False
        
        # 2. Verificar estado actual (opcional)
        if verify_first:
            print("\nPaso 1: Verificación del estado actual...")
            DESFireVerifyCommands.verify_card_state(self.connection)
        
        # 3. Autenticarse con clave maestra DES
        print("\nPaso 2: Autenticación con clave maestra DES...")
        if not self.auth.authenticate_des(0, key_data):
            print("Error: No se pudo autenticar con clave maestra DES")
            return False
        
        # 4. Formatear la tarjeta
        print("\nPaso 3: Ejecutando comando FORMAT PICC...")
        return DESFireFormatPICC.execute(self.connection, confirm)

# =============================================================================
# EJEMPLO DE USO SIMPLIFICADO
# =============================================================================

def ejemplo_formateo():
    """Sistema completo de formateo y cambio de claves DESFire EV1"""
    print("=== Sistema DESFire EV1 - Formateo y Cambio de Claves ===\n")
    
    # Verificar dependencias
    if not SMARTCARD_AVAILABLE:
        print("❌ Error: pyscard no está disponible")
        print("Instale con: pip install pyscard")
        return False
    
    if not CRYPTO_AVAILABLE:
        print("❌ Error: PyCryptodome no está disponible")
        print("Instale con: pip install pycryptodome")
        return False
    
    print("✅ Todas las dependencias están disponibles\n")
    
    # Crear manager y conectar
    manager = DESFireFormatManager(debug=True)
    
    if not manager.connect():
        print("Error: No se pudo conectar al lector")
        return False
    
    try:
        # Menú de opciones ampliado
        print("Seleccione una opción:")
        print("1. Formateo con autenticación DES (por defecto)")
        print("2. Formateo con autenticación AES")
        print("3. Cambio de clave DES a AES (sin formateo)")
        print("4. Cambio de clave AES a DES (sin formateo)")
        print("5. Solo verificar estado de la tarjeta")
        
        choice = input("Opción (1-5): ").strip()
        result = False
        
        if choice == "1":
            # Formateo con DES
            print("\n=== OPCIÓN 1: Formateo con autenticación DES ===")
            result = manager.format_card_with_des_auth()
            
        elif choice == "2":
            # Formateo con AES
            print("\n=== OPCIÓN 2: Formateo con autenticación AES ===")
            result = manager.format_card_with_aes_auth()
            
        elif choice == "3":
            # Cambio de clave DES a AES
            print("\n=== OPCIÓN 3: Cambio de clave DES a AES ===")
            print("Esta opción cambiará la clave maestra de DES a AES sin formatear.")
            print("ADVERTENCIA: Asegúrese de que la tarjeta tiene clave DES por defecto.")
            
            confirm = input("¿Desea continuar? (s/n): ").lower()
            if confirm == 's':
                result = manager.change_key_des_to_aes_complete()
            else:
                print("Operación cancelada.")
                result = True  # No es un error, solo cancelado
                
        elif choice == "4":
            # Cambio de clave AES a DES
            print("\n=== OPCIÓN 4: Cambio de clave AES a DES ===")
            print("Esta opción cambiará la clave maestra de AES a DES sin formatear.")
            print("ADVERTENCIA: Asegúrese de que la tarjeta tiene clave AES actual.")
            
            confirm = input("¿Desea continuar? (s/n): ").lower()
            if confirm == 's':
                result = manager.change_key_aes_to_des_complete()
                # result = manager.change_key_aes_to_des_complete_alternative()
            else:
                print("Operación cancelada.")
                result = True  # No es un error, solo cancelado
                
        elif choice == "5":
            # Solo verificar estado
            print("\n=== OPCIÓN 5: Verificación de estado ===")
            if DESFireSelectApplication.select_master_application(manager.connection):
                DESFireVerifyCommands.verify_card_state(manager.connection)
                result = True
            else:
                print("Error: No se pudo seleccionar aplicación maestra")
                result = False
                
        else:
            print("Opción inválida")
            result = False
        
        # Mostrar resultado final
        if result:
            print("\n🎉 ¡Operación completada exitosamente!")
            
            if choice in ["1", "2"]:
                print("La tarjeta ha sido formateada y está lista para uso.")
            elif choice == "3":
                print("La clave maestra ha sido cambiada de DES a AES.")
                print("🔧 Próximos pasos recomendados:")
                print("   • Verifique que puede autenticarse con AES")
                print("   • Considere cambiar la clave por defecto por una personalizada")
            elif choice == "4":
                print("La clave maestra ha sido cambiada de AES a DES.")
                print("🔧 Próximos pasos recomendados:")
                print("   • Verifique que puede autenticarse con DES")
                print("   • Considere formatear si desea empezar limpio")
            elif choice == "5":
                print("Estado de la tarjeta verificado.")
        else:
            print("\n❌ Error durante la operación")
        
        return result
        
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario")
        return False
    except Exception as e:
        print(f"Error inesperado: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        manager.disconnect()

if __name__ == "__main__":
    ejemplo_formateo()