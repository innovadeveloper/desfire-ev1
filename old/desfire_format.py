#!/usr/bin/env python3
"""
DESFire EV1 - Clases refactorizadas y organizadas
Implementación completa de comandos DESFire siguiendo sintaxis consistente
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
# CLASE PARA AUTENTICACIÓN
# =============================================================================

class DESFireChangeKey:
    """Comando CHANGE KEY para DESFire EV1"""
    
    COMMAND_CODE = 0xC4
    
    def __init__(self, connection: DESFireReaderConnection):
        self.connection = connection
        self.crypto_utils = DESFireCryptoUtils()
    
    def create_new_key(self, key_no: int, new_key: bytes, session_key: bytes, 
                       session_iv: bytes, key_version: int = 0x00) -> bool:
        """
        Crea una nueva clave en la aplicación
        
        Args:
            key_no: Número de clave (1-13)
            new_key: Nueva clave AES (16 bytes)
            session_key: Clave de sesión actual
            session_iv: IV de sesión actual
            key_version: Versión de la clave
            
        Returns:
            bool: True si la creación fue exitosa
        """
        print(f"Creando clave #{key_no} con valor AES por defecto...")
        
        try:
            # Para crear una nueva clave (no cambiar existente), usar cryptogram simple
            # Cryptogram = nueva_clave + version + CRC32
            
            # Construir datos para CRC32 (comando completo)
            crc_data = bytes([self.COMMAND_CODE, key_no]) + new_key + bytes([key_version])
            crc32 = self.crypto_utils.calculate_crc32(crc_data)
            
            # Construir cryptogram
            cryptogram = new_key + bytes([key_version]) + struct.pack('<L', crc32)
            
            # Aplicar padding PKCS7 a 16 bytes
            cryptogram_padded = self.crypto_utils.pad_pkcs7(cryptogram, 16)
            cryptogram_bytes = bytes(cryptogram_padded)
            
            print(f"Cryptogram antes de cifrar: {cryptogram_bytes.hex().upper()}")
            
            # Cifrar con clave de sesión y IV actualizado
            encrypted_cryptogram = self.crypto_utils.aes_encrypt(
                cryptogram_bytes, session_key, session_iv
            )
            encrypted_bytes = bytes(encrypted_cryptogram)
            
            print(f"Cryptogram cifrado: {encrypted_bytes.hex().upper()}")
            
            # Construir comando APDU correctamente
            apdu = [0x90, self.COMMAND_CODE, 0x00, 0x00, len(encrypted_bytes) + 1, key_no] + list(encrypted_bytes) + [0x00]
            
            response, sw1, sw2 = self.connection.send_apdu(apdu)
            
            if sw1 == OPERATION_OK and sw2 == STATUS_OK:
                print(f"✅ Clave #{key_no} creada exitosamente")
                return True
            else:
                print(f"❌ Error creando clave #{key_no}: SW={hex(sw1)}{hex(sw2)}")
                if sw1 == OPERATION_OK and sw2 == 0x1E:
                    print("   Error de integridad - problema con CRC32 o padding")
                elif sw1 == OPERATION_OK and sw2 == 0xAE:
                    print("   Error de autenticación - sesión expirada o permisos")
                return False
                
        except Exception as e:
            print(f"Error en creación de clave: {e}")
            import traceback
            traceback.print_exc()
            return False


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
        if key_data is None:
            key_data = [0x00] * 16
        
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
    def create_des_application(connection: DESFireReaderConnection, aid: List[int], 
                              num_keys: int = 1, settings: int = 0x0F) -> bool:
        """
        Crea una aplicación con claves DES/3DES
        
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
        
        # Para DES/3DES: solo el número de claves
        key_config = num_keys
        
        return DESFireCreateApplication.create_application(
            connection, aid, settings, key_config, "DES/3DES"
        )
    
    @staticmethod
    def create_3k3des_application(connection: DESFireReaderConnection, aid: List[int], 
                                 num_keys: int = 1, settings: int = 0x0F) -> bool:
        """
        Crea una aplicación con claves 3K3DES
        
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
        
        # Para 3K3DES: 0x40 | num_keys
        key_config = 0x40 | num_keys
        
        return DESFireCreateApplication.create_application(
            connection, aid, settings, key_config, "3K3DES"
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
            DESFireCreateApplication._print_settings_meaning(settings)
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
    
    @staticmethod
    def _print_settings_meaning(settings: int):
        """Imprime el significado de los bits de configuración"""
        print("\nConfiguración de la aplicación:")
        print(f"  • Clave maestra {'PUEDE' if settings & 0x01 else 'NO PUEDE'} cambiarse")
        print(f"  • Listar archivos {'NO REQUIERE' if settings & 0x02 else 'REQUIERE'} autenticación")
        print(f"  • Crear/eliminar archivos {'NO REQUIERE' if settings & 0x04 else 'REQUIERE'} autenticación")
        print(f"  • Configuración {'PUEDE' if settings & 0x08 else 'NO PUEDE'} cambiarse")
        
        if settings & 0x02:
            print("⚠️ ADVERTENCIA: Listar archivos no requiere autenticación")
        if settings & 0x04:
            print("⚠️ ADVERTENCIA: Crear/eliminar archivos no requiere autenticación")

# =============================================================================
# CLASE PARA APLICACIONES PERSONALIZADAS
# =============================================================================

class DESFireCustomApplications:
    """Plantillas para aplicaciones comunes de DESFire"""
    
    @staticmethod
    def setup_application_keys(connection: DESFireReaderConnection, aid: List[int], 
                              auth: DESFireAuthenticate) -> bool:
        """
        Configura las claves de una aplicación después de crearla
        
        Args:
            connection: Conexión con el lector
            aid: Application ID de la aplicación
            auth: Instancia de autenticación
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        print(f"\n=== Configurando claves para aplicación {toHexString(aid)} ===")
        
        # 1. Seleccionar la aplicación
        if not DESFireSelectApplication.select_application(connection, aid):
            print("Error: No se pudo seleccionar la aplicación")
            return False
        
        # 2. Autenticarse con clave master por defecto
        print("Autenticándose con clave master por defecto...")
        if not auth.authenticate_aes(0, bytes(16)):  # 16 zeros
            print("Error: No se pudo autenticar con clave master")
            return False
        
        # 3. Crear las claves adicionales
        change_key = DESFireChangeKey(connection)
        
        # Crear clave #1 (lectura) 
        print("Creando clave #1 (lectura)...")
        key1_value = bytes(16)  # AES por defecto
        if not change_key.create_new_key(1, key1_value, auth.session_key, auth.current_iv):
            print("Error: No se pudo crear clave #1")
            return False
        
        # Crear clave #2 (escritura)
        print("Creando clave #2 (escritura)...")
        key2_value = bytes(16)  # AES por defecto
        if not change_key.create_new_key(2, key2_value, auth.session_key, auth.current_iv):
            print("Error: No se pudo crear clave #2")
            return False
        
        print("✅ Claves configuradas exitosamente:")
        print("  • Clave #0 (Master): AES por defecto")
        print("  • Clave #1 (Lectura): AES por defecto") 
        print("  • Clave #2 (Escritura): AES por defecto")
        
        return True
    
    @staticmethod
    def create_wallet_application(connection: DESFireReaderConnection, 
                                 aid: List[int] = None) -> bool:
        """
        Crea una aplicación de monedero con 3 claves AES
        - Clave 0: Administración general
        - Clave 1: Operaciones de débito
        - Clave 2: Operaciones de crédito
        
        Args:
            connection: Conexión con el lector
            aid: Application ID personalizado (opcional)
            
        Returns:
            bool: True si la creación fue exitosa
        """
        if aid is None:
            aid = [0xF0, 0x01, 0x01]  # AID por defecto para monedero
        
        print("=== Creando Aplicación de Monedero ===")
        print("Configuración:")
        print("  • Tipo: AES con 1 clave (simplificado)")
        print("  • Clave 0: Administración general y operaciones")
        print("  • Configuración: Segura (requiere autenticación)")
        print("  • Nota: Usar clave master para todos los permisos")
        
        # Configuración segura: requiere autenticación para operaciones
        settings = DESFireCreateApplication.SETTINGS_SECURE
        
        result = DESFireCreateApplication.create_aes_application(
            connection, aid, num_keys=1, settings=settings
        )
        
        if result:
            print(f"\n✅ Aplicación de monedero creada: AID={toHexString(aid)}")
            print("\n🎉 Aplicación de monedero completamente configurada:")
            print("  • Aplicación creada con 1 clave AES (master)")
            print("  • Clave master configurada con valor por defecto (16 zeros)")
            print("  • Lista para crear archivos STD seguros usando solo clave master")
            print("  • Configuración simplificada: R=Key0, W=Key0, C=Key0")
            
            # Seleccionar automáticamente la aplicación creada
            return DESFireSelectApplication.select_application(connection, aid)
        
        return False
    
    @staticmethod
    def create_access_control_application(connection: DESFireReaderConnection, 
                                        aid: List[int] = None) -> bool:
        """
        Crea una aplicación de control de acceso con 2 claves AES
        - Clave 0: Administración
        - Clave 1: Acceso a datos
        
        Args:
            connection: Conexión con el lector
            aid: Application ID personalizado (opcional)
            
        Returns:
            bool: True si la creación fue exitosa
        """
        if aid is None:
            aid = [0xA0, 0x01, 0x01]  # AID por defecto para control de acceso
        
        print("=== Creando Aplicación de Control de Acceso ===")
        print("Configuración:")
        print("  • Tipo: AES con 2 claves")
        print("  • Clave 0: Administración")
        print("  • Clave 1: Acceso a datos")
        print("  • Configuración: Muy segura")
        
        # Configuración muy restrictiva
        settings = DESFireCreateApplication.SETTINGS_RESTRICTED
        
        result = DESFireCreateApplication.create_aes_application(
            connection, aid, num_keys=2, settings=settings
        )
        
        if result:
            print(f"\n✅ Aplicación de control de acceso creada: AID={toHexString(aid)}")
            return DESFireSelectApplication.select_application(connection, aid)
        
        return False
    
    @staticmethod
    def create_loyalty_application(connection: DESFireReaderConnection, 
                                  aid: List[int] = None) -> bool:
        """
        Crea una aplicación de fidelización con configuración abierta
        - Clave 0: Administración
        
        Args:
            connection: Conexión con el lector
            aid: Application ID personalizado (opcional)
            
        Returns:
            bool: True si la creación fue exitosa
        """
        if aid is None:
            aid = [0xC0, 0x01, 0x01]  # AID por defecto para fidelización
        
        print("=== Creando Aplicación de Fidelización ===")
        print("Configuración:")
        print("  • Tipo: AES con 1 clave")
        print("  • Clave 0: Administración")
        print("  • Configuración: Abierta (fácil acceso)")
        
        # Configuración abierta para facilitar el uso
        settings = DESFireCreateApplication.SETTINGS_OPEN
        
        result = DESFireCreateApplication.create_aes_application(
            connection, aid, num_keys=1, settings=settings
        )
        
        if result:
            print(f"\n✅ Aplicación de fidelización creada: AID={toHexString(aid)}")
            return DESFireSelectApplication.select_application(connection, aid)
        
        return False

# =============================================================================
# CLASE PRINCIPAL PARA GESTIÓN COMPLETA
# =============================================================================

class DESFireManager:
    """Clase principal para gestión completa de DESFire EV1"""
    
    def __init__(self, debug: bool = True):
        self.connection = DESFireReaderConnection(debug)
        self.auth = None
        self.debug = debug
    
    def connect(self) -> bool:
        """Establece conexión con el lector"""
        if self.connection.connect_reader():
            self.auth = DESFireAuthenticate(self.connection)
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
    
    def setup_new_card(self, format_first: bool = True) -> bool:
        """
        Configura una tarjeta nueva desde cero
        
        Args:
            format_first: Si True, formatea la tarjeta primero
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        print("=== Configuración de Tarjeta Nueva ===")
        
        # 1. Autenticarse con clave maestra por defecto
        print("Paso 1: Autenticación con clave maestra...")
        if not self.authenticate_master_key_des():
            print("Error: No se pudo autenticar con clave maestra")
            return False
        
        # 2. Formatear si se solicita
        if format_first:
            print("Paso 2: Formateando tarjeta...")
            if not self.format_card(confirm=True):
                print("Error: No se pudo formatear la tarjeta")
                return False
            
            # Re-autenticarse después del formateo
            if not self.authenticate_master_key_des():
                print("Error: No se pudo re-autenticar después del formateo")
                return False
        
        print("✅ Tarjeta configurada y lista para crear aplicaciones")
        return True
    
    def create_wallet_setup(self, aid: List[int] = None) -> bool:
        """
        Configuración completa de monedero electrónico
        
        Args:
            aid: Application ID personalizado
            
        Returns:
            bool: True si la configuración fue exitosa
        """
        print("=== Configuración Completa de Monedero ===")
        
        # 1. Configurar tarjeta base
        if not self.setup_new_card():
            return False
        
        # 2. Crear aplicación de monedero
        print("Paso 3: Creando aplicación de monedero...")
        if not DESFireCustomApplications.create_wallet_application(self.connection, aid):
            print("Error: No se pudo crear la aplicación de monedero")
            return False
        
        print("✅ Monedero electrónico configurado exitosamente")
        print("📋 La aplicación está lista para:")
        print("  • Cambiar claves por defecto")
        print("  • Crear archivos de valor")
        print("  • Implementar operaciones de débito/crédito")
        
        return True

# =============================================================================
# EJEMPLOS DE USO Y PRUEBAS
# =============================================================================

def ejemplo_uso_completo():
    """Ejemplo de uso completo del sistema DESFire"""
    print("=== Ejemplo de Uso Completo DESFire EV1 ===\n")
    
    # 1. Crear manager y conectar
    manager = DESFireManager(debug=True)
    
    if not manager.connect():
        print("Error: No se pudo conectar al lector")
        return False
    
    try:
        # 2. Configurar tarjeta nueva (con formateo)
        print("1. Configurando tarjeta nueva...")
        if not manager.setup_new_card(format_first=True):
            print("Error en configuración inicial")
            return False
        
        # 3. Crear aplicación de monedero
        print("\n2. Creando aplicación de monedero...")
        wallet_aid = [0xF0, 0x01, 0x01]
        if not DESFireCustomApplications.create_wallet_application(manager.connection, wallet_aid):
            print("Error al crear aplicación de monedero")
            return False
        
        # 4. RE-AUTENTICARSE para crear más aplicaciones
        print("\n3. Re-autenticándose para crear aplicaciones adicionales...")
        if not manager.authenticate_master_key_des():
            print("Error: No se pudo re-autenticar con clave maestra")
            return False
        
        # 5. Crear aplicación de control de acceso
        print("\n4. Creando aplicación de control de acceso...")
        access_aid = [0xA0, 0x01, 0x01]
        if not DESFireCustomApplications.create_access_control_application(manager.connection, access_aid):
            print("Error al crear aplicación de control de acceso")
            return False
        
        # 6. RE-AUTENTICARSE nuevamente si necesitas crear más aplicaciones
        print("\n5. Re-autenticándose para operaciones adicionales...")
        if not manager.authenticate_master_key_des():
            print("Error: No se pudo re-autenticar con clave maestra")
            return False
        
        # 7. Crear aplicación de fidelización
        print("\n6. Creando aplicación de fidelización...")
        loyalty_aid = [0xC0, 0x01, 0x01]
        if not DESFireCustomApplications.create_loyalty_application(manager.connection, loyalty_aid):
            print("Error al crear aplicación de fidelización")
            return False
        
        # 8. Demostrar autenticación en aplicación específica
        print("\n7. Autenticándose en aplicación de monedero...")
        if DESFireSelectApplication.select_application(manager.connection, wallet_aid):
            if manager.auth.authenticate_aes(0):  # Clave maestra de la aplicación
                print("✅ Autenticación exitosa en aplicación de monedero")
            else:
                print("❌ Error en autenticación de aplicación")
        
        print("\n🎉 ¡Configuración completa exitosa!")
        print("La tarjeta está lista para uso en producción.")
        print("\n📋 Aplicaciones creadas:")
        print(f"  • Monedero: {toHexString(wallet_aid)}")
        print(f"  • Control de Acceso: {toHexString(access_aid)}")
        print(f"  • Fidelización: {toHexString(loyalty_aid)}")
        
        return True
        
    except Exception as e:
        print(f"Error durante la configuración: {e}")
        return False
    
    finally:
        # Siempre desconectar
        manager.disconnect()

# =============================================================================
# MÉTODO MEJORADO PARA CREACIÓN MÚLTIPLE DE APLICACIONES
# =============================================================================

class DESFireBatchOperations:
    """Operaciones por lotes para DESFire EV1"""
    
    @staticmethod
    def create_multiple_applications(manager: DESFireManager, 
                                   applications: List[dict]) -> bool:
        """
        Crea múltiples aplicaciones gestionando automáticamente la re-autenticación
        
        Args:
            manager: Instancia del DESFireManager
            applications: Lista de diccionarios con configuraciones de aplicaciones
                        Formato: [{'aid': [0xF0, 0x01, 0x01], 'type': 'wallet'}, ...]
        
        Returns:
            bool: True si todas las aplicaciones se crearon exitosamente
        """
        print(f"=== Creando {len(applications)} aplicaciones ===")
        
        # Asegurar autenticación inicial
        if not manager.authenticate_master_key_des():
            print("Error: No se pudo autenticar inicialmente")
            return False
        
        created_apps = []
        
        for i, app_config in enumerate(applications):
            print(f"\nCreando aplicación {i+1}/{len(applications)}...")
            
            # Re-autenticarse antes de cada aplicación (excepto la primera)
            if i > 0:
                print("Re-autenticándose con aplicación maestra...")
                if not manager.authenticate_master_key_des():
                    print(f"Error: Re-autenticación falló para aplicación {i+1}")
                    return False
            
            # Crear aplicación según tipo
            result = False
            app_type = app_config.get('type', 'wallet')
            aid = app_config['aid']
            
            if app_type == 'wallet':
                result = DESFireCustomApplications.create_wallet_application(
                    manager.connection, aid
                )
            elif app_type == 'access_control':
                result = DESFireCustomApplications.create_access_control_application(
                    manager.connection, aid
                )
            elif app_type == 'loyalty':
                result = DESFireCustomApplications.create_loyalty_application(
                    manager.connection, aid
                )
            else:
                print(f"Error: Tipo de aplicación desconocido: {app_type}")
                continue
            
            if result:
                created_apps.append({'aid': aid, 'type': app_type})
                print(f"✅ Aplicación {app_type} creada: {toHexString(aid)}")
            else:
                print(f"❌ Error creando aplicación {app_type}: {toHexString(aid)}")
                return False
        
        print(f"\n🎉 ¡{len(created_apps)} aplicaciones creadas exitosamente!")
        return True

def ejemplo_uso_mejorado():
    """Ejemplo mejorado con gestión automática de re-autenticación"""
    print("=== Ejemplo Mejorado - Creación Múltiple de Aplicaciones ===\n")
    
    manager = DESFireManager(debug=True)
    
    if not manager.connect():
        print("Error: No se pudo conectar al lector")
        return False
    
    try:
        # 1. Configurar tarjeta nueva
        print("1. Configurando tarjeta nueva...")
        if not manager.setup_new_card(format_first=True):
            print("Error en configuración inicial")
            return False
        
        # 2. Definir aplicaciones a crear
        applications = [
            {'aid': [0xF0, 0x01, 0x01], 'type': 'wallet'},
            # {'aid': [0xA0, 0x01, 0x01], 'type': 'access_control'},
            # {'aid': [0xC0, 0x01, 0x01], 'type': 'loyalty'},
            # {'aid': [0xF1, 0x02, 0x01], 'type': 'wallet'},  # Segundo monedero
        ]
        
        # 3. Crear todas las aplicaciones con gestión automática
        print("\n2. Creando múltiples aplicaciones...")
        if not DESFireBatchOperations.create_multiple_applications(manager, applications):
            print("Error en creación de aplicaciones")
            return False
        
        # 4. Verificar aplicaciones creadas
        print("\n3. Verificando aplicaciones...")
        for app in applications:
            if DESFireSelectApplication.select_application(manager.connection, app['aid']):
                print(f"✅ Aplicación {app['type']} verificada: {toHexString(app['aid'])}")
            else:
                print(f"❌ Error verificando aplicación: {toHexString(app['aid'])}")
        
        print("\n🎉 ¡Todas las aplicaciones configuradas exitosamente!")
        return True
        
    except Exception as e:
        print(f"Error durante la configuración: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        manager.disconnect()

if __name__ == "__main__":
    print("DESFire EV1 - Sistema de Gestión Completo")
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
    
    print("✅ Todas las dependencias están disponibles")
    print()
    
    # Menú de opciones
    print("Seleccione una opción:")
    print("1. Ejemplo básico (original)")
    print("2. Ejemplo mejorado (con re-autenticación automática)")
    print("3. Solo configurar tarjeta nueva")
    
    try:
        choice = input("Opción (1-3): ").strip()
        
        if choice == "1":
            ejemplo_uso_completo()
        elif choice == "2":
            ejemplo_uso_mejorado()
        elif choice == "3":
            # Solo configurar tarjeta
            manager = DESFireManager(debug=True)
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