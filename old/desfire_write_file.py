#!/usr/bin/env python3
"""
DESFire EV1 - Escritura de Archivos
Implementación para escribir datos en archivos STD de DESFire EV1
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
    def pad_data_iso(data: bytes) -> bytes:
        """Aplica padding ISO (0x80 + 0x00s)"""
        padded = bytearray(data)
        padded.append(0x80)
        
        while len(padded) % 16 != 0:
            padded.append(0x00)
            
        return bytes(padded)
    
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
        
        reader_index = 0
        if len(reader_list) > 1:
            try:
                reader_index = int(input(f"Seleccione un lector (0-{len(reader_list)-1}): "))
                if reader_index < 0 or reader_index >= len(reader_list):
                    reader_index = 0
            except ValueError:
                reader_index = 0

        # Usar primer lector disponible
        # self.reader = reader_list[0]
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
# CLASE PARA AUTENTICACIÓN AES
# =============================================================================

class DESFireAuthenticateAdvanced:
    """Comandos de autenticación avanzados para DESFire EV1"""
    
    COMMAND_AES = 0xAA
    
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
    
    def _abort_transaction(self):
        """Aborta transacciones pendientes"""
        abort_command = bytes([0xA7])
        self.connection.send_command_unified(abort_command)
    
    def is_authenticated(self) -> bool:
        """Verifica si hay una autenticación activa"""
        return self.authenticated_key is not None and self.session_key is not None

# =============================================================================
# CLASE PARA ESCRITURA DE ARCHIVOS
# =============================================================================

class DESFireFileWriter:
    """Escritura de archivos para DESFire EV1"""
    
    def __init__(self, connection: DESFireReaderConnection, auth: DESFireAuthenticateAdvanced):
        self.connection = connection
        self.auth = auth
    
    def create_std_data_file(self, file_id: int, file_size: int, comm_mode: CommMode = CommMode.PLAIN,
                           read_key: int = 0xE, write_key: int = 0xE, 
                           read_write_key: int = 0xE, change_key: int = 0x0) -> bool:
        """
        Crea un archivo de datos estándar
        
        Args:
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
        if not self.auth.is_authenticated():
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
            
            # Para archivos públicos simples, usar 0x0EEE es problemático
            # Mejor usar 0xEEE0 para acceso completamente libre
            if read_key == 0xE and write_key == 0xE and read_write_key == 0xE:
                access_rights = 0xEEE0  # Acceso libre para lectura/escritura, solo master puede cambiar config
            
            # Construir comando CreateStdDataFile
            command_data = struct.pack('<BBH', file_id, comm_mode.value, access_rights)
            command_data += struct.pack('<L', file_size)[0:3]  # Solo 3 bytes para file size
            
            command = bytes([0xCD]) + command_data
            print(f"Comando CreateStdDataFile: {command.hex().upper()}")
            print(f"  File ID: {file_id}")
            print(f"  Comm Mode: {comm_mode.value}")
            print(f"  Access Rights: 0x{access_rights:04X}")
            print(f"  File Size: {file_size}")
            
            response = self.connection.send_command_unified(command)
            
            if response[0] == 0x00:
                print("¡Archivo creado exitosamente!")
                return True
            else:
                print(f"Error al crear archivo: {response[0]:02X}")
                return False
                
        except Exception as e:
            print(f"Error en creación de archivo: {e}")
            return False
    
    def write_data(self, file_id: int, offset: int, data: Union[bytes, str], comm_mode: CommMode = CommMode.PLAIN) -> bool:
        """
        Escribe datos en un archivo
        
        Args:
            file_id: ID del archivo
            offset: Posición inicial de escritura
            data: Datos a escribir
            comm_mode: Modo de comunicación del archivo
            
        Returns:
            bool: True si la escritura fue exitosa
        """
        if not self.auth.is_authenticated():
            print("Error: Debe estar autenticado para escribir archivos")
            return False
        
        print(f"\n=== Escribiendo datos en archivo #{file_id} (modo {comm_mode.name}) ===")
        
        try:
            # Convertir datos a bytes si es string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            print(f"Offset: {offset}")
            print(f"Datos ({len(data)} bytes): {data.hex().upper()}")
            print(f"Texto: {data.decode('utf-8', errors='ignore')}")
            
            if comm_mode == CommMode.PLAIN:
                # Escritura simple sin cifrado
                return self._write_plain_data(file_id, offset, data)
            elif comm_mode == CommMode.ENCRYPTED:
                # Escritura con cifrado completo
                return self._write_encrypted_data(file_id, offset, data)
            else:
                print(f"Error: Modo de comunicación {comm_mode.name} no soportado")
                return False
                
        except Exception as e:
            print(f"Error en escritura de datos: {e}")
            return False
    
    def _write_plain_data(self, file_id: int, offset: int, data: bytes) -> bool:
        """Escribe datos en modo PLAIN (sin cifrado)"""
        # Construir comando WriteData
        command_data = struct.pack('<BL', file_id, offset)[0:4]  # file_id + 3 bytes offset
        command = bytes([0x3D]) + command_data + data
        
        print(f"Comando WriteData (PLAIN): {command.hex().upper()}")
        
        response = self.connection.send_command_unified(command)
        
        if response[0] == 0x00:
            print("¡Datos escritos exitosamente!")
            return True
        else:
            print(f"Error al escribir datos: {response[0]:02X}")
            self._print_error_details(response[0])
            return False
    
    def _write_encrypted_data(self, file_id: int, offset: int, data: bytes) -> bool:
        """Escribe datos en modo ENCRYPTED (con cifrado)"""
        # 1. Primero cifrar los datos para conocer su longitud
        padded_data = self.auth.crypto_utils.pad_data_iso(data)
        print(f"Datos con padding: {padded_data.hex().upper()}")
        
        encrypted_data = bytes(self.auth.crypto_utils.aes_encrypt(
            padded_data, 
            self.auth.session_key, 
            self.auth.session_iv
        ))
        print(f"Datos cifrados: {encrypted_data.hex().upper()}")
        
        # 2. Actualizar IV para CMAC
        self.auth.session_iv = encrypted_data[-16:]
        
        # 3. Construir comando completo para CMAC:
        # cmd + file_id + offset + length + datos_cifrados
        # IMPORTANTE: Length es la longitud de los datos ORIGINALES (sin cifrar), no de los datos cifrados + CMAC
        original_data_length = len(data)  # Longitud de los datos originales
        
        print(f"Longitud datos originales: {original_data_length} bytes")
        print(f"Longitud datos cifrados: {len(encrypted_data)} bytes")
        
        cmac_command = bytes([0x3D])  # WriteData command
        cmac_command += struct.pack('<B', file_id)  # File ID
        cmac_command += struct.pack('<L', offset)[0:3]  # Offset (3 bytes, little-endian)
        cmac_command += struct.pack('<L', original_data_length)[0:3]  # Length (3 bytes, little-endian)
        cmac_command += encrypted_data  # Datos cifrados
        
        # 4. Calcular CMAC sobre el comando completo
        cmac = self._calculate_cmac(cmac_command)
        print(f"CMAC calculado: {cmac.hex().upper()}")
        
        # 5. Construir parámetros del comando APDU:
        command_params = struct.pack('<B', file_id)  # File ID
        command_params += struct.pack('<L', offset)[0:3]  # Offset (3 bytes, little-endian)
        command_params += struct.pack('<L', original_data_length)[0:3]  # Length (3 bytes, little-endian)
        
        # 6. Calcular Lc correcto: parámetros + datos cifrados + CMAC
        lc = len(command_params) + len(encrypted_data) + len(cmac)
        
        # 7. Construir comando APDU completo
        command = bytes([0x90, 0x3D, 0x00, 0x00, lc]) + command_params + encrypted_data + cmac + bytes([0x00])
        
        print(f"\n=== Comando WriteData corregido ===")
        print(f"APDU: {command.hex().upper()}")
        print(f"\nDesglose:")
        print(f"├── 90 3D 00 00: Encabezado APDU")
        print(f"├── {lc:02X}: Lc = {lc} bytes ({1+3+3+len(encrypted_data)+len(cmac)})")
        print(f"├── {file_id:02X}: File ID")
        print(f"├── {offset:06X}: Offset = {offset}")
        print(f"├── {original_data_length:06X}: Length = {original_data_length} bytes (datos originales)")
        print(f"├── Length en hex: {struct.pack('<L', original_data_length)[0:3].hex().upper()} (little-endian)")
        print(f"├── {encrypted_data.hex().upper()}: {len(encrypted_data)} bytes datos cifrados")
        print(f"├── {cmac.hex().upper()}: {len(cmac)} bytes CMAC")
        print(f"└── 00: Le")
        
        # Usar send_apdu directamente para el comando APDU completo
        response, sw1, sw2 = self.connection.send_apdu(list(command))
        
        # Procesar respuesta
        if sw1 == 0x90 and sw2 == 0x00:
            print("¡Datos escritos exitosamente!")
            return True
        elif sw1 == 0x91:
            if sw2 == 0x00:
                print("¡Datos escritos exitosamente!")
                return True
            else:
                print(f"Error al escribir datos: {sw2:02X}")
                self._print_error_details(sw2)
                return False
        else:
            print(f"Error al escribir datos: SW1={sw1:02X}, SW2={sw2:02X}")
            return False
    
    def _print_error_details(self, error_code: int):
        """Imprime detalles del código de error"""
        if error_code == 0x7E:
            print("Error: Parámetros inválidos")
        elif error_code == 0xAE:
            print("Error: Autenticación requerida")
        elif error_code == 0x9D:
            print("Error: Permisos insuficientes")
        elif error_code == 0xA0:
            print("Error: Archivo no encontrado")
        elif error_code == 0xBE:
            print("Error: Modo de comunicación incorrecto")
        elif error_code == 0xEE:
            print("Error: Archivo ya existe")
    
    
    def _calculate_cmac(self, data: bytes) -> bytes:
        """Calcula CMAC para los datos dados"""
        if not data:
            data = bytes()
        
        k1, k2 = self.auth.crypto_utils.generate_cmac_subkeys(self.auth.session_key)
        
        # Aplicar padding si es necesario
        if len(data) == 0 or len(data) % 16 != 0:
            padded_data = self.auth.crypto_utils.pad_data_iso(data)
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
        
        # Cifrar con CBC usando IV actual
        encrypted = bytes(self.auth.crypto_utils.aes_encrypt(
            cmac_data, self.auth.session_key, self.auth.session_iv
        ))
        
        # Actualizar IV de sesión y retornar primeros 8 bytes como CMAC
        self.auth.session_iv = encrypted[-16:]
        return encrypted[-16:][:8]
    
    def read_data(self, file_id: int, offset: int, length: int, comm_mode: CommMode = CommMode.PLAIN) -> Optional[bytes]:
        """
        Lee datos de un archivo
        
        Args:
            file_id: ID del archivo
            offset: Posición inicial de lectura
            length: Cantidad de bytes a leer
            comm_mode: Modo de comunicación del archivo
            
        Returns:
            bytes: Datos leídos o None si hay error
        """
        print(f"\n=== Leyendo datos de archivo #{file_id} (modo {comm_mode.name}) ===")
        
        try:
            print(f"Offset: {offset}")
            print(f"Longitud: {length}")
            
            # Construir comando ReadData
            command_data = struct.pack('<BL', file_id, offset)[0:4]  # file_id + 3 bytes offset
            command_data += struct.pack('<L', length)[0:3]  # 3 bytes length
            command = bytes([0xBD]) + command_data
            
            print(f"Comando ReadData: {command.hex().upper()}")
            
            response = self.connection.send_command_unified(command)
            
            if response[0] == 0x00:
                data = response[1:]
                print(f"Datos leídos ({len(data)} bytes): {data.hex().upper()}")
                
                if comm_mode == CommMode.PLAIN:
                    # Datos en texto plano
                    print(f"Texto: {data.decode('utf-8', errors='ignore')}")
                    return data
                elif comm_mode == CommMode.ENCRYPTED:
                    # Descifrar los datos
                    decrypted_data = self._decrypt_data_from_read(data)
                    if decrypted_data:
                        print(f"Datos descifrados: {decrypted_data.hex().upper()}")
                        print(f"Texto: {decrypted_data.decode('utf-8', errors='ignore')}")
                        return decrypted_data
                    else:
                        return None
                else:
                    print(f"Error: Modo de comunicación {comm_mode.name} no soportado")
                    return None
            else:
                print(f"Error al leer datos: {response[0]:02X}")
                return None
                
        except Exception as e:
            print(f"Error en lectura de datos: {e}")
            return None
    
    def _decrypt_data_from_read(self, encrypted_data: bytes) -> Optional[bytes]:
        """
        Descifra datos leídos de archivo con modo cifrado
        
        Args:
            encrypted_data: Datos cifrados
            
        Returns:
            bytes: Datos descifrados sin padding o None si hay error
        """
        try:
            # Descifrar usando clave de sesión y IV actual
            decrypted = bytes(self.auth.crypto_utils.aes_decrypt(
                encrypted_data,
                self.auth.session_key,
                self.auth.session_iv
            ))
            
            # Actualizar IV de sesión
            self.auth.session_iv = encrypted_data[-16:] if len(encrypted_data) >= 16 else self.auth.session_iv
            
            # Remover padding ISO (buscar 0x80 y remover todo después)
            try:
                padding_start = decrypted.index(0x80)
                return decrypted[:padding_start]
            except ValueError:
                # No se encontró padding ISO, devolver datos completos
                return decrypted
                
        except Exception as e:
            print(f"Error al descifrar datos: {e}")
            return None

# =============================================================================
# CLASE PARA SELECCIÓN DE APLICACIONES
# =============================================================================

class DESFireSelectApplication:
    """Comando SELECT APPLICATION para DESFire EV1"""
    
    COMMAND_CODE = 0x5A
    MASTER_APPLICATION_AID = [0x00, 0x00, 0x00]
    
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
        
        if len(aid) != 3:
            raise ValueError("AID debe ser de 3 bytes")
        
        apdu = [0x90, DESFireSelectApplication.COMMAND_CODE, 0x00, 0x00, 0x03] + aid + [0x00]
        response, sw1, sw2 = connection.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación {toHexString(aid)} seleccionada correctamente.")
            return True
        else:
            print(f"Error al seleccionar aplicación: SW={hex(sw1)}{hex(sw2)}")
            return False

# =============================================================================
# FUNCIÓN PRINCIPAL DE DEMOSTRACIÓN
# =============================================================================

def demo_write_file():
    """Demostración de escritura de archivos"""
    print("=== DESFire EV1 - Escritura de Archivos ===\n")
    
    # Verificar dependencias
    if not SMARTCARD_AVAILABLE or not CRYPTO_AVAILABLE:
        print("❌ Error: Dependencias faltantes")
        return False
    
    # Crear conexión
    connection = DESFireReaderConnection(debug=True)
    
    if not connection.connect_reader():
        print("Error: No se pudo conectar al lector")
        return False
    
    try:
        # Crear instancia de autenticación
        auth = DESFireAuthenticateAdvanced(connection)
        
        # Seleccionar aplicación (usar una aplicación existente)
        app_aid = [0xF0, 0x01, 0x01]  # Aplicación del ejemplo anterior
        if not DESFireSelectApplication.select_application(connection, app_aid):
            print("Error: No se pudo seleccionar la aplicación")
            return False
        
        # Autenticarse (usar la clave que se estableció anteriormente)
        master_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                           0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])
        
        if not auth.authenticate_aes(0, master_key):
            print("Error: No se pudo autenticar")
            return False
        
        # Crear instancia de escritor de archivos
        file_writer = DESFireFileWriter(connection, auth)
        
        # Usar archivo existente que sabemos que funciona del ejemplo original
        file_id = 2  # El archivo que ya fue creado exitosamente
        print(f"Usando archivo existente #{file_id}...")
        
        # Listar archivos existentes
        print("--- Listando archivos existentes ---")
        list_files_command = bytes([0x6F])  # GetFileIDs
        files_response = connection.send_command_unified(list_files_command)
        if files_response[0] == 0x00:
            file_ids = list(files_response[1:])
            print(f"Archivos encontrados: {[f'0x{fid:02X}' for fid in file_ids]}")
            if file_id not in file_ids:
                print(f"Archivo #{file_id} no encontrado. Creando nuevo archivo...")
                # Intentar crear el archivo que sabemos que funciona
                success = file_writer.create_std_data_file(
                    file_id=file_id, 
                    file_size=32, 
                    comm_mode=CommMode.ENCRYPTED,  # Usar el modo que sabemos que funciona
                    read_key=0x0,   # Clave master
                    write_key=0x0,  # Clave master
                    read_write_key=0x0,
                    change_key=0x0
                )
                if not success:
                    print("Error: No se pudo crear archivo")
                    return False
        else:
            print(f"Error listando archivos: {files_response[0]:02X}")
        
        # Verificar información del archivo creado
        print(f"\n--- Verificando archivo #{file_id} ---")
        get_file_settings = bytes([0xF5, file_id])  # GetFileSettings
        settings_response = connection.send_command_unified(get_file_settings)
        if settings_response[0] == 0x00:
            settings_data = settings_response[1:]
            print(f"Configuración del archivo: {settings_data.hex().upper()}")
            if len(settings_data) >= 7:
                file_type = settings_data[0]
                comm_settings = settings_data[1]
                access_rights = int.from_bytes(settings_data[2:4], 'little')
                file_size = int.from_bytes(settings_data[4:7], 'little')
                print(f"  Tipo: {file_type:02X}")
                print(f"  Comm Settings: {comm_settings:02X}")
                print(f"  Access Rights: {access_rights:04X}")
                print(f"  Tamaño: {file_size}")
        
        # Escribir datos de prueba
        test_data = "Hola DESFire!"
        print(f"\n--- Intentando escribir en archivo #{file_id} ---")
        
        # Determinar el modo de comunicación del archivo
        detected_comm_mode = CommMode.ENCRYPTED  # Por defecto asumir cifrado
        if 'comm_settings' in locals():
            if comm_settings == 0x00:
                detected_comm_mode = CommMode.PLAIN
                print("Archivo detectado en modo PLAIN")
            elif comm_settings == 0x03:
                detected_comm_mode = CommMode.ENCRYPTED
                print("Archivo detectado en modo ENCRYPTED")
            else:
                print(f"Archivo en modo desconocido: {comm_settings:02X}, usando ENCRYPTED")
        else:
            print("No se pudo obtener configuración, asumiendo modo ENCRYPTED")
        
        if file_writer.write_data(file_id, 0, test_data, detected_comm_mode):
            print("✅ Escritura exitosa")
            
            # Leer datos para verificar
            read_data = file_writer.read_data(file_id, 0, len(test_data), detected_comm_mode)
            if read_data:
                print("✅ Lectura exitosa")
                print(f"Datos verificados: '{read_data.decode('utf-8')}'")
                return True
            else:
                print("❌ Error en lectura")
                return False
        else:
            print("❌ Error en escritura")
            return False
            
    finally:
        connection.disconnect()

if __name__ == "__main__":
    print("DESFire EV1 - Escritura de Archivos")
    print("=" * 40)
    
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
    
    try:
        success = demo_write_file()
        if success:
            print("\n✅ ¡Demostración completada exitosamente!")
        else:
            print("\n❌ Error en la demostración")
            
    except KeyboardInterrupt:
        print("\nOperación cancelada por el usuario")
    except Exception as e:
        print(f"Error inesperado: {e}")
        import traceback
        traceback.print_exc()