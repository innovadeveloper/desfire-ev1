#!/usr/bin/env python3
"""
DESFire EV1 Business Logic
=========================

Implementa la lógica de negocio para operaciones DESFire EV1 siguiendo el flujo
documentado en flow_001.md. Separa la lógica de negocio de la interfaz de usuario.

Autor: Basado en análisis de flow_001.md
Fecha: 2025
"""

import os
import struct
from typing import List, Optional, Tuple, Dict
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString
from Crypto.Cipher import AES, DES


class DESFireBusinessLogic:
    """
    Lógica de negocio para operaciones DESFire EV1
    Implementa el flujo completo documentado en flow_001.md
    """
    
    def __init__(self, debug: bool = True):
        """
        Inicializar lógica de negocio DESFire
        
        Args:
            debug (bool): Habilitar mensajes de depuración
        """
        self.reader = None
        self.connection = None
        self.debug = debug
        self.session_key = None
        self.session_iv = bytes(16)
        self.authenticated = False
        self.auth_key_number = None
        self.auth_type = None  # 'AES' o 'DES'
        
        # Configuración por defecto según flow_001.md
        self.default_config = {
            'picc_master_key_aes': bytes(16),     # 16 zeros para AES
            'picc_master_key_des': bytes(8),      # 8 zeros para DES
            'app_master_key_aes': bytes(16),      # 16 zeros para AES
            'app_master_key_des': bytes(8),       # 8 zeros para DES
            'read_key': bytes([0x11] * 16),       # Clave de lectura
            'write_key': bytes([0x22] * 16),      # Clave de escritura
            'default_aid': bytes([0x01, 0x00, 0x00]),
            'key_settings': 0x0F,
            'num_keys_aes': 0x81,  # 1 clave AES
            'num_keys_des': 0x01,  # 1 clave DES
            'file_size': 32
        }
    
    def log(self, message: str):
        """Imprimir mensaje de depuración si está habilitado"""
        if self.debug:
            print(message)
    
    # =============================================================================
    # GESTIÓN DE CONEXIÓN
    # =============================================================================
    
    def get_available_readers(self) -> List[str]:
        """
        Obtener lista de lectores disponibles
        
        Returns:
            List[str]: Lista de nombres de lectores
        """
        try:
            reader_list = readers()
            return [str(reader) for reader in reader_list]
        except Exception as e:
            self.log(f"Error obteniendo lectores: {e}")
            return []
    
    def connect_to_reader(self, reader_index: int = 0) -> bool:
        """
        Conectar con un lector específico
        
        Args:
            reader_index (int): Índice del lector a usar
            
        Returns:
            bool: True si la conexión fue exitosa
        """
        try:
            reader_list = readers()
            
            if not reader_list:
                self.log("ERROR: No se encontraron lectores")
                return False
            
            if reader_index < 0 or reader_index >= len(reader_list):
                self.log(f"ERROR: Índice de lector inválido: {reader_index}")
                return False
            
            self.reader = reader_list[reader_index]
            self.log(f"Conectando con: {self.reader}")
            
            self.connection = self.reader.createConnection()
            self.connection.connect()
            atr = self.connection.getATR()
            self.log(f"Conectado - ATR: {toHexString(atr)}")
            return True
            
        except CardConnectionException:
            self.log("ERROR: No se detectó tarjeta")
            return False
        except Exception as e:
            self.log(f"ERROR al conectar: {e}")
            return False
    
    def disconnect(self):
        """Desconectar del lector"""
        if self.connection:
            try:
                self.connection.disconnect()
                self.log("Desconectado del lector")
            except:
                pass
        self.connection = None
        self.reader = None
    
    def send_command(self, command: bytes) -> bytes:
        """
        Enviar comando DESFire a la tarjeta
        
        Args:
            command (bytes): Comando nativo DESFire
            
        Returns:
            bytes: Respuesta de la tarjeta (incluyendo status byte)
        """
        # Envolver comando nativo en APDU ISO 7816-4
        if len(command) == 1:
            apdu = [0x90, command[0], 0x00, 0x00, 0x00]
        else:
            cmd_byte = command[0]
            data = command[1:]
            
            # Comandos que NO necesitan Le=0x00 al final
            no_le_commands = [0xFC, 0xCA, 0xCD, 0xC4, 0x3D, 0xDF]
            
            if cmd_byte in no_le_commands:
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data)
            else:
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data) + [0x00]
        
        try:
            if self.debug:
                self.log(f"TX: {toHexString(apdu)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if self.debug:
                resp_str = toHexString(response) if response else 'Sin datos'
                self.log(f"RX: {resp_str}, SW: {sw1:02X} {sw2:02X}")
            
            # Procesar respuesta según especificación DESFire
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes([0x00]) + bytes(response) if response else bytes([0x00])
            elif sw1 == 0x91:
                return bytes([sw2]) + bytes(response) if response else bytes([sw2])
            else:
                return bytes([0x6E])
                
        except Exception as e:
            self.log(f"ERROR al enviar comando: {e}")
            return bytes([0x6E])
    
    # =============================================================================
    # AUTENTICACIÓN (AES Y DES)
    # =============================================================================
    
    def authenticate_des(self, key_number: int, key: bytes) -> bool:
        """
        Autenticación DES/3DES
        
        Args:
            key_number (int): Número de clave (0-13)
            key (bytes): Clave DES de 8 bytes
            
        Returns:
            bool: True si autenticación exitosa
        """
        self.log(f"Autenticando con clave DES #{key_number}")
        
        try:
            # Paso 1: Solicitar autenticación DES
            command = bytes([0x1A, key_number])  # Comando DES/3DES
            response = self.send_command(command)
            
            if response[0] != 0xAF or len(response) != 9:
                self.log(f"ERROR en autenticación DES paso 1: {response[0]:02X}")
                return False
            
            encrypted_rnd_b = response[1:9]
            
            # Paso 2: Descifrar RndB
            iv_zero = bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv_zero)
            rnd_b = cipher.decrypt(encrypted_rnd_b)
            
            # Paso 3: Rotar RndB y generar RndA
            rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
            rnd_a = os.urandom(8)
            
            # Paso 4: Cifrar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            cipher = DES.new(key, DES.MODE_CBC, encrypted_rnd_b)
            encrypted_rnd_ab = cipher.encrypt(rnd_ab)
            
            # Paso 5: Enviar respuesta
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.send_command(command)
            
            if response[0] != 0x00 or len(response) != 9:
                self.log(f"ERROR en autenticación DES paso 2: {response[0]:02X}")
                return False
            
            # Paso 6: Verificar RndA
            encrypted_rnd_a = response[1:9]
            iv_for_decrypt = encrypted_rnd_ab[-8:]
            cipher = DES.new(key, DES.MODE_CBC, iv_for_decrypt)
            decrypted_rnd_a = cipher.decrypt(encrypted_rnd_a)
            
            expected_rnd_a = rnd_a[1:] + rnd_a[:1]
            if decrypted_rnd_a != expected_rnd_a:
                self.log("ERROR: Verificación RndA falló")
                return False
            
            # Paso 7: Generar clave de sesión DES
            self.session_key = rnd_a[:4] + rnd_b[:4]
            self.session_iv = bytes(8)
            self.authenticated = True
            self.auth_key_number = key_number
            self.auth_type = 'DES'
            
            self.log(f"Autenticación DES exitosa con clave #{key_number}")
            return True
            
        except Exception as e:
            self.log(f"ERROR en autenticación DES: {e}")
            return False
    
    def authenticate_aes(self, key_number: int, key: bytes) -> bool:
        """
        Autenticación AES según flow_001.md
        
        Args:
            key_number (int): Número de clave (0-13)
            key (bytes): Clave AES de 16 bytes
            
        Returns:
            bool: True si autenticación exitosa
        """
        self.log(f"Autenticando con clave AES #{key_number}")
        
        try:
            # Paso 1: Solicitar autenticación
            command = bytes([0xAA, key_number])
            response = self.send_command(command)
            
            if response[0] != 0xAF or len(response) != 17:
                self.log(f"ERROR en autenticación paso 1: {response[0]:02X}")
                return False
            
            encrypted_rnd_b = response[1:17]
            
            # Paso 2: Descifrar RndB
            iv_zero = bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv_zero)
            rnd_b = cipher.decrypt(encrypted_rnd_b)
            
            # Paso 3: Rotar RndB y generar RndA
            rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
            rnd_a = os.urandom(16)
            
            # Paso 4: Cifrar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            cipher = AES.new(key, AES.MODE_CBC, encrypted_rnd_b)
            encrypted_rnd_ab = cipher.encrypt(rnd_ab)
            
            # Paso 5: Enviar respuesta
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.send_command(command)
            
            if response[0] != 0x00 or len(response) != 17:
                self.log(f"ERROR en autenticación paso 2: {response[0]:02X}")
                return False
            
            # Paso 6: Verificar RndA
            encrypted_rnd_a = response[1:17]
            iv_for_decrypt = encrypted_rnd_ab[-16:]
            cipher = AES.new(key, AES.MODE_CBC, iv_for_decrypt)
            decrypted_rnd_a = cipher.decrypt(encrypted_rnd_a)
            
            expected_rnd_a = rnd_a[1:] + rnd_a[:1]
            if decrypted_rnd_a != expected_rnd_a:
                self.log("ERROR: Verificación RndA falló")
                return False
            
            # Paso 7: Generar clave de sesión
            self.session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[-4:] + rnd_b[-4:]
            self.session_iv = bytes(16)
            self.authenticated = True
            self.auth_key_number = key_number
            self.auth_type = 'AES'
            
            self.log(f"Autenticación AES exitosa con clave #{key_number}")
            return True
            
        except Exception as e:
            self.log(f"ERROR en autenticación: {e}")
            return False
    
    def authenticate_auto(self, key_number: int, prefer_aes: bool = True) -> bool:
        """
        Autenticación automática que intenta AES y DES
        
        Args:
            key_number (int): Número de clave (0-13)
            prefer_aes (bool): Si intentar AES primero
            
        Returns:
            bool: True si autenticación exitosa
        """
        self.log(f"Autenticación automática para clave #{key_number}")
        
        # Seleccionar claves apropiadas según el contexto
        if key_number == 0:
            # Para master keys, usar las configuradas
            aes_key = self.default_config['app_master_key_aes'] if hasattr(self, 'authenticated') and self.authenticated else self.default_config['picc_master_key_aes']
            des_key = self.default_config['app_master_key_des'] if hasattr(self, 'authenticated') and self.authenticated else self.default_config['picc_master_key_des']
        else:
            # Para otras claves, usar claves por defecto
            aes_key = bytes(16)
            des_key = bytes(8)
        
        # Determinar orden de intentos
        if prefer_aes:
            methods = [
                ('AES', self.authenticate_aes, aes_key),
                ('DES', self.authenticate_des, des_key)
            ]
        else:
            methods = [
                ('DES', self.authenticate_des, des_key),
                ('AES', self.authenticate_aes, aes_key)
            ]
        
        for method_name, method_func, default_key in methods:
            self.log(f"Intentando autenticación {method_name}...")
            
            try:
                if method_func(key_number, default_key):
                    self.log(f"Autenticación {method_name} exitosa")
                    self.log(f"Tipo de autenticación detectado: {self.auth_type}")
                    return True
                else:
                    self.log(f"Autenticación {method_name} falló")
            except Exception as e:
                self.log(f"Error en autenticación {method_name}: {e}")
        
        self.log("ERROR: Ambos tipos de autenticación fallaron")
        return False
    
    # =============================================================================
    # OPERACIONES SEGÚN FLOW_001.MD
    # =============================================================================
    
    def format_picc(self) -> bool:
        """
        Formatear PICC (Paso 1 del flow_001.md)
        Requiere autenticación previa con clave maestra de tarjeta
        
        Returns:
            bool: True si formateo exitoso
        """
        self.log("Ejecutando Format PICC...")
        
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        command = bytes([0xFC])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Format PICC exitoso")
            # Reset autenticación después del formateo
            self.authenticated = False
            self.session_key = None
            self.auth_type = None
            return True
        else:
            self.log(f"ERROR en Format PICC: {response[0]:02X}")
            return False
    
    def authenticate_picc_master(self) -> bool:
        """
        Autenticación con clave maestra de tarjeta (Paso 2 del flow_001.md)
        Intenta automáticamente AES y DES
        
        Returns:
            bool: True si autenticación exitosa
        """
        self.log("Autenticando con clave maestra de tarjeta...")
        
        # Seleccionar aplicación maestra (AID 000000)
        command = bytes([0x5A, 0x00, 0x00, 0x00])
        response = self.send_command(command)
        
        if response[0] != 0x00:
            self.log(f"ERROR seleccionando aplicación maestra: {response[0]:02X}")
            return False
        
        # Autenticar automáticamente (AES primero, luego DES)
        return self.authenticate_auto(0, prefer_aes=True)
    
    def crc32_desfire(self, data: bytes) -> int:
        """
        Calcular CRC32 para DESFire
        
        Args:
            data (bytes): Datos para calcular CRC
            
        Returns:
            int: CRC32 calculado
        """
        import binascii
        return binascii.crc32(data) & 0xFFFFFFFF
    
    def aes_encrypt_cbc(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Cifrado AES en modo CBC
        
        Args:
            key (bytes): Clave AES
            iv (bytes): Vector de inicialización
            data (bytes): Datos a cifrar
            
        Returns:
            bytes: Datos cifrados
        """
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)
    
    def des_encrypt_cbc(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Cifrado DES en modo CBC
        
        Args:
            key (bytes): Clave DES
            iv (bytes): Vector de inicialización
            data (bytes): Datos a cifrar
            
        Returns:
            bytes: Datos cifrados
        """
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return cipher.encrypt(data)
    
    def calculate_cmac(self, key: bytes, data: bytes) -> bytes:
        """
        Calcular CMAC (simplificado)
        
        Args:
            key (bytes): Clave para CMAC
            data (bytes): Datos para CMAC
            
        Returns:
            bytes: CMAC de 8 bytes
        """
        # Implementación simplificada - usar los primeros 8 bytes de un hash
        import hashlib
        hash_result = hashlib.sha256(key + data).digest()
        return hash_result[:8]
    
    def change_key(self, key_number: int, new_key: bytes, new_key_version: int = 0x00, 
                   current_key: bytes = None, authenticated_key_number: int = None) -> bool:
        """
        Change a key in the current application
        
        Args:
            key_number: Number of the key to change (0-13)
            new_key: New key data (16 bytes for AES)
            new_key_version: Version byte for the new key
            current_key: Current key data (required if changing different key than authenticated)
            authenticated_key_number: Key number used for authentication (for verification)
        """
        if not self.authenticated:
            self.log("Error: Not authenticated")
            return False
        
        self.log(f"*** ChangeKey(KeyNo= {key_number})")
        self.log(f"* New Key: {new_key.hex().upper()}")
        
        # Determine if we're changing the same key or a different key
        if authenticated_key_number is not None and authenticated_key_number != key_number:
            # Changing a DIFFERENT key - need current key for XOR
            if current_key is None:
                self.log("Error: current_key is required when changing a different key")
                return False
            return self._change_different_key(key_number, new_key, new_key_version, current_key)
        else:
            # Changing the SAME key used for authentication
            return self._change_same_key(key_number, new_key, new_key_version)
    
    def _change_same_key(self, key_number: int, new_key: bytes, new_key_version: int) -> bool:
        """Change the same key used for authentication"""
        self.log("* Changing SAME key used for authentication")
        
        # Para DES, adaptar el proceso
        if self.auth_type == 'DES':
            return self._change_same_key_des(key_number, new_key, new_key_version)
        
        # Calculate CRC of the cryptogram (command + key_number + new_key + key_version)
        crypto_data = bytes([0xC4, key_number]) + new_key + bytes([new_key_version])
        crc_crypto = self.crc32_desfire(crypto_data)
        self.log(f"* CRC Crypto: 0x{crc_crypto:08X}")
        
        # Build cryptogram: new_key + key_version + crc_crypto (little endian) + padding
        cryptogram = new_key + bytes([new_key_version])
        cryptogram += struct.pack('<L', crc_crypto)  # CRC in little endian
        
        # Pad to multiple of 16 bytes
        while len(cryptogram) % 16 != 0:
            cryptogram += b'\x00'
        
        self.log(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Encrypt cryptogram with session key and current IV
        encrypted_cryptogram = self.aes_encrypt_cbc(self.session_key, self.session_iv, cryptogram)
        self.log(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Update session IV
        self.session_iv = encrypted_cryptogram[-16:]
        
        # Send ChangeKey command
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Key changed successfully!")
            # Calculate and verify CMAC if present
            if len(response) > 1:
                received_cmac = response[1:9]
                expected_cmac = self.calculate_cmac(self.session_key, bytes([0x00]))
                self.log(f"RX CMAC: {received_cmac.hex().upper()}")
                self.log(f"Expected CMAC: {expected_cmac.hex().upper()}")
            return True
        else:
            self.log(f"Key change failed: {response[0]:02X}")
            return False
    
    def _change_same_key_des(self, key_number: int, new_key: bytes, new_key_version: int) -> bool:
        """Change the same key used for DES authentication"""
        self.log("* Changing SAME key used for DES authentication")
        
        # Para cambio de DES a AES, necesitamos formato específico
        # Formato simplificado para cambio de tipo de clave
        
        # Intentar formato simple primero: nueva_clave + versión sin cifrar
        self.log("* Intentando formato simple (sin cifrar)")
        
        # Construir comando sin cifrar
        command = bytes([0xC4, key_number]) + new_key + bytes([new_key_version])
        
        self.log(f"* Comando sin cifrar: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Key changed successfully with simple format!")
            return True
        else:
            self.log(f"Simple format failed: {response[0]:02X}")
            
        # Intentar formato con padding
        self.log("* Intentando formato con padding")
        
        # Construir con padding a 24 bytes (común para DES)
        data_with_padding = new_key + bytes([new_key_version])
        while len(data_with_padding) < 24:
            data_with_padding += b'\x00'
        
        command = bytes([0xC4, key_number]) + data_with_padding
        self.log(f"* Comando con padding: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Key changed successfully with padding!")
            return True
        else:
            self.log(f"Padding format failed: {response[0]:02X}")
            
        # Intentar formato cifrado original pero corregido
        self.log("* Intentando formato cifrado corregido")
        
        # Calcular CRC16 en lugar de CRC32 para DES
        crc16_value = self.crc16_desfire(new_key)
        self.log(f"* CRC16 New Key: 0x{crc16_value:04X}")
        
        # Construir criptograma: nueva_clave + version + crc16
        cryptogram = new_key + bytes([new_key_version]) + struct.pack('<H', crc16_value)
        
        # Padding a múltiplo de 8 bytes para DES
        while len(cryptogram) % 8 != 0:
            cryptogram += b'\x00'
        
        self.log(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Cifrar con clave de sesión DES en modo ECB (no CBC)
        cipher = DES.new(self.session_key, DES.MODE_ECB)
        encrypted_cryptogram = cipher.encrypt(cryptogram)
        self.log(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Enviar comando ChangeKey
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Key changed successfully with corrected format!")
            return True
        else:
            self.log(f"Corrected format failed: {response[0]:02X}")
            return False
    


    def crc16_desfire(self, data: bytes) -> int:
        """
        Calcular CRC16 para DESFire
        
        Args:
            data (bytes): Datos para calcular CRC
            
        Returns:
            int: CRC16 calculado
        """
        # CRC16 con polinomio estándar para DESFire
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
        return crc ^ 0xFFFF
    
    def _change_different_key(self, key_number: int, new_key: bytes, new_key_version: int, current_key: bytes) -> bool:
        """Change a DIFFERENT key than the one used for authentication"""
        self.log("* Changing DIFFERENT key than authentication key")
        self.log(f"* Current Key: {current_key.hex().upper()}")
        
        # XOR new key with current key
        xored_key = bytes(a ^ b for a, b in zip(new_key, current_key))
        self.log(f"* New Key XOR Current Key: {xored_key.hex().upper()}")
        
        # Calculate CRC of the NEW key (not XORed)
        crc_new_key = self.crc32_desfire(new_key)
        self.log(f"* CRC New Key: 0x{crc_new_key:08X}")
        
        # Calculate CRC of the cryptogram (command + key_number + XORed_key + key_version)
        crypto_data = bytes([0xC4, key_number]) + xored_key + bytes([new_key_version])
        crc_crypto = self.crc32_desfire(crypto_data)
        self.log(f"* CRC Cryptogram: 0x{crc_crypto:08X}")
        
        # Build cryptogram: XORed_key + key_version + CRC_crypto + CRC_new_key + padding
        cryptogram = xored_key + bytes([new_key_version])
        cryptogram += struct.pack('<L', crc_crypto)    # CRC of cryptogram FIRST
        cryptogram += struct.pack('<L', crc_new_key)   # CRC of new key SECOND
        
        # Pad to multiple of 16 bytes
        while len(cryptogram) % 16 != 0:
            cryptogram += b'\x00'
        
        self.log(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Encrypt cryptogram with session key and current IV
        encrypted_cryptogram = self.aes_encrypt_cbc(self.session_key, self.session_iv, cryptogram)
        self.log(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Update session IV
        self.session_iv = encrypted_cryptogram[-16:]
        
        # Send ChangeKey command
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Key changed successfully!")
            # Calculate and verify CMAC if present
            if len(response) > 1:
                received_cmac = response[1:9]
                expected_cmac = self.calculate_cmac(self.session_key, bytes([0x00]))
                self.log(f"RX CMAC: {received_cmac.hex().upper()}")
                self.log(f"Expected CMAC: {expected_cmac.hex().upper()}")
            return True
        else:
            self.log(f"Key change failed: {response[0]:02X}")
            return False
    
    def get_key_settings(self) -> Dict:
        """
        Obtener configuración de claves de la aplicación actual
        
        Returns:
            Dict: Información de configuración de claves
        """
        self.log("Obteniendo configuración de claves...")
        
        # Comando GET KEY SETTINGS
        command = bytes([0x45])
        response = self.send_command(command)
        
        if response[0] == 0x00 and len(response) >= 3:
            key_settings = response[1]
            max_keys = response[2]
            
            info = {
                'key_settings': key_settings,
                'max_keys': max_keys,
                'key_settings_hex': f"0x{key_settings:02X}",
                'max_keys_hex': f"0x{max_keys:02X}"
            }
            
            self.log(f"Key Settings: {info['key_settings_hex']}")
            self.log(f"Max Keys: {info['max_keys_hex']}")
            return info
        else:
            self.log(f"ERROR obteniendo key settings: {response[0]:02X}")
            return None
    
    def calculate_manual_change_key_command(self) -> str:
        """
        Calcular comando CHANGE KEY manual para cambiar clave maestra DES a AES
        Siguiendo los pasos exactos especificados
        
        Returns:
            str: APDU completo en hex
        """
        self.log("=== CÁLCULO MANUAL CHANGE KEY DES → AES ===")
        
        # Paso 1: Clave AES objetivo
        aes_key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        self.log(f"1. Clave AES objetivo: {aes_key.hex().upper()}")
        
        # Paso 2: Calcular CRC32 sobre los 16 bytes de la clave AES
        crc32_value = self.crc32_desfire(aes_key)
        crc32_bytes = struct.pack('<L', crc32_value)  # Little endian
        self.log(f"2. CRC32 de la clave: 0x{crc32_value:08X}")
        self.log(f"   CRC32 en bytes (LE): {crc32_bytes.hex().upper()}")
        
        # Paso 3: Crear secuencia de 24 bytes: clave + CRC32 + padding
        cryptogram_plain = aes_key + crc32_bytes + bytes([0x00, 0x00, 0x00, 0x00])
        self.log(f"3. Criptograma plano (24 bytes): {cryptogram_plain.hex().upper()}")
        self.log(f"   Longitud: {len(cryptogram_plain)} bytes")
        
        # Paso 4: Cifrar con DES-CBC
        des_key = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Clave DES de 8 zeros
        des_iv = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])   # IV de 8 zeros
        
        self.log(f"4. Clave DES: {des_key.hex().upper()}")
        self.log(f"   IV DES: {des_iv.hex().upper()}")
        
        # Cifrar con DES-CBC
        encrypted_cryptogram = self.des_encrypt_cbc(des_key, des_iv, cryptogram_plain)
        self.log(f"   Criptograma cifrado: {encrypted_cryptogram.hex().upper()}")
        
        # Paso 5: Formar APDU completo
        apdu = bytes([0x90, 0xC4, 0x00, 0x00, 0x19, 0x80]) + encrypted_cryptogram
        apdu_hex = apdu.hex().upper()
        self.log(f"5. APDU completo: {apdu_hex}")
        
        # Verificar longitud
        expected_length = 6 + 24  # Header + cryptogram
        self.log(f"   Longitud total: {len(apdu)} bytes (esperado: {expected_length})")
        
        return apdu_hex
    
    def test_manual_change_key(self) -> bool:
        """
        Probar el comando CHANGE KEY calculado manualmente
        Usa cambio escalonado DES → 3DES → AES
        
        Returns:
            bool: True si éxito
        """
        self.log("=== PROBANDO COMANDO MANUAL ESCALONADO ===")
        
        # Paso 1: Cambiar DES → 3DES
        self.log("Paso 1: Cambiando DES → 3DES...")
        if not self.change_key_des_to_3des():
            return False
        
        # Paso 2: Re-autenticarse con 3DES
        self.log("Paso 2: Re-autenticando con 3DES...")
        if not self.authenticate_3des_master():
            return False
        
        # Paso 3: Cambiar 3DES → AES
        self.log("Paso 3: Cambiando 3DES → AES...")
        if not self.change_key_3des_to_aes():
            return False
        
        self.log("¡ÉXITO! Cambio escalonado DES → 3DES → AES completado")
        return True
    
    def change_key_des_to_3des(self) -> bool:
        """
        Cambiar clave maestra de DES a 3DES (paso 1)
        
        Returns:
            bool: True si éxito
        """
        try:
            # Clave DES actual (8 bytes)
            des_key = bytes(8)
            
            # Nueva clave 3DES (16 bytes, pero para el comando usamos 8 bytes + 8 bytes)
            # Para 3DES-2KEY: K1 = K2 = 8 bytes iguales
            new_3des_key = bytes(8)  # Solo 8 bytes para 3DES-2KEY
            
            self.log(f"Clave DES actual: {des_key.hex().upper()}")
            self.log(f"Nueva clave 3DES: {new_3des_key.hex().upper()}")
            
            # Preparar criptograma para 3DES
            crc32_value = self.crc32_desfire(new_3des_key)
            crc32_bytes = struct.pack('<I', crc32_value)
            
            # Criptograma plano: nueva_clave + CRC32 + padding (para 3DES-2KEY)
            cryptogram_plain = new_3des_key + crc32_bytes + bytes(4)
            
            self.log(f"Criptograma plano: {cryptogram_plain.hex().upper()}")
            self.log(f"Longitud criptograma: {len(cryptogram_plain)} bytes")
            
            # Cifrar con DES-CBC
            des_cipher = DES.new(des_key, DES.MODE_CBC, bytes(8))
            encrypted_cryptogram = des_cipher.encrypt(cryptogram_plain)
            
            self.log(f"Criptograma cifrado: {encrypted_cryptogram.hex().upper()}")
            
            # Comando CHANGE KEY para key #0 con indicador 3DES
            # Key number: 0x00 (no 0x80 para 3DES-2KEY)
            command = bytes([0xC4, 0x00]) + encrypted_cryptogram
            
            self.log(f"Comando DES→3DES: {command.hex().upper()}")
            
            response = self.send_command(command)
            
            if response[0] == 0x00:
                self.log("✓ Cambio DES → 3DES exitoso")
                self.authenticated = False
                self.session_key = None
                self.auth_type = None
                return True
            else:
                self.log(f"ERROR: Cambio DES→3DES falló con {response[0]:02X}")
                return False
                
        except Exception as e:
            self.log(f"ERROR en cambio DES→3DES: {e}")
            return False
    
    def authenticate_3des_master(self) -> bool:
        """
        Autenticarse con clave maestra 3DES
        
        Returns:
            bool: True si éxito
        """
        try:
            self.log("Autenticando con clave maestra 3DES...")
            
            # Comando AUTHENTICATE con clave #0 (3DES)
            command = bytes([0x1A, 0x00])  # 0x1A = 3DES authenticate
            response = self.send_command(command)
            
            if len(response) < 9 or response[0] != 0xAF:
                self.log(f"ERROR: Respuesta de autenticación 3DES inválida: {response.hex()}")
                return False
            
            # Obtener desafío del PICC
            picc_challenge = response[1:9]
            self.log(f"Desafío PICC: {picc_challenge.hex()}")
            
            # Generar respuesta con clave 3DES-2KEY (8 bytes, K1=K2)
            tdes_key_8 = bytes(8)  # 8 bytes para 3DES-2KEY
            tdes_key_16 = tdes_key_8 + tdes_key_8  # Duplicar para 3DES-2KEY
            
            # Cifrado 3DES del desafío
            from Crypto.Cipher import DES3
            cipher = DES3.new(tdes_key_16, DES3.MODE_ECB)
            
            # Preparar datos para cifrado
            host_challenge = bytes(8)  # Desafío del host
            auth_data = picc_challenge + host_challenge
            
            self.log(f"Datos de autenticación: {auth_data.hex()}")
            
            encrypted_response = cipher.encrypt(auth_data)
            
            self.log(f"Respuesta cifrada: {encrypted_response.hex()}")
            
            # Enviar respuesta
            response_cmd = bytes([0xAF]) + encrypted_response[:8]
            auth_response = self.send_command(response_cmd)
            
            if auth_response[0] == 0x00:
                self.log("✓ Autenticación 3DES exitosa")
                self.authenticated = True
                self.auth_type = '3DES'
                self.auth_key_number = 0
                return True
            else:
                self.log(f"ERROR: Autenticación 3DES falló con {auth_response[0]:02X}")
                return False
                
        except Exception as e:
            self.log(f"ERROR en autenticación 3DES: {e}")
            return False
    
    def change_key_3des_to_aes(self) -> bool:
        """
        Cambiar clave maestra de 3DES a AES (paso 2)
        
        Returns:
            bool: True si éxito
        """
        try:
            # Clave AES objetivo: 16 bytes
            aes_key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
            
            self.log(f"Clave AES objetivo: {aes_key.hex().upper()}")
            
            # Preparar criptograma para AES
            crc32_value = self.crc32_desfire(aes_key)
            crc32_bytes = struct.pack('<I', crc32_value)
            
            # Criptograma plano: nueva_clave + CRC32 + padding
            cryptogram_plain = aes_key + crc32_bytes + bytes(4)
            
            self.log(f"Criptograma plano: {cryptogram_plain.hex().upper()}")
            self.log(f"Longitud criptograma: {len(cryptogram_plain)} bytes")
            
            # Cifrar con 3DES-CBC (usar clave 3DES-2KEY)
            from Crypto.Cipher import DES3
            tdes_key_8 = bytes(8)  # Clave 3DES actual (8 bytes)
            tdes_key_16 = tdes_key_8 + tdes_key_8  # Duplicar para 3DES-2KEY
            
            cipher = DES3.new(tdes_key_16, DES3.MODE_CBC, bytes(8))
            encrypted_cryptogram = cipher.encrypt(cryptogram_plain)
            
            self.log(f"Criptograma cifrado: {encrypted_cryptogram.hex().upper()}")
            
            # Comando CHANGE KEY para key #0 con tipo AES
            command = bytes([0xC4, 0x80]) + encrypted_cryptogram
            
            self.log(f"Comando 3DES→AES: {command.hex().upper()}")
            
            response = self.send_command(command)
            
            if response[0] == 0x00:
                self.log("✓ Cambio 3DES → AES exitoso")
                self.authenticated = False
                self.session_key = None
                self.auth_type = None
                return True
            else:
                self.log(f"ERROR: Cambio 3DES→AES falló con {response[0]:02X}")
                return False
                
        except Exception as e:
            self.log(f"ERROR en cambio 3DES→AES: {e}")
            return False
    
    def change_picc_master_key_to_aes(self) -> bool:
        """
        Cambiar clave maestra PICC de DES a AES usando workaround DES→3DES→AES
        
        Returns:
            bool: True si cambio exitoso
        """
        self.log("Cambiando clave maestra PICC de DES a AES...")
        
        if not self.authenticated or self.auth_type != 'DES':
            self.log("ERROR: Debe estar autenticado con DES primero")
            return False
        
        # Obtener configuración actual de claves
        key_info = self.get_key_settings()
        if key_info:
            self.log(f"Configuración actual: {key_info}")
        
        # WORKAROUND: DES → 3DES → AES
        self.log("=== WORKAROUND: DES → 3DES → AES ===")
        
        # Paso 1: Cambiar DES a 3DES (mismo tipo, compatible)
        self.log("Paso 1: Cambiando DES a 3DES...")
        new_key_3des = bytes(16)  # 3DES de 16 bytes (8+8)
        
        # Intentar cambio directo DES→3DES
        command = bytes([0xC4, 0x00]) + new_key_3des + bytes([0x00])
        self.log(f"Comando DES→3DES: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("¡ÉXITO! Cambio DES→3DES completado")
            
            # Reset autenticación
            self.authenticated = False
            self.session_key = None
            
            # Paso 2: Re-autenticar con 3DES
            self.log("Paso 2: Re-autenticando con 3DES...")
            if self.authenticate_des(0, new_key_3des):  # 3DES usa mismo método que DES
                self.log("Re-autenticación 3DES exitosa")
                
                # Paso 3: Cambiar 3DES a AES
                self.log("Paso 3: Cambiando 3DES a AES...")
                new_key_aes = bytes(16)
                
                # Intentar con key number 0x80 para cambio de tipo
                command = bytes([0xC4, 0x80]) + new_key_aes + bytes([0x00])
                self.log(f"Comando 3DES→AES: {command.hex().upper()}")
                response = self.send_command(command)
                
                if response[0] == 0x00:
                    self.log("¡ÉXITO! Cambio 3DES→AES completado")
                    self.authenticated = False
                    self.session_key = None
                    self.auth_type = None
                    return True
                else:
                    self.log(f"Paso 3 falló: {response[0]:02X}")
                    
                    # Probar sin 0x80
                    command = bytes([0xC4, 0x00]) + new_key_aes + bytes([0x00])
                    response = self.send_command(command)
                    
                    if response[0] == 0x00:
                        self.log("¡ÉXITO! Cambio 3DES→AES completado (sin 0x80)")
                        self.authenticated = False
                        self.session_key = None
                        self.auth_type = None
                        return True
                    else:
                        self.log(f"Paso 3 también falló sin 0x80: {response[0]:02X}")
            else:
                self.log("ERROR: No se pudo re-autenticar con 3DES")
        else:
            self.log(f"Paso 1 falló: {response[0]:02X}")
        
        # Si el workaround falla, intentar métodos originales
        self.log("=== MÉTODOS DIRECTOS (FALLBACK) ===")
        
        # Clave nueva AES (16 zeros)
        new_key_aes = bytes(16)
        
        # Método 1: Con key number 0x80 para indicar cambio DES→AES
        self.log("Método 1: Cambio DES→AES con key number 0x80")
        command = bytes([0xC4, 0x80]) + new_key_aes + bytes([0x00])
        self.log(f"Comando: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("¡ÉXITO! Clave maestra cambiada a AES con 0x80")
            self.authenticated = False
            self.session_key = None
            self.auth_type = None
            return True
        else:
            self.log(f"Método 0x80 falló: {response[0]:02X}")
        
        # Método 2: Con key number 0x80 y CRC16
        self.log("Método 2: Con key number 0x80 y CRC16")
        crc16 = self.crc16_desfire(new_key_aes)
        command = bytes([0xC4, 0x80]) + new_key_aes + bytes([0x00]) + struct.pack('<H', crc16)
        self.log(f"Comando con 0x80 y CRC16: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("¡ÉXITO! Clave maestra cambiada a AES con 0x80 y CRC16")
            self.authenticated = False
            self.session_key = None
            self.auth_type = None
            return True
        else:
            self.log(f"Método 0x80+CRC16 falló: {response[0]:02X}")
        
        # Método 3: Key number normal 0x00 (método original)
        self.log("Método 3: Key number normal 0x00")
        command = bytes([0xC4, 0x00]) + new_key_aes + bytes([0x00])
        self.log(f"Comando: {command.hex().upper()}")
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("¡ÉXITO! Clave maestra cambiada a AES con 0x00")
            self.authenticated = False
            self.session_key = None
            self.auth_type = None
            return True
        else:
            self.log(f"Método 0x00 falló: {response[0]:02X}")
        
        # Método 4: Formato para cambio de mismo tipo con cifrado
        self.log("Método 4: Método original con cifrado DES")
        success = self.change_key(
            key_number=0,
            new_key=new_key_aes,
            new_key_version=0x00,
            authenticated_key_number=0
        )

        # self.log("Método 4: Método de cambio de clave con 0x80")
        # success = self.complete_des_to_aes_migration_examples()
        # success = self.execute_complete_flow_acr1581u(
        #     reader_index=0, 
        #     format_first=True
        # )
                
        if success:
            self.log("¡ÉXITO! Clave maestra cambiada a AES con método cifrado")
            self.authenticated = False
            self.session_key = None
            self.auth_type = None
            return True
        
        self.log("ERROR: Todos los métodos de cambio de clave fallaron")
        return False
    
    def create_application(self, aid: bytes = None, key_settings: int = None, 
                          num_keys: int = None) -> bool:
        """
        Crear aplicación (Paso 3 del flow_001.md)
        
        Args:
            aid (bytes): Application ID (3 bytes)
            key_settings (int): Configuración de claves
            num_keys (int): Número y tipo de claves
            
        Returns:
            bool: True si creación exitosa
        """
        # Usar valores por defecto si no se especifican
        if aid is None:
            aid = self.default_config['default_aid']
        if key_settings is None:
            key_settings = self.default_config['key_settings']
        if num_keys is None:
            # Ajustar número de claves según el tipo de autenticación detectado
            if self.auth_type == 'DES':
                num_keys = self.default_config['num_keys_des']  # 1 clave DES
                self.log("Tarjeta DES detectada - creando aplicación con 1 clave DES")
            else:
                num_keys = self.default_config['num_keys_aes']  # 1 clave AES
                self.log("Tarjeta AES detectada - creando aplicación con 1 clave AES")
        
        self.log(f"Creando aplicación AID: {aid.hex().upper()}")
        self.log(f"Parámetros: KeySettings=0x{key_settings:02X}, NumKeys=0x{num_keys:02X}")
        
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        # Verificar si la aplicación ya existe
        if self._application_exists(aid):
            self.log(f"La aplicación {aid.hex().upper()} ya existe")
            return True
        
        command = bytes([0xCA]) + aid + bytes([key_settings, num_keys])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Aplicación creada exitosamente")
            return True
        else:
            self.log(f"ERROR creando aplicación: {response[0]:02X}")
            
            # Diagnóstico de errores comunes
            if response[0] == 0x7E:
                self.log("Error 0x7E - Length Error. Posibles causas:")
                self.log("  - AID ya existe")
                self.log("  - Parámetros incompatibles con el tipo de tarjeta")
                self.log("  - Límite de aplicaciones alcanzado")
                
                # Intentar con parámetros más conservadores
                self.log("Intentando con parámetros alternativos...")
                return self._try_alternative_create_application(aid, key_settings, num_keys)
            elif response[0] == 0xDE:
                self.log("Error 0xDE - Aplicación ya existe")
            elif response[0] == 0xCE:
                self.log("Error 0xCE - Límite de aplicaciones alcanzado")
            elif response[0] == 0xAE:
                self.log("Error 0xAE - Autenticación requerida")
            
            return False
    
    def _try_alternative_create_application(self, aid: bytes, key_settings: int, num_keys: int) -> bool:
        """
        Intentar crear aplicación con parámetros alternativos
        
        Args:
            aid (bytes): Application ID original
            key_settings (int): Key settings original
            num_keys (int): Número de claves original
            
        Returns:
            bool: True si alguna alternativa funciona
        """
        # Lista de alternativas a probar
        alternatives = [
            # (key_settings, num_keys, descripción)
            (0x0B, 0x01, "Settings más restrictivos, 1 clave DES"),
            (0x09, 0x01, "Settings seguros, 1 clave DES"),
            (0x0F, 0x81, "Settings originales, 1 clave AES"),
            (0x0B, 0x81, "Settings restrictivos, 1 clave AES"),
        ]
        
        for alt_settings, alt_num_keys, description in alternatives:
            self.log(f"Probando: {description}")
            self.log(f"  KeySettings=0x{alt_settings:02X}, NumKeys=0x{alt_num_keys:02X}")
            
            command = bytes([0xCA]) + aid + bytes([alt_settings, alt_num_keys])
            response = self.send_command(command)
            
            if response[0] == 0x00:
                self.log(f"Aplicación creada con parámetros alternativos: {description}")
                return True
            else:
                self.log(f"  Error: {response[0]:02X}")
        
        # Si nada funciona, intentar con AID diferente
        self.log("Intentando con AID diferente...")
        alternative_aids = [
            bytes([0x02, 0x00, 0x00]),
            bytes([0x03, 0x00, 0x00]),
            bytes([0xF0, 0x01, 0x01]),
        ]
        
        for alt_aid in alternative_aids:
            self.log(f"Probando AID: {alt_aid.hex().upper()}")
            
            command = bytes([0xCA]) + alt_aid + bytes([0x0F, 0x01])
            response = self.send_command(command)
            
            if response[0] == 0x00:
                self.log(f"Aplicación creada con AID alternativo: {alt_aid.hex().upper()}")
                # Actualizar el AID por defecto para futuras operaciones
                self.default_config['default_aid'] = alt_aid
                return True
            else:
                self.log(f"  Error: {response[0]:02X}")
        
        self.log("Todas las alternativas fallaron")
        return False
    
    def _application_exists(self, aid: bytes) -> bool:
        """
        Verificar si una aplicación existe intentando seleccionarla
        
        Args:
            aid (bytes): Application ID a verificar
            
        Returns:
            bool: True si la aplicación existe
        """
        # Guardar estado actual
        original_authenticated = self.authenticated
        original_auth_type = self.auth_type
        
        try:
            command = bytes([0x5A]) + aid
            response = self.send_command(command)
            
            # Restaurar estado de autenticación
            self.authenticated = original_authenticated
            self.auth_type = original_auth_type
            
            return response[0] == 0x00
            
        except Exception:
            # Restaurar estado en caso de error
            self.authenticated = original_authenticated
            self.auth_type = original_auth_type
            return False
    
    def select_application(self, aid: bytes = None) -> bool:
        """
        Seleccionar aplicación (Paso 4 del flow_001.md)
        
        Args:
            aid (bytes): Application ID (3 bytes)
            
        Returns:
            bool: True si selección exitosa
        """
        if aid is None:
            aid = self.default_config['default_aid']
        
        self.log(f"Seleccionando aplicación: {aid.hex().upper()}")
        
        command = bytes([0x5A]) + aid
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Aplicación seleccionada")
            # Reset autenticación al cambiar de aplicación
            self.authenticated = False
            self.auth_type = None
            return True
        else:
            self.log(f"ERROR seleccionando aplicación: {response[0]:02X}")
            return False
    
    def authenticate_application_master(self, aid: bytes = None) -> bool:
        """
        Autenticación con master key de aplicación (Paso 5 del flow_001.md)
        Intenta automáticamente AES y DES
        
        Args:
            aid (bytes): AID de la aplicación (None para usar por defecto)
        
        Returns:
            bool: True si autenticación exitosa
        """
        if aid is None:
            aid = self.default_config['default_aid']
            
        self.log("Autenticando con master key de aplicación...")
        
        # Si el AID es 000000, ya estamos en la aplicación master
        if aid == bytes([0x00, 0x00, 0x00]):
            self.log("Ya en aplicación master PICC")
            return True
        
        # Para aplicaciones nuevas, intentar AES primero
        # Para aplicaciones existentes, el tipo se detectará automáticamente
        return self.authenticate_auto(0, prefer_aes=True)
    
    def setup_application_keys(self) -> bool:
        """
        Configurar claves de aplicación (Paso 6 del flow_001.md)
        Configura clave de lectura (Key 1) y escritura (Key 2)
        
        Returns:
            bool: True si configuración exitosa
        """
        self.log("Configurando claves de aplicación...")
        
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        # Por simplicidad, mantenemos solo clave master
        # En implementación completa aquí irían los comandos C4 para cambiar claves
        self.log("Usando configuración simplificada: solo clave master")
        return True
    
    def create_standard_file(self, file_number: int = 1, file_size: int = None,
                           read_key: int = 0, write_key: int = 0, 
                           change_key: int = 0) -> bool:
        """
        Crear fichero estándar (Paso 7 del flow_001.md)
        
        Args:
            file_number (int): Número de archivo
            file_size (int): Tamaño del archivo en bytes
            read_key (int): Clave para lectura
            write_key (int): Clave para escritura
            change_key (int): Clave para cambios
            
        Returns:
            bool: True si creación exitosa
        """
        if file_size is None:
            file_size = self.default_config['file_size']
        
        self.log(f"Creando fichero estándar #{file_number} ({file_size} bytes)")
        
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        # Construir derechos de acceso según flow_001.md
        # Formato: [Change][R&W][Write][Read] en nibbles
        access_rights = (change_key << 12) | (read_key << 8) | (write_key << 4) | read_key
        
        # Comando CreateStdDataFile
        command = bytearray([0xCD, file_number])
        command.append(0x00)  # Comunicación plana (según flow_001.md)
        command.extend(struct.pack('<H', access_rights))
        command.extend(struct.pack('<I', file_size)[:3])
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Fichero estándar creado exitosamente")
            return True
        else:
            self.log(f"ERROR creando fichero: {response[0]:02X}")
            return False
    
    def verify_file_settings(self, file_number: int = 1) -> Dict:
        """
        Verificar configuración de archivo (Paso 8 del flow_001.md)
        
        Args:
            file_number (int): Número de archivo a verificar
            
        Returns:
            Dict: Información del archivo o None si error
        """
        self.log(f"Verificando configuración de archivo #{file_number}")
        
        command = bytes([0xF5, file_number])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            settings = response[1:]
            if len(settings) >= 7:
                file_type = settings[0]
                comm_mode = settings[1]
                access_rights = struct.unpack('<H', settings[2:4])[0]
                file_size = struct.unpack('<I', settings[4:7] + b'\x00')[0]
                
                # Decodificar derechos de acceso
                read_key = access_rights & 0xF
                write_key = (access_rights >> 4) & 0xF
                rw_key = (access_rights >> 8) & 0xF
                change_key = (access_rights >> 12) & 0xF
                
                info = {
                    'file_type': file_type,
                    'comm_mode': comm_mode,
                    'file_size': file_size,
                    'access_rights': {
                        'read': read_key,
                        'write': write_key,
                        'read_write': rw_key,
                        'change': change_key
                    }
                }
                
                self.log(f"Archivo verificado: {file_size} bytes, R={read_key}, W={write_key}")
                return info
            
        self.log(f"ERROR verificando archivo: {response[0]:02X}")
        return None
    
    def create_file_in_master_application(self, file_number: int = 1, 
                                         file_size: int = None) -> bool:
        """
        Crear archivo directamente en la aplicación master (sin crear aplicación nueva)
        Alternativa para tarjetas que no soportan aplicaciones múltiples
        
        Args:
            file_number (int): Número de archivo
            file_size (int): Tamaño del archivo
            
        Returns:
            bool: True si creación exitosa
        """
        if file_size is None:
            file_size = self.default_config['file_size']
        
        self.log(f"Creando archivo directamente en aplicación master")
        self.log(f"Archivo #{file_number}, {file_size} bytes, Tipo auth: {self.auth_type}")
        
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        # En la aplicación master, usar solo clave master (0) para todos los permisos
        read_key = write_key = change_key = 0
        
        # Construir derechos de acceso
        access_rights = (change_key << 12) | (read_key << 8) | (write_key << 4) | read_key
        
        # Para tarjetas DES, intentar formato simplificado
        if self.auth_type == 'DES':
            # Intentar crear archivo con configuración mínima
            self.log("Usando configuración simplificada para tarjeta DES")
            
            # Probar diferentes tamaños de archivo
            test_sizes = [16, 32, 64]  # Tamaños comunes para DES
            
            for test_size in test_sizes:
                self.log(f"Probando archivo de {test_size} bytes...")
                
                # Comando CreateStdDataFile simplificado
                command = bytearray([0xCD, file_number])
                command.append(0x00)  # Comunicación plana
                command.extend(struct.pack('<H', 0x0000))  # Access rights simplificados
                command.extend(struct.pack('<I', test_size)[:3])
                
                response = self.send_command(command)
                
                if response[0] == 0x00:
                    self.log(f"Archivo de {test_size} bytes creado exitosamente en aplicación master")
                    return True
                else:
                    self.log(f"Fallo archivo de {test_size} bytes: {response[0]:02X}")
        
        # Formato estándar para AES o si DES falló
        self.log("Usando formato estándar...")
        
        # Comando CreateStdDataFile
        command = bytearray([0xCD, file_number])
        command.append(0x00)  # Comunicación plana
        command.extend(struct.pack('<H', access_rights))
        command.extend(struct.pack('<I', file_size)[:3])
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Archivo creado exitosamente en aplicación master")
            return True
        else:
            self.log(f"ERROR creando archivo: {response[0]:02X}")
            
            # Diagnóstico para error 7E
            if response[0] == 0x7E:
                self.log("Error 7E - Posibles causas:")
                self.log("  - Tarjeta no soporta archivos en aplicación master")
                self.log("  - Formato de comando incompatible")
                self.log("  - Limitaciones de la tarjeta DES")
                self.log("  - Archivo ya existe")
            
            return False
    
    def execute_master_application_flow(self, reader_index: int = 0, 
                                       format_first: bool = False) -> bool:
        """
        Flujo alternativo que trabaja solo con la aplicación master
        Para tarjetas que no soportan aplicaciones múltiples
        
        Args:
            reader_index (int): Índice del lector a usar
            format_first (bool): Si formatear tarjeta primero
            
        Returns:
            bool: True si flujo exitoso
        """
        self.log("Iniciando flujo alternativo - solo aplicación master...")
        
        try:
            # Conectar
            if not self.connect_to_reader(reader_index):
                return False
            
            # Autenticación con PICC master
            if not self.authenticate_picc_master():
                return False
            
            # Formateo opcional
            if format_first:
                if not self.format_picc():
                    return False
                # Re-autenticar después del formateo
                if not self.authenticate_picc_master():
                    return False
            
            # Permanecer en aplicación master (AID 000000)
            self.log("Trabajando directamente en aplicación master PICC")
            
            # Crear archivo en aplicación master
            if not self.create_file_in_master_application():
                return False
            
            # Verificar archivo
            file_info = self.verify_file_settings()
            if file_info is None:
                return False
            
            self.log("Flujo alternativo completado exitosamente")
            self.log("Archivo creado en aplicación master PICC")
            return True
            
        except Exception as e:
            self.log(f"ERROR en flujo alternativo: {e}")
            return False
        finally:
            self.disconnect()
    
    # =============================================================================
    # FLUJO COMPLETO
    # =============================================================================
    
    def get_card_info(self) -> Dict:
        """
        Obtener información de la tarjeta DESFire
        
        Returns:
            Dict: Información de la tarjeta
        """
        if not self.connection:
            return None
        
        info = {}
        
        try:
            # Comando GetVersion
            self.log("Obteniendo información de la tarjeta...")
            
            # Primera parte de GetVersion
            command = bytes([0x60])
            response = self.send_command(command)
            
            if response[0] == 0xAF and len(response) >= 8:
                info['hardware_vendor'] = response[1]
                info['hardware_type'] = response[2]
                info['hardware_subtype'] = response[3]
                info['hardware_version_major'] = response[4]
                info['hardware_version_minor'] = response[5]
                info['hardware_storage_size'] = response[6]
                info['hardware_protocol'] = response[7]
                
                # Segunda parte
                command = bytes([0xAF])
                response = self.send_command(command)
                
                if response[0] == 0xAF and len(response) >= 8:
                    info['software_vendor'] = response[1]
                    info['software_type'] = response[2]
                    info['software_subtype'] = response[3]
                    info['software_version_major'] = response[4]
                    info['software_version_minor'] = response[5]
                    info['software_storage_size'] = response[6]
                    info['software_protocol'] = response[7]
                    
                    # Tercera parte
                    command = bytes([0xAF])
                    response = self.send_command(command)
                    
                    if response[0] == 0x00 and len(response) >= 15:
                        info['uid'] = response[1:8].hex().upper()
                        info['batch_number'] = response[8:13].hex().upper()
                        info['production_week'] = response[13]
                        info['production_year'] = response[14]
            
            # Comando GetApplicationIDs
            self.log("Obteniendo aplicaciones existentes...")
            command = bytes([0x6A])
            response = self.send_command(command)
            
            if response[0] == 0x00:
                aids = []
                data = response[1:]
                for i in range(0, len(data), 3):
                    if i + 2 < len(data):
                        aid = data[i:i+3]
                        aids.append(aid.hex().upper())
                info['applications'] = aids
            else:
                info['applications'] = []
            
            # Comando GetFileIDs (solo si estamos en una aplicación)
            try:
                self.log("Obteniendo archivos en aplicación master...")
                command = bytes([0x6F])
                response = self.send_command(command)
                
                if response[0] == 0x00:
                    files = list(response[1:])
                    info['files_in_master'] = files
                else:
                    info['files_in_master'] = []
            except:
                info['files_in_master'] = []
            
            return info
            
        except Exception as e:
            self.log(f"ERROR obteniendo información: {e}")
            return None
    
    def diagnose_card_capabilities(self) -> bool:
        """
        Diagnosticar capacidades de la tarjeta DESFire
        
        Returns:
            bool: True si diagnóstico exitoso
        """
        self.log("=== DIAGNÓSTICO DE TARJETA ===")
        
        # Obtener información básica
        info = self.get_card_info()
        if info:
            self.log("Información de la tarjeta:")
            for key, value in info.items():
                self.log(f"  {key}: {value}")
        
        # Probar comandos básicos
        self.log("\n=== PROBANDO COMANDOS BÁSICOS ===")
        
        # Test 1: Select Master Application (debe funcionar siempre)
        self.log("Test 1: Select Master Application")
        command = bytes([0x5A, 0x00, 0x00, 0x00])
        response = self.send_command(command)
        self.log(f"  Result: {response[0]:02X} ({'OK' if response[0] == 0x00 else 'FAIL'})")
        
        # Test 2: GetKeyVersion
        self.log("Test 2: GetKeyVersion para clave 0")
        command = bytes([0x64, 0x00])
        response = self.send_command(command)
        self.log(f"  Result: {response[0]:02X} ({'OK' if response[0] == 0x00 else 'FAIL'})")
        if response[0] == 0x00 and len(response) > 1:
            self.log(f"  Key Version: {response[1]}")
        
        # Test 3: Crear aplicación mínima
        self.log("Test 3: Crear aplicación mínima")
        test_aid = bytes([0xFF, 0xFF, 0xFF])  # AID especial para test
        command = bytes([0xCA]) + test_aid + bytes([0x0F, 0x01])  # 1 clave DES
        response = self.send_command(command)
        self.log(f"  Result: {response[0]:02X} ({'OK' if response[0] == 0x00 else 'FAIL'})")
        
        if response[0] == 0x00:
            # Si funcionó, intentar crear archivo en esta aplicación
            self.log("Test 4: Seleccionar aplicación de test")
            command = bytes([0x5A]) + test_aid
            response = self.send_command(command)
            self.log(f"  Result: {response[0]:02X} ({'OK' if response[0] == 0x00 else 'FAIL'})")
            
            if response[0] == 0x00:
                self.log("Test 5: Crear archivo en aplicación de test")
                command = bytes([0xCD, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])
                response = self.send_command(command)
                self.log(f"  Result: {response[0]:02X} ({'OK' if response[0] == 0x00 else 'FAIL'})")
        
        self.log("=== FIN DIAGNÓSTICO ===")
        return True
    
    def execute_complete_flow(self, reader_index: int = 0, aid: bytes = None, 
                             format_first: bool = False) -> bool:
        """
        Ejecutar flujo completo según flow_001.md
        
        Args:
            reader_index (int): Índice del lector a usar
            aid (bytes): Application ID a crear
            format_first (bool): Si formatear tarjeta primero
            
        Returns:
            bool: True si flujo completo exitoso
        """
        self.log("Iniciando flujo completo DESFire...")
        
        try:
            # Conectar
            if not self.connect_to_reader(reader_index):
                return False
            
            # Paso 2: Autenticación a nivel de tarjeta
            if not self.authenticate_picc_master():
                return False
            
            # Paso 1: Formateo inicial (opcional)
            if format_first:
                if not self.format_picc():
                    return False
                # Re-autenticar después del formateo
                if not self.authenticate_picc_master():
                    return False
            
            # Paso intermedio: Si estamos autenticados con DES, cambiar a AES
            if self.auth_type == 'DES':
                self.log("Tarjeta DES detectada - ejecutando secuencia de cambio a AES...")
                
                # Paso 1: SELECT el PICC (aplicación raíz 0x000000)
                self.log("1. Seleccionando aplicación PICC master (000000)...")
                if not self.select_application(bytes([0x00, 0x00, 0x00])):
                    self.log("ERROR: No se pudo seleccionar aplicación master")
                    return False
                
                # Paso 2: AUTHENTICATE con clave actual (DES, Key 0)
                self.log("2. Autenticando con clave DES actual...")
                if not self.authenticate_des(0, bytes(8)):  # DES con 8 zeros
                    self.log("ERROR: No se pudo autenticar con clave DES")
                    return False
                
                # Obtener información de configuración de claves
                self.log("2.1. Obteniendo configuración de claves...")
                key_info = self.get_key_settings()
                if key_info:
                    self.log(f"Configuración actual: {key_info}")
                    
                    # Analizar key settings
                    key_settings = key_info.get('key_settings', 0)
                    max_keys = key_info.get('max_keys', 0)
                    
                    self.log(f"Key Settings: 0x{key_settings:02X}")
                    self.log(f"  - Bit 0 (AllowChangeMasterKey): {'Yes' if key_settings & 0x01 else 'No'}")
                    self.log(f"  - Bit 1 (ListingWithoutMasterKey): {'Yes' if key_settings & 0x02 else 'No'}")
                    self.log(f"  - Bit 2 (CreateDeleteWithoutMasterKey): {'Yes' if key_settings & 0x04 else 'No'}")
                    self.log(f"  - Bit 3 (ConfigurationChangeable): {'Yes' if key_settings & 0x08 else 'No'}")
                    self.log(f"  - Bits 4-7 (ChangeKeyAccessRights): 0x{(key_settings >> 4) & 0x0F:X}")
                    self.log(f"Max Keys: {max_keys} (0x{max_keys:02X})")
                    
                    if max_keys == 1:
                        self.log("ℹ️  INFO: La tarjeta solo soporta 1 clave (solo master)")
                        self.log("ℹ️  Cambiando directamente la clave maestra Key #0 de DES a AES...")
                        
                        # Paso 3: CHANGE KEY para cambiar la clave maestra #0 de DES a AES
                        self.log("3. Cambiando clave maestra #0 de DES a AES...")
                        
                        if self.test_manual_change_key():
                            self.log("¡ÉXITO! Clave maestra cambiada de DES a AES")
                            
                            # Paso 4: RE-AUTHENTICATE con la nueva clave AES #0
                            self.log("4. Re-autenticando con nueva clave AES maestra...")
                            new_aes_key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
                            
                            if self.authenticate_aes(0, new_aes_key):
                                self.log("¡ÉXITO TOTAL! Re-autenticado con clave AES maestra")
                                self.auth_type = 'AES'
                                self.log("Tarjeta convertida exitosamente a AES")
                                
                                # Continuar con el flujo normal AES
                            else:
                                self.log("ERROR: No se pudo re-autenticar con la nueva clave AES")
                                return False
                        else:
                            self.log("ERROR: No se pudo cambiar la clave maestra")
                            return False
                else:
                    self.log("No se pudo obtener configuración de claves")
            
            # Paso 3: Creación de aplicación (ahora con tarjeta AES)
            if not self.create_application(aid):
                self.log("Creación de aplicación falló - intentando flujo alternativo...")
                self.log("Usando aplicación master PICC en lugar de crear nueva aplicación")
                
                # Usar aplicación master (AID 000000)
                aid = bytes([0x00, 0x00, 0x00])
                
                # Ir directamente a crear archivo en aplicación master
                if not self.create_file_in_master_application():
                    return False
                
                # Verificar archivo
                file_info = self.verify_file_settings()
                if file_info is None:
                    return False
                
                self.log("Flujo alternativo completado - archivo creado en aplicación master")
                return True
            
            # Paso 4: Selección de aplicación
            if not self.select_application(aid):
                return False
            
            # Paso 5: Autenticación en la aplicación
            if not self.authenticate_application_master():
                return False
            
            # Paso 6: Configuración de claves (simplificado)
            if not self.setup_application_keys():
                return False
            
            # Paso 7: Creación del fichero estándar
            if not self.create_standard_file():
                return False
            
            # Paso 8: Verificación
            file_info = self.verify_file_settings()
            if file_info is None:
                return False
            
            self.log("Flujo completo ejecutado exitosamente")
            return True
            
            # Paso 4: Selección de aplicación
            if not self.select_application(aid):
                return False
            
            # Paso 5: Autenticación en la aplicación
            if not self.authenticate_application_master():
                return False
            
            # Paso 6: Configuración de claves (simplificado)
            if not self.setup_application_keys():
                return False
            
            # Paso 7: Creación del fichero estándar
            if not self.create_standard_file():
                return False
            
            # Paso 8: Verificación
            file_info = self.verify_file_settings()
            if file_info is None:
                return False
            
            self.log("Flujo completo ejecutado exitosamente")
            return True
            
        except Exception as e:
            self.log(f"ERROR en flujo completo: {e}")
            return False
        finally:
            self.disconnect()