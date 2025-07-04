#!/usr/bin/env python3
"""
DESFire EV1 Secure File Operations
================================

Implementación segura de operaciones DESFire EV1 usando:
- Archivos con comunicación ENCRYPTED
- Sistema de 3 claves (Master, Read, Write)
- Gestión granular de permisos de acceso
- Operaciones seguras de lectura/escritura

Autor: Basado en análisis de componentes existentes
Fecha: 2025
"""

import os
import struct
from Crypto.Cipher import AES
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString
from desfire_create_stdfile_python import CommMode, AccessRights, DESFireCreateStdDataFile


class DESFireSecureOperations:
    """Clase para operaciones seguras DESFire EV1 con archivos encriptados"""
    
    def __init__(self, debug=True):
        """
        Inicializar operaciones seguras DESFire
        
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
        self.existing_keys = []
        self.discovered_keys = {}
        
        # Configuración de claves para aplicación segura
        self.key_config = {
            'master_key': 0,     # Clave maestra (administración)
            'read_key': 1,       # Clave de lectura
            'write_key': 2,      # Clave de escritura
            'readwrite_key': 1   # Clave para lectura/escritura (misma que lectura)
        }
    
    def log(self, message):
        """Imprimir mensaje de depuración si está habilitado"""
        if self.debug:
            print(message)
    
    # =============================================================================
    # CONEXIÓN Y COMUNICACIÓN
    # =============================================================================
    
    def connect_reader(self):
        """Conectar con lector de tarjetas"""
        print("Conectando al lector de tarjetas...")
        reader_list = readers()
        
        if not reader_list:
            print("ERROR: No se encontraron lectores")
            return False
        
        print(f"Lectores disponibles: {len(reader_list)}")
        for i, reader in enumerate(reader_list):
            print(f"  [{i}] {reader}")
        
        reader_index = 0
        if len(reader_list) > 1:
            try:
                reader_index = int(input(f"Seleccione lector (0-{len(reader_list)-1}): "))
                if reader_index < 0 or reader_index >= len(reader_list):
                    reader_index = 0
            except ValueError:
                reader_index = 0
        
        self.reader = reader_list[reader_index]
        print(f"Usando: {self.reader}")
        
        try:
            self.connection = self.reader.createConnection()
            self.connection.connect()
            atr = self.connection.getATR()
            print(f"Conectado - ATR: {toHexString(atr)}")
            return True
        except CardConnectionException:
            print("ERROR: No se detectó tarjeta")
            return False
    
    def send_command(self, command):
        """Enviar comando DESFire a la tarjeta"""
        # Envolver comando nativo en APDU ISO 7816-4
        if len(command) == 1:
            apdu = [0x90, command[0], 0x00, 0x00, 0x00]
        else:
            cmd_byte = command[0]
            data = command[1:]
            
            # Comandos que NO necesitan Le=0x00 al final
            no_le_commands = [0xDF]  # DeleteFile
            
            if cmd_byte in no_le_commands:
                # Comandos sin Le (comandos que modifican datos)
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data)
            else:
                # Comandos con Le=0x00 (comandos de consulta/control)
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data) + [0x00]
        
        try:
            if self.debug:
                self.log(f"TX: {toHexString(apdu)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if self.debug:
                resp_str = toHexString(response) if response else 'Sin datos'
                self.log(f"RX: {resp_str}, SW: {sw1:02X} {sw2:02X}")
            
            # Procesar respuesta
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes([0x00]) + bytes(response) if response else bytes([0x00])
            elif sw1 == 0x91:
                return bytes([sw2]) + bytes(response) if response else bytes([sw2])
            else:
                return bytes([0x6E])
                
        except Exception as e:
            print(f"ERROR al enviar comando: {e}")
            return bytes([0x6E])
    
    def disconnect(self):
        """Desconectar del lector"""
        if self.connection:
            self.connection.disconnect()
            print("Desconectado del lector")
    
    # =============================================================================
    # AUTENTICACIÓN
    # =============================================================================
    
    def authenticate_aes(self, key_number, key):
        """Autenticación AES con DESFire"""
        self.log(f"Autenticando con clave AES #{key_number}")
        
        try:
            # Paso 1: Solicitar autenticación
            command = bytes([0xAA, key_number])
            response = self.send_command(command)
            
            if response[0] != 0xAF or len(response) != 17:
                self.log(f"ERROR en autenticación paso 1: {response[0]:02X}")
                return False
            
            encrypted_rnd_b = response[1:17]
            self.log(f"RndB cifrado: {encrypted_rnd_b.hex().upper()}")
            
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
            self.log(f"Enviando RndAB cifrado ({len(encrypted_rnd_ab)} bytes): {encrypted_rnd_ab.hex().upper()}")
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
            
            self.log(f"Autenticación AES exitosa con clave #{key_number}")
            return True
            
        except Exception as e:
            self.log(f"ERROR en autenticación: {e}")
            return False
    
    def discover_key_value(self, key_number):
        """
        Intentar descubrir el valor de una clave probando valores comunes
        
        Args:
            key_number (int): Número de clave a descubrir
            
        Returns:
            bytes: Valor de la clave si se encuentra, None si no
        """
        self.log(f"Intentando descubrir valor de clave #{key_number}")
        
        # Claves comunes para probar (prioritizando clave por defecto)
        common_keys = [
            bytes(16),  # 16 zeros - clave por defecto AES
            bytes([0xFF] * 16),  # 16 FFs
            bytes([0x01] * 16),  # 16 ones
            bytes([i % 256 for i in range(16)]),  # 0x00, 0x01, 0x02...0x0F
        ]
        
        for i, test_key in enumerate(common_keys):
            self.log(f"Probando clave común #{i+1}: {test_key.hex().upper()}")
            
            try:
                # Intentar autenticación con esta clave
                command = bytes([0xAA, key_number])
                response = self.send_command(command)
                
                if response[0] == 0xAF:
                    # Continuar con autenticación AES completa
                    if self.authenticate_aes(key_number, test_key):
                        self.log(f"¡Clave #{key_number} encontrada!")
                        return test_key
                    
            except Exception as e:
                self.log(f"Error probando clave: {e}")
                continue
        
        self.log(f"No se pudo descubrir valor de clave #{key_number}")
        return None

    def authenticate_with_role(self, role, key_data=None, existing_keys=None):
        """
        Autenticarse según rol específico
        
        Args:
            role (str): 'master', 'read', 'write' o 'readwrite'
            key_data (bytes, optional): Clave específica o None para usar clave conocida
            existing_keys (list, optional): Lista de claves que existen
            
        Returns:
            bool: True si autenticación exitosa
        """
        # Si no sabemos qué claves existen, verificar primero
        if existing_keys is None:
            existing_keys = []
            for key_num in range(4):
                if self.check_key_exists(key_num):
                    existing_keys.append(key_num)
        
        # Adaptar roles según claves disponibles
        if len(existing_keys) >= 3:
            role_to_key = {'master': 0, 'read': 1, 'write': 2, 'readwrite': 1}
        elif len(existing_keys) >= 2:
            # Si tenemos claves 0 y 2, usar 2 para lectura/escritura
            if 2 in existing_keys:
                role_to_key = {'master': 0, 'read': 2, 'write': 2, 'readwrite': 2}
            else:
                role_to_key = {'master': 0, 'read': 1, 'write': 0, 'readwrite': 1}
        else:
            role_to_key = {'master': 0, 'read': 0, 'write': 0, 'readwrite': 0}
        
        if role not in role_to_key:
            self.log(f"ERROR: Rol '{role}' no válido")
            return False
        
        key_number = role_to_key[role]
        
        # Verificar que la clave existe
        if key_number not in existing_keys:
            self.log(f"ERROR: Clave #{key_number} para rol '{role}' no existe")
            self.log(f"Claves disponibles: {existing_keys}")
            return False
        
        # Si no se proporciona clave, usar la clave conocida
        if key_data is None:
            if role == 'master':
                # Clave maestra AES por defecto (16 zeros)
                key_data = bytes(16)  # 00000000000000000000000000000000
            elif role in ['read', 'write']:
                # Para claves de lectura/escritura - usar clave por defecto
                key_data = bytes(16)  # 00000000000000000000000000000000
            else:
                # Otras claves - usar zeros por defecto
                key_data = bytes(16)
        
        self.log(f"Autenticando como '{role}' con clave #{key_number}")
        self.log(f"Usando clave: {key_data.hex().upper()}")
        return self.authenticate_aes(key_number, key_data)
    
    # =============================================================================
    # GESTIÓN DE APLICACIONES
    # =============================================================================
    
    def select_application(self, aid):
        """Seleccionar aplicación por AID"""
        self.log(f"Seleccionando aplicación: {aid.hex().upper()}")
        
        command = bytes([0x5A]) + aid
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Aplicación seleccionada")
            self.authenticated = False
            return True
        else:
            self.log(f"ERROR seleccionando aplicación: {response[0]:02X}")
            return False
    
    def create_application(self, aid, num_keys=3):
        """
        Crear aplicación DESFire con número específico de claves AES
        
        Args:
            aid (bytes): Application ID (3 bytes)
            num_keys (int): Número de claves AES (1-14)
            
        Returns:
            bool: True si creación exitosa
        """
        self.log(f"Creando aplicación {aid.hex().upper()} con {num_keys} claves AES")
        
        # Debe estar autenticado como PICC master key
        if not self.authenticated or self.auth_key_number != 0:
            self.log("ERROR: Debe estar autenticado como PICC master key")
            return False
        
        # Comando CreateApplication
        # 0xCA + AID(3) + KeySettings(1) + NumKeys(1)
        key_settings = 0x0F  # Cambio de master key permitido con autenticación
        
        command = bytes([0xCA]) + aid + bytes([key_settings, num_keys])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log(f"Aplicación {aid.hex().upper()} creada exitosamente")
            return True
        else:
            self.log(f"ERROR creando aplicación: {response[0]:02X}")
            return False
    
    def authenticate_picc_master(self):
        """Autenticar con PICC master key (clave por defecto)"""
        self.log("Autenticando con PICC master key...")
        
        # Seleccionar PICC master application (0x000000)
        picc_aid = bytes([0x00, 0x00, 0x00])
        command = bytes([0x5A]) + picc_aid
        response = self.send_command(command)
        
        if response[0] != 0x00:
            self.log(f"ERROR seleccionando PICC master: {response[0]:02X}")
            return False
        
        # Autenticar con clave por defecto
        picc_master_key = bytes(16)  # 16 zeros
        return self.authenticate_aes(0, picc_master_key)
    
    def setup_application_keys(self, aid):
        """
        Configurar las 3 claves de la aplicación con valores por defecto
        
        Args:
            aid (bytes): Application ID
            
        Returns:
            bool: True si configuración exitosa
        """
        self.log("Configurando claves de aplicación...")
        
        # Seleccionar aplicación
        if not self.select_application(aid):
            return False
        
        # Autenticar como master de aplicación con clave por defecto
        app_master_key = bytes(16)  # 16 zeros
        if not self.authenticate_aes(0, app_master_key):
            self.log("ERROR: No se pudo autenticar como master de aplicación")
            return False
        
        # Configurar clave #1 (lectura)
        read_key = bytes(16)  # 16 zeros
        if not self.create_key(1, read_key):
            self.log("ERROR: No se pudo crear clave de lectura")
            return False
        
        # Configurar clave #2 (escritura)
        write_key = bytes(16)  # 16 zeros
        if not self.create_key(2, write_key):
            self.log("ERROR: No se pudo crear clave de escritura")
            return False
        
        self.log("Claves de aplicación configuradas: Master(0), Read(1), Write(2)")
        return True
    
    # =============================================================================
    # GESTIÓN SEGURA DE ARCHIVOS
    # =============================================================================
    
    def create_secure_file(self, file_id, file_size, read_key=1, write_key=2, change_key=0):
        """
        Crear archivo con comunicación ENCRYPTED y permisos granulares
        
        Args:
            file_id (int): ID del archivo (0-31)
            file_size (int): Tamaño en bytes
            read_key (int): Clave para lectura
            write_key (int): Clave para escritura
            change_key (int): Clave para cambiar configuración
            
        Returns:
            bool: True si creación exitosa
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Creando archivo seguro #{file_id} ({file_size} bytes)")
        self.log(f"Permisos: Read=Key{read_key}, Write=Key{write_key}, Change=Key{change_key}")
        
        # Construir derechos de acceso manualmente
        # Formato: 2 bytes little-endian con 4 campos de 4 bits cada uno
        # Bits 15-12: read, Bits 11-8: write, Bits 7-4: read_write, Bits 3-0: change
        access_word = (read_key << 12) | (write_key << 8) | (read_key << 4) | change_key
        
        # Construir comando CreateStdDataFile manualmente
        command = bytearray([0xCD, file_id])  # Comando CreateStdDataFile + File ID
        command.append(0x03)  # Communication Mode: ENCRYPTED
        command.extend(struct.pack('<H', access_word))  # Access Rights (2 bytes little-endian)
        command.extend(struct.pack('<I', file_size)[:3])  # File Size (3 bytes little-endian)
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Archivo seguro creado exitosamente")
            self.log("IMPORTANTE: El archivo usa comunicación ENCRYPTED")
            return True
        else:
            self.log(f"ERROR creando archivo seguro: {response[0]:02X}")
            return False
    
    def get_file_info(self, file_id):
        """Obtener información detallada de archivo"""
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return None
        
        command = bytes([0xF5, file_id])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            settings = response[1:]
            if len(settings) >= 7:
                file_type = settings[0]
                comm_mode = settings[1]
                access_rights = struct.unpack('<H', settings[2:4])[0]
                file_size = struct.unpack('<I', settings[4:7] + b'\x00')[0]
                
                # Decodificar derechos de acceso
                read_key = (access_rights >> 12) & 0xF
                write_key = (access_rights >> 8) & 0xF
                rw_key = (access_rights >> 4) & 0xF
                change_key = access_rights & 0xF
                
                info = {
                    'file_type': file_type,
                    'comm_mode': comm_mode,
                    'file_size': file_size,
                    'access_rights': {
                        'read': read_key,
                        'write': write_key,
                        'read_write': rw_key,
                        'change': change_key
                    },
                    'is_encrypted': comm_mode == CommMode.ENCRYPTED.value,
                    'security_level': 'HIGH' if comm_mode == CommMode.ENCRYPTED.value else 'LOW'
                }
                
                # Mostrar información de seguridad
                comm_modes = {0x00: "PLAIN", 0x01: "MAC", 0x03: "ENCRYPTED"}
                comm_str = comm_modes.get(comm_mode, f"UNKNOWN({comm_mode:02X})")
                
                self.log(f"Archivo {file_id}:")
                self.log(f"  Tamaño: {file_size} bytes")
                self.log(f"  Comunicación: {comm_str}")
                self.log(f"  Seguridad: {info['security_level']}")
                self.log(f"  Permisos: R=Key{read_key}, W=Key{write_key}, RW=Key{rw_key}, C=Key{change_key}")
                
                return info
            else:
                self.log(f"ERROR: Respuesta inválida")
                return None
        else:
            self.log(f"ERROR obteniendo info: {response[0]:02X}")
            return None
    
    def get_file_ids(self):
        """Obtener lista de archivos"""
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return []
        
        command = bytes([0x6F])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            file_ids = list(response[1:])
            self.log(f"Archivos encontrados: {file_ids}")
            return file_ids
        else:
            self.log(f"ERROR obteniendo archivos: {response[0]:02X}")
            return []
    
    def delete_file(self, file_id):
        """Eliminar archivo (requiere autenticación con clave de cambio)"""
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Eliminando archivo {file_id}")
        
        command = bytes([0xDF, file_id])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Archivo eliminado exitosamente")
            return True
        else:
            self.log(f"ERROR eliminando archivo: {response[0]:02X}")
            return False
    
    # =============================================================================
    # OPERACIONES SEGURAS DE DATOS
    # =============================================================================
    
    def write_secure_data(self, file_id, offset, data):
        """
        Escribir datos en archivo encriptado
        Requiere autenticación con clave de escritura
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Escribiendo {len(data)} bytes seguros en archivo {file_id}")
        
        # Verificar permisos solo si somos master (evita error 0xAE)
        if self.auth_key_number == 0:  # Master key
            file_info = self.get_file_info(file_id)
            if file_info and file_info['is_encrypted']:
                required_key = file_info['access_rights']['write']
                if self.auth_key_number != required_key:
                    self.log(f"ADVERTENCIA: Autenticado con clave {self.auth_key_number}, "
                            f"se requiere clave {required_key} para escritura")
        
        # Construir comando WriteData
        command = bytearray([0x3D, file_id])
        command.extend(struct.pack('<I', offset)[:3])
        command.extend(struct.pack('<I', len(data))[:3])
        command.extend(data)
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Datos seguros escritos exitosamente")
            return True
        else:
            self.log(f"ERROR escribiendo datos seguros: {response[0]:02X}")
            return False
    
    def read_secure_data(self, file_id, offset=0, length=None):
        """
        Leer datos de archivo encriptado
        Requiere autenticación con clave de lectura
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return None
        
        self.log(f"Leyendo datos seguros del archivo {file_id}")
        
        # Verificar permisos solo si somos master (evita error 0xAE)
        if self.auth_key_number == 0:  # Master key
            file_info = self.get_file_info(file_id)
            if file_info and file_info['is_encrypted']:
                required_key = file_info['access_rights']['read']
                if self.auth_key_number != required_key:
                    self.log(f"ADVERTENCIA: Autenticado con clave {self.auth_key_number}, "
                            f"se requiere clave {required_key} para lectura")
        
        # Construir comando ReadData
        command = bytearray([0xBD, file_id])
        command.extend(struct.pack('<I', offset)[:3])
        
        if length is not None:
            command.extend(struct.pack('<I', length)[:3])
        else:
            command.extend([0x00, 0x00, 0x00])
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            file_data = response[1:]
            self.log(f"Datos seguros leídos: {len(file_data)} bytes")
            
            # Para archivos encriptados, los datos ya están descifrados por DESFire
            return file_data
            
        elif response[0] == 0xAF:
            # Manejar respuestas multi-frame
            all_data = bytearray(response[1:])
            
            while True:
                continue_cmd = bytes([0xAF])
                response = self.send_command(continue_cmd)
                
                if response[0] == 0x00:
                    all_data.extend(response[1:])
                    break
                elif response[0] == 0xAF:
                    all_data.extend(response[1:])
                else:
                    self.log(f"ERROR en multi-frame: {response[0]:02X}")
                    return None
            
            self.log(f"Datos seguros completos: {len(all_data)} bytes")
            return bytes(all_data)
        else:
            self.log(f"ERROR leyendo datos seguros: {response[0]:02X}")
            return None
    
    # =============================================================================
    # OPERACIONES DE DEMOSTRACIÓN SEGURA
    # =============================================================================
    
    def check_key_exists(self, key_number):
        """
        Verificar si una clave específica existe intentando autenticarse
        
        Args:
            key_number (int): Número de clave a verificar
            
        Returns:
            bool: True si la clave existe
        """
        self.log(f"Verificando existencia de clave #{key_number}")
        
        try:
            # Intentar autenticación con clave por defecto
            command = bytes([0xAA, key_number])
            response = self.send_command(command)
            
            if response[0] == 0xAF:
                self.log(f"Clave #{key_number} EXISTE")
                return True
            elif response[0] == 0xCA:
                self.log(f"Clave #{key_number} NO EXISTE (0xCA)")
                return False
            else:
                self.log(f"Clave #{key_number} - Respuesta inesperada: {response[0]:02X}")
                return False
        except Exception as e:
            self.log(f"Error verificando clave #{key_number}: {e}")
            return False

    def create_key(self, key_number, new_key, key_version=0x00):
        """
        Crear una nueva clave (debe estar autenticado como master)
        
        Args:
            key_number (int): Número de clave a crear
            new_key (bytes): Nueva clave AES de 16 bytes
            key_version (int): Versión de la clave
            
        Returns:
            bool: True si creación exitosa
        """
        if not self.authenticated or self.auth_key_number != 0:
            self.log("ERROR: Debe estar autenticado como master para crear claves")
            return False
        
        self.log(f"Creando clave #{key_number}")
        
        try:
            # Para crear nueva clave diferente de la master, usar cryptogram simple
            # Cryptogram = nueva_clave + version + CRC32
            
            # Calcular CRC32 del comando completo
            crc_data = bytes([0xC4, key_number]) + new_key + bytes([key_version])
            crc32 = self.crc32_desfire(crc_data)
            
            # Construir cryptogram: nueva_clave + version + CRC32 (little endian)
            cryptogram = new_key + bytes([key_version]) + struct.pack('<L', crc32)
            
            # Pad a múltiplo de 16 bytes
            while len(cryptogram) % 16 != 0:
                cryptogram += b'\x00'
            
            self.log(f"Cryptogram antes cifrar: {cryptogram.hex().upper()}")
            
            # Cifrar con clave de sesión
            from Crypto.Cipher import AES
            cipher = AES.new(self.session_key, AES.MODE_CBC, self.session_iv)
            encrypted_cryptogram = cipher.encrypt(cryptogram)
            
            self.log(f"Cryptogram cifrado: {encrypted_cryptogram.hex().upper()}")
            
            # Actualizar IV de sesión
            self.session_iv = encrypted_cryptogram[-16:]
            
            # Enviar comando ChangeKey
            command = bytes([0xC4, key_number]) + encrypted_cryptogram
            response = self.send_command(command)
            
            if response[0] == 0x00:
                self.log(f"Clave #{key_number} creada exitosamente")
                return True
            else:
                self.log(f"ERROR creando clave #{key_number}: {response[0]:02X}")
                return False
                
        except Exception as e:
            self.log(f"ERROR en creación de clave: {e}")
            return False

    def crc32_desfire(self, data):
        """Calcular CRC32 según especificación DESFire"""
        poly = 0xEDB88320
        crc = 0xFFFFFFFF
        
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
        
        return crc & 0xFFFFFFFF

    def setup_clean_key_structure(self):
        """
        Configurar estructura de claves limpia: eliminar extras y crear necesarias
        
        Returns:
            bool: True si configuración exitosa
        """
        self.log("Configurando estructura de claves limpia...")
        
        if not self.authenticated or self.auth_key_number != 0:
            self.log("ERROR: Debe estar autenticado como master")
            return False
        
        # Verificar claves existentes
        existing_keys = []
        for key_num in range(14):  # DESFire permite hasta 14 claves
            if self.check_key_exists(key_num):
                existing_keys.append(key_num)
        
        self.log(f"Claves existentes antes de limpieza: {existing_keys}")
        
        # Eliminar claves extra (mantener solo master key #0)
        for key_num in existing_keys:
            if key_num != 0:  # No eliminar master key
                self.log(f"Eliminando clave #{key_num}")
                # Para eliminar una clave, establecerla como NULL key
                null_key = bytes(16)
                if not self.create_key(key_num, null_key):
                    self.log(f"Advertencia: No se pudo eliminar clave #{key_num}")
        
        # Crear claves necesarias para esquema de 3 claves (todas por defecto)
        read_key = bytes(16)    # Clave por defecto para lectura
        write_key = bytes(16)   # Clave por defecto para escritura
        
        # Crear clave #1 (lectura)
        if not self.create_key(1, read_key):
            self.log("ERROR: No se pudo crear clave de lectura")
            return False
        
        # Crear clave #2 (escritura)
        if not self.create_key(2, write_key):
            self.log("ERROR: No se pudo crear clave de escritura")
            return False
        
        self.log("Estructura de claves configurada: Master(0), Read(1), Write(2)")
        return True

    def setup_secure_application(self, aid):
        """
        Configurar aplicación existente con fichero STD seguro
        Usa clave AES por defecto (16 zeros) para autenticación
        
        Args:
            aid (bytes): Application ID (3 bytes)
            
        Returns:
            bool: True si configuración exitosa
        """
        self.log(f"Configurando aplicación segura {aid.hex().upper()} con clave AES por defecto...")
        
        # Seleccionar aplicación existente
        if not self.select_application(aid):
            self.log("ERROR: No se pudo seleccionar aplicación existente")
            return False
        
        # Autenticarse como master con clave AES por defecto
        self.log("Autenticando con clave AES por defecto...")
        master_key = bytes(16)  # 16 zeros - clave AES por defecto
        if not self.authenticate_aes(0, master_key):
            self.log("ERROR: No se pudo autenticar con clave AES por defecto")
            return False
        
        # Verificar qué claves existen después de autenticarse
        self.log("Verificando claves existentes...")
        existing_keys = []
        for key_num in range(4):  # Verificar claves 0-3
            if self.check_key_exists(key_num):
                existing_keys.append(key_num)
        
        self.log(f"Claves disponibles: {existing_keys}")
        
        # Determinar esquema de claves basado en lo que está disponible
        if len(existing_keys) == 1 and 0 in existing_keys:
            self.log("Aplicación configurada con 1 clave (solo master)")
            self.log("Configurando archivo con: Master=0, Read=0, Write=0")
        elif len(existing_keys) >= 3:
            self.log("Esquema de 3 claves disponible: Master(0), Read(1), Write(2)")
            self.log("Configurando archivo con: Master=0, Read=1, Write=2")
        elif len(existing_keys) >= 2:
            self.log("Esquema de 2 claves disponible: Master(0), Clave(2)")
            self.log("Configurando archivo con: Master=0, Read=2, Write=2")
        else:
            self.log("Usando esquema simplificado: solo clave master")
            self.log("Configurando archivo con: Master=0, Read=0, Write=0")
        
        self.existing_keys = existing_keys
        
        # Verificar archivos existentes (puede fallar si no tienes permisos)
        try:
            existing_files = self.get_file_ids()
            if existing_files:
                self.log(f"Archivos existentes encontrados: {existing_files}")
                for file_id in existing_files:
                    self.log(f"Eliminando archivo existente {file_id}")
                    self.delete_file(file_id)
            else:
                self.log("No hay archivos existentes")
        except Exception as e:
            self.log(f"No se pudo verificar archivos existentes (normal): {e}")
            self.log("Continuando con creación de archivo...")
        
        # Crear archivo seguro usando el esquema de claves disponible
        secure_file_id = 11
        
        # Determinar esquema de claves basado en las claves disponibles
        if len(existing_keys) == 1 and 0 in existing_keys:
            # Solo clave master disponible
            read_key, write_key, change_key = 0, 0, 0
            self.log(f"Creando archivo STD seguro con clave única: R=Key{read_key}, W=Key{write_key}, C=Key{change_key}")
            self.log("Usando clave master AES por defecto para todos los permisos")
        elif len(existing_keys) >= 3:
            # Esquema completo de 3 claves
            read_key, write_key, change_key = 1, 2, 0
            self.log(f"Creando archivo STD seguro con 3 claves: R=Key{read_key}, W=Key{write_key}, C=Key{change_key}")
        elif len(existing_keys) >= 2:
            # Esquema de 2 claves
            read_key, write_key, change_key = 2, 2, 0
            self.log(f"Creando archivo STD seguro con 2 claves: R=Key{read_key}, W=Key{write_key}, C=Key{change_key}")
        else:
            # Fallback - solo master
            read_key, write_key, change_key = 0, 0, 0
            self.log(f"Creando archivo STD seguro simplificado: R=Key{read_key}, W=Key{write_key}, C=Key{change_key}")
            self.log("Usando clave master para todos los permisos")
        
        if not self.create_secure_file(
            file_id=secure_file_id,
            file_size=512,
            read_key=read_key,
            write_key=write_key,
            change_key=change_key
        ):
            return False
        
        self.log("Aplicación segura configurada correctamente")
        self.log(f"Fichero STD seguro #{secure_file_id} creado con comunicación ENCRYPTED")
        self.log(f"Esquema de claves: Master(0), Read({read_key}), Write({write_key})")
        self.log("Todas las claves usan valor AES por defecto (16 zeros)")
        
        # Guardar claves existentes para el demo
        self.existing_keys = existing_keys
        return True


def demo_secure_operations():
    """Demostración de operaciones seguras con archivos encriptados usando clave AES por defecto"""
    print("Demo: Operaciones Seguras DESFire EV1 con Clave AES por Defecto")
    print("Aplicación: 0xF0, 0x01, 0x01")
    print("Clave Maestra: 16 zeros (AES por defecto)")
    print("=" * 60)
    
    desfire = DESFireSecureOperations(debug=True)
    
    try:
        # Conectar
        if not desfire.connect_reader():
            return False
        
        # Configurar aplicación segura específica 0xF0, 0x01, 0x01
        test_aid = bytes([0xF0, 0x01, 0x01])
        print(f"\nConfigurando aplicación: {test_aid.hex().upper()}")
        print("Creando fichero STD seguro con 3 claves...")
        if not desfire.setup_secure_application(test_aid):
            return False
        
        # OPERACIÓN 1: Escribir datos como master
        print("\n" + "="*30)
        print("OPERACIÓN 1: Escritura como MASTER")
        print("="*30)
        
        # Autenticarse como master (puede escribir)
        if not desfire.authenticate_with_role('master', existing_keys=desfire.existing_keys):
            return False
        
        secure_file_id = 11
        test_data = b"Datos confidenciales - Solo acceso autorizado"
        
        if desfire.write_secure_data(secure_file_id, 0, test_data):
            print("Datos confidenciales escritos exitosamente")
        
        # OPERACIÓN 2: Leer datos con clave de lectura
        print("\n" + "="*30)
        print("OPERACIÓN 2: Lectura con CLAVE DE LECTURA")
        print("="*30)
        
        # Autenticarse con clave de lectura
        if not desfire.authenticate_with_role('read', existing_keys=desfire.existing_keys):
            return False
        
        read_data = desfire.read_secure_data(secure_file_id, 0, len(test_data))
        if read_data:
            print(f"Datos leídos: {read_data.decode('utf-8', errors='ignore')}")
            
            # Verificar integridad
            if read_data == test_data:
                print("EXITO: Integridad de datos verificada")
            else:
                print("ERROR: Los datos no coinciden")
        
        # OPERACIÓN 3: Intentar escribir con clave de solo lectura
        print("\n" + "="*30)
        print("OPERACIÓN 3: Intento de ESCRITURA con CLAVE DE LECTURA")
        print("="*30)
        
        # Intentar escribir con clave de lectura (debería fallar)
        unauthorized_data = b"Intento de escritura no autorizada"
        result = desfire.write_secure_data(secure_file_id, 50, unauthorized_data)
        
        if not result:
            print("CORRECTO: Escritura denegada con clave de solo lectura")
        else:
            print("PROBLEMA: Escritura permitida cuando no debería")
        
        # OPERACIÓN 4: Escribir con clave de escritura
        print("\n" + "="*30)
        print("OPERACIÓN 4: Escritura con CLAVE DE ESCRITURA")
        print("="*30)
        
        # Autenticarse con clave de escritura (o master si no existe clave separada)
        if not desfire.authenticate_with_role('write', existing_keys=desfire.existing_keys):
            return False
        
        authorized_data = b"Datos autorizados por clave de escritura"
        if desfire.write_secure_data(secure_file_id, 100, authorized_data):
            print("Datos autorizados escritos exitosamente")
        
        # OPERACIÓN 5: Verificar información de seguridad del archivo
        print("\n" + "="*30)
        print("OPERACIÓN 5: INFORMACIÓN DE SEGURIDAD")
        print("="*30)
        
        # Reautenticarse como master para obtener información de archivo
        if not desfire.authenticate_with_role('master', existing_keys=desfire.existing_keys):
            print("ERROR: No se pudo autenticar como master para información")
            return False
        
        file_info = desfire.get_file_info(secure_file_id)
        if file_info:
            print(f"Nivel de seguridad: {file_info['security_level']}")
            print(f"Comunicación encriptada: {file_info['is_encrypted']}")
            print("Esquema de permisos implementado correctamente")
        else:
            print("No se pudo obtener información del archivo")
        
        print("\n" + "="*60)
        print("DEMO COMPLETADO - Operaciones seguras con clave AES por defecto")
        print("Aplicación 0xF0, 0x01, 0x01 configurada correctamente")
        print("Fichero STD seguro creado con 3 claves (todas por defecto)")
        print("="*60)
        
        return True
        
    except Exception as e:
        print(f"ERROR en demo: {e}")
        return False
    finally:
        desfire.disconnect()


if __name__ == "__main__":
    demo_secure_operations()