#!/usr/bin/env python3
"""
DESFire EV1 Unified Operations - Fixed Version
=============================================

Biblioteca simplificada para operaciones esenciales con tarjetas DESFire EV1:
- Autenticación (AES y DES automática)
- Selección de aplicaciones
- Gestión de archivos (crear, listar, eliminar)
- Lectura y escritura de datos
- Información de archivos

Versión corregida sin emojis y con WriteData arreglado.
"""

import os
import struct
from Crypto.Cipher import AES, DES
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString


class DESFireOperations:
    """Clase principal para operaciones DESFire EV1"""
    
    def __init__(self, debug=True):
        """
        Inicializar operaciones DESFire
        
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
    
    def log(self, message):
        """Imprimir mensaje de depuración si está habilitado"""
        if self.debug:
            print(message)
    
    # =============================================================================
    # CONEXIÓN Y COMUNICACIÓN
    # =============================================================================
    
    def connect_reader(self):
        """
        Conectar con lector de tarjetas
        
        Returns:
            bool: True si conexión exitosa, False en caso contrario
        """
        print("Buscando lectores disponibles...")
        reader_list = readers()
        
        if not reader_list:
            print("ERROR: No se encontraron lectores de tarjetas")
            return False
        
        print(f"Encontrados {len(reader_list)} lector(es):")
        for i, reader in enumerate(reader_list):
            print(f"  [{i}] {reader}")
        
        # Seleccionar lector
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
            print("ERROR: No se detectó tarjeta en el lector")
            return False
    
    def send_command(self, command):
        """
        Enviar comando DESFire a la tarjeta
        
        Args:
            command (bytes): Comando nativo DESFire
            
        Returns:
            bytes: Respuesta de la tarjeta (primer byte = código de estado)
        """
        # Envolver comando nativo en APDU ISO 7816-4
        if len(command) == 1:
            apdu = [0x90, command[0], 0x00, 0x00, 0x00]
        else:
            cmd_byte = command[0]
            data = command[1:]
            
            # Comandos que NO necesitan Le=0x00 al final (escriben datos)
            no_le_commands = [0x3D, 0xCD, 0xAF]  # WriteData, CreateStdDataFile, AdditionalFrame
            
            if cmd_byte in no_le_commands:
                # Sin Le para comandos de escritura
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data)
            else:
                # Con Le=0x00 para comandos de lectura/control
                apdu = [0x90, cmd_byte, 0x00, 0x00, len(data)] + list(data) + [0x00]
        
        try:
            if self.debug:
                self.log(f"APDU: {toHexString(apdu)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if self.debug:
                resp_str = toHexString(response) if response else 'Sin datos'
                self.log(f"Response: {resp_str}, SW: {sw1:02X} {sw2:02X}")
            
            # Procesar respuesta según códigos de estado
            if sw1 == 0x90 and sw2 == 0x00:
                return bytes([0x00]) + bytes(response) if response else bytes([0x00])
            elif sw1 == 0x91:
                return bytes([sw2]) + bytes(response) if response else bytes([sw2])
            else:
                return bytes([0x6E])  # Error de comunicación
                
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
        """
        Autenticación AES con DESFire
        
        Args:
            key_number (int): Número de clave (0-13)
            key (bytes): Clave AES de 16 bytes
            
        Returns:
            bool: True si autenticación exitosa
        """
        self.log(f"Iniciando autenticación AES - Clave #{key_number}")
        
        try:
            # Paso 1: Solicitar autenticación
            command = bytes([0xAA, key_number])
            response = self.send_command(command)
            
            if response[0] != 0xAF or len(response) != 17:
                self.log(f"ERROR en paso 1: {response[0]:02X}")
                return False
            
            encrypted_rnd_b = response[1:17]
            self.log(f"RndB cifrado: {encrypted_rnd_b.hex().upper()}")
            
            # Paso 2: Descifrar RndB
            iv_zero = bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv_zero)
            rnd_b = cipher.decrypt(encrypted_rnd_b)
            self.log(f"RndB: {rnd_b.hex().upper()}")
            
            # Paso 3: Rotar RndB y generar RndA
            rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
            rnd_a = os.urandom(16)
            self.log(f"RndA: {rnd_a.hex().upper()}")
            
            # Paso 4: Cifrar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            cipher = AES.new(key, AES.MODE_CBC, encrypted_rnd_b)
            encrypted_rnd_ab = cipher.encrypt(rnd_ab)
            
            # Paso 5: Enviar respuesta
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.send_command(command)
            
            if response[0] != 0x00 or len(response) != 17:
                self.log(f"ERROR en paso 2: {response[0]:02X}")
                return False
            
            # Paso 6: Verificar RndA rotado
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
            
            self.log(f"Autenticación AES exitosa!")
            return True
            
        except Exception as e:
            self.log(f"ERROR en autenticación AES: {e}")
            return False
    
    def authenticate_des(self, key_number, key):
        """
        Autenticación DES/3DES con DESFire
        
        Args:
            key_number (int): Número de clave (0-13)
            key (bytes): Clave DES de 8 bytes
            
        Returns:
            bool: True si autenticación exitosa
        """
        self.log(f"Iniciando autenticación DES - Clave #{key_number}")
        
        try:
            # Paso 1: Solicitar autenticación DES
            command = bytes([0x1A, key_number])
            response = self.send_command(command)
            
            if response[0] != 0xAF or len(response) != 9:
                self.log(f"ERROR en paso 1: {response[0]:02X}")
                return False
            
            encrypted_rnd_b = response[1:9]
            self.log(f"RndB cifrado: {encrypted_rnd_b.hex().upper()}")
            
            # Paso 2: Descifrar RndB
            iv_zero = bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv_zero)
            rnd_b = cipher.decrypt(encrypted_rnd_b)
            self.log(f"RndB: {rnd_b.hex().upper()}")
            
            # Paso 3: Rotar RndB y generar RndA
            rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
            rnd_a = os.urandom(8)
            self.log(f"RndA: {rnd_a.hex().upper()}")
            
            # Paso 4: Cifrar RndA + RndB'
            rnd_ab = rnd_a + rnd_b_rotated
            cipher = DES.new(key, DES.MODE_CBC, encrypted_rnd_b)
            encrypted_rnd_ab = cipher.encrypt(rnd_ab)
            
            # Paso 5: Enviar respuesta
            command = bytes([0xAF]) + encrypted_rnd_ab
            response = self.send_command(command)
            
            if response[0] != 0x00 or len(response) != 9:
                self.log(f"ERROR en paso 2: {response[0]:02X}")
                return False
            
            # Paso 6: Verificar RndA rotado
            encrypted_rnd_a = response[1:9]
            iv_for_decrypt = encrypted_rnd_ab[-8:]
            cipher = DES.new(key, DES.MODE_CBC, iv_for_decrypt)
            decrypted_rnd_a = cipher.decrypt(encrypted_rnd_a)
            
            expected_rnd_a = rnd_a[1:] + rnd_a[:1]
            if decrypted_rnd_a != expected_rnd_a:
                self.log("ERROR: Verificación RndA falló")
                return False
            
            # Paso 7: Configurar sesión DES
            self.session_key = key + key  # Duplicar para compatibilidad
            self.session_iv = bytes(8)
            self.authenticated = True
            self.auth_key_number = key_number
            
            self.log(f"Autenticación DES exitosa!")
            return True
            
        except Exception as e:
            self.log(f"ERROR en autenticación DES: {e}")
            return False
    
    def authenticate_auto(self, key_number, aes_key=None, des_key=None):
        """
        Autenticación automática (intenta AES y DES)
        
        Args:
            key_number (int): Número de clave
            aes_key (bytes, optional): Clave AES de 16 bytes
            des_key (bytes, optional): Clave DES de 8 bytes
            
        Returns:
            bool: True si alguna autenticación fue exitosa
        """
        self.log(f"Autenticación automática - Clave #{key_number}")
        
        # Intentar con claves proporcionadas
        if aes_key is not None:
            self.log("Probando AES...")
            if self.authenticate_aes(key_number, aes_key):
                return True
        
        if des_key is not None:
            self.log("Probando DES...")
            if self.authenticate_des(key_number, des_key):
                return True
        
        # Intentar con claves por defecto
        if aes_key is None and des_key is None:
            self.log("Probando claves por defecto...")
            if self.authenticate_aes(key_number, bytes(16)):
                return True
            if self.authenticate_des(key_number, bytes(8)):
                return True
        
        self.log("ERROR: Todas las autenticaciones fallaron")
        return False
    
    # =============================================================================
    # GESTIÓN DE APLICACIONES
    # =============================================================================
    
    def select_application(self, aid):
        """
        Seleccionar aplicación por AID
        
        Args:
            aid (bytes): Application ID (3 bytes)
            
        Returns:
            bool: True si selección exitosa
        """
        self.log(f"Seleccionando aplicación: {aid.hex().upper()}")
        
        command = bytes([0x5A]) + aid
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Aplicación seleccionada")
            self.authenticated = False  # Reset autenticación
            return True
        else:
            self.log(f"ERROR seleccionando aplicación: {response[0]:02X}")
            return False
    
    def get_application_ids(self):
        """
        Obtener lista de aplicaciones
        
        Returns:
            list: Lista de AIDs encontrados
        """
        self.log("Obteniendo lista de aplicaciones...")
        
        command = bytes([0x6A])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            aids = []
            data = response[1:]
            for i in range(0, len(data), 3):
                if i + 2 < len(data):
                    aid = data[i:i+3]
                    aids.append(aid)
            
            self.log(f"Encontradas {len(aids)} aplicaciones")
            return aids
        else:
            self.log(f"ERROR obteniendo aplicaciones: {response[0]:02X}")
            return []
    
    # =============================================================================
    # GESTIÓN DE ARCHIVOS
    # =============================================================================
    
    def get_file_ids(self):
        """
        Obtener lista de archivos en aplicación actual
        
        Returns:
            list: Lista de File IDs
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return []
        
        self.log("Obteniendo lista de archivos...")
        
        command = bytes([0x6F])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            file_ids = list(response[1:])
            self.log(f"Encontrados {len(file_ids)} archivos: {file_ids}")
            return file_ids
        else:
            self.log(f"ERROR obteniendo archivos: {response[0]:02X}")
            return []
    
    def get_file_info(self, file_id):
        """
        Obtener información de un archivo
        
        Args:
            file_id (int): ID del archivo (0-31)
            
        Returns:
            dict: Información del archivo o None si error
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return None
        
        self.log(f"Obteniendo info del archivo {file_id}")
        
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
                    }
                }
                
                comm_modes = {0x00: "PLAIN", 0x01: "MAC", 0x03: "ENCRYPTED"}
                comm_str = comm_modes.get(comm_mode, f"UNKNOWN({comm_mode:02X})")
                
                self.log(f"Archivo {file_id}:")
                self.log(f"   Tamaño: {file_size} bytes")
                self.log(f"   Modo: {comm_str}")
                self.log(f"   Acceso: R={read_key}, W={write_key}, RW={rw_key}, C={change_key}")
                
                return info
            else:
                self.log(f"ERROR: Respuesta inválida: {len(settings)} bytes")
                return None
        else:
            self.log(f"ERROR obteniendo info: {response[0]:02X}")
            return None
    
    def create_standard_file(self, file_id, file_size, comm_mode=0x00, access_rights=0xEEEE):
        """
        Crear archivo de datos estándar
        
        Args:
            file_id (int): ID del archivo (0-31)
            file_size (int): Tamaño en bytes
            comm_mode (int): Modo de comunicación (0x00=PLAIN, 0x01=MAC, 0x03=ENCRYPTED)
            access_rights (int): Derechos de acceso (0xEEEE=acceso libre)
            
        Returns:
            bool: True si creación exitosa
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Creando archivo {file_id} ({file_size} bytes)")
        
        # Construir comando CreateStdDataFile
        command = bytearray([0xCD, file_id, comm_mode])
        command.extend(struct.pack('<H', access_rights))
        command.extend(struct.pack('<I', file_size)[:3])
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Archivo creado exitosamente")
            return True
        else:
            self.log(f"ERROR creando archivo: {response[0]:02X}")
            return False
    
    def delete_file(self, file_id):
        """
        Eliminar archivo
        
        Args:
            file_id (int): ID del archivo a eliminar
            
        Returns:
            bool: True si eliminación exitosa
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Eliminando archivo {file_id}")
        
        command = bytes([0xDF, file_id])
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Archivo eliminado")
            return True
        else:
            self.log(f"ERROR eliminando archivo: {response[0]:02X}")
            return False
    
    # =============================================================================
    # LECTURA Y ESCRITURA DE DATOS
    # =============================================================================
    
    def write_file_data(self, file_id, offset, data):
        """
        Escribir datos en archivo
        
        Args:
            file_id (int): ID del archivo
            offset (int): Posición de inicio
            data (bytes): Datos a escribir
            
        Returns:
            bool: True si escritura exitosa
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return False
        
        self.log(f"Escribiendo {len(data)} bytes en archivo {file_id} (offset {offset})")
        
        # CORREGIDO: Construir comando WriteData sin el byte extra al final
        command = bytearray([0x3D, file_id])
        command.extend(struct.pack('<I', offset)[:3])      # Offset (3 bytes)
        command.extend(struct.pack('<I', len(data))[:3])   # Length (3 bytes)
        command.extend(data)                               # Data payload
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            self.log("Datos escritos exitosamente")
            return True
        else:
            self.log(f"ERROR escribiendo datos: {response[0]:02X}")
            return False
    
    def read_file_data(self, file_id, offset=0, length=None, auto_trim=True):
        """
        Leer datos de archivo
        
        Args:
            file_id (int): ID del archivo
            offset (int): Posición de inicio
            length (int, optional): Número de bytes a leer (None=todos)
            auto_trim (bool): Recortar automáticamente padding/MAC
            
        Returns:
            bytes: Datos leídos o None si error
        """
        if not self.authenticated:
            self.log("ERROR: Debe autenticarse primero")
            return None
        
        self.log(f"Leyendo archivo {file_id} (offset {offset}, length {length or 'ALL'})")
        
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
            self.log(f"Datos raw ({len(file_data)} bytes): {file_data.hex().upper()}")
            
            # Auto-trim si está habilitado y tenemos datos extra
            if auto_trim and length is not None and len(file_data) > length:
                expected_data = file_data[:length]
                extra_data = file_data[length:]
                
                self.log(f"Recortando: {len(expected_data)} bytes útiles, {len(extra_data)} extras")
                return expected_data
            
            return file_data
            
        elif response[0] == 0xAF:
            # Manejo de respuestas multi-frame
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
            
            self.log(f"Datos completos ({len(all_data)} bytes)")
            
            # Aplicar auto-trim también a respuestas multi-frame
            if auto_trim and length is not None and len(all_data) > length:
                return bytes(all_data[:length])
            
            return bytes(all_data)
        else:
            self.log(f"ERROR leyendo datos: {response[0]:02X}")
            return None


# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

def format_bytes(data, bytes_per_line=16):
    """Formatear bytes para visualización hexadecimal"""
    if not data:
        return "Sin datos"
    
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:04X}: {hex_part:<48} |{ascii_part}|")
    
    return '\n'.join(lines)


def demo_basic_operations():
    """Demostración de operaciones básicas"""
    print("Demo: Operaciones Básicas DESFire EV1")
    print("=" * 50)
    
    # Inicializar
    desfire = DESFireOperations(debug=True)
    
    try:
        # Conectar
        if not desfire.connect_reader():
            return False
        
        # Listar aplicaciones disponibles primero
        print("\nListando aplicaciones disponibles...")
        available_apps = desfire.get_application_ids()
        if available_apps:
            print("Aplicaciones encontradas:")
            for i, aid in enumerate(available_apps):
                print(f"  [{i}] {aid.hex().upper()}")
        else:
            print("No se encontraron aplicaciones")
        
        # Seleccionar aplicación de prueba
        test_aid = bytes([0xF0, 0x01, 0x01])
        print(f"\nIntentando seleccionar aplicación: {test_aid.hex().upper()}")
        if not desfire.select_application(test_aid):
            print(f"ADVERTENCIA: Aplicación {test_aid.hex().upper()} no encontrada")
            
            # Si hay aplicaciones disponibles, usar la primera
            if available_apps:
                test_aid = available_apps[0]
                print(f"Usando aplicación disponible: {test_aid.hex().upper()}")
                if not desfire.select_application(test_aid):
                    return False
            else:
                return False
        
        # Autenticación automática
        if not desfire.authenticate_auto(0):
            print("ERROR: Falló la autenticación")
            return False
        
        # Listar archivos
        file_ids = desfire.get_file_ids()
        
        # Crear archivo de prueba si no existe
        test_file_id = 25
        if test_file_id not in file_ids:
            print(f"\nCreando archivo de prueba {test_file_id}")
            if not desfire.create_standard_file(test_file_id, 256):
                return False
        
        # Obtener información del archivo
        print(f"\nInformación del archivo {test_file_id}:")
        file_info = desfire.get_file_info(test_file_id)
        
        # Escribir datos de prueba más cortos
        test_data = b"Hola DESFire! Test OK."
        print(f"\nEscribiendo datos de prueba...")
        if not desfire.write_file_data(test_file_id, 0, test_data):
            return False
        
        # Leer datos
        print(f"\nLeyendo datos...")
        read_data = desfire.read_file_data(test_file_id, 0, len(test_data))
        
        if read_data:
            print(f"Datos leídos:")
            print(format_bytes(read_data))
            print(f"Como texto: {read_data.decode('utf-8', errors='ignore')}")
            
            # Verificar integridad
            if read_data == test_data:
                print("EXITO: Integridad de datos verificada!")
            else:
                print("ERROR: Los datos no coinciden")
        
        print("\nDemo completado exitosamente!")
        return True
        
    except Exception as e:
        print(f"ERROR en demo: {e}")
        return False
    finally:
        desfire.disconnect()


if __name__ == "__main__":
    # Ejecutar demostración
    demo_basic_operations()