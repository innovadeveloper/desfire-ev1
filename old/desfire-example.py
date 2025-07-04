#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para formatear tarjetas MIFARE DESFire EV1 vírgenes
Implementa autenticación completa DES/3DES antes del formateo
Versión corregida con manejo mejorado de tipos de bytes
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import CardConnectionException
import sys
import os

# Importar bibliotecas criptográficas
try:
    from Crypto.Cipher import DES
    CRYPTO_AVAILABLE = True
except ImportError:
    print("Advertencia: Biblioteca PyCrypto no encontrada.")
    print("Ejecute: pip install pycryptodome")
    CRYPTO_AVAILABLE = False

# Comandos APDU para DESFire
DESFIRE_GET_VERSION = [0x90, 0x60, 0x00, 0x00, 0x00]
DESFIRE_FORMAT_PICC = [0x90, 0xFC, 0x00, 0x00, 0x00]
DESFIRE_ABORT = [0x90, 0xA7, 0x00, 0x00, 0x00]
DESFIRE_MORE_DATA = [0x90, 0xAF, 0x00, 0x00, 0x00]
DESFIRE_SELECT_APPLICATION = [0x90, 0x5A, 0x00, 0x00, 0x03]
DESFIRE_AUTHENTICATE_ISO = [0x90, 0x1A, 0x00, 0x00, 0x01, 0x00, 0x00]  # Auth ISO (DES/3DES) con clave 0
DESFIRE_AUTHENTICATE_AES = [0x90, 0xAA, 0x00, 0x00]  # + key_no + Le

# Códigos de estado
OPERATION_OK = 0x91
ADDITIONAL_FRAME = 0xAF
STATUS_OK = 0x00

class DESFireFormatter:
    def __init__(self, debug=True):
        self.reader = None
        self.connection = None
        self.debug = debug
        self.authenticated_with_key = None  # Para rastrear con qué clave nos autenticamos
        self.session_key = None  # Para almacenar la clave de sesión
        
    def log(self, message):
        """Imprime mensaje de depuración si el modo debug está activado"""
        if self.debug:
            print(message)
    
    def connect_reader(self):
        """Conecta con el primer lector disponible"""
        print("Buscando lectores disponibles...")
        reader_list = readers()
        
        if not reader_list:
            print("No se han encontrado lectores de tarjetas. Verifica que el lector esté conectado.")
            sys.exit(1)
        
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
        
        self.reader = reader_list[reader_index]
        print(f"Usando lector: {self.reader}")
        
        try:
            # Conecta con la tarjeta
            self.connection = self.reader.createConnection()
            self.connection.connect()
            print("Conexión establecida con la tarjeta.")
            atr = self.connection.getATR()
            print(f"ATR: {toHexString(atr)}")
            return True
        except CardConnectionException:
            print("No se ha detectado ninguna tarjeta. Por favor, coloque una tarjeta sobre el lector.")
            return False
    
    def send_apdu(self, apdu):
        """Envía un comando APDU a la tarjeta y devuelve la respuesta"""
        try:
            response, sw1, sw2 = self.connection.transmit(apdu)
            if self.debug:
                print(f"Comando: {toHexString(apdu)}")
                print(f"Respuesta: {toHexString(response) if response else 'Sin datos'}, SW: {hex(sw1)} {hex(sw2)}")
            return response, sw1, sw2
        except Exception as e:
            print(f"Error al enviar APDU: {e}")
            return [], 0, 0
    
    def authenticate_des(self):
        """Implementa autenticación completa DES con la clave predeterminada"""
        if not CRYPTO_AVAILABLE:
            print("Error: Se requiere PyCryptodome para la autenticación DES/3DES.")
            print("Instale la biblioteca con: pip install pycryptodome")
            return False
            
        print("\n=== Realizando autenticación DES completa ===")
        
        # 1. Abortar cualquier operación pendiente
        print("Abortando transacciones pendientes...")
        self.send_apdu(DESFIRE_ABORT)
        
        # 2. Seleccionar aplicación maestra (AID = 000000)
        print("Seleccionando aplicación maestra...")
        select_apdu = DESFIRE_SELECT_APPLICATION + [0x00, 0x00, 0x00] + [0x00]
        select_response, select_sw1, select_sw2 = self.send_apdu(select_apdu)
        
        # 3. Iniciar autenticación DES (clave por defecto todo ceros)
        print("Iniciando autenticación DES/3DES...")
        auth_response, auth_sw1, auth_sw2 = self.send_apdu(DESFIRE_AUTHENTICATE_ISO)
        
        if (auth_sw1 != OPERATION_OK or auth_sw2 != ADDITIONAL_FRAME) and (auth_sw1 != ADDITIONAL_FRAME):
            print(f"Error al iniciar autenticación: {hex(auth_sw1)} {hex(auth_sw2)}")
            return False
        
        # 4. La tarjeta envía un desafío cifrado (RndB encriptado)
        # La respuesta contiene 8 bytes (RndB cifrado con la clave DES)
        encrypted_challenge = auth_response
        if len(encrypted_challenge) != 8:
            print(f"Error: Longitud de desafío cifrado incorrecta ({len(encrypted_challenge)} bytes)")
            return False
        
        # 5. Descifrar el desafío usando la clave maestra por defecto (00...00)
        default_key = bytes([0x00] * 8)  # Clave DES de 8 bytes todo ceros
        iv = bytes([0x00] * 8)  # IV inicial (todo ceros)
        
        try:
            # Convertir la respuesta a bytes (importante para evitar errores de tipo)
            encrypted_challenge_bytes = bytes(encrypted_challenge)
            print(f"Desafío cifrado (bytes): {encrypted_challenge_bytes.hex()}")
            
            # Descifrar el desafío RndB
            cipher = DES.new(default_key, DES.MODE_CBC, iv)
            decrypted_challenge = cipher.decrypt(encrypted_challenge_bytes)
            print(f"Desafío descifrado (RndB): {decrypted_challenge.hex()}")
            
            # 6. Generar un desafío propio (RndA)
            rnd_a = os.urandom(8)
            print(f"Desafío generado (RndA): {rnd_a.hex()}")
            
            # 7. Rotar RndB un byte a la izquierda
            rotated_challenge = decrypted_challenge[1:] + decrypted_challenge[:1]
            print(f"Desafío rotado (RndB'): {rotated_challenge.hex()}")
            
            # 8. Concatenar RndA + RndB rotado
            token = rnd_a + rotated_challenge
            print(f"Token a cifrar (RndA + RndB'): {token.hex()}")
            
            # 9. Cifrar el token con la clave usando IV de la respuesta anterior
            cipher = DES.new(default_key, DES.MODE_CBC, encrypted_challenge_bytes)
            encrypted_token = cipher.encrypt(token)
            print(f"Token cifrado: {encrypted_token.hex()}")
            
            # 10. Enviar el token cifrado a la tarjeta
            # Convertir de bytes a lista para el comando APDU
            encrypted_token_list = list(encrypted_token)
            token_apdu = [0x90, 0xAF, 0x00, 0x00, len(encrypted_token_list)] + encrypted_token_list + [0x00]
            token_response, token_sw1, token_sw2 = self.send_apdu(token_apdu)
            
            if token_sw1 != OPERATION_OK or token_sw2 != STATUS_OK:
                print(f"Error en respuesta de token: {hex(token_sw1)} {hex(token_sw2)}")
                return False
            
            # 11. Verificar la respuesta de la tarjeta (debería ser RndA rotado y cifrado)
            if len(token_response) == 8:
                # Convertir respuesta a bytes
                token_response_bytes = bytes(token_response)
                
                # Descifrar la respuesta de la tarjeta
                # Usar como IV los últimos 8 bytes del token cifrado enviado
                response_iv = encrypted_token[-8:]
                cipher = DES.new(default_key, DES.MODE_CBC, response_iv)
                decrypted_response = cipher.decrypt(token_response_bytes)
                print(f"Respuesta descifrada: {decrypted_response.hex()}")
                
                # Rotar RndA un byte a la izquierda para comparar
                expected_response = rnd_a[1:] + rnd_a[:1]
                print(f"Respuesta esperada (RndA'): {expected_response.hex()}")
                
                if decrypted_response == expected_response:
                    print("¡Autenticación exitosa! La tarjeta respondió correctamente.")
                    return True
                else:
                    print("Error: La respuesta de la tarjeta no coincide con lo esperado.")
                    return False
            else:
                print(f"Error: Longitud de respuesta incorrecta ({len(token_response)} bytes)")
                return False
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en proceso de autenticación: {e}")
            return False
    
    def authenticate_aes(self, key_no, key_data=None):
        """
        Implementa autenticación completa AES con la clave especificada
        
        Parámetros:
            key_no (int): Número de clave para autenticación (0-13)
            key_data (list/bytes): Clave AES (16 bytes). Si es None, usa la clave por defecto.
        
        Retorna:
            bool: True si la autenticación fue exitosa, False en caso de error
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
        except ImportError:
            print("Error: Se requiere PyCryptodome para la autenticación AES.")
            print("Instale la biblioteca con: pip install pycryptodome")
            return False
                
        print(f"\n=== Realizando autenticación AES con clave #{key_no} ===")
        
        # Si no se proporciona la clave, usar la clave por defecto (todos ceros)
        if key_data is None:
            key_data = [0x00] * 16  # Clave AES de 16 bytes todo ceros
        
        # Asegurar que la clave esté en formato bytes
        if isinstance(key_data, list):
            key_data = bytes(key_data)
        
        # Validar longitud de la clave
        if len(key_data) != 16:
            print(f"Error: La clave AES debe tener 16 bytes (actual: {len(key_data)})")
            return False
        
        # 1. Abortar cualquier operación pendiente
        print("Abortando transacciones pendientes...")
        self.send_apdu(DESFIRE_ABORT)
        
        # 2. Seleccionar la aplicación actual si es necesario
        # Esto es opcional y depende de tu flujo de trabajo
        
        # 3. Iniciar autenticación AES con la clave especificada
        print(f"Iniciando autenticación AES para clave #{key_no}...")
        # Comando de autenticación AES: 90 AA 00 00 01 [key_no] 00
        auth_apdu = [0x90, 0xAA, 0x00, 0x00, 0x01, key_no, 0x00]
        auth_response, auth_sw1, auth_sw2 = self.send_apdu(auth_apdu)
        
        if not ((auth_sw1 == OPERATION_OK and auth_sw2 == ADDITIONAL_FRAME) or 
                (auth_sw1 == ADDITIONAL_FRAME)):
            print(f"Error al iniciar autenticación: {hex(auth_sw1)} {hex(auth_sw2)}")
            return False
        
        # 4. La tarjeta envía un desafío cifrado (RndB encriptado)
        # La respuesta contiene 16 bytes (RndB cifrado con AES)
        encrypted_challenge = auth_response
        if len(encrypted_challenge) != 16:
            print(f"Error: Longitud de desafío cifrado incorrecta ({len(encrypted_challenge)} bytes)")
            return False
        
        # 5. Descifrar el desafío usando la clave especificada
        iv = bytes([0x00] * 16)  # IV inicial para AES (todo ceros)
        
        try:
            # Convertir la respuesta a bytes
            encrypted_challenge_bytes = bytes(encrypted_challenge)
            print(f"Desafío cifrado (bytes): {encrypted_challenge_bytes.hex()}")
            
            # Descifrar el desafío RndB
            cipher = AES.new(key_data, AES.MODE_CBC, iv)
            decrypted_challenge = cipher.decrypt(encrypted_challenge_bytes)
            print(f"Desafío descifrado (RndB): {decrypted_challenge.hex()}")
            
            # 6. Generar un desafío propio (RndA)
            rnd_a = os.urandom(16)  # 16 bytes para AES
            print(f"Desafío generado (RndA): {rnd_a.hex()}")
            
            # 7. Rotar RndB un byte a la izquierda
            rotated_challenge = decrypted_challenge[1:] + decrypted_challenge[:1]
            print(f"Desafío rotado (RndB'): {rotated_challenge.hex()}")
            
            # 8. Concatenar RndA + RndB rotado
            token = rnd_a + rotated_challenge
            print(f"Token a cifrar (RndA + RndB'): {token.hex()}")
            
            # 9. Cifrar el token con la clave AES usando como IV el desafío cifrado
            cipher = AES.new(key_data, AES.MODE_CBC, encrypted_challenge_bytes)
            encrypted_token = cipher.encrypt(token)
            print(f"Token cifrado: {encrypted_token.hex()}")
            
            # 10. Enviar el token cifrado a la tarjeta
            encrypted_token_list = list(encrypted_token)
            token_apdu = [0x90, 0xAF, 0x00, 0x00, len(encrypted_token_list)] + encrypted_token_list + [0x00]
            token_response, token_sw1, token_sw2 = self.send_apdu(token_apdu)
            
            if token_sw1 != OPERATION_OK:
                print(f"Error en respuesta de token: {hex(token_sw1)} {hex(token_sw2)}")
                return False
            
            # 11. Verificar la respuesta de la tarjeta (RndA rotado y cifrado)
            if len(token_response) != 16:
                print(f"Error: Longitud de respuesta incorrecta ({len(token_response)} bytes)")
                return False
            
            # Convertir respuesta a bytes
            token_response_bytes = bytes(token_response)
            
            # Descifrar la respuesta usando como IV los últimos 16 bytes del token cifrado
            response_iv = encrypted_token[-16:]
            cipher = AES.new(key_data, AES.MODE_CBC, response_iv)
            decrypted_response = cipher.decrypt(token_response_bytes)
            print(f"Respuesta descifrada: {decrypted_response.hex()}")
            
            # Rotar RndA un byte a la izquierda para comparar
            expected_response = rnd_a[1:] + rnd_a[:1]
            print(f"Respuesta esperada (RndA'): {expected_response.hex()}")
            
            if decrypted_response == expected_response:
                print("¡Autenticación AES exitosa!")
                
                # 12. Generar clave de sesión (para futuras operaciones cifradas)
                # La clave de sesión se forma concatenando:
                # - Los primeros 4 bytes de RndA
                # - Los primeros 4 bytes de RndB
                # - Los últimos 4 bytes de RndA
                # - Los últimos 4 bytes de RndB
                session_key = rnd_a[:4] + decrypted_challenge[:4] + rnd_a[-4:] + decrypted_challenge[-4:]
                print(f"Clave de sesión generada: {bytes(session_key).hex()}")
                
                # Guardar estado de autenticación (para cambio de claves)
                self.authenticated_with_key = key_no
                self.session_key = session_key
                
                return True
            else:
                print("Error: La respuesta de la tarjeta no coincide con lo esperado.")
                return False
                    
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error en proceso de autenticación AES: {e}")
            return False
    
    def format_card(self):
        """Formatea la tarjeta después de autenticación"""
        print("\n=== Formateando tarjeta ===")
        print("ADVERTENCIA: Este proceso borrará TODOS los datos de la tarjeta.")
        confirmation = input("¿Está seguro de que desea continuar? (s/n): ")
        
        if confirmation.lower() != 's':
            print("Formateo cancelado.")
            return False
        
        # Envía el comando de formateo
        format_response, format_sw1, format_sw2 = self.send_apdu(DESFIRE_FORMAT_PICC)
        
        if format_sw1 == OPERATION_OK and format_sw2 == STATUS_OK:
            print("¡Tarjeta formateada exitosamente!")
            return True
        else:
            print(f"Error al formatear la tarjeta: SW={hex(format_sw1)}{hex(format_sw2)}")
            
            if format_sw1 == 0x91 and format_sw2 == 0xAE:
                print("Error de autenticación. Debe autenticarse antes de formatear.")
            elif format_sw1 == 0x91 and format_sw2 == 0xCA:
                print("Comando abortado. Pruebe a restablecer la tarjeta e iniciar de nuevo.")
            
            return False

    def select_application(self, aid):
        """Selecciona una aplicación por su AID"""
        print(f"\n=== Seleccionando aplicación {toHexString(aid)} ===")
        # Crear el comando APDU para seleccionar la aplicación
        apdu = DESFIRE_SELECT_APPLICATION + aid + [0x00]  # Le + bytes del AID + Le
        response, sw1, sw2 = self.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación {toHexString(aid)} seleccionada correctamente.")
            return True
        else:
            print(f"Error al seleccionar la aplicación: SW1={hex(sw1)}, SW2={hex(sw2)}")
            return False
        
    # CREACION DE APLICACION

    def create_application(self, aid, settings=0x0F, num_keys=0x83, key_type="AES"):
        """
        Crea una nueva aplicación en la tarjeta DESFire EV1
        
        Parámetros:
            aid (list): Application ID - lista de 3 bytes, ej: [0x01, 0x02, 0x03]
            settings (int): Configuración de la aplicación (1 byte)
                        - bit 0: Clave maestra puede cambiarse (1=sí)
                        - bit 1: Acceso libre para listar archivos (1=sí)
                        - bit 2: Acceso libre para crear/eliminar archivos (1=sí)
                        - bit 3: Configuración puede cambiarse (1=sí)
            num_keys (int): Número y tipo de claves
                        - Para AES: 0x80 + número de claves (1-14)
                        - Para 3K3DES: 0x40 + número de claves (1-14) 
                        - Para DES/3DES: número de claves (1-14)
            key_type (str): "AES", "3K3DES", o "DES" (informativo, determina el formato de num_keys)
        
        Retorna:
            bool: True si se creó correctamente, False en caso contrario
        """
        print(f"\n=== Creando aplicación con AID={toHexString(aid)} ===")
        
        # Validar parámetros
        if len(aid) != 3:
            print("Error: AID debe ser de 3 bytes")
            return False
        
        # Validar key_type y ajustar num_keys si es necesario
        if key_type == "AES" and (num_keys & 0x80) != 0x80:
            print(f"Advertencia: Ajustando num_keys para AES: 0x{num_keys:02X} -> 0x{(num_keys | 0x80):02X}")
            num_keys |= 0x80
        elif key_type == "3K3DES" and (num_keys & 0x40) != 0x40:
            print(f"Advertencia: Ajustando num_keys para 3K3DES: 0x{num_keys:02X} -> 0x{(num_keys | 0x40):02X}")
            num_keys |= 0x40
        
        # Número de claves real (sin bits de tipo)
        real_num_keys = num_keys & 0x0F
        if real_num_keys < 1 or real_num_keys > 14:
            print(f"Error: Número de claves inválido: {real_num_keys}")
            return False
        
        # Construir el APDU para CreateApplication
        data = aid + [settings, num_keys]
        apdu = [0x90, 0xCA, 0x00, 0x00, len(data)] + data + [0x00]
        
        # Enviar comando
        response, sw1, sw2 = self.send_apdu(apdu)
        
        # Verificar respuesta
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación creada exitosamente: AID={toHexString(aid)}")
            print(f"  - Configuración: 0x{settings:02X}")
            print(f"  - Tipo de claves: {key_type}")
            print(f"  - Número de claves: {real_num_keys}")
            
            # Imprimir significado de los bits de configuración
            self._print_settings_meaning(settings)
            
            return True
        else:
            print(f"Error al crear la aplicación: SW={hex(sw1)}{hex(sw2)}")
            
            # Interpretación de errores comunes
            if sw1 == OPERATION_OK:
                if sw2 == 0xDE:
                    print("Error: La aplicación ya existe")
                elif sw2 == 0xAE:
                    print("Error: Autenticación requerida")
                elif sw2 == 0x9D:
                    print("Error: Permiso denegado")
            
            return False
        
    def _print_settings_meaning(self, settings):
        """Imprime el significado de los bits de configuración de la aplicación"""
        print("\nSignificado de la configuración (settings):")
        print(f"  - Bit 0: Clave maestra {'PUEDE' if settings & 0x01 else 'NO PUEDE'} cambiarse")
        print(f"  - Bit 1: Listar archivos {'NO REQUIERE' if settings & 0x02 else 'REQUIERE'} autenticación")
        print(f"  - Bit 2: Crear/eliminar archivos {'NO REQUIERE' if settings & 0x04 else 'REQUIERE'} autenticación")
        print(f"  - Bit 3: Configuración {'PUEDE' if settings & 0x08 else 'NO PUEDE'} cambiarse en el futuro")
        
        # Advertencias de seguridad
        if settings & 0x02:
            print("\n⚠️ ADVERTENCIA DE SEGURIDAD: Listar archivos no requiere autenticación")
        if settings & 0x04:
            print("⚠️ ADVERTENCIA DE SEGURIDAD: Crear/eliminar archivos no requiere autenticación")


    def create_wallet_application(self):
        """
        Ejemplo: Crea una aplicación de monedero electrónico con 3 claves AES
        - Clave 0: Clave maestra (administración)
        - Clave 1: Clave de débito (para operaciones de pago)
        - Clave 2: Clave de crédito (para operaciones de recarga)
        """
        # Seleccionar un AID para la aplicación de monedero
        wallet_aid = [0xF0, 0x01, 0x01]  # Ejemplo: F00101 para monedero
        
        # Configuración: 0x0F
        # - Clave maestra puede cambiarse (bit 0 = 1)
        # - Listado de archivos requiere autenticación (bit 1 = 0)
        # - Crear/eliminar archivos requiere autenticación (bit 2 = 0)
        # - Configuración puede cambiarse en el futuro (bit 3 = 1)
        settings = 0x0F
        
        # Número de claves: 0x83 = AES (0x80) + 3 claves (0x03)
        num_keys = 0x83
        
        # Crear la aplicación
        result = self.create_application(wallet_aid, settings, num_keys, "AES")
        
        if result:
            print("\n=== Aplicación de monedero creada exitosamente ===")
            print("  AID: F00101")
            print("  Claves:")
            print("    - Clave 0: Clave maestra (administración)")
            print("    - Clave 1: Clave de débito (para operaciones de pago)")
            print("    - Clave 2: Clave de crédito (para operaciones de recarga)")
            print("\nIMPORTANTE: Las claves actuales son las predeterminadas (todo ceros)")
            print("           Debe cambiarlas por razones de seguridad")
            
            # Opcional: Seleccionar la aplicación recién creada
            self.select_application(wallet_aid)
        
        return result
    
    # CAMBIO DE CLAVES DE APLICACION CREADA

    def aes_encrypt(self, data, key, iv=b'\x00'*16):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
        except ImportError:
            print("Error: Se requiere PyCryptodome para la autenticación AES.")
            print("Instale la biblioteca con: pip install pycryptodome")
            return False
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv)
        return list(cipher.encrypt(bytes(data)))

    def pad_pkcs7(self, data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        return data + [pad_len] * pad_len
    
    def calculate_crc32(self, data):
        """
        Calcula CRC32 según el polinomio DESFire
        Polinomio: x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1
        """
        poly = 0xEDB88320
        crc = 0xFFFFFFFF
        
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
        
        return crc & 0xFFFFFFFF  # Asegurar 32 bits

    def encrypt_data(self, data):
        try:
            # Importar la biblioteca de cifrado si aún no está disponible
            from Crypto.Cipher import AES
        except ImportError:
            print("Error: PyCryptodome es necesario para cifrar el comando ChangeKey")
            print("Instale con: pip install pycryptodome")
            return False
        """
        Cifra datos usando AES-CBC con la clave de sesión
        """
        if not self.session_key:
            raise Exception("No hay clave de sesión disponible")
        
        # Usar el último bloque enviado como IV (o IV actual)
        iv = self.current_iv if hasattr(self, 'current_iv') else bytes(16)
        
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        
        # Actualizar IV para próxima operación
        self.current_iv = encrypted[-16:]
        
        return encrypted

    def create_and_setup_wallet_application(self):
        """
        Ejemplo completo: Crea una aplicación de monedero y configura sus claves
        """
        # 1. Definir el AID para la aplicación de monedero
        wallet_aid = [0xF0, 0x01, 0x01]
        
        # 2. Crear la aplicación con 3 claves AES
        if not self.create_application(wallet_aid, 0x0F, 0x83, "AES"):
            print("Error al crear la aplicación de monedero.")
            return False
        
        print("Aplicación de monedero creada. Configurando claves...")
        
        # 3. Configurar las claves de la aplicación
        result = self.setup_application_keys(wallet_aid)
        
        if result:
            print("\n=== Aplicación de monedero configurada correctamente ===")
            print("La aplicación está lista para usar.")
        else:
            print("\n❌ ERROR: No se pudo completar la configuración de la aplicación.")
        
        return result

def main():
    formatter = DESFireFormatter(debug=True)
    
    if formatter.connect_reader():
        print("\n=== Menú de Formateo de DESFire EV1 ===")
        print("Este script implementa autenticación DES completa y formateo.")
        print("¡Use bajo su propia responsabilidad!")
        
        if not CRYPTO_AVAILABLE:
            print("\nADVERTENCIA: La biblioteca PyCryptodome no está instalada.")
            print("Instale la biblioteca primero con:")
            print("pip install pycryptodome")
            return
        
        # Menú principal
        while True:
            print("\n=== Menú de Gestión de Aplicaciones DESFire EV1 ===")
            print("1. Formatear tarjeta")
            print("2. Crear aplicación de monedero (3 claves AES)")
            print("3. Configurar claves")
            print("5. Salir")
            
            choice = input("Seleccione una opción (1-5): ")
            if choice == "1":
                # Autenticarse primero y luego formatear
                if formatter.authenticate_des():
                    # Si la autenticación fue exitosa, formatear
                    formatter.format_card()
            elif choice == "2":
                formatter.create_wallet_application()
            elif choice == "5":
                print("Programa terminado.")
                break
            else:
                print("Opción no válida.")

if __name__ == "__main__":
    main()