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

# Códigos de estado
OPERATION_OK = 0x91
ADDITIONAL_FRAME = 0xAF
STATUS_OK = 0x00

class DESFireFormatter:
    def __init__(self, debug=True):
        self.reader = None
        self.connection = None
        self.debug = debug
        
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
        
        # Realizar autenticación DES
        if formatter.authenticate_des():
            # Si la autenticación fue exitosa, formatear
            formatter.format_card()
        else:
            print("No se pudo autenticar. No se formateará la tarjeta.")
        
        print("\nOperación completada.")

if __name__ == "__main__":
    main()