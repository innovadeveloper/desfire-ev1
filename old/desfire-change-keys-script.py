#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para cambiar múltiples claves en una aplicación DESFire EV1
Supone que ya has creado una aplicación con 3 claves AES (num_keys=0x83)
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import CardConnectionException
import sys
import binascii
import os

# Comandos APDU para DESFire
DESFIRE_SELECT_APPLICATION = [0x90, 0x5A, 0x00, 0x00, 0x03]  # + AID + Le
DESFIRE_AUTHENTICATE_AES = [0x90, 0xAA, 0x00, 0x00]  # + Key No + Le
DESFIRE_CHANGE_KEY = [0x90, 0xC4, 0x00, 0x00]  # + datos + Le
DESFIRE_MORE_DATA = [0x90, 0xAF, 0x00, 0x00, 0x00]

# Códigos de estado
OPERATION_OK = 0x91
ADDITIONAL_FRAME = 0xAF
STATUS_OK = 0x00

class DESFireKeyManager:
    def __init__(self):
        self.reader = None
        self.connection = None
        self.verbose = True  # Mostrar información detallada
        
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
            if self.verbose:
                print(f"Enviando: {toHexString(apdu)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if self.verbose:
                print(f"Respuesta: {toHexString(response) if response else 'Sin datos'}, SW: {hex(sw1)} {hex(sw2)}")
            
            return response, sw1, sw2
        except Exception as e:
            print(f"Error al enviar APDU: {e}")
            return [], 0, 0
    
    def select_application(self, aid):
        """Selecciona una aplicación por su AID"""
        print(f"\n=== Seleccionando aplicación {toHexString(aid)} ===")
        apdu = DESFIRE_SELECT_APPLICATION + aid + [0x00]
        response, sw1, sw2 = self.send_apdu(apdu)
        
        if sw1 == OPERATION_OK and sw2 == STATUS_OK:
            print(f"Aplicación {toHexString(aid)} seleccionada correctamente.")
            return True
        else:
            print(f"Error al seleccionar la aplicación: SW={hex(sw1)}{hex(sw2)}")
            return False
    
    def authenticate(self, key_no, key_data=None):
        """
        Inicia el proceso de autenticación AES con la clave especificada
        
        Nota: Esta es una implementación simplificada que solo verifica si la autenticación
        se puede iniciar correctamente. Una implementación completa requeriría manejar
        el challenge-response con cifrado AES.
        
        Parámetros:
        - key_no: Número de clave (0-13)
        - key_data: Datos de la clave (16 bytes para AES)
        """
        print(f"\n=== Autenticando con clave #{key_no} ===")
        
        # Comando de autenticación AES
        apdu = DESFIRE_AUTHENTICATE_AES + [0x01, key_no, 0x00]
        response, sw1, sw2 = self.send_apdu(apdu)
        
        if (sw1 == ADDITIONAL_FRAME) or (sw1 == OPERATION_OK and sw2 == ADDITIONAL_FRAME):
            print(f"Autenticación iniciada correctamente. Se recibió challenge de la tarjeta.")
            print("NOTA: Este script simplificado no completa el proceso de autenticación.")
            print("      Para una implementación completa, se necesitaría:")
            print("      1. Descifrar el challenge recibido")
            print("      2. Generar y enviar una respuesta cifrada")
            print("      3. Verificar la respuesta final de la tarjeta")
            
            # Simulamos una autenticación exitosa para propósitos de demostración
            # En una implementación real, necesitaríamos manejar el cifrado AES
            return True
        else:
            print(f"Error al iniciar la autenticación: SW={hex(sw1)}{hex(sw2)}")
            
            if sw1 == OPERATION_OK and sw2 == 0xAE:
                print("Error de autenticación - Clave incorrecta.")
            
            return False
    
    def change_key(self, key_no, new_key_data, old_key_data=None):
        """
        Cambiar una clave en la aplicación actual
        
        Esta es una implementación conceptual. En un entorno real, necesitarías
        implementar el cifrado y los cálculos CRC adecuados.
        
        Parámetros:
        - key_no: Número de clave a cambiar (0-13)
        - new_key_data: Nueva clave (lista de 16 bytes para AES)
        - old_key_data: Clave actual (opcional, solo necesaria en casos específicos)
        """
        print(f"\n=== Cambiando la clave #{key_no} ===")
        
        # En un escenario real, el proceso sería:
        # 1. Si key_no no es la clave actualmente autenticada, XOR la nueva clave con la antigua
        # 2. Calcular un CRC
        # 3. Formatear todos los datos según la especificación DESFire
        
        # Para este ejemplo simplificado, solo mostramos el concepto:
        
        # En un caso real, esto sería calculado según la especificación
        key_version = 0x00  # Versión de la clave (opcional)
        
        # Datos para el comando Change Key
        # En un escenario real, estos datos serían más complejos y dependerían 
        # de la clave actual, la clave nueva, etc.
        data = [key_no] + new_key_data + [key_version]
        
        # Construir APDU
        apdu = DESFIRE_CHANGE_KEY + [len(data)] + data + [0x00]
        
        # En un caso real, este APDU necesitaría ser procesado según las reglas
        # de cifrado y preparación específicas de DESFire
        
        print("NOTA: Este es un ejemplo conceptual. El comando real requeriría:")
        print("      - Cifrado apropiado")
        print("      - Cálculo de CRC")
        print("      - Formateo específico según la especificación DESFire")
        
        # Como esto es solo conceptual, no enviamos el comando
        # response, sw1, sw2 = self.send_apdu(apdu)
        
        # En su lugar, explicamos qué sucedería
        print("\nEn una implementación completa:")
        print("1. Se enviaría un comando cifrado C4 (ChangeKey)")
        print("2. Se verificaría el código de estado (91 00 = éxito)")
        print("3. Se confirmaría el cambio intentando autenticarse con la nueva clave")
        
        return True  # Simulamos éxito para este ejemplo

def generate_random_key():
    """Genera una clave AES aleatoria de 16 bytes"""
    return list(os.urandom(16))

def main():
    manager = DESFireKeyManager()
    
    if manager.connect_reader():
        # AID de la aplicación (personalizar según tu configuración)
        aid = [0x01, 0x02, 0x03]
        
        # Seleccionar la aplicación
        if not manager.select_application(aid):
            print("No se pudo seleccionar la aplicación. Terminando.")
            return
        
        # Definir claves nuevas (en una aplicación real, generarías claves aleatorias seguras)
        master_key = generate_random_key()  # Clave 0 (maestra)
        credit_key = generate_random_key()  # Clave 1 (para crédito)
        debit_key = generate_random_key()   # Clave 2 (para débito)
        
        # Mostrar las claves generadas (solo para demostración)
        print("\n=== Claves generadas (guardar en lugar seguro) ===")
        print(f"Clave Maestra (0): {toHexString(master_key)}")
        print(f"Clave de Crédito (1): {toHexString(credit_key)}")
        print(f"Clave de Débito (2): {toHexString(debit_key)}")
        
        # Autenticarse con la clave maestra actual (la predeterminada para nuevas aplicaciones)
        default_key = [0x00] * 16  # Clave predeterminada (16 bytes de 0x00)
        
        if manager.authenticate(0, default_key):
            # Cambiar la clave maestra (clave 0)
            if manager.change_key(0, master_key, default_key):
                print("Proceso conceptual de cambio de clave maestra completado.")
                
                # En una implementación real, necesitarías reautenticarte con la nueva clave
                # antes de cambiar las otras claves
                print("\nPara cambiar las demás claves, necesitarías:")
                print("1. Reautenticarte con la nueva clave maestra")
                print("2. Cambiar la clave 1 (crédito)")
                print("3. Cambiar la clave 2 (débito)")
            else:
                print("Error al cambiar la clave maestra.")
        else:
            print("Error en la autenticación.")
        
        print("\n=== IMPORTANTE ===")
        print("Este script es conceptual y no implementa el proceso completo.")
        print("Para una implementación funcional se requiere:")
        print("1. Biblioteca criptográfica para AES")
        print("2. Manejo completo del protocolo de autenticación")
        print("3. Preparación correcta de los comandos ChangeKey")
        
        # Se recomienda utilizar librerías como pyscard + pycrypto o libfreefare para una implementación completa

if __name__ == "__main__":
    main()
