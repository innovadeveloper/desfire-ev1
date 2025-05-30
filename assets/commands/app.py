#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para explorar tarjetas MIFARE DESFire EV1 con el lector ACR1581U
Utiliza la biblioteca pyscard para la comunicación con el lector
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import CardConnectionException
import sys
import time

# Comandos APDU para DESFire
DESFIRE_GET_VERSION = [0x90, 0x60, 0x00, 0x00, 0x00]  # Comando para obtener versión (formato APDU)
DESFIRE_GET_APPLICATION_IDS = [0x90, 0x6A, 0x00, 0x00, 0x00]  # Comando para obtener AIDs (formato APDU)
DESFIRE_SELECT_APPLICATION = [0x90, 0x5A, 0x00, 0x00, 0x03]  # Comando base para seleccionar aplicación
DESFIRE_MORE_DATA = [0x90, 0xAF, 0x00, 0x00, 0x00]  # Comando para solicitar más datos
DESFIRE_ABORT = [0x90, 0xA7, 0x00, 0x00, 0x00]

# Códigos de estado
OPERATION_OK = 0x91
ADDITIONAL_FRAME = 0xAF
STATUS_OK = 0x00

class DESFireScanner:
    def __init__(self):
        self.reader = None
        self.connection = None
        
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
        
        # Usa el primer lector por defecto (puedes modificar para seleccionar otro)
        self.reader = reader_list[2]
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
            sw = (sw1 << 8) + sw2
            return response, sw1, sw2
        except Exception as e:
            print(f"Error al enviar APDU: {e}")
            return [], 0, 0
    
    def get_version(self):
        """Obtiene la información de versión de la tarjeta DESFire"""
        print("\n=== Obteniendo información de versión ===")
        
        # Primera parte de la versión
        response, sw1, sw2 = self.send_apdu(DESFIRE_GET_VERSION)
        
        # CORRECCIÓN: En DESFire, cuando se recibe 0x91 0xAF, es una indicación
        # de que hay más datos disponibles, pero todavía es un estado válido
        if sw1 == OPERATION_OK and sw2 == ADDITIONAL_FRAME:
            # Todo está bien, hay tramas adicionales
            pass
        elif sw1 != ADDITIONAL_FRAME:  # Mantener la comprobación original como respaldo
            print(f"Error al obtener la versión, SW: {hex(sw1)} {hex(sw2)}")
            # En lugar de retornar, continuamos para intentar recuperar la conexión
            # Enviar un comando de cancelación para intentar resetear el estado
            self.send_apdu(DESFIRE_ABORT)
            print("Intentando recuperar la conexión...")
            return None, None, None
        
        hardware_data = response
        print("Datos de hardware:")
        if len(response) >= 7:
            vendor_id = response[0]
            hardware_type = response[1]
            hardware_subtype = response[2]
            hardware_major_version = response[3]
            hardware_minor_version = response[4]
            storage_size = response[5]
            protocol = response[6]
            
            print(f"  Vendor ID: {hex(vendor_id)} (NXP: 0x04)")
            print(f"  Tipo de hardware: {hex(hardware_type)}")
            print(f"  Subtipo de hardware: {hex(hardware_subtype)}")
            print(f"  Versión de hardware: {hardware_major_version}.{hardware_minor_version}")
            
            # Decodificar el tamaño de almacenamiento
            if storage_size == 0x18:
                print("  Tamaño de almacenamiento: 4KB")
            elif storage_size == 0x16:
                print("  Tamaño de almacenamiento: 2KB")
            elif storage_size == 0x1A:
                print("  Tamaño de almacenamiento: 8KB")
            else:
                print(f"  Tamaño de almacenamiento: {hex(storage_size)}")
            
            print(f"  Protocolo: {hex(protocol)}")
        else:
            print(f"  Datos incompletos: {toHexString(response)}")
        
        # Segunda parte de la versión (software)
        response, sw1, sw2 = self.send_apdu(DESFIRE_MORE_DATA)
        
        # CORRECCIÓN: Verificamos ambos tipos de respuesta posibles
        if sw1 == OPERATION_OK and sw2 == ADDITIONAL_FRAME:
            # Todo está bien, hay más tramas
            pass
        elif sw1 != ADDITIONAL_FRAME:  # Mantener la comprobación original como respaldo
            print(f"Error al obtener la versión de software, SW: {hex(sw1)} {hex(sw2)}")
            # Intentamos continuar de todos modos
            software_data = response
            general_data = []
            return hardware_data, software_data, general_data
        
        software_data = response
        print("\nDatos de software:")
        if len(response) >= 7:
            vendor_id = response[0]
            software_type = response[1]
            software_subtype = response[2]
            software_major_version = response[3]
            software_minor_version = response[4]
            storage_size = response[5]
            protocol = response[6]
            
            print(f"  Vendor ID: {hex(vendor_id)} (NXP: 0x04)")
            print(f"  Tipo de software: {hex(software_type)}")
            print(f"  Subtipo de software: {hex(software_subtype)}")
            print(f"  Versión de software: {software_major_version}.{software_minor_version}")
            print(f"  Tamaño de almacenamiento: {hex(storage_size)}")
            print(f"  Protocolo: {hex(protocol)}")
        else:
            print(f"  Datos incompletos: {toHexString(response)}")
            
        # Tercera parte de la versión (general)
        response, sw1, sw2 = self.send_apdu(DESFIRE_MORE_DATA)
        
        # La última respuesta debería tener código 0x91 0x00 (éxito)
        if sw1 != OPERATION_OK:
            print(f"Error al obtener datos generales, SW: {hex(sw1)} {hex(sw2)}")
            general_data = []
            return hardware_data, software_data, general_data
        
        general_data = response
        print("\nDatos generales:")
        if len(response) >= 14:
            print(f"  UID: {toHexString(response[0:7])}")
            print(f"  Production batch: {toHexString(response[7:12])}")
            print(f"  Week of production: {response[12]}")
            print(f"  Year of production: {response[13]}")
        else:
            print(f"  Datos incompletos: {toHexString(response)}")
        
        return hardware_data, software_data, general_data
    
    def get_application_ids(self):
        """Obtiene los AIDs (Application IDs) presentes en la tarjeta"""
        print("\n=== Obteniendo AIDs ===")
        response, sw1, sw2 = self.send_apdu(DESFIRE_GET_APPLICATION_IDS)
        
        # Comprueba si hay más datos o si es una respuesta final
        if sw1 == ADDITIONAL_FRAME:
            print("Se requieren tramas adicionales...")
            all_data = response
            
            # Solicita tramas adicionales
            while sw1 == ADDITIONAL_FRAME:
                response, sw1, sw2 = self.send_apdu(DESFIRE_MORE_DATA)
                all_data += response
            
            print(f"Datos completos: {toHexString(all_data)}")
            self._parse_application_ids(all_data)
            
        elif sw1 == OPERATION_OK and sw2 == STATUS_OK:
            # No hay AIDs o respuesta vacía
            print("No se encontraron aplicaciones en la tarjeta.")
            
        elif sw1 == 0x91 and sw2 == 0x0C:
            # 91 0C: No hay cambios (tarjeta vacía)
            print("La tarjeta está vacía, no hay aplicaciones.")
            
        else:
            print(f"Error o respuesta inesperada: SW1={hex(sw1)}, SW2={hex(sw2)}")
            if len(response) > 0:
                print(f"Respuesta: {toHexString(response)}")
    
    def _parse_application_ids(self, data):
        """Analiza los datos de respuesta para extraer los AIDs"""
        if len(data) % 3 != 0:
            print(f"Datos de AIDs con formato incorrecto (longitud: {len(data)})")
            return
        
        aids_count = len(data) // 3
        print(f"Se encontraron {aids_count} aplicaciones:")
        
        for i in range(aids_count):
            aid = data[i*3:(i+1)*3]
            print(f"  AID #{i+1}: {toHexString(aid)} ({int.from_bytes(aid, byteorder='little')})")
    
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
    
    def select_master_application(self):
        """Selecciona la aplicación maestra (AID=000000)"""
        print("\n=== Seleccionando aplicación maestra ===")
        
        # Para tarjetas vírgenes, primero intenta abortar cualquier operación pendiente
        # Esto puede ayudar a restablecer el estado de la tarjeta
        abort_response, abort_sw1, abort_sw2 = self.send_apdu(DESFIRE_ABORT)
        print(f"Restaurando estado de la tarjeta: SW={hex(abort_sw1)}{hex(abort_sw2)}")
        
        # Intenta seleccionar la aplicación maestra
        result = self.select_application([0x00, 0x00, 0x00])
        
        # Si falla y obtenemos error 0x91 0xCA (Command Aborted)
        # esto puede ser normal para tarjetas vírgenes sin formatear
        if not result:
            print("Nota: El error al seleccionar la aplicación maestra es normal en tarjetas vírgenes.")
            print("La tarjeta probablemente necesita ser formateada primero.")
            
            # Intenta enviar el comando GetApplicationIDs de todos modos, que a veces
            # funciona incluso sin seleccionar explícitamente la aplicación maestra
            print("Intentando continuar...")
        
        return result

def main():
    scanner = DESFireScanner()
    
    if scanner.connect_reader():
        # Obtener información de la versión
        version_data = scanner.get_version()
        
        # Seleccionar la aplicación maestra antes de obtener AIDs
        # Esto es una buena práctica para asegurarnos de estar en el contexto correcto
        master_result = scanner.select_master_application()
        
        # Verificar si estamos tratando con una tarjeta virgen
        if not master_result and version_data:
            # Tarjeta virgen detectada, ofrecemos opciones adicionales
            print("\n=== Tarjeta virgen detectada ===")
            print("1. Continuar intentando leer AIDs de todos modos")
            print("2. Formatear la tarjeta (no implementado en este script)")
            print("3. Salir")
            
            choice = input("Seleccione una opción (1-3): ")
            
            if choice == "1":
                # Obtener los AIDs de todos modos
                scanner.get_application_ids()
            elif choice == "2":
                print("La función de formateo no está implementada en este script básico.")
                print("Para formatear una tarjeta DESFire EV1, necesitarías implementar:")
                print("1. Autenticación con la clave maestra predeterminada")
                print("2. Comando FormatPICC (0xFC)")
            else:
                print("Operación cancelada.")
                return
        else:
            # Obtener los AIDs normalmente
            scanner.get_application_ids()
        
        print("\nOperaciones completadas.")
    
    print("Fin del programa.")

if __name__ == "__main__":
    main()