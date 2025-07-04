#!/usr/bin/env python3
"""
DESFire EV1 CREATE STD DATA FILE Implementation
Comando 0xCD para crear archivos de datos estándar
"""

import struct
from enum import IntEnum
from typing import Optional, Union

class CommMode(IntEnum):
    """Modos de comunicación para archivos DESFire"""
    PLAIN = 0x00        # Sin cifrado
    MAC = 0x01          # Con código de autenticación
    ENCRYPTED = 0x03    # Completamente cifrado (recomendado)

class AccessRights:
    """Manejo de derechos de acceso para archivos DESFire"""
    
    # Valores especiales
    FREE_ACCESS = 0xE   # Acceso libre
    DENY_ACCESS = 0xF   # Acceso denegado
    
    def __init__(self, read: int = 0, write: int = 0, read_write: int = 0, change: int = 0):
        """
        Inicializa los derechos de acceso
        
        Args:
            read: Clave para lectura (0-13, 0xE=libre, 0xF=denegado)
            write: Clave para escritura (0-13, 0xE=libre, 0xF=denegado)
            read_write: Clave para lectura y escritura (0-13, 0xE=libre, 0xF=denegado)
            change: Clave para cambiar derechos (0-13, 0xE=libre, 0xF=denegado)
        """
        self.read = self._validate_access_value(read)
        self.write = self._validate_access_value(write)
        self.read_write = self._validate_access_value(read_write)
        self.change = self._validate_access_value(change)
    
    @staticmethod
    def _validate_access_value(value: int) -> int:
        """Valida que el valor de acceso esté en el rango correcto"""
        if not (0 <= value <= 13 or value in [0xE, 0xF]):
            raise ValueError(f"Valor de acceso inválido: {value}. Debe ser 0-13, 0xE o 0xF")
        return value
    
    def to_bytes(self) -> bytes:
        """Convierte los derechos de acceso a 2 bytes"""
        # Empaqueta los 4 campos de 4 bits cada uno en 2 bytes
        access_word = (self.read << 12) | (self.write << 8) | (self.read_write << 4) | self.change
        return struct.pack('<H', access_word)  # Little-endian
    
    @classmethod
    def public_read_write(cls) -> 'AccessRights':
        """Crea derechos de acceso público para lectura y escritura"""
        return cls(read=cls.FREE_ACCESS, write=cls.FREE_ACCESS, 
                  read_write=cls.FREE_ACCESS, change=cls.FREE_ACCESS)
    
    @classmethod
    def read_only(cls, read_key: int = 0, change_key: int = 0) -> 'AccessRights':
        """Crea derechos de solo lectura"""
        return cls(read=read_key, write=cls.DENY_ACCESS, 
                  read_write=read_key, change=change_key)
    
    @classmethod
    def secure_file(cls, access_key: int = 0, change_key: int = 1) -> 'AccessRights':
        """Crea derechos de acceso seguro con claves específicas"""
        return cls(read=access_key, write=access_key, 
                  read_write=access_key, change=change_key)
    
    def __str__(self) -> str:
        """Representación en string de los derechos de acceso"""
        def format_access(value):
            if value == self.FREE_ACCESS:
                return "FREE"
            elif value == self.DENY_ACCESS:
                return "DENY"
            else:
                return f"Key{value}"
        
        return (f"AccessRights(Read={format_access(self.read)}, "
                f"Write={format_access(self.write)}, "
                f"R&W={format_access(self.read_write)}, "
                f"Change={format_access(self.change)})")

class DESFireGetFileIDs:
    """Clase para crear comandos GET FILE IDS de DESFire"""
    
    COMMAND_CODE = 0x6F
    MAX_FILE_ID = 0x1F  # 31 archivos máximo por aplicación
    
    @staticmethod
    def create_command() -> bytes:
        """
        Crea el comando GET FILE IDS
        
        Returns:
            bytes: Comando completo listo para enviar
        """
        # Comando simple sin parámetros
        return bytes([DESFireGetFileIDs.COMMAND_CODE])
    
    @staticmethod
    def list_files() -> bytes:
        """
        Alias para create_command() - más semánticamente correcto
        
        Returns:
            bytes: Comando GET FILE IDS
        """
        return DESFireGetFileIDs.create_command()
    
    @staticmethod
    def parse_response(response: bytes) -> list:
        """
        Parsea la respuesta del comando GET FILE IDS
        
        Args:
            response: Respuesta de la tarjeta (sin código de estado)
            
        Returns:
            list: Lista de File IDs encontrados
        """
        if not response:
            return []
        
        file_ids = []
        for byte_val in response:
            if 0 <= byte_val <= DESFireGetFileIDs.MAX_FILE_ID:
                file_ids.append(byte_val)
        
        return sorted(file_ids)
    
    @staticmethod
    def file_exists(file_id: int, file_list: list) -> bool:
        """
        Verifica si un archivo específico existe en la lista
        
        Args:
            file_id: ID del archivo a buscar
            file_list: Lista de archivos obtenida de parse_response()
            
        Returns:
            bool: True si el archivo existe, False en caso contrario
        """
        return file_id in file_list
    
    @staticmethod
    def get_available_file_id(file_list: list) -> int:
        """
        Encuentra el primer File ID disponible
        
        Args:
            file_list: Lista de archivos existentes
            
        Returns:
            int: Primer File ID disponible, o -1 si no hay disponibles
        """
        for file_id in range(DESFireGetFileIDs.MAX_FILE_ID + 1):
            if file_id not in file_list:
                return file_id
        return -1  # No hay IDs disponibles
    
    @staticmethod
    def count_files(file_list: list) -> dict:
        """
        Cuenta estadísticas de archivos
        
        Args:
            file_list: Lista de archivos existentes
            
        Returns:
            dict: Estadísticas de archivos
        """
        total_files = len(file_list)
        max_files = DESFireGetFileIDs.MAX_FILE_ID + 1
        available = max_files - total_files
        
        return {
            'total_files': total_files,
            'max_files': max_files,
            'available_slots': available,
            'usage_percentage': (total_files / max_files) * 100,
            'file_ids': sorted(file_list),
            'next_available_id': DESFireGetFileIDs.get_available_file_id(file_list)
        }

class DESFireDeleteFile:
    """Clase para crear comandos DELETE FILE de DESFire"""
    
    COMMAND_CODE = 0xDF
    MAX_FILE_ID = 0x1F  # 31 archivos máximo por aplicación
    
    @staticmethod
    def create_command(file_id: int) -> bytes:
        """
        Crea el comando DELETE FILE
        
        Args:
            file_id: ID del archivo a eliminar (0-31)
            
        Returns:
            bytes: Comando completo listo para enviar
            
        Raises:
            ValueError: Si el file_id está fuera de rango
        """
        # Validación
        if not (0 <= file_id <= DESFireDeleteFile.MAX_FILE_ID):
            raise ValueError(f"File ID fuera de rango: {file_id}. Debe ser 0-{DESFireDeleteFile.MAX_FILE_ID}")
        
        # Construir el comando (muy simple: comando + file_id)
        return bytes([DESFireDeleteFile.COMMAND_CODE, file_id])
    
    @staticmethod
    def delete_file(file_id: int) -> bytes:
        """
        Alias para create_command() - más semánticamente correcto
        
        Args:
            file_id: ID del archivo a eliminar
            
        Returns:
            bytes: Comando DELETE FILE
        """
        return DESFireDeleteFile.create_command(file_id)

class DESFireCreateStdDataFile:
    """Clase para crear comandos CREATE STD DATA FILE de DESFire"""
    
    COMMAND_CODE = 0xCD
    MAX_FILE_ID = 0x1F  # 31 archivos máximo por aplicación
    MAX_FILE_SIZE = 0xFFFFFF  # 16MB máximo
    
    @staticmethod
    def create_command(
        file_id: int,
        file_size: int,
        access_rights: AccessRights,
        comm_mode: CommMode = CommMode.ENCRYPTED
    ) -> bytes:
        """
        Crea el comando CREATE STD DATA FILE
        
        Args:
            file_id: ID del archivo (0-31)
            file_size: Tamaño del archivo en bytes (1-16777215)
            access_rights: Derechos de acceso
            comm_mode: Modo de comunicación
            
        Returns:
            bytes: Comando completo listo para enviar
            
        Raises:
            ValueError: Si los parámetros están fuera de rango
        """
        # Validaciones
        if not (0 <= file_id <= DESFireCreateStdDataFile.MAX_FILE_ID):
            raise ValueError(f"File ID fuera de rango: {file_id}. Debe ser 0-{DESFireCreateStdDataFile.MAX_FILE_ID}")
        
        if not (1 <= file_size <= DESFireCreateStdDataFile.MAX_FILE_SIZE):
            raise ValueError(f"File size fuera de rango: {file_size}. Debe ser 1-{DESFireCreateStdDataFile.MAX_FILE_SIZE}")
        
        if not isinstance(comm_mode, CommMode):
            raise ValueError(f"Modo de comunicación inválido: {comm_mode}")
        
        # Construir el comando
        command = bytearray()
        command.append(DESFireCreateStdDataFile.COMMAND_CODE)  # Comando 0xCD
        command.append(file_id)                               # File ID
        command.append(comm_mode.value)                       # Communication Mode
        command.extend(access_rights.to_bytes())              # Access Rights (2 bytes)
        command.extend(struct.pack('<I', file_size)[:3])      # File Size (3 bytes, little-endian)
        
        return bytes(command)
    
    @staticmethod
    def create_public_file(file_id: int, file_size: int) -> bytes:
        """
        Crea un archivo público con acceso libre
        
        Args:
            file_id: ID del archivo
            file_size: Tamaño del archivo
            
        Returns:
            bytes: Comando CREATE STD DATA FILE
        """
        access_rights = AccessRights.public_read_write()
        return DESFireCreateStdDataFile.create_command(
            file_id, file_size, access_rights, CommMode.PLAIN
        )
    
    @staticmethod
    def create_secure_file(file_id: int, file_size: int, access_key: int = 0) -> bytes:
        """
        Crea un archivo seguro con cifrado AES
        
        Args:
            file_id: ID del archivo
            file_size: Tamaño del archivo
            access_key: Clave para acceso (por defecto 0)
            
        Returns:
            bytes: Comando CREATE STD DATA FILE
        """
        access_rights = AccessRights.secure_file(access_key)
        return DESFireCreateStdDataFile.create_command(
            file_id, file_size, access_rights, CommMode.ENCRYPTED
        )
    
    @staticmethod
    def create_readonly_file(file_id: int, file_size: int, read_key: int = 0) -> bytes:
        """
        Crea un archivo de solo lectura
        
        Args:
            file_id: ID del archivo
            file_size: Tamaño del archivo
            read_key: Clave para lectura (por defecto 0)
            
        Returns:
            bytes: Comando CREATE STD DATA FILE
        """
        access_rights = AccessRights.read_only(read_key)
        return DESFireCreateStdDataFile.create_command(
            file_id, file_size, access_rights, CommMode.MAC
        )

def parse_get_file_ids_command(command: bytes) -> dict:
    """
    Parsea un comando GET FILE IDS y devuelve sus componentes
    
    Args:
        command: Comando en bytes
        
    Returns:
        dict: Diccionario con los componentes del comando
    """
    if len(command) != 1:
        raise ValueError(f"Comando GET FILE IDS debe tener exactamente 1 byte, recibido: {len(command)}")
    
    if command[0] != DESFireGetFileIDs.COMMAND_CODE:
        raise ValueError(f"Código de comando incorrecto: {command[0]:02X}, esperado: {DESFireGetFileIDs.COMMAND_CODE:02X}")
    
    return {
        'command_code': command[0],
        'raw_command': command.hex().upper()
    }

def parse_delete_command(command: bytes) -> dict:
    """
    Parsea un comando DELETE FILE y devuelve sus componentes
    
    Args:
        command: Comando en bytes
        
    Returns:
        dict: Diccionario con los componentes del comando
    """
    if len(command) != 2:
        raise ValueError(f"Comando DELETE FILE debe tener exactamente 2 bytes, recibido: {len(command)}")
    
    if command[0] != DESFireDeleteFile.COMMAND_CODE:
        raise ValueError(f"Código de comando incorrecto: {command[0]:02X}, esperado: {DESFireDeleteFile.COMMAND_CODE:02X}")
    
    file_id = command[1]
    
    return {
        'command_code': command[0],
        'file_id': file_id,
        'raw_command': command.hex().upper()
    }

def parse_create_command(command: bytes) -> dict:
    """
    Parsea un comando CREATE STD DATA FILE y devuelve sus componentes
    
    Args:
        command: Comando en bytes
        
    Returns:
        dict: Diccionario con los componentes del comando
    """
    if len(command) < 7:
        raise ValueError("Comando demasiado corto")
    
    if command[0] != DESFireCreateStdDataFile.COMMAND_CODE:
        raise ValueError(f"Código de comando incorrecto: {command[0]:02X}")
    
    file_id = command[1]
    comm_mode = CommMode(command[2])
    
    # Decodificar access rights
    access_word = struct.unpack('<H', command[3:5])[0]
    read = (access_word >> 12) & 0xF
    write = (access_word >> 8) & 0xF
    read_write = (access_word >> 4) & 0xF
    change = access_word & 0xF
    
    access_rights = AccessRights(read, write, read_write, change)
    
    # Decodificar file size (3 bytes little-endian)
    file_size = struct.unpack('<I', command[5:8] + b'\x00')[0]
    
    return {
        'command_code': command[0],
        'file_id': file_id,
        'comm_mode': comm_mode,
        'access_rights': access_rights,
        'file_size': file_size,
        'raw_command': command.hex().upper()
    }

# Ejemplos de uso
if __name__ == "__main__":
    print("=== DESFire File Management Examples ===\n")
    
    print("=== GET FILE IDS Examples ===\n")
    
    # Ejemplo 1: Listar archivos
    print("1. Comando para listar archivos:")
    list_cmd = DESFireGetFileIDs.list_files()
    print(f"   Comando: {list_cmd.hex().upper()}")
    parsed_list = parse_get_file_ids_command(list_cmd)
    print(f"   Detalles: {parsed_list}")
    print()
    
    # Ejemplo 2: Simular respuesta y parsear
    print("2. Ejemplo de respuesta simulada:")
    # Simulamos que la tarjeta tiene archivos con IDs: 1, 3, 5, 10, 15
    simulated_response = bytes([1, 3, 5, 10, 15])
    file_list = DESFireGetFileIDs.parse_response(simulated_response)
    print(f"   Respuesta simulada: {simulated_response.hex().upper()}")
    print(f"   Archivos encontrados: {file_list}")
    print()
    
    # Ejemplo 3: Verificar si archivo existe
    print("3. Verificar existencia de archivos:")
    test_ids = [1, 2, 5, 20]
    for test_id in test_ids:
        exists = DESFireGetFileIDs.file_exists(test_id, file_list)
        status = "✅ EXISTE" if exists else "❌ NO EXISTE"
        print(f"   Archivo ID {test_id:2d}: {status}")
    print()
    
    # Ejemplo 4: Estadísticas de archivos
    print("4. Estadísticas de archivos:")
    stats = DESFireGetFileIDs.count_files(file_list)
    print(f"   Total de archivos: {stats['total_files']}")
    print(f"   Archivos máximos: {stats['max_files']}")
    print(f"   Slots disponibles: {stats['available_slots']}")
    print(f"   Uso de memoria: {stats['usage_percentage']:.1f}%")
    print(f"   Próximo ID disponible: {stats['next_available_id']}")
    print(f"   IDs en uso: {stats['file_ids']}")
    print()
    
    print("=== CREATE STD DATA FILE Examples ===\n")
    
    # Ejemplo 5: Crear archivo usando próximo ID disponible
    next_id = stats['next_available_id']
    if next_id != -1:
        print(f"5. Crear archivo usando próximo ID disponible ({next_id}):")
        create_cmd = DESFireCreateStdDataFile.create_secure_file(next_id, 256)
        print(f"   Comando: {create_cmd.hex().upper()}")
        print()
    
    # Ejemplo 6: Archivo público
    print("6. Archivo público (4KB):")
    cmd1 = DESFireCreateStdDataFile.create_public_file(25, 1024)
    print(f"   Comando: {cmd1.hex().upper()}")
    parsed1 = parse_create_command(cmd1)
    print(f"   Detalles: {parsed1['access_rights']}")
    print()
    
    # Ejemplo 7: Archivo seguro con AES
    print("7. Archivo seguro con AES (128 bytes):")
    cmd2 = DESFireCreateStdDataFile.create_secure_file(26, 128, access_key=0)
    print(f"   Comando: {cmd2.hex().upper()}")
    parsed2 = parse_create_command(cmd2)
    print(f"   Detalles: {parsed2['access_rights']}")
    print()
    
    print("=== DELETE FILE Examples ===\n")
    
    # Ejemplo 8: Eliminar archivos existentes
    print("8. Eliminar archivos existentes:")
    for file_id in [1, 5, 10]:
        if DESFireGetFileIDs.file_exists(file_id, file_list):
            del_cmd = DESFireDeleteFile.delete_file(file_id)
            print(f"   Eliminar archivo {file_id}: {del_cmd.hex().upper()}")
        else:
            print(f"   Archivo {file_id}: NO EXISTE (saltar eliminación)")
    print()
    
    # Ejemplo 9: Flujo completo de gestión
    print("=== Flujo Completo de Gestión ===")
    management_file_id = 20
    
    print(f"9. Gestión completa del archivo ID {management_file_id}:")
    
    # Paso 1: Listar archivos
    list_cmd = DESFireGetFileIDs.list_files()
    print(f"   a) Listar archivos: {list_cmd.hex().upper()}")
    
    # Paso 2: Verificar si existe
    exists = DESFireGetFileIDs.file_exists(management_file_id, file_list)
    print(f"   b) Archivo {management_file_id} existe: {'Sí' if exists else 'No'}")
    
    # Paso 3: Crear si no existe, eliminar si existe
    if not exists:
        create_cmd = DESFireCreateStdDataFile.create_secure_file(management_file_id, 512)
        print(f"   c) Crear archivo: {create_cmd.hex().upper()}")
    else:
        del_cmd = DESFireDeleteFile.delete_file(management_file_id)
        print(f"   c) Eliminar archivo: {del_cmd.hex().upper()}")
    print()
    
    # Ejemplo 10: Gestión de múltiples archivos
    print("10. Gestión de múltiples archivos:")
    batch_operations = []
    
    # Crear varios archivos si no existen
    for file_id in range(16, 20):
        if not DESFireGetFileIDs.file_exists(file_id, file_list):
            cmd = DESFireCreateStdDataFile.create_public_file(file_id, 64)
            batch_operations.append(f"Crear {file_id}: {cmd.hex().upper()}")
        else:
            batch_operations.append(f"Archivo {file_id}: Ya existe")
    
    for operation in batch_operations:
        print(f"   {operation}")
    print()
    
    # Mostrar cálculo de memoria
    print("=== Gestión de Memoria ===")
    print("Memoria por tamaño de archivo:")
    sizes = [1, 32, 33, 64, 100, 128]
    for size in sizes:
        allocated = ((size + 31) // 32) * 32  # Redondeo hacia arriba a múltiplo de 32
        print(f"   Tamaño solicitado: {size:3d} bytes -> Memoria asignada: {allocated:3d} bytes")
    
    print("\n=== Mejores Prácticas ===")
    print("📋 Gestión de Archivos:")
    print("• Siempre verificar existencia antes de crear/eliminar")
    print("• Usar GET FILE IDS para obtener lista actualizada")
    print("• Planificar IDs para evitar conflictos")
    print("• Monitorear uso de slots (máximo 32 archivos)")
    print("• Considerar FORMAT PICC para liberar memoria fragmentada")
    
    print("\n🔒 Seguridad:")
    print("• Usar modo ENCRYPTED para datos sensibles")
    print("• Configurar Access Rights apropiados")
    print("• Autenticarse antes de operaciones de archivo")
    print("• Validar respuestas de comandos")
    
    print("\n⚡ Rendimiento:")
    print("• Reutilizar IDs de archivos eliminados")
    print("• Agrupar operaciones cuando sea posible")
    print("• Considerar tamaño de archivo vs memoria asignada")
    print("• Usar archivos de tamaño múltiplo de 32 bytes")