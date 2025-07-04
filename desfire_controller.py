#!/usr/bin/env python3
"""
DESFire EV1 Controller
=====================

Controlador principal que maneja la interfaz de usuario y coordina las operaciones
de negocio. Separa la presentación de la lógica de negocio.

Autor: Controlador basado en DESFireBusinessLogic
Fecha: 2025
"""

import sys
from typing import List, Optional
from desfire_business_logic import DESFireBusinessLogic


class DESFireController:
    """
    Controlador principal para operaciones DESFire EV1
    Maneja la interfaz de usuario y coordina con la lógica de negocio
    """
    
    def __init__(self, debug: bool = True):
        """
        Inicializar controlador DESFire
        
        Args:
            debug (bool): Habilitar mensajes de depuración
        """
        self.business_logic = DESFireBusinessLogic(debug)
        self.debug = debug
    
    def log(self, message: str):
        """Imprimir mensaje de depuración si está habilitado"""
        if self.debug:
            print(message)
    
    # =============================================================================
    # GESTIÓN DE LECTORES
    # =============================================================================
    
    def select_reader_interactive(self) -> int:
        """
        Selección interactiva de lector
        
        Returns:
            int: Índice del lector seleccionado o -1 si error
        """
        readers_list = self.business_logic.get_available_readers()
        
        if not readers_list:
            print("ERROR: No se encontraron lectores de tarjetas")
            return -1
        
        print(f"Lectores disponibles: {len(readers_list)}")
        for i, reader in enumerate(readers_list):
            print(f"  [{i}] {reader}")
        
        # Selección automática si solo hay un lector
        if len(readers_list) == 1:
            selected_index = 0
            print(f"Seleccionado automáticamente: {readers_list[0]}")
        else:
            # Solicitar selección al usuario
            while True:
                try:
                    user_input = input(f"Seleccione lector (0-{len(readers_list)-1}): ").strip()
                    selected_index = int(user_input)
                    
                    if 0 <= selected_index < len(readers_list):
                        break
                    else:
                        print(f"ERROR: Índice inválido. Debe estar entre 0 y {len(readers_list)-1}")
                        
                except ValueError:
                    print("ERROR: Debe ingresar un número válido")
                except KeyboardInterrupt:
                    print("\nOperación cancelada por el usuario")
                    return -1
        
        print(f"Lector seleccionado: {readers_list[selected_index]}")
        return selected_index
    
    def select_reader_automatic(self, preferred_index: int = 0) -> int:
        """
        Selección automática de lector
        
        Args:
            preferred_index (int): Índice preferido de lector
            
        Returns:
            int: Índice del lector seleccionado o -1 si error
        """
        readers_list = self.business_logic.get_available_readers()
        
        if not readers_list:
            self.log("ERROR: No se encontraron lectores de tarjetas")
            return -1
        
        # Usar índice preferido si es válido
        if 0 <= preferred_index < len(readers_list):
            selected_index = preferred_index
        else:
            # Usar primer lector disponible como fallback
            selected_index = 0
        
        self.log(f"Lector seleccionado automáticamente: {readers_list[selected_index]}")
        return selected_index
    
    # =============================================================================
    # OPERACIONES PRINCIPALES
    # =============================================================================
    
    def format_and_setup_card(self, reader_index: int = None, 
                             aid: bytes = None, interactive: bool = True) -> bool:
        """
        Formatear y configurar tarjeta completa
        
        Args:
            reader_index (int): Índice del lector (None para selección interactiva)
            aid (bytes): Application ID personalizado
            interactive (bool): Si usar modo interactivo
            
        Returns:
            bool: True si operación exitosa
        """
        print("=" * 60)
        print("FORMATEO Y CONFIGURACIÓN COMPLETA DE TARJETA DESFIRE EV1")
        print("=" * 60)
        
        try:
            # Seleccionar lector
            if reader_index is None:
                if interactive:
                    reader_index = self.select_reader_interactive()
                else:
                    reader_index = self.select_reader_automatic()
                
                if reader_index == -1:
                    return False
            
            # Confirmar formateo
            if interactive:
                print("\nADVERTENCIA: Esta operación:")
                print("  1. Formateará la tarjeta (borrará todos los datos)")
                print("  2. Creará una nueva aplicación")
                print("  3. Configurará un fichero estándar")
                
                # confirmation = input("\n¿Desea continuar? (s/n): ").strip().lower()
                # if confirmation != 's':
                #     print("Operación cancelada por el usuario")
                #     return False
            
            # Ejecutar flujo completo
            print("\nEjecutando flujo completo...")
            success = self.business_logic.execute_complete_flow(
                reader_index=reader_index,
                aid=aid,
                format_first=True
            )
            
            if success:
                print("\n" + "=" * 60)
                print("TARJETA CONFIGURADA EXITOSAMENTE")
                print("=" * 60)
                print("La tarjeta está lista para uso:")
                print("  - Aplicación creada y configurada")
                print("  - Fichero estándar disponible")
                print("  - Claves configuradas con valores por defecto")
                return True
            else:
                print("\n" + "=" * 60)
                print("ERROR EN CONFIGURACIÓN")
                print("=" * 60)
                print("La configuración de la tarjeta falló")
                return False
                
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario")
            return False
        except Exception as e:
            print(f"\nERROR inesperado: {e}")
            return False
    
    def setup_card_without_format(self, reader_index: int = None, 
                                 aid: bytes = None, interactive: bool = True) -> bool:
        """
        Configurar tarjeta sin formateo
        
        Args:
            reader_index (int): Índice del lector
            aid (bytes): Application ID personalizado
            interactive (bool): Si usar modo interactivo
            
        Returns:
            bool: True si operación exitosa
        """
        print("=" * 60)
        print("CONFIGURACIÓN DE TARJETA DESFIRE EV1 (SIN FORMATEO)")
        print("=" * 60)
        
        try:
            # Seleccionar lector
            if reader_index is None:
                if interactive:
                    reader_index = self.select_reader_interactive()
                else:
                    reader_index = self.select_reader_automatic()
                
                if reader_index == -1:
                    return False
            
            # Ejecutar flujo sin formateo
            print("\nEjecutando configuración...")
            success = self.business_logic.execute_complete_flow(
                reader_index=reader_index,
                aid=aid,
                format_first=False
            )
            
            if success:
                print("\n" + "=" * 60)
                print("CONFIGURACIÓN COMPLETADA")
                print("=" * 60)
                return True
            else:
                print("\n" + "=" * 60)
                print("ERROR EN CONFIGURACIÓN")
                print("=" * 60)
                return False
                
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario")
            return False
        except Exception as e:
            print(f"\nERROR inesperado: {e}")
            return False
    
    def test_connection(self, reader_index: int = None) -> bool:
        """
        Probar conexión con tarjeta
        
        Args:
            reader_index (int): Índice del lector
            
        Returns:
            bool: True si conexión exitosa
        """
        try:
            if reader_index is None:
                reader_index = self.select_reader_interactive()
                if reader_index == -1:
                    return False
            
            print("Probando conexión...")
            success = self.business_logic.connect_to_reader(reader_index)
            
            if success:
                print("Conexión exitosa")
                self.business_logic.disconnect()
                return True
            else:
                print("ERROR: No se pudo conectar")
                return False
                
        except Exception as e:
            print(f"ERROR en prueba de conexión: {e}")
            return False
    
    # =============================================================================
    # MENÚS DE USUARIO
    # =============================================================================
    
    def show_main_menu(self):
        """Mostrar menú principal"""
        print("\n" + "=" * 50)
        print("DESFIRE EV1 - CONTROLADOR PRINCIPAL")
        print("=" * 50)
        print("1. Formatear y configurar tarjeta completa")
        print("2. Configurar tarjeta (sin formateo)")
        print("3. Probar conexión con tarjeta")
        print("4. Configuración automática (lector 2)")
        print("5. Salir")
        print("=" * 50)
    
    def run_interactive_menu(self):
        """Ejecutar menú interactivo"""
        while True:
            try:
                self.show_main_menu()
                choice = input("Seleccione una opción (1-5): ").strip()
                
                if choice == "1":
                    self.format_and_setup_card()
                elif choice == "2":
                    self.setup_card_without_format()
                elif choice == "3":
                    self.test_connection()
                elif choice == "4":
                    # Configuración automática usando lector índice 2
                    print("Ejecutando configuración automática con lector 2...")
                    aid = bytes([0xF0, 0x01, 0x01])  # AID específico
                    self.format_and_setup_card(reader_index=2, aid=aid, interactive=False)
                elif choice == "5":
                    print("Saliendo...")
                    break
                else:
                    print("Opción inválida. Intente nuevamente.")
                    
                input("\nPresione Enter para continuar...")
                
            except KeyboardInterrupt:
                print("\nSaliendo...")
                break
            except Exception as e:
                print(f"ERROR: {e}")
                input("Presione Enter para continuar...")
    
    # =============================================================================
    # OPERACIONES ESPECÍFICAS
    # =============================================================================
    
    def quick_setup_wallet_app(self, reader_index: int = 2) -> bool:
        """
        Configuración rápida para aplicación de monedero
        Usa el lector índice 2 y AID específico F0:01:01
        
        Args:
            reader_index (int): Índice del lector (por defecto 2)
            
        Returns:
            bool: True si configuración exitosa
        """
        print("Configuración rápida - Aplicación de Monedero")
        print("Lector: Índice 2")
        print("AID: F0:01:01")
        
        # AID específico para aplicación de monedero
        wallet_aid = bytes([0xF0, 0x01, 0x01])
        
        return self.business_logic.execute_complete_flow(
            reader_index=reader_index,
            aid=wallet_aid,
            format_first=True
        )


def main():
    """Función principal"""
    print("DESFire EV1 Controller - Gestión de Tarjetas")
    print("=" * 50)
    
    # Verificar dependencias básicas
    try:
        from smartcard.System import readers
        from Crypto.Cipher import AES
    except ImportError as e:
        print(f"ERROR: Dependencia faltante - {e}")
        print("Instale las dependencias:")
        print("  pip install pyscard pycryptodome")
        sys.exit(1)
    
    # Crear controlador
    controller = DESFireController(debug=True)
    
    # Verificar argumentos de línea de comandos
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "quick":
            # Configuración rápida
            print("Modo: Configuración rápida")
            success = controller.quick_setup_wallet_app()
            sys.exit(0 if success else 1)
        elif command == "test":
            # Prueba de conexión
            print("Modo: Prueba de conexión")
            success = controller.test_connection()
            sys.exit(0 if success else 1)
        elif command == "menu":
            # Menú interactivo
            controller.run_interactive_menu()
        else:
            print(f"Comando desconocido: {command}")
            print("Comandos válidos: quick, test, menu")
            sys.exit(1)
    else:
        # Modo por defecto: menú interactivo
        controller.run_interactive_menu()


if __name__ == "__main__":
    main()