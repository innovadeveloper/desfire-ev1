# Secuencia Completa para Crear Fichero Estándar con Claves en DESFire EV1

## 1. FORMATEO INICIAL (Opcional)
```
Comando: FC
Descripción: Format PICC
Requisito: Autenticación previa con clave maestra de tarjeta
```

## 2. AUTENTICACIÓN A NIVEL DE TARJETA
```
Comando: AA 00
Descripción: Authenticate con clave maestra de tarjeta (Key 0)
Clave por defecto: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (16 bytes de ceros)
```

## 3. CREACIÓN DE APLICACIÓN
```
Comando: CA 01 00 00 0F 83
Descripción: Create Application
Parámetros:
- AID: 01 00 00 (identificador único)
- Key Settings: 0F (configuración permisiva)
- Num Keys: 83 (3 claves + AES habilitado)
```

## 4. SELECCIÓN DE APLICACIÓN
```
Comando: 5A 01 00 00
Descripción: Select Application
Parámetros: AID de la aplicación creada
```

## 5. AUTENTICACIÓN EN LA APLICACIÓN
```
Comando: AA 00
Descripción: Authenticate con master key de la aplicación
Clave inicial: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

## 6. CONFIGURACIÓN DE CLAVES

### Clave de Lectura (Key 1)
```
Comando: C4 01 [16 bytes nueva clave] [versión] [CRC]
Ejemplo: C4 01 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 01 [CRC]
```

### Clave de Escritura (Key 2)
```
Comando: C4 02 [16 bytes nueva clave] [versión] [CRC]
Ejemplo: C4 02 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 01 [CRC]
```

## 7. CREACIÓN DEL FICHERO ESTÁNDAR
```
Comando: CD 01 00 12 00 00 00 00 20
Descripción: Create Std Data File
Parámetros:
- File Number: 01
- Comm Settings: 00 (comunicación plana)
- Access Rights: 12 00
  * Read: Key 1
  * Write: Key 2
  * Read&Write: Key 0 (master)
  * Change Settings: Key 0 (master)
- File Size: 00 00 00 20 (32 bytes)
```

## 8. VERIFICACIÓN
```
Comando: F5 01
Descripción: Get File Settings
Verifica que el archivo se creó correctamente con los permisos establecidos
```

## Notas Importantes:

1. **Orden de Operaciones**: Es crítico seguir el orden exacto
2. **Autenticación**: Cada cambio de contexto requiere nueva autenticación
3. **CRC**: Los comandos Change Key requieren cálculo correcto del CRC
4. **Access Rights**: El formato es nibbles: [Change][R&W][Write][Read]
5. **Comunicación**: Considerar si usar cifrado (0x03) o plano (0x00)

## Uso Posterior del Fichero:

### Para Leer:
1. Autenticarse con clave 1 (lectura)
2. Comando BD 01 00 00 00 00 [longitud] (Read Data)

### Para Escribir:
1. Autenticarse con clave 2 (escritura)  
2. Comando 3D 01 00 00 00 00 [longitud] [datos] (Write Data)

### Para Operaciones Administrativas:
1. Autenticarse con clave 0 (master)
2. Ejecutar comandos como Change File Settings, etc.