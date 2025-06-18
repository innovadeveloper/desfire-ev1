# APDU Utils

## About

This repository contains a very thin abstraction layer for the creation of DESFire and ISO/IEC 7816 [Application Protocol Data Unit (APDU)](https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit) commands. It is completely decoupled from and agnostic to the PCD a user implements as part of their DESFire application. It imports no modules and has no dependencies. What this project offers is simply an organized collection of python routines that make the creation of APDUs less painful and less error-prone. The commands are organized into four categories:

- Security-related commands (security_commands.py) for:
    - Top level authentication in different modes
    - Key management
    - Card configuration
- Card level commands (application_commands.py) for:
    - Application creation/ deletion/ selection
    - Obtaining key settings and file infomation
    - Card formatting
    - Obtaining card version details
    - Obtaining additional communication frames
- Application level commands (file_commands.py)
    - File creation/ deletion
    - Obtaining and changing file settings
- File level commands (data_commands.py)
    - Reading and writing data to a file
    - Crediting and debiting value files

In addition, this project also contains a table of DESFire APDU response codes located in response_codes.py.


## Sources

- [NXP MIFARE DESFire EV1 Protocol Manual](https://raw.githubusercontent.com/revk/DESFireAES/master/DESFire.pdf) - written by [RevK](https://github.com/revk)
- [EFTlab's Complete APDU Reponses document](https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses)
- [Project] (https://www.d-logic.com/nfc-rfid-reader-sdk/software/desfire-c-console/)
- [Commands] (https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html)

## Steps
```shell
desfire_refactored_classes_2.py
    - format card
    - create and select multiple applications
desfire_aes_keychange.py
    - change same key that authenticated
desfire_aes_keychange_2.py
    - change key with distinct authentication key
        # demo_change_different_key()
    - create STD files
        # mainCreateSTDFile
```


```shell
=== Creando archivo STD #1 (1024 bytes) ===
Comando CreateStdDataFile: CD0100EE0E000400
  File ID: 1
  Comm Mode: 0
  Access Rights: 0x0EEE
  File Size: 1024
APDU: 90 CD 00 00 07 01 00 EE 0E 00 04 00 00
Response: 52 30 1D B5 7A 5D E0 59, SW: 0x91 0x0
¡Archivo creado exitosamente!

=== Creando archivo STD #2 (32 bytes) ===
Comando CreateStdDataFile: CD0203000E200000
  File ID: 2
  Comm Mode: 3
  Access Rights: 0x0E00
  File Size: 32
APDU: 90 CD 00 00 07 02 03 00 0E 20 00 00 00
Response: AB 33 FC 7B 81 D8 1D 8A, SW: 0x91 0x0
¡Archivo creado exitosamente!


--- Verificando archivo #2 ---
APDU: 90 F5 00 00 01 02 00
Response: 00 03 00 0E 20 00 00 48 91 75 A9 4F 57 1F 3B, SW: 0x91 0x0
Configuración del archivo: 0003000E200000489175A94F571F3B
  Tipo: 00
  Comm Settings: 03
  Access Rights: 0E00
  Tamaño: 32

--- Intentando escribir en archivo #2 ---
Archivo detectado en modo ENCRYPTED

=== Escribiendo datos en archivo #2 (modo ENCRYPTED) ===
Offset: 0
Datos (13 bytes): 486F6C61204445534669726521
Texto: Hola DESFire!
Datos con padding: 486F6C61204445534669726521800000
Datos cifrados: EABC2CC2BF4E481E7DB46A6977F20CFE
CMAC calculado: 79F3B837A5E54746
Comando WriteData (ENCRYPTED): 3D02000000EABC2CC2BF4E481E7DB46A6977F20CFE79F3B837A5E54746
APDU: 90 3D 00 00 1C 02 00 00 00 EA BC 2C C2 BF 4E 48 1E 7D B4 6A 69 77 F2 0C FE 79 F3 B8 37 A5 E5 47 46 00
Response: Sin datos, SW: 0x91 0xbe
Error al escribir datos: BE
Error: Modo de comunicación incorrecto
❌ Error en escritura
Desconectado del lector.

❌ Error en la demostración

----
Encabezado APDU:

90: CLA (Class)
3D: INS (WriteData instruction)
00 00: P1 P2 (Parameters)
27: Lc (Length = 7 bytes header + 32 bytes data)

Datos del comando DESFire:

02: File ID
00 00 00: Offset (3 bytes, little-endian)
20 00 00: Length (3 bytes, little-endian = 32 bytes)
[datos]: 32 bytes de datos a escribir

=== Escribiendo datos de prueba ===
Datos: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
       10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F

APDU completo:
90 3D 00 00 27 02 00 00 00 20 00 00 00 01 02 03 04 05 06 07 
08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 
1C 1D 1E 1F 00


-------------
APDU: 
90 3D 00 00 
1C (28)
fileid : 02 
offset : 00 00 00 
lenght : EA BC 2C 
data : C2 BF 4E 48 1E 7D B4 6A 69 77 F2 0C FE 79 F3 B8 37 A5 E5 47 46 00


903D00001F
02
00 00 00 
0D 00 00 
DAF3042844CE5701BAF199866C54BD1861C10EFCE3C7F39400
```