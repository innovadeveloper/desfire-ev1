## CONFIGURACION 
Filename : desfire_refactored_classes_2.py
    - format card (opción 3) : Solo formatea la tarjeta y se autentica con la clave MASTERpor defecto "00000000000000000000000000000000"
    - create and select multiple applications (Opción 2) : Crea 4 aplicaciones 
        - Las aplicaciones de tipo wallet tienen 3 claves : Clave 0: Administración general, Clave 1: Operaciones de débito, Clave 2: Operaciones de crédito 
            applications = [
                {'aid': [0xF0, 0x01, 0x01], 'type': 'wallet'},
                {'aid': [0xA0, 0x01, 0x01], 'type': 'access_control'},
                {'aid': [0xC0, 0x01, 0x01], 'type': 'loyalty'},
                {'aid': [0xF1, 0x02, 0x01], 'type': 'wallet'},  # Segundo monedero
            ]
## SELECCION DE AID Y CAMBIO DE CLAVES 
Filename : desfire_aes_keychange_2.py
    - Se selecciona la aplicación "0xF0, 0x01, 0x01" y se autentica con la clave AES defaul (16 bytes of zeros)
    - Listar las aplicaciones
    - Crea un archivo público : Id 10, Size 256 bytes
    - Obtiene información del archivo público recientemente creado
    - Realiza intento de escritura en el fichero público
    - Realiza intento de lectura del fichero público (autotrim true/false)

Filename : desfire_aes_keychange.py
    - Se selecciona la aplicación "0xF0, 0x01, 0x01" y se autentica con la clave AES default (16 bytes of zeros)
    - [CONTINUE...]