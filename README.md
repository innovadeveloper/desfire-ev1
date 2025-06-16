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
