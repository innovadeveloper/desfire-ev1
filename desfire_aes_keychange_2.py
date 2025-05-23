#!/usr/bin/env python3
"""
DESFire EV1 AES Authentication and Key Change Script
Based on the communication examples from DESFIRE-COMMANDS-SAMPLE.pdf
Corrected for proper ISO 7816-4 APDU wrapping
"""

import os
import struct
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

class DESFireAES:
    def __init__(self, reader_interface):
        """
        Initialize DESFire AES handler
        reader_interface: Object with send_command(cmd) method that returns response bytes
        """
        self.reader = reader_interface
        self.session_key = None
        self.session_iv = bytes(16)  # AES uses 16-byte IV
        self.authenticated = False
        
    def wrap_native_command(self, command):
        """
        Wrap DESFire native command in ISO 7816-4 APDU
        Format: CLA INS P1 P2 Lc Data
        """
        if len(command) == 1:
            # Single byte command (no data)
            return [0x90, command[0], 0x00, 0x00, 0x00]
        else:
            # Command with data
            cmd_byte = command[0]
            data = command[1:]
            lc = len(data)
            apdu = [0x90, cmd_byte, 0x00, 0x00, lc] + list(data) + [0x00]
            return apdu
    
    def send_command(self, command):
        """Send DESFire command to card and return response"""
        # Wrap native command in ISO APDU
        apdu = self.wrap_native_command(command)
        response = self.reader.send_apdu(apdu)
        return response
    
    def crc32_desfire(self, data):
        """Calculate CRC32 as used in DESFire (polynomial 0xEDB88320)"""
        poly = 0xEDB88320
        crc = 0xFFFFFFFF
        
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
        
        return crc & 0xFFFFFFFF
    
    def pad_data(self, data):
        """Add padding for AES encryption (0x80 + 0x00s)"""
        padded = bytearray(data)
        padded.append(0x80)
        
        while len(padded) % 16 != 0:
            padded.append(0x00)
            
        return bytes(padded)
    
    def aes_encrypt_cbc(self, key, iv, data):
        """AES CBC encryption"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)
    
    def aes_decrypt_cbc(self, key, iv, data):
        """AES CBC decryption"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)
    
    def generate_cmac_subkeys(self, key):
        """Generate CMAC subkeys K1 and K2"""
        # Encrypt 16 zeros with the session key
        cipher = AES.new(key, AES.MODE_ECB)
        l = cipher.encrypt(bytes(16))
        
        # Generate K1
        k1 = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            k1[i] = ((l[i] << 1) | carry) & 0xFF
            carry = (l[i] >> 7) & 1
        
        if l[0] & 0x80:  # MSB of L is 1
            k1[15] ^= 0x87
        
        # Generate K2
        k2 = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            k2[i] = ((k1[i] << 1) | carry) & 0xFF
            carry = (k1[i] >> 7) & 1
        
        if k1[0] & 0x80:  # MSB of K1 is 1
            k2[15] ^= 0x87
        
        return bytes(k1), bytes(k2)
    
    def calculate_cmac(self, key, data):
        """Calculate CMAC for given data"""
        if not data:
            data = bytes()
        
        k1, k2 = self.generate_cmac_subkeys(key)
        
        # Pad data if necessary
        if len(data) == 0 or len(data) % 16 != 0:
            padded_data = self.pad_data(data)
            last_block_key = k2
        else:
            padded_data = data
            last_block_key = k1
        
        # XOR last block with appropriate subkey
        last_block = bytearray(padded_data[-16:])
        for i in range(16):
            last_block[i] ^= last_block_key[i]
        
        # Replace last block
        cmac_data = padded_data[:-16] + bytes(last_block)
        
        # Encrypt with CBC mode using zero IV
        iv = bytes(16)
        encrypted = self.aes_encrypt_cbc(key, iv, cmac_data)
        
        # Update session IV and return first 8 bytes as CMAC
        self.session_iv = encrypted[-16:]
        return encrypted[-16:][:8]  # Return first 8 bytes
    
    def select_application(self, aid):
        """Select application by AID"""
        print(f"*** SelectApplication({aid.hex().upper()})")
        
        command = bytes([0x5A]) + aid
        response = self.send_command(command)
        
        if response[0] == 0x00:
            print("Application selected successfully")
            self.authenticated = False  # Reset authentication
            return True
        else:
            print(f"Error selecting application: {response[0]:02X}")
            return False
    
    def authenticate_aes(self, key_number, key):
        """Perform AES authentication"""
        print(f"*** Authenticate(KeyNo= {key_number}, AES Key)")
        
        # Step 1: Send authentication request
        command = bytes([0xAA, key_number])
        response = self.send_command(command)
        
        if response[0] != 0xAF or len(response) != 17:
            print(f"Authentication failed at step 1: {response[0]:02X}")
            return False
        
        encrypted_rnd_b = response[1:17]
        print(f"* RndB_enc: {encrypted_rnd_b.hex().upper()}")
        
        # Step 2: Decrypt RndB
        iv_zero = bytes(16)
        rnd_b = self.aes_decrypt_cbc(key, iv_zero, encrypted_rnd_b)
        print(f"* RndB: {rnd_b.hex().upper()}")
        
        # Step 3: Rotate RndB left by 1 byte
        rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
        print(f"* RndB_rot: {rnd_b_rotated.hex().upper()}")
        
        # Step 4: Generate RndA
        rnd_a = os.urandom(16)
        print(f"* RndA: {rnd_a.hex().upper()}")
        
        # Step 5: Concatenate RndA + RndB'
        rnd_ab = rnd_a + rnd_b_rotated
        print(f"* RndAB: {rnd_ab.hex().upper()}")
        
        # Step 6: Encrypt RndAB with IV = encrypted_rnd_b
        encrypted_rnd_ab = self.aes_encrypt_cbc(key, encrypted_rnd_b, rnd_ab)
        print(f"* RndAB_enc: {encrypted_rnd_ab.hex().upper()}")
        
        # Step 7: Send encrypted RndAB
        command = bytes([0xAF]) + encrypted_rnd_ab
        response = self.send_command(command)
        
        if response[0] != 0x00 or len(response) != 17:
            print(f"Authentication failed at step 2: {response[0]:02X}")
            return False
        
        # Step 8: Decrypt and verify RndA'
        encrypted_rnd_a = response[1:17]
        print(f"* RndA_enc: {encrypted_rnd_a.hex().upper()}")
        
        # IV for this decryption is the last 16 bytes we sent
        iv_for_decrypt = encrypted_rnd_ab[-16:]
        decrypted_rnd_a = self.aes_decrypt_cbc(key, iv_for_decrypt, encrypted_rnd_a)
        print(f"* RndA_dec: {decrypted_rnd_a.hex().upper()}")
        
        # RndA should be rotated left by 1 byte
        expected_rnd_a = rnd_a[1:] + rnd_a[:1]
        print(f"* RndA_rot: {expected_rnd_a.hex().upper()}")
        
        if decrypted_rnd_a != expected_rnd_a:
            print("Authentication failed: RndA verification failed")
            return False
        
        # Step 9: Generate session key
        # Session key = first 4 bytes of RndA + first 4 bytes of RndB + last 4 bytes of RndA + last 4 bytes of RndB
        self.session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[-4:] + rnd_b[-4:]
        print(f"* SessKey: {self.session_key.hex().upper()}")
        
        # Reset session IV
        self.session_iv = bytes(16)
        self.authenticated = True
        
        print("Authentication successful!")
        return True
    
    def change_key(self, key_number, new_key, new_key_version=0x00, current_key=None, authenticated_key_number=None):
        """
        Change a key in the current application
        
        Args:
            key_number: Number of the key to change (0-13)
            new_key: New key data (16 bytes for AES)
            new_key_version: Version byte for the new key
            current_key: Current key data (required if changing different key than authenticated)
            authenticated_key_number: Key number used for authentication (for verification)
        """
        if not self.authenticated:
            print("Error: Not authenticated")
            return False
        
        print(f"*** ChangeKey(KeyNo= {key_number})")
        print(f"* New Key: {new_key.hex().upper()}")
        
        # Determine if we're changing the same key or a different key
        if authenticated_key_number is not None and authenticated_key_number != key_number:
            # Changing a DIFFERENT key - need current key for XOR
            if current_key is None:
                print("Error: current_key is required when changing a different key")
                return False
            return self._change_different_key(key_number, new_key, new_key_version, current_key)
        else:
            # Changing the SAME key used for authentication
            return self._change_same_key(key_number, new_key, new_key_version)
    
    def _change_same_key(self, key_number, new_key, new_key_version):
        """Change the same key used for authentication"""
        print("* Changing SAME key used for authentication")
        
        # Calculate CRC of the cryptogram (command + key_number + new_key + key_version)
        crypto_data = bytes([0xC4, key_number]) + new_key + bytes([new_key_version])
        crc_crypto = self.crc32_desfire(crypto_data)
        print(f"* CRC Crypto: 0x{crc_crypto:08X}")
        
        # Build cryptogram: new_key + key_version + crc_crypto (little endian) + padding
        cryptogram = new_key + bytes([new_key_version])
        cryptogram += struct.pack('<L', crc_crypto)  # CRC in little endian
        
        # Pad to multiple of 16 bytes
        while len(cryptogram) % 16 != 0:
            cryptogram += b'\x00'
        
        print(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Encrypt cryptogram with session key and current IV
        encrypted_cryptogram = self.aes_encrypt_cbc(self.session_key, self.session_iv, cryptogram)
        print(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Update session IV
        self.session_iv = encrypted_cryptogram[-16:]
        
        # Send ChangeKey command
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            print("Key changed successfully!")
            # Calculate and verify CMAC if present
            if len(response) > 1:
                received_cmac = response[1:9]
                expected_cmac = self.calculate_cmac(self.session_key, bytes([0x00]))
                print(f"RX CMAC: {received_cmac.hex().upper()}")
                print(f"Expected CMAC: {expected_cmac.hex().upper()}")
            return True
        else:
            print(f"Key change failed: {response[0]:02X}")
            return False
    
     
    def _change_different_key(self, key_number, new_key, new_key_version, current_key):
        """Change a DIFFERENT key than the one used for authentication"""
        print("* Changing DIFFERENT key than authentication key")
        print(f"* Current Key: {current_key.hex().upper()}")
        
        # XOR new key with current key
        xored_key = bytes(a ^ b for a, b in zip(new_key, current_key))
        print(f"* New Key XOR Current Key: {xored_key.hex().upper()}")
        
        # Calculate CRC of the NEW key (not XORed)
        crc_new_key = self.crc32_desfire(new_key)
        print(f"* CRC New Key: 0x{crc_new_key:08X}")
        
        # Calculate CRC of the cryptogram (command + key_number + XORed_key + key_version)
        # NOTE: According to the PDF example, CRC crypto is calculated WITHOUT the CRC_new_key
        crypto_data = bytes([0xC4, key_number]) + xored_key + bytes([new_key_version])
        crc_crypto = self.crc32_desfire(crypto_data)
        print(f"* CRC Cryptogram: 0x{crc_crypto:08X}")
        
        # Build cryptogram: XORed_key + key_version + CRC_crypto + CRC_new_key + padding
        # CORRECTED ORDER: According to PDF example, CRC_crypto comes BEFORE CRC_new_key
        cryptogram = xored_key + bytes([new_key_version])
        cryptogram += struct.pack('<L', crc_crypto)    # CRC of cryptogram FIRST
        cryptogram += struct.pack('<L', crc_new_key)   # CRC of new key SECOND
        
        # Pad to multiple of 16 bytes
        while len(cryptogram) % 16 != 0:
            cryptogram += b'\x00'
        
        print(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Encrypt cryptogram with session key and current IV
        encrypted_cryptogram = self.aes_encrypt_cbc(self.session_key, self.session_iv, cryptogram)
        print(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Update session IV
        self.session_iv = encrypted_cryptogram[-16:]
        
        # Send ChangeKey command
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            print("Key changed successfully!")
            # Calculate and verify CMAC if present
            if len(response) > 1:
                received_cmac = response[1:9]
                expected_cmac = self.calculate_cmac(self.session_key, bytes([0x00]))
                print(f"RX CMAC: {received_cmac.hex().upper()}")
                print(f"Expected CMAC: {expected_cmac.hex().upper()}")
            return True
        else:
            print(f"Key change failed: {response[0]:02X}")
            return False

    def _change_different_key_2(self, key_number, new_key, new_key_version, current_key):
        """Change a DIFFERENT key than the one used for authentication"""
        print("* Changing DIFFERENT key than authentication key")
        print(f"* Current Key: {current_key.hex().upper()}")
        
        # XOR new key with current key
        xored_key = bytes(a ^ b for a, b in zip(new_key, current_key))
        print(f"* New Key XOR Current Key: {xored_key.hex().upper()}")
        
        # Calculate CRC of the NEW key (not XORed)
        crc_new_key = self.crc32_desfire(new_key)
        print(f"* CRC New Key: 0x{crc_new_key:08X}")
        
        # Cryptogram = nueva_clave_XOR_clave_actual + versión + CRC32_nueva_clave + CRC32_cryptogram

        # Calculate CRC of the cryptogram (command + key_number + XORed_key + key_version + CRC_new_key)
        crypto_data = bytes([0xC4, key_number]) + xored_key + bytes([new_key_version]) + struct.pack('<L', crc_new_key)
        crc_crypto = self.crc32_desfire(crypto_data)
        print(f"* CRC Cryptogram: 0x{crc_crypto:08X}")
        
        # Build cryptogram: XORed_key + key_version + CRC_new_key + CRC_cryptogram + padding
        cryptogram = xored_key + bytes([new_key_version])
        cryptogram += struct.pack('<L', crc_crypto)    # CRC of cryptogram
        cryptogram += struct.pack('<L', crc_new_key)   # CRC of new key
        
        # Pad to multiple of 16 bytes
        while len(cryptogram) % 16 != 0:
            cryptogram += b'\x00'
        
        print(f"* Cryptogram: {cryptogram.hex().upper()}")
        
        # Encrypt cryptogram with session key and current IV
        encrypted_cryptogram = self.aes_encrypt_cbc(self.session_key, self.session_iv, cryptogram)
        print(f"* CryptogrEnc: {encrypted_cryptogram.hex().upper()}")
        
        # Update session IV
        self.session_iv = encrypted_cryptogram[-16:]
        
        # Send ChangeKey command
        command = bytes([0xC4, key_number]) + encrypted_cryptogram
        response = self.send_command(command)
        
        if response[0] == 0x00:
            print("Key changed successfully!")
            # Calculate and verify CMAC if present
            if len(response) > 1:
                received_cmac = response[1:9]
                expected_cmac = self.calculate_cmac(self.session_key, bytes([0x00]))
                print(f"RX CMAC: {received_cmac.hex().upper()}")
                print(f"Expected CMAC: {expected_cmac.hex().upper()}")
            return True
        else:
            print(f"Key change failed: {response[0]:02X}")
            return False


# Real reader interface
class SmartCardReader:
    def __init__(self, debug=True):
        self.reader = None
        self.connection = None
        self.debug = debug
        
    def connect_reader(self):
        """Conecta con el primer lector disponible"""
        from smartcard.System import readers
        from smartcard.Exceptions import CardConnectionException
        from smartcard.util import toHexString
        import sys
        
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
        """Envía un APDU a la tarjeta y devuelve la respuesta en formato DESFire"""
        from smartcard.util import toHexString
        
        try:
            if self.debug:
                print(f"APDU: {toHexString(apdu)}")
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if self.debug:
                print(f"Response: {toHexString(response) if response else 'Sin datos'}, SW: {hex(sw1)} {hex(sw2)}")
            
            # Procesar respuesta según los códigos de estado
            if sw1 == 0x90 and sw2 == 0x00:
                # Comando exitoso ISO
                return bytes([0x00]) + bytes(response) if response else bytes([0x00])
            elif sw1 == 0x91:
                # DESFire status code en SW2
                return bytes([sw2]) + bytes(response) if response else bytes([sw2])
            elif sw1 == 0x61:
                # Más datos disponibles, usar GET RESPONSE
                get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
                response2, sw1_2, sw2_2 = self.connection.transmit(get_response)
                if sw1_2 == 0x90 and sw2_2 == 0x00:
                    all_response = (response if response else []) + (response2 if response2 else [])
                    return bytes([0x00]) + bytes(all_response)
                else:
                    return bytes([sw1_2])
            else:
                # Error
                if self.debug:
                    print(f"Error en comunicación: SW1={sw1:02X}, SW2={sw2:02X}")
                return bytes([0x6E])  # Communication error
                
        except Exception as e:
            print(f"Error al enviar APDU: {e}")
            return bytes([0x6E])  # Communication error
    
    def send_command(self, command):
        """Compatibility method for DESFireAES class"""
        # This shouldn't be called directly, but included for compatibility
        return self.send_apdu(list(command))


def get_version():
    """Test function to verify DESFire communication"""
    reader = SmartCardReader(debug=True)
    
    if not reader.connect_reader():
        return False
    
    try:
        # Send GetVersion command (0x60)
        print("\n*** Testing GetVersion command ***")
        apdu = [0x90, 0x60, 0x00, 0x00, 0x00]  # Wrapped DESFire GetVersion
        response = reader.send_apdu(apdu)
        
        if response[0] == 0xAF:  # More frames follow
            print("Version info received (partial):")
            print(f"Hardware: {response[1:].hex().upper()}")
            
            # Get additional frames
            for i in range(2):  # Usually 3 total frames
                apdu = [0x90, 0xAF, 0x00, 0x00, 0x00]  # Continue
                response = reader.send_apdu(apdu)
                if response[0] == 0xAF:
                    print(f"Frame {i+2}: {response[1:].hex().upper()}")
                elif response[0] == 0x00:
                    print(f"Final frame: {response[1:].hex().upper()}")
                    break
            
            return True
        else:
            print(f"Unexpected response: {response.hex().upper()}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if reader.connection:
            reader.connection.disconnect()


def demo_change_different_key():
    """Demostrar cómo cambiar una clave diferente a la de autenticación"""
    
    print("\n" + "="*60)
    print("DEMO: Cambiar una clave DIFERENTE a la de autenticación")
    print("="*60)
    
    reader = SmartCardReader(debug=True)
    if not reader.connect_reader():
        return False
    
    desfire = DESFireAES(reader)
    
    # Application ID
    aid = bytes([0xF0, 0x01, 0x01])
    
    # Claves conocidas
    master_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                        0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])  # Nueva clave 0 del ejemplo anterior
    
    key1_current = bytes(16)  # Clave 1 actual (supongamos que son ceros)
    key1_new = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])  # Nueva clave 1
    key1_new = bytes(16)  # Clave 1 actual (supongamos que son ceros)

    try:
        # Paso 1: Seleccionar aplicación
        if not desfire.select_application(aid):
            return False
        
        # Paso 2: Autenticarse con la clave 0 (master key)
        print("\n--- Autenticándose con clave 0 (master) ---")
        if not desfire.authenticate_aes(0, master_key):
            return False
        
        # Paso 3: Cambiar la clave 1 (diferente a la clave 0 usada para autenticación)
        print("\n--- Cambiando clave 1 (diferente a la de autenticación) ---")
        success = desfire.change_key(
            key_number=1,                    # Cambiar clave 1
            new_key=key1_new,               # Nueva clave para key 1
            new_key_version=0x20,           # Versión 0x20
            current_key=key1_current,       # Clave actual de key 1
            authenticated_key_number=0      # Nos autenticamos con clave 0
        )
        
        if success:
            print("\n✅ Clave 1 cambiada exitosamente!")
            return True
        else:
            print("\n❌ Falló el cambio de clave 1")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if reader.connection:
            reader.connection.disconnect()


def main():
    """Main function to demonstrate AES authentication and key change"""
    
    # Test basic communication first
    print("Testing basic DESFire communication...")
    if not get_version():
        print("Basic communication test failed!")
        return False
    
    print("\n" + "="*60)
    print("Starting AES Authentication and Key Change Process")
    print("="*60)
    
    # Initialize with real reader
    reader = SmartCardReader(debug=True)
    
    # Connect to card reader
    if not reader.connect_reader():
        print("No se pudo conectar con el lector o la tarjeta")
        return False
    
    desfire = DESFireAES(reader)
    
    # Application ID: 0xF00101
    aid = bytes([0xF0, 0x01, 0x01])
    
    # Current key (the one we changed to in previous run)
    current_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                         0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])
    
    # New key to set
    new_key = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00])
    
    current_key_B = bytes(16)  # 16 zeros for AES

    try:
        # Step 1: Select application
        if not desfire.select_application(aid):
            print("Failed to select application. Application may not exist.")
            return False
        
        # Step 2: Authenticate with key 0
        if not desfire.authenticate_aes(0, current_key):
            print("Authentication failed. Check if key is correct.")
            return False
        
        # Step 3: Change key 0 to new key (SAME KEY)
        # print("\n--- Ejemplo 1: Cambiar la MISMA clave (clave 0) ---")
        # if not desfire.change_key(0, new_key, 0x30, authenticated_key_number=0):
        #     print("Key change failed.")
        #     return False
        
        # Step 4: Change key 2 to new key (SAME KEY)
        print("\n--- Ejemplo 2: Cambiar otra clave (clave 1) ---")
        # if not desfire.change_key(1, new_key, 0x30, current_key, authenticated_key_number=0):
        if not desfire.change_key(1, current_key_B, 0x30, current_key_B, authenticated_key_number=0):
            print("Key change failed.")
            return False
        
        print("\n" + "="*50)
        print("Process completed successfully!")
        print("Key 0 has been changed to the new key.")
        print("="*50)
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Close connection
        if reader.connection:
            reader.connection.disconnect()


if __name__ == "__main__":
    print("DESFire EV1 AES Authentication and Key Change")
    print("=" * 50)
    
    # # Ejecutar ejemplo principal
    # success = main()
    
    # if success:
    # Ejecutar demo de cambio de clave diferente
    demo_change_different_key()

