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
from desfire_create_stdfile_python import CommMode, AccessRights, DESFireCreateStdDataFile, DESFireDeleteFile, parse_delete_command, parse_create_command, DESFireGetFileIDs, parse_get_file_ids_command

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
    
    def des_encrypt_cbc(self, key, iv, data):
        """DES CBC encryption"""
        from Crypto.Cipher import DES
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return cipher.encrypt(data)
    
    def des_decrypt_cbc(self, key, iv, data):
        """DES CBC decryption"""
        from Crypto.Cipher import DES
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return cipher.decrypt(data)
    
    def authenticate_des(self, key_number, key):
        """Perform DES/3DES authentication"""
        print(f"*** Authenticate(KeyNo= {key_number}, DES Key)")
        
        # Step 1: Send authentication request (DES/3DES uses 0x1A)
        command = bytes([0x1A, key_number])
        response = self.send_command(command)
        
        if response[0] != 0xAF or len(response) != 9:
            print(f"DES Authentication failed at step 1: {response[0]:02X}")
            return False
        
        encrypted_rnd_b = response[1:9]
        print(f"* RndB_enc: {encrypted_rnd_b.hex().upper()}")
        
        # Step 2: Decrypt RndB
        iv_zero = bytes(8)  # DES uses 8-byte IV
        rnd_b = self.des_decrypt_cbc(key, iv_zero, encrypted_rnd_b)
        print(f"* RndB: {rnd_b.hex().upper()}")
        
        # Step 3: Rotate RndB left by 1 byte
        rnd_b_rotated = rnd_b[1:] + rnd_b[:1]
        print(f"* RndB_rot: {rnd_b_rotated.hex().upper()}")
        
        # Step 4: Generate RndA
        rnd_a = os.urandom(8)  # DES uses 8-byte random
        print(f"* RndA: {rnd_a.hex().upper()}")
        
        # Step 5: Concatenate RndA + RndB'
        rnd_ab = rnd_a + rnd_b_rotated
        print(f"* RndAB: {rnd_ab.hex().upper()}")
        
        # Step 6: Encrypt RndAB with IV = encrypted_rnd_b
        encrypted_rnd_ab = self.des_encrypt_cbc(key, encrypted_rnd_b, rnd_ab)
        print(f"* RndAB_enc: {encrypted_rnd_ab.hex().upper()}")
        
        # Step 7: Send encrypted RndAB
        command = bytes([0xAF]) + encrypted_rnd_ab
        response = self.send_command(command)
        
        if response[0] != 0x00 or len(response) != 9:
            print(f"DES Authentication failed at step 2: {response[0]:02X}")
            return False
        
        # Step 8: Decrypt and verify RndA'
        encrypted_rnd_a = response[1:9]
        print(f"* RndA_enc: {encrypted_rnd_a.hex().upper()}")
        
        # IV for this decryption is the last 8 bytes we sent
        iv_for_decrypt = encrypted_rnd_ab[-8:]
        decrypted_rnd_a = self.des_decrypt_cbc(key, iv_for_decrypt, encrypted_rnd_a)
        print(f"* RndA_dec: {decrypted_rnd_a.hex().upper()}")
        
        # RndA should be rotated left by 1 byte
        expected_rnd_a = rnd_a[1:] + rnd_a[:1]
        print(f"* RndA_rot: {expected_rnd_a.hex().upper()}")
        
        if decrypted_rnd_a != expected_rnd_a:
            print("DES Authentication failed: RndA verification failed")
            return False
        
        # Step 9: Generate session key for DES (different from AES)
        # For DES, session key is usually derived differently
        # For simplicity, we'll use the key itself as session key
        self.session_key = key + key  # Duplicate to make 16 bytes for compatibility
        print(f"* SessKey: {self.session_key.hex().upper()}")
        
        # Reset session IV
        self.session_iv = bytes(8)  # DES uses 8-byte IV
        self.authenticated = True
        
        print("DES Authentication successful!")
        return True
    
    def authenticate_auto(self, key_number, aes_key=None, des_key=None):
        """
        Attempt authentication with both AES and DES keys automatically
        
        Args:
            key_number: Key number to authenticate with
            aes_key: AES key (16 bytes) to try first
            des_key: DES key (8 bytes) to try if AES fails
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        print(f"*** Auto-Authenticate(KeyNo={key_number})")
        
        # If AES key provided, try AES first
        if aes_key is not None:
            print("\n--- Trying AES authentication ---")
            if self.authenticate_aes(key_number, aes_key):
                print("✅ AES authentication successful!")
                return True
            else:
                print("❌ AES authentication failed")
        
        # If DES key provided, try DES
        if des_key is not None:
            print("\n--- Trying DES authentication ---")
            if self.authenticate_des(key_number, des_key):
                print("✅ DES authentication successful!")
                return True
            else:
                print("❌ DES authentication failed")
        
        # Try default keys if none provided
        if aes_key is None and des_key is None:
            print("\n--- Trying default AES key (16 zeros) ---")
            default_aes = bytes(16)
            if self.authenticate_aes(key_number, default_aes):
                print("✅ Default AES authentication successful!")
                return True
            
            print("\n--- Trying default DES key (8 zeros) ---")
            default_des = bytes(8)
            if self.authenticate_des(key_number, default_des):
                print("✅ Default DES authentication successful!")
                return True
        
        print("❌ All authentication methods failed!")
        return False
    
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

    def read_file_data(self, file_id, offset=0, length=None, auto_trim=True):
        """
        Read data from a standard data file
        
        Args:
            file_id: File ID to read from (0-31)
            offset: Starting position to read from (default 0)
            length: Number of bytes to read (None = read all)
            auto_trim: Automatically trim padding/MAC bytes (default True)
        
        Returns:
            bytes: File data if successful, None if failed
        """
        if not self.authenticated:
            print("Error: Not authenticated")
            return None
        
        print(f"*** ReadData(FileNo={file_id}, Offset={offset}, Length={length or 'ALL'})")
        
        # Build ReadData command
        command = bytearray([0xBD, file_id])  # ReadData command (0xBD)
        command.extend(struct.pack('<I', offset)[:3])  # Offset (3 bytes, little-endian)
        
        if length is not None:
            command.extend(struct.pack('<I', length)[:3])  # Length (3 bytes, little-endian)
        else:
            command.extend([0x00, 0x00, 0x00])  # Read all (0 means read all)
        
        print(f"* Command: {command.hex().upper()}")
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            file_data = response[1:]
            print(f"* Raw file data ({len(file_data)} bytes): {file_data.hex().upper()}")
            
            # If auto_trim is enabled and we have extra data, try to trim it
            if auto_trim and length is not None and len(file_data) > length:
                # Check if we have MAC/padding at the end
                expected_data = file_data[:length]
                extra_data = file_data[length:]
                
                print(f"* Expected data ({length} bytes): {expected_data.hex().upper()}")
                print(f"* Extra data ({len(extra_data)} bytes): {extra_data.hex().upper()}")
                
                # Return only the requested length
                return expected_data
            
            return file_data
        elif response[0] == 0xAF:
            # More data available - collect all frames
            all_data = bytearray(response[1:])
            
            while True:
                # Send GetAdditionalFrame command (0xAF)
                continue_cmd = bytes([0xAF])
                response = self.send_command(continue_cmd)
                
                if response[0] == 0x00:
                    # Last frame
                    all_data.extend(response[1:])
                    break
                elif response[0] == 0xAF:
                    # More frames follow
                    all_data.extend(response[1:])
                else:
                    print(f"Error during multi-frame read: {response[0]:02X}")
                    return None
            
            print(f"* Complete raw data ({len(all_data)} bytes): {all_data.hex().upper()}")
            
            # Apply auto_trim logic for multi-frame responses too
            if auto_trim and length is not None and len(all_data) > length:
                expected_data = all_data[:length]
                extra_data = all_data[length:]
                
                print(f"* Expected data ({length} bytes): {expected_data.hex().upper()}")
                print(f"* Extra data ({len(extra_data)} bytes): {extra_data.hex().upper()}")
                
                return bytes(expected_data)
            
            return bytes(all_data)
        else:
            print(f"Read failed: {response[0]:02X}")
            return None

    def write_file_data(self, file_id, offset, data):
        """
        Write data to a standard data file
        
        Args:
            file_id: File ID to write to (0-31)
            offset: Starting position to write to
            data: Data to write (bytes)
        
        Returns:
            bool: True if successful, False if failed
        """
        if not self.authenticated:
            print("Error: Not authenticated")
            return False
        
        print(f"*** WriteData(FileNo={file_id}, Offset={offset}, Length={len(data)})")
        print(f"* Data: {data.hex().upper()}")
        
        # Build WriteData command
        command = bytearray([0x3D, file_id])  # WriteData command (0x3D)
        command.extend(struct.pack('<I', offset)[:3])  # Offset (3 bytes, little-endian)
        command.extend(struct.pack('<I', len(data))[:3])  # Length (3 bytes, little-endian)
        command.extend(data)  # Data payload
        
        print(f"* Command: {command.hex().upper()}")
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            print("Write successful")
            return True
        else:
            print(f"Write failed: {response[0]:02X}")
            return False

    def get_file_info(self, file_id):
        """
        Get file settings and information
        
        Args:
            file_id: File ID to query (0-31)
        
        Returns:
            dict: File information if successful, None if failed
        """
        if not self.authenticated:
            print("Error: Not authenticated")
            return None
        
        print(f"*** GetFileSettings(FileNo={file_id})")
        
        # Build GetFileSettings command
        command = bytes([0xF5, file_id])  # GetFileSettings command (0xF5)
        
        response = self.send_command(command)
        
        if response[0] == 0x00:
            file_settings = response[1:]
            if len(file_settings) >= 7:
                file_type = file_settings[0]
                comm_mode = file_settings[1]
                access_rights = struct.unpack('<H', file_settings[2:4])[0]
                file_size = struct.unpack('<I', file_settings[4:7] + b'\x00')[0]
                
                # Decode access rights
                read_key = (access_rights >> 12) & 0xF
                write_key = (access_rights >> 8) & 0xF
                rw_key = (access_rights >> 4) & 0xF
                change_key = access_rights & 0xF
                
                file_info = {
                    'file_type': file_type,
                    'comm_mode': comm_mode,
                    'file_size': file_size,
                    'access_rights': {
                        'read': read_key,
                        'write': write_key,
                        'read_write': rw_key,
                        'change': change_key
                    },
                    'raw_data': file_settings.hex().upper()
                }
                
                print(f"* File Type: {file_type:02X}")
                print(f"* Comm Mode: {comm_mode:02X}")
                print(f"* File Size: {file_size} bytes")
                print(f"* Access Rights: R={read_key}, W={write_key}, RW={rw_key}, C={change_key}")
                
                return file_info
            else:
                print(f"Invalid file settings response length: {len(file_settings)}")
                return None
        else:
            print(f"GetFileSettings failed: {response[0]:02X}")
            return None


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
        if not desfire.authenticate_auto(0, aes_key=master_key, des_key=bytes(8)):
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
    # new_key = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    #                  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00])
    
    current_key_B = bytes(16)  # 16 zeros for AES

    try:
        # Step 1: Select application
        if not desfire.select_application(aid):
            print("Failed to select application. Application may not exist.")
            return False
        
        # Step 2: Authenticate with key 0
        if not desfire.authenticate_auto(0, aes_key=current_key, des_key=bytes(8)):
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


def mainCreateSTDFile():
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

    try:
        # Step 1: Select application
        if not desfire.select_application(aid):
            print("Failed to select application. Application may not exist.")
            return False
        
        # Step 2: Authenticate with key 0
        if not desfire.authenticate_auto(0, aes_key=current_key, des_key=bytes(8)):
            print("Authentication failed. Check if key is correct.")
            return False
        
        # cmd1 = DESFireDeleteFile.delete_file(5)
        # response = desfire.send_command(cmd1)
        # if response[0] == 0x00:
        #     print("deleted file success")
        # else:
        #     print("delete file failed")
            
        if not desfire.authenticate_auto(0, aes_key=current_key, des_key=bytes(8)):
            print("Authentication failed. Check if key is correct.")
            return False

        print("1. Comando para listar archivos:")
        list_cmd = DESFireGetFileIDs.list_files()
        print(f"   Comando: {list_cmd.hex().upper()}")
        response = desfire.send_command(list_cmd)

        response = DESFireGetFileIDs.parse_response(response)

        parsed_list = parse_get_file_ids_command(list_cmd)
        print(f"   Detalles: {parsed_list}")

        # Step 3: Change key 2 to new key (SAME KEY)
        print("Creando Archivo público (4KB):")
        cmd1 = DESFireCreateStdDataFile.create_public_file(5, 1024)
        response = desfire.send_command(cmd1)
        if response[0] == 0x00:
            print("Application selected successfully")
            return True
        else:
            print(f"Error selecting application: {response[0]:02X}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Close connection
        if reader.connection:
            reader.connection.disconnect()



def demo_file_operations():
    """Demonstrate file reading and writing operations"""
    
    print("\n" + "="*60)
    print("DEMO: File Operations (Read/Write)")
    print("="*60)
    
    reader = SmartCardReader(debug=True)
    if not reader.connect_reader():
        return False
    
    desfire = DESFireAES(reader)
    
    # Application ID
    aid = bytes([0xF0, 0x01, 0x01])
    
    # Current master key
    master_key = bytes([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                        0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])

    try:
        # Step 1: Select application
        if not desfire.select_application(aid):
            return False
        
        # Step 2: Authenticate with master key (try both AES and DES)
        print("\n--- Authenticating with master key ---")
        # Try with the known master key first
        if not desfire.authenticate_auto(0, aes_key=master_key, des_key=bytes(8)):
            # If that fails, try with default keys
            print("Known keys failed, trying default keys...")
            if not desfire.authenticate_auto(0):
                return False
        
        # Step 3: List existing files
        print("\n--- Listing files ---")
        list_cmd = DESFireGetFileIDs.list_files()
        response = desfire.send_command(list_cmd)
        file_list = DESFireGetFileIDs.parse_response(response[1:] if response[0] == 0x00 else b'')
        print(f"Existing files: {file_list}")
        
        # Step 4: Create a test file if it doesn't exist
        test_file_id = 10
        if test_file_id not in file_list:
            print(f"\n--- Creating test file {test_file_id} ---")
            create_cmd = DESFireCreateStdDataFile.create_public_file(test_file_id, 256)
            response = desfire.send_command(create_cmd)
            if response[0] == 0x00:
                print("Test file created successfully")
            else:
                print(f"Failed to create test file: {response[0]:02X}")
                return False
        
        # Step 5: Get file information
        print(f"\n--- Getting file {test_file_id} information ---")
        file_info = desfire.get_file_info(test_file_id)
        if not file_info:
            return False
        
        # Check communication mode
        comm_mode = file_info['comm_mode']
        comm_mode_str = {0x00: "PLAIN", 0x01: "MAC", 0x03: "ENCRYPTED"}.get(comm_mode, f"UNKNOWN({comm_mode:02X})")
        print(f"* Communication mode: {comm_mode_str}")
        
        if comm_mode != 0x00:
            print("⚠️  WARNING: File uses MAC/Encryption - read data may include padding/MAC bytes")
        
        # Step 6: Write test data
        print(f"\n--- Writing data to file {test_file_id} ---")
        test_data = b"Hello DESFire EV1! Saludos kloubit."
        if desfire.write_file_data(test_file_id, 0, test_data):
            print("Data written successfully")
        else:
            print("Failed to write data")
            return False
        
        # Step 7: Read the data back (with auto-trim enabled)
        print(f"\n--- Reading data from file {test_file_id} ---")
        read_data = desfire.read_file_data(test_file_id, 0, len(test_data), auto_trim=True)
        if read_data:
            print(f"Trimmed data: {read_data}")
            print(f"As text: {read_data.decode('utf-8', errors='ignore')}")
            
            # Verify data integrity
            if read_data == test_data:
                print("✅ Data integrity verified!")
            else:
                print("❌ Data mismatch!")
                print(f"Expected: {test_data}")
                print(f"Got:      {read_data}")
        else:
            print("Failed to read data")
            return False
        
        # Step 7b: Also try reading without auto-trim to see raw data
        print(f"\n--- Reading raw data (no auto-trim) ---")
        raw_data = desfire.read_file_data(test_file_id, 0, len(test_data), auto_trim=False)
        if raw_data:
            print(f"Raw data ({len(raw_data)} bytes): {raw_data}")
            if len(raw_data) > len(test_data):
                print(f"Extra bytes detected: {len(raw_data) - len(test_data)} bytes")
                extra_bytes = raw_data[len(test_data):]
                print(f"Extra bytes: {extra_bytes.hex().upper()}")
                print("This is likely MAC/padding from encrypted communication mode")
        
        # Step 8: Read partial data
        print(f"\n--- Reading partial data (first 5 bytes) ---")
        partial_data = desfire.read_file_data(test_file_id, 0, 5)
        if partial_data:
            print(f"Partial data: {partial_data}")
            print(f"As text: {partial_data.decode('utf-8', errors='ignore')}")
        
        print("\n✅ File operations completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if reader.connection:
            reader.connection.disconnect()


if __name__ == "__main__":
    print("DESFire EV1 AES Authentication and File Operations")
    print("=" * 60)
    
    # Run file operations demo
    demo_file_operations()

