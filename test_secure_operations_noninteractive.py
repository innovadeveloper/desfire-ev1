#!/usr/bin/env python3
"""
Non-interactive test of secure operations
"""
import struct
from desfire_secure_operations import DESFireSecureOperations

class MockReader:
    """Mock reader for testing without hardware"""
    def createConnection(self):
        return MockConnection()

class MockConnection:
    """Mock connection for testing"""
    def connect(self):
        pass
    
    def getATR(self):
        return [0x3B, 0x81, 0x80, 0x01, 0x80, 0x80]
    
    def transmit(self, apdu):
        # Simulate successful responses
        if apdu[1] == 0xCD:  # CreateStdDataFile
            print(f"Mock CreateStdDataFile APDU: {' '.join(f'{b:02X}' for b in apdu)}")
            return [], 0x91, 0x00  # Success
        elif apdu[1] == 0x3D:  # WriteData
            print(f"Mock WriteData APDU: {' '.join(f'{b:02X}' for b in apdu)}")
            return [], 0x91, 0x00  # Success
        return [], 0x91, 0x6E  # Default error

def test_secure_operations():
    """Test secure operations with mock hardware"""
    
    # Create instance with mock reader
    desfire = DESFireSecureOperations(debug=True)
    desfire.reader = MockReader()
    desfire.connection = MockConnection()
    desfire.authenticated = True  # Skip authentication for test
    
    print("Testing CreateStdDataFile command construction...")
    
    # Test the create_secure_file method
    create_result = desfire.create_secure_file(
        file_id=11,
        file_size=512,
        read_key=1,
        write_key=2,
        change_key=0
    )
    print(f"Create secure file result: {create_result}")
    
    print("\nTesting WriteData command construction...")
    
    # Test the write_secure_data method
    test_data = b"Datos autorizados por clave de escritura"
    write_result = desfire.write_secure_data(11, 100, test_data)
    print(f"Write secure data result: {write_result}")
    
    return create_result and write_result

if __name__ == "__main__":
    success = test_secure_operations()
    print(f"\nSecure operations test {'PASSED' if success else 'FAILED'}")