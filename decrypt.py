from Crypto.Cipher import AES
import binascii

def decrypt_aes_blocks(encrypted_data_hex, key):
    try:
        encrypted_bytes = binascii.unhexlify(encrypted_data_hex.replace(" ", ""))
        
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        
        # Decrypt each 16-byte block
        decrypted_blocks = []
        for i in range(0, len(encrypted_bytes), 16):
            block = encrypted_bytes[i:i+16]
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            decrypted_blocks.append(cipher.decrypt(block))
            # if cipher.decrypt(block).decode('ascii', errors='ignore').strip() == 'EmbeddedSecurity':
            #     memory = block

        return [data.decode('ascii', errors='ignore').strip() for data in decrypted_blocks]
    
    except Exception as e:
        return f"Decryption failed: {e}"
    
def parse_hex_file(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", "").replace(":", "")
    
    data_bytes = []
    i = 0
    while i < len(hex_string):
        # Extract record fields
        byte_count = int(hex_string[i:i+2], 16)
        record_type = hex_string[i+6:i+8]
        
        if record_type == "00":
            data_start = i+8
            data_end = data_start + (byte_count * 2)
            data_hex = hex_string[data_start:data_end]
            data_bytes.append(data_hex)
        
        i += 2 + 4 + 2 + (byte_count * 2) + 2
    
    return data_bytes

key = "10358899ahnelson"

with open('./micro-ecc-CWNANO.hex', 'r') as file:
    hex_file = file.read()

encrypted_hex = ''.join(parse_hex_file(hex_file))

decrypted_text = decrypt_aes_blocks(encrypted_hex, key)
#print(f"Encrypted Hex: {encrypted_hex}")
# print(f"Decrypted Text: {decrypted_text}")
for i in decrypted_text:
    if len(i) == 16:
        print(i)
# print(decrypted_text)

# 01 b9 29 38 ed 3d 50 93 11 73 c3 11 60 4f 97 bb is the secret key in memory address is 080042f0 - 080042ff