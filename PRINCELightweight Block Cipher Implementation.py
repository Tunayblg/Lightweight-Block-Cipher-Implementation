import struct

# Anahtar genişletmesi (128-bit -> 64-bit kısımlara)
def key_schedule(key):
    k1 = key >> 64  # İlk 64-bit anahtar
    k2 = key & 0xFFFFFFFFFFFFFFFF  # Son 64-bit anahtar
    return k1, k2

# Permütasyon fonksiyonu (Bit kaydırma)
def permutation(block):
    return ((block >> 32) | (block << 32)) & 0xFFFFFFFFFFFFFFFF  # 64-bit bit kaydırma

# Substitution işlemi (Basit XOR, ama gerçek algoritmada daha karmaşıktır)
def substitution(block):
    return block ^ 0xFFFFFFFFFFFFFFFF  # XOR işlemi, gerçek algoritmada farklı olabilir

# Şifreleme işlemi (64-bitlik blok üzerinde)
def prince_encrypt_block(block, key):
    k1, k2 = key_schedule(key)

    # 12 tur boyunca işleme
    for round in range(12):
        # Adım 1: Substitution (veriyi değiştir)
        block = substitution(block)
        
        # Adım 2: Permütasyon (bit kaydırma)
        block = permutation(block)
        
        # Adım 3: Anahtarlarla XOR işlemi
        if round % 2 == 0:
            block ^= k1
        else:
            block ^= k2

    return block

# Çözme işlemi (64-bitlik blok üzerinde)
def prince_decrypt_block(block, key):
    k1, k2 = key_schedule(key)

    # 12 tur çözme işlemi (ters sırayla yapılır)
    for round in range(11, -1, -1):  # Ters sırayla çözülür
        # Adım 1: Permütasyon (bit kaydırma)
        block = permutation(block)
        
        # Adım 2: Substitution (veriyi değiştir)
        block = substitution(block)

        # Adım 3: Anahtarlarla XOR işlemi
        if round % 2 == 0:
            block ^= k1
        else:
            block ^= k2

    return block

# 64-bitlik veri bloğuna ayırma ve şifreleme işlemi
def encrypt(plaintext, key):
    ciphertext = b''
    for i in range(0, len(plaintext), 8):
        block = int.from_bytes(plaintext[i:i+8].encode(), 'big')  # 8 byte'lık blok
        encrypted_block = prince_encrypt_block(block, key)
        ciphertext += struct.pack('>Q', encrypted_block)  # 64-bitlik şifreli veri

    return ciphertext

# Şifreli metni çözme işlemi
def decrypt(ciphertext, key):
    plaintext = ''
    for i in range(0, len(ciphertext), 8):
        block = struct.unpack('>Q', ciphertext[i:i+8])[0]  # 64-bitlik şifreli blok
        decrypted_block = prince_decrypt_block(block, key)
        plaintext += decrypted_block.to_bytes(8, 'big').decode()  # Şifre çözme ve metni oluşturma

    return plaintext

# Kullanıcı arayüzü
def main():
    key = 0x1234567890abcdef1234567890abcdef  # 128-bit anahtar (16 byte)
    
    while True:
        # Kullanıcıdan işlem seçimi
        print("\n1: Şifreleme")
        print("2: Deşifreleme")
        print("3: Çıkış")
        choice = input("Lütfen yapmak istediğiniz işlemi seçin (1/2/3): ")
        
        if choice == "1":
            plaintext = input("Şifrelenecek metni girin: ")
            encrypted = encrypt(plaintext, key)
            print(f"Şifreli metin: {encrypted.hex()}")
        elif choice == "2":
            ciphertext_hex = input("Deşifre edilecek metni (hex formatında) girin: ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
                decrypted = decrypt(ciphertext, key)
                print(f"Çözülmüş metin: {decrypted}")
            except Exception as e:
                print(f"Hata: Geçersiz şifreli metin! ({e})")
        elif choice == "3":
            print("Programdan çıkılıyor...")
            break
        else:
            print("Hatalı seçim! Lütfen 1, 2 veya 3 girin.")

if __name__ == "__main__":
    main()
