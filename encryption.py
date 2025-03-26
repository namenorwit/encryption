from Crypto.Cipher import AES
import os

# 🗝 กำหนด Key และ IV (ควรใช้ Secure Storage แทน Hardcoded)
SECRET_KEY = b"thisisaverysecretkey123456789101"  # 32-byte Key
IV = b"thisisasecretiv1"  # 16-byte IV

# ✅ ฟังก์ชันเข้ารหัสข้อมูล
def encrypt_data(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    # 🔹 Padding ให้ครบ 16-byte
    padding = 16 - (len(data) % 16)
    data += bytes([padding]) * padding

    encrypted_data = cipher.encrypt(data)
    return encrypted_data

# 🔓 ฟังก์ชันถอดรหัสข้อมูล
def decrypt_data(encrypted_data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    decrypted_data = cipher.decrypt(encrypted_data)

    # 🔹 ลบ Padding ที่เติมไว้
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]

    return decrypted_data

# ✅ ฟังก์ชันเข้ารหัสไฟล์
def encrypt_mode():
    input_file = input("🔹 กรุณาใส่ชื่อไฟล์ที่ต้องการเข้ารหัส: ").strip()

    if not os.path.exists(input_file):
        print("❌ ไม่พบไฟล์ที่ต้องการเข้ารหัส")
        return

    output_file = input_file + ".enc"

    with open(input_file, "rb") as f:
        file_data = f.read()

    encrypted_data = encrypt_data(file_data)

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ รูปภาพถูกเข้ารหัสแล้ว: {output_file}")

# 🔓 ฟังก์ชันถอดรหัสไฟล์
def decrypt_mode():
    input_file = input("🔹 กรุณาใส่ชื่อไฟล์ที่ต้องการถอดรหัส: ").strip()

    if not os.path.exists(input_file):
        print("❌ ไม่พบไฟล์ที่ต้องการถอดรหัส")
        return

    output_file = input_file.replace(".enc", "")  # ลบ .enc ออกเมื่อถอดรหัส

    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_data(encrypted_data)

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"✅ รูปภาพถูกถอดรหัสแล้ว: {output_file}")

# 🔥 เริ่มโปรแกรม
if __name__ == "__main__":
    print("🔹 เลือกโหมดที่ต้องการ:")
    print("1. เข้ารหัสไฟล์ (Encrypt)")
    print("2. ถอดรหัสไฟล์ (Decrypt)")

    choice = input("🔸 กรุณาเลือก (1 หรือ 2): ").strip()

    if choice == "1":
        encrypt_mode()
    elif choice == "2":
        decrypt_mode()
    else:
        print("❌ ตัวเลือกไม่ถูกต้อง")