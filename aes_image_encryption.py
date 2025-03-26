from Crypto.Cipher import AES
import os

from dotenv import load_dotenv
# 🗝 กำหนด Key และ IV (ควรใช้ Secure Storage แทน Hardcoded)
# โหลดตัวแปรจากไฟล์ .env
load_dotenv()

# 🔧 ฟังก์ชันปรับความยาวคีย์ให้ถูกต้อง
def adjust_key_length(key, target_length=16):
    if len(key) < target_length:
        return key.ljust(target_length, b'\0')  # เพิ่มความยาวให้ครบ
    elif len(key) > target_length:
        return key[:target_length]  # ตัดให้เหลือตามต้องการ
    return key

# 🗝 ดึงและปรับแต่ง Key และ IV
SECRET_KEY = os.getenv("SECRET_KEY")
IV = os.getenv("IV")

if not SECRET_KEY or not IV:
    print("⚠️ กรุณาตั้งค่า SECRET_KEY และ IV ในไฟล์ .env")
    exit(1)

SECRET_KEY = adjust_key_length(SECRET_KEY.encode("utf-8"), 32)  # ใช้ AES-128
IV = adjust_key_length(IV.encode("utf-8"), 16)

print(f"🔑 Key Length: {len(SECRET_KEY)} bytes")
print(f"🔹 IV Length: {len(IV)} bytes")


# ✅ ฟังก์ชันเข้ารหัสไฟล์รูป (Encryption)
def encrypt_image(input_file, output_file):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    with open(input_file, "rb") as f:
        file_data = f.read()

    # 🔹 Padding ให้ครบ 16-byte
    padding = 16 - (len(file_data) % 16)
    file_data += bytes([padding]) * padding

    encrypted_data = cipher.encrypt(file_data)

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

    print(f"🔐 รูปภาพถูกเข้ารหัสแล้ว: {output_file}")

# 🔓 ฟังก์ชันถอดรหัสไฟล์รูป (Decryption)
def decrypt_image(input_file, output_file):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    # 🔹 ลบ Padding ที่เติมไว้
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"🔓 รูปภาพถูกถอดรหัสแล้ว: {output_file}")

# 🔥 ทดสอบการเข้ารหัสและถอดรหัส
if __name__ == "__main__":
    input_file = "test.jpg"  # ไฟล์รูปภาพต้นฉบับ
    encrypted_file = "test.bin"  # ไฟล์ที่ถูกเข้ารหัส
    decrypted_file = "test.jpg"  # ไฟล์รูปที่ถอดรหัสกลับมา

    encrypt_image(input_file, encrypted_file)
    decrypt_image(encrypted_file, decrypted_file)