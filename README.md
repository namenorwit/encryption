# Environment Configuration

โปรเจกต์นี้จำเป็นต้องตั้งค่าตัวแปรสภาพแวดล้อมบางอย่างเพื่อให้ทำงานได้อย่างถูกต้อง ไฟล์ `env.example` เป็นเทมเพลตสำหรับการตั้งค่าเหล่านี้ ในการตั้งค่าตัวแปรสภาพแวดล้อมของคุณ ให้สร้างไฟล์ `.env` ในไดเรกทอรีรากของโปรเจกต์ แล้วใส่ค่าที่คุณกำหนดเองเข้าไป

## Configuration Variables

- **SECRET_KEY**

  - **Description**: A secret key used for cryptographic operations. This key should be kept confidential and should be a long, random string to ensure security.
    - **คำอธิบาย**: กุญแจลับที่ใช้สำหรับการทำงานทางการเข้ารหัส ควรเก็บกุญแจนี้ให้เป็นความลับและควรเป็นสตริงที่ยาวและสุ่มเพื่อให้ปลอดภัย
  - **Example**: `s1u2p3a4w5e6e7w8o9n868ledd5f4t89`
  - **Note**: Do not share this key or hard-code it into any client-side code.
    - **หมายเหตุ**: อย่าแชร์กุญแจนี้หรือฝังไว้ในโค้ดฝั่งไคลเอนต์

- **IV**

  - **Description**: The Initialization Vector (IV) used for encryption processes. It should be unique and random to ensure that encryptions are secure.
    - **คำอธิบาย**: เวกเตอร์เริ่มต้น (IV) ที่ใช้สำหรับกระบวนการเข้ารหัส ควรมีความเป็นเอกลักษณ์และสุ่มเพื่อให้แน่ใจว่าการเข้ารหัสมีความปลอดภัย
  - **Example**: `supawadee888w2e6`
  - **Note**: Just like the secret key, keep this value secure and separate from your codebase.
    - **หมายเหตุ**: เช่นเดียวกับกุญแจลับ ควรรักษาค่านี้ให้ปลอดภัยและแยกจากฐานโค้ดของคุณ

## Setup Steps

1. Duplicate the `env.example` file and rename the copy to `.env`.
   - ให้คัดลอกไฟล์ `env.example` แล้วเปลี่ยนชื่อเป็น `.env`
2. Open the `.env` file and replace the example values with your actual configuration values.
   - เปิดไฟล์ `.env` แล้วแทนที่ค่าตัวอย่างด้วยค่าที่คุณกำหนดเอง
3. Save the `.env` file.
   - บันทึกไฟล์ `.env`

By setting these environment variables, you'll ensure the application runs securely and properly configured. Always keep the `.env` file out of version control by adding it to your `.gitignore` file.
- โดยการตั้งค่าตัวแปรสภาพแวดล้อม, คุณจะมั่นใจได้ว่าแอปพลิเคชันจะทำงานได้อย่างปลอดภัยและถูกตั้งค่าอย่างเหมาะสม ควรเก็บไฟล์ `.env` ไว้นอกการควบคุมเวอร์ชันโดยเพิ่มลงในไฟล์ `.gitignore`
