# HSHONAD Launcher Auth (Backend ใหม่)

## สิ่งที่รวมไว้
- `server.js`: Node.js + Express, Discord OAuth2 (`identify`) และตรวจ Whitelist จาก Google Sheets โดยตรง
- `package.json`: dependencies สำหรับ Render
- `Form1.cs`: เปิด OAuth2 ในเบราว์เซอร์หลักและ poll ผลกลับเข้า WebView2
- `wwwroot/index.html`: หน้า Launcher เดิมของคุณ

## ตั้งค่า Render
1. สร้าง Web Service จาก Git repository ที่มี `server.js` และ `package.json`
2. Build Command: `npm install`
3. Start Command: `npm start`
4. เพิ่ม Environment Variables:
   - `BASE_URL` = URL Render จริง เช่น `https://hsho-launcher-auth.onrender.com`
   - `DISCORD_CLIENT_ID` = Application ID ของ Discord Application
   - `DISCORD_CLIENT_SECRET` = Client Secret จาก Discord Developer Portal
   - `GOOGLE_SHEET_ID` = `1pMjqVGFpQ4Tla-PercIzX90v9bryOze7xEQrMdJWmQw`
   - `SHEET_RANGE` = `ชีต1!D2:D`
   - `GOOGLE_SERVICE_ACCOUNT_JSON` = JSON ทั้งก้อนของ Service Account (ค่าเดียว ห้ามใส่ใน Launcher หรือ Git)
5. ใน Discord Developer Portal > OAuth2 เพิ่ม Redirect URL ให้ตรงเป๊ะ:
   `https://YOUR-RENDER-DOMAIN/auth/discord/callback`
6. ใน Google Cloud เปิด Google Sheets API, สร้าง Service Account และแชร์ Google Sheet ให้กับอีเมล `client_email` ของ Service Account เป็น Viewer
7. ทดสอบ `https://YOUR-RENDER-DOMAIN/health` ควรได้ `{"ok":true}`

## ตั้งค่า Launcher
- แทนที่ `Form1.cs` ด้วยไฟล์นี้
- แทนที่ไฟล์ `wwwroot/index.html` ด้วยไฟล์ในโฟลเดอร์นี้
- เปลี่ยน `BackendBaseUrl` ใน `Form1.cs` ให้ตรงกับ Render URL จริงของคุณ
- ตรวจสอบว่าโปรเจกต์ติดตั้ง `Microsoft.Web.WebView2` และคัดลอก `wwwroot/index.html` ไปยัง output directory ตามเดิม

## สำคัญ
- ตรวจ Whitelist จาก Discord ID ในคอลัมน์ D เท่านั้น แถวแรกเริ่มที่ D2 ตามหัวตาราง
- OAuth2 callback ตรวจ `state` ที่สุ่มไว้ และ Launcher ใช้ session secret แบบ Bearer เพื่ออ่านผล
- Session อยู่ใน memory เหมาะกับเดโม/ทดสอบหนึ่ง instance; การ restart หรือ scale หลาย instance อาจทำให้ session หาย/อ่านไม่เจอ ก่อนใช้งานจริงควรย้าย session ไป Redis หรือฐานข้อมูลกลาง
- อย่า commit `.env`, Client Secret หรือ service account private key ลง Git
- ไม่ได้ตรวจสอบการตั้งค่า Discord/Google/Render จริงจากไฟล์นี้ ต้องกรอกค่าจริงและทดสอบ deploy
