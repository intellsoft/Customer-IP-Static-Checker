
```markdown
# 🖥️ Customer IP Static Checker - نظارت بر وضعیت آی‌پی مشتریان

یک ابزار پایتونی برای بررسی وضعیت آنلاین/آفلاین بودن آی‌پی و پورتهای مشتریان با رابط کاربری گرافیکی.

![نرم‌افزار Customer IP Static Checker، ابزاری هوشمند برای نظارت بر وضعیت شبکه](https://intellsoft.ir/%d9%86%d8%b1%d9%85%d8%a7%d9%81%d8%b2%d8%a7%d8%b1-customer-ip-static-checker-%d8%a7%d8%a8%d8%b2%d8%a7%d8%b1%db%8c-%d9%87%d9%88%d8%b4%d9%85%d9%86%d8%af-%d8%a8%d8%b1%d8%a7%db%8c-%d9%86%d8%b8%d8%a7%d8%b1/)

## ✨ ویژگیهای کلیدی
- ✅ نمایش وضعیت بلادرنگ با رنگبندی متفاوت
- ✅ هشدار صوتی هنگام قطع ارتباط
- ✅ مدیریت لیست مشتریان با قابلیت ویرایش مستقیم
- ✅ وارد کردن داده‌ها از فایل CSV
- ✅ رمزنگاری امن دادههای ذخیره شده
- ✅ جستجوی سریع در لیست مشتریان
- ✅ تنظیم بازه زمانی بررسی خودکار (پیشفرض: ۲ ساعت)

## 🛠️ نحوه نصب و اجرا
۱. پیشنیازها:
   ```bash
   pip install -r requirements.txt
   ```
   فایل `requirements.txt`:
   ```
   cryptography==39.0.2
   tkinter==0.1.0
   winsound==1.0.0
   ```

۲. اجرای برنامه:
   ```bash
   python ipstatic.py
   ```

## ⚙️ پیکربندی
- فایل `config.json` را ویرایش کنید:
  ```json
  {
    "ping_interval": 7200  // بازه بررسی به ثانیه (7200 = ۲ ساعت)
  }
  ```
- داده‌ها به صورت رمزنگاری شده در `data.enc` ذخیره میشوند.
- برای ایمپورت داده‌ها از منوی اصلی استفاده کنید (فرمت CSV: `Name,IP,Port`).

## ⚠️ هشدارها
- ❌ هنگام حذف آیتم‌ها احتیاط کنید (غیرقابل بازگشت!).
- 🔒 فایلهای `secret.key` و `data.enc` را پشتیبانگیری کنید.
- 💻 در محیط ویندوز اجرا شود (به دلیل استفاده از `winsound`).

---

# 🖥️ Customer IP Static Checker 

A Python-based GUI tool for monitoring client IP/Port status with real-time updates.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)

## ✨ Key Features
- ✅ Real-time status monitoring with color coding
- ✅ Audio alerts for downtime detection
- ✅ In-place table editing capabilities
- ✅ CSV data import functionality
- ✅ Secure data encryption
- ✅ Quick search/filter functionality
- ✅ Configurable check interval (default: 2 hours)

## 🛠️ Installation & Usage
۱. Requirements:
   ```bash
   pip install -r requirements.txt
   ```
   `requirements.txt`:
   ```
   cryptography==39.0.2
   tkinter==0.1.0
   winsound==1.0.0
   ```

۲. Run application:
   ```bash
   python ipstatic.py
   ```

## ⚙️ Configuration
- Edit `config.json`:
  ```json
  {
    "ping_interval": 7200  // Check interval in seconds (7200 = 2 hours)
  }
  ```
- Data stored encrypted in `data.enc`.
- Use CSV import (format: `Name,IP,Port`).

## ⚠️ Warnings
- ❌ Deletion is permanent! Use with caution.
- 🔒 Backup `secret.key` and `data.enc` files.
- 💻 Designed for Windows environment (uses `winsound`).

## 📄 License  
MIT License © 2023 [Ali Abbaspour](https://intellsoft.ir)  
[![Website](https://img.shields.io/badge/Visit-Website-blue?style=flat-square)](https://intellsoft.ir)
```

✅ آماده است!