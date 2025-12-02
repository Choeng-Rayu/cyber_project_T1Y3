import smtplib
import ssl

smtp_server = "smtp.gmail.com"
port = 587
sender_email = "yo4tube.company168@gmail.com"
password = "nabzxqwuyngaqvym"
receiver_email = "tepsomnang875@gmail.com"  # Your email

message = f"""Subject: DIRECT TEST - Please reply if you get this
From: {sender_email}
To: {receiver_email}
Importance: high

Hi,

This is a direct test email from the Python script.

If you receive this, please reply with "GOT IT" so I know it worked.

Thanks!"""

context = ssl.create_default_context()

print("="*50)
print("TEST 1: Direct Email Test")
print("="*50)

try:
    print("1. Connecting to server...")
    server = smtplib.SMTP(smtp_server, port)
    
    print("2. Starting TLS...")
    server.starttls(context=context)
    
    print("3. Logging in...")
    server.login(sender_email, password)
    
    print("4. Sending email...")
    server.sendmail(sender_email, receiver_email, message)
    
    print("✓ Email supposedly sent!")
    print("\n⚠️  Please check:")
    print("   a. Inbox of: tepsomnang875@gmail.com")
    print("   b. SPAM folder")
    print("   c. Promotions tab")
    print("   d. Search: 'DIRECT TEST'")
    
except Exception as e:
    print(f"❌ Error during sending: {e}")
    
finally:
    try:
        server.quit()
        print("\n🔒 Connection closed")
    except:
        pass