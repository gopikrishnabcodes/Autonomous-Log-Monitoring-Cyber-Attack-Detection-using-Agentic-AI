"""
test_email.py
-------------
Test script to verify email configuration works.

Usage:
    python test_email.py
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_email_config():
    """Test email configuration by sending a test message."""
    
    # Get config from .env
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    alert_email = os.getenv("ALERT_EMAIL_TO")
    email_enabled = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
    
    print("=" * 60)
    print("CyberWatch Email Configuration Test")
    print("=" * 60)
    print(f"Email Enabled: {email_enabled}")
    print(f"SMTP User: {smtp_user}")
    print(f"SMTP Password: {'*' * len(smtp_password) if smtp_password else 'NOT SET'}")
    print(f"Alert Email: {alert_email}")
    print("=" * 60)
    
    if not email_enabled:
        print("\n⚠️  EMAIL_ENABLED is set to false in .env")
        print("Set EMAIL_ENABLED=true to enable email alerts")
        return False
    
    if not all([smtp_user, smtp_password, alert_email]):
        print("\n❌ Missing required email configuration!")
        print("Please check your .env file has:")
        print("  - SMTP_USER")
        print("  - SMTP_PASSWORD")
        print("  - ALERT_EMAIL_TO")
        return False
    
    # Test connection
    print("\n🔄 Testing SMTP connection to Gmail...")
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = alert_email
        msg['Subject'] = "CyberWatch Test Alert - Configuration Verified"
        
        body = """
        ✅ CyberWatch Email Configuration Test
        
        This is a test message to verify your email alert configuration.
        
        If you received this email, your CyberWatch system is correctly
        configured to send email alerts.
        
        Configuration Details:
        - SMTP Server: smtp.gmail.com:587
        - From: {smtp_user}
        - To: {alert_email}
        
        Next Steps:
        1. Run the main pipeline: python main.py --demo
        2. Check for ALERT-level threats
        3. Verify you receive email notifications
        
        ---
        CyberWatch Autonomous Attack Detection System
        """.format(smtp_user=smtp_user, alert_email=alert_email)
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to Gmail SMTP
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        
        print("🔐 Authenticating...")
        server.login(smtp_user, smtp_password)
        
        print("📧 Sending test email...")
        server.send_message(msg)
        server.quit()
        
        print("\n✅ SUCCESS! Test email sent successfully!")
        print(f"📬 Check {alert_email} for the test message")
        print("\nNote: If you don't see it, check your spam folder.")
        print("\n⚠️  IMPORTANT: If using Gmail, you may need an App Password:")
        print("   1. Go to: https://myaccount.google.com/security")
        print("   2. Enable 2-Step Verification")
        print("   3. Generate App Password for 'Mail'")
        print("   4. Update SMTP_PASSWORD in .env with the 16-char app password")
        
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("\n❌ AUTHENTICATION FAILED!")
        print("\nPossible issues:")
        print("  1. Incorrect password")
        print("  2. Need to use Gmail App Password (not regular password)")
        print("  3. 2-Step Verification not enabled")
        print("\nTo fix:")
        print("  1. Go to: https://myaccount.google.com/security")
        print("  2. Enable 2-Step Verification")
        print("  3. Go to: https://myaccount.google.com/apppasswords")
        print("  4. Generate App Password for 'Mail'")
        print("  5. Update SMTP_PASSWORD in .env with the 16-char code")
        return False
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nPlease check:")
        print("  - Internet connection")
        print("  - Gmail SMTP settings")
        print("  - Firewall/antivirus blocking port 587")
        return False


if __name__ == "__main__":
    success = test_email_config()
    exit(0 if success else 1)
