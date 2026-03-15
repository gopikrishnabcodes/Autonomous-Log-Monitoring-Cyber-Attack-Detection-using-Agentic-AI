# Email Alert Setup Instructions

## Current Status
⚠️ Email configuration is set but authentication failed. Gmail requires an **App Password** instead of your regular password.

## Configuration in `.env`
```
EMAIL_ENABLED=true
SMTP_USER=gopikrishnachinnam8555@gmail.com
SMTP_PASSWORD=Krishna*164  ← This needs to be an App Password
ALERT_EMAIL_TO=gopikrishnachinnam123@gmail.com
```

## How to Get Gmail App Password

### Step 1: Enable 2-Step Verification
1. Go to: https://myaccount.google.com/security
2. Click on **2-Step Verification**
3. Follow the prompts to enable it (you'll need your phone)

### Step 2: Generate App Password
1. Go to: https://myaccount.google.com/apppasswords
   - Or: Google Account → Security → 2-Step Verification → App passwords
2. Select app: **Mail**
3. Select device: **Windows Computer** (or Other)
4. Click **Generate**
5. Google will show you a 16-character password like: `abcd efgh ijkl mnop`

### Step 3: Update `.env` File
1. Open `.env` in your editor
2. Replace the `SMTP_PASSWORD` line with the 16-character app password:
   ```
   SMTP_PASSWORD=abcdefghijklmnop
   ```
   (Remove spaces when copying)
3. Save the file

### Step 4: Test Email Configuration
Run the test script:
```bash
python test_email.py
```

You should see:
```
✅ SUCCESS! Test email sent successfully!
📬 Check gopikrishnachinnam123@gmail.com for the test message
```

## Alternative: Use Less Secure Apps (Not Recommended)
If you don't want to use 2-Step Verification:
1. Go to: https://myaccount.google.com/lesssecureapps
2. Turn on "Allow less secure apps"
3. Try `python test_email.py` again

⚠️ **Warning**: This is less secure and Google may disable it at any time.

## Testing the Full Pipeline with Email Alerts

Once email is configured, test the full system:

```bash
# Run demo mode
python main.py --demo

# Check console output for:
# [AlertAgent] 📧 Email sent to gopikrishnachinnam123@gmail.com

# Check your email inbox for alerts
```

## Troubleshooting

### "Authentication Failed"
- ✅ Use App Password, not regular password
- ✅ Enable 2-Step Verification first
- ✅ Remove spaces from the 16-char app password

### "Connection Refused"
- Check firewall/antivirus blocking port 587
- Check internet connection
- Try disabling VPN temporarily

### "Email Not Received"
- Check spam/junk folder
- Verify `ALERT_EMAIL_TO` is correct
- Check Gmail sent folder of `SMTP_USER`

### "No Emails Sent"
- Check `EMAIL_ENABLED=true` in `.env`
- Check `EMAIL_MIN_LEVEL=ALERT` (only ALERT-level threats trigger emails)
- Run demo mode to generate test alerts

## Current Configuration Summary

| Setting | Value |
|---------|-------|
| Email Enabled | ✅ Yes |
| SMTP Server | smtp.gmail.com:587 |
| From Address | gopikrishnachinnam8555@gmail.com |
| To Address | gopikrishnachinnam123@gmail.com |
| Min Alert Level | ALERT |
| Status | ⚠️ Needs App Password |

## Next Steps

1. ✅ Generate Gmail App Password
2. ✅ Update `.env` with app password
3. ✅ Run `python test_email.py`
4. ✅ Run `python main.py --demo`
5. ✅ Check email inbox for alerts

---

**Need Help?**
- Gmail App Passwords: https://support.google.com/accounts/answer/185833
- 2-Step Verification: https://support.google.com/accounts/answer/185839
