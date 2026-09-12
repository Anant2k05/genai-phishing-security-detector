"""Synthetic demo messages for the "Load Example" button. No real personal data."""

DEMO_EXAMPLES = [
    {
        "id": "bank-verification",
        "title": "Fake bank account verification",
        "input_type": "message",
        "content": (
            "Dear Customer,\n\n"
            "We detected unauthorized access on your account. Your account will be "
            "suspended within 24 hours unless you verify your identity immediately.\n\n"
            "Please confirm your account by clicking the link below and entering your "
            "card number, CVV, and net banking password:\n"
            "http://secure-login-bankofamerica-verify.com/account\n\n"
            "Failure to act now will result in permanent account suspension.\n\n"
            "Bank Security Team"
        ),
    },
    {
        "id": "password-reset",
        "title": "Fake Microsoft password reset",
        "input_type": "message",
        "content": (
            "Microsoft Account Security Alert\n\n"
            "Your password has expired and unusual sign-in activity was detected. "
            "Verify your identity within 12 hours or your account will be locked.\n\n"
            "Click here to reset your password: http://microsoft-account-verify.top/reset\n\n"
            "Enter your current password and the verification code sent to your phone "
            "to confirm it's you.\n\nMicrosoft Support Team"
        ),
    },
    {
        "id": "prize-scam",
        "title": "Prize / reward scam",
        "input_type": "message",
        "content": (
            "CONGRATULATIONS!!! You have been selected as a winner of our annual "
            "lottery draw! You are eligible for a cash prize of $850,000.\n\n"
            "To claim your prize, reply immediately with your full name, bank details, "
            "and a small processing fee of $50 via gift card. Claim now, this offer "
            "expires today!"
        ),
    },
    {
        "id": "tech-support",
        "title": "Fake IT support message",
        "input_type": "message",
        "content": (
            "Windows Security Alert: Your computer has been infected with a virus. "
            "Unauthorized access detected on your device.\n\n"
            "Call Microsoft Support Team immediately at the number below or download "
            "TeamViewer so our technician can remotely access your computer to remove "
            "the threat. Do not turn off your computer.\n\n"
            "Action required immediately."
        ),
    },
    {
        "id": "benign-notification",
        "title": "Benign legitimate notification",
        "input_type": "message",
        "content": (
            "Hi Alex,\n\n"
            "Your monthly statement for August is now available in your account "
            "dashboard. You can view or download it anytime by logging into your "
            "account directly at our website.\n\n"
            "No action is required. If you have any questions, contact us through "
            "the support page on our official site.\n\nThanks,\nAccount Services"
        ),
    },
]
