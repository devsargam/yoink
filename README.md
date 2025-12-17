# yoink

> yoinks your Netflix OTP codes from Gmail straight to Telegram

## Credentials Required

| Credential | Where to get it |
|------------|-----------------|
| `GOOGLE_CLIENT_ID` | [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials |
| `GOOGLE_CLIENT_SECRET` | Same as above |
| `TELEGRAM_BOT_TOKEN` | [@BotFather](https://t.me/botfather) on Telegram |

## Project Structure

```
├── access-token-service/   # OAuth service to get Gmail tokens
└── tg-service/             # Telegram bot that fetches OTP codes
```

## Usage

1. Run `access-token-service` and authenticate with Google
2. Save the token to `tg-service/token.json`
3. Run `tg-service` with your Telegram bot token
4. Send `/emails` to your bot to get the latest Netflix OTP code
