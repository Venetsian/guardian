"""
WP-Guardian Telegram Setup Wizard
Interactive tool to configure Telegram bot alerts.
Helps users find their chat_id without any web tools.
"""

import sys
import os
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def _input(prompt):
    """Python 2/3 compatible input."""
    try:
        return raw_input(prompt)
    except NameError:
        return input(prompt)


def validate_token(token):
    """Test if a bot token is valid by calling getMe."""
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get('ok'):
            bot_info = data['result']
            return True, bot_info
        else:
            return False, data.get('description', 'Unknown error')
    except requests.Timeout:
        return False, "Connection timed out"
    except requests.ConnectionError:
        return False, "Cannot connect to Telegram API (check internet)"
    except Exception as e:
        return False, str(e)


def poll_for_chat_id(token, timeout=120):
    """
    Poll getUpdates to find the chat_id from a user message.
    The user should send any message to the bot while this runs.
    """
    url = f"https://api.telegram.org/bot{token}/getUpdates"

    # First, clear old updates by getting the latest offset
    try:
        resp = requests.get(url, params={'limit': 1, 'offset': -1}, timeout=10)
        data = resp.json()
        offset = 0
        if data.get('ok') and data.get('result'):
            offset = data['result'][-1]['update_id'] + 1
    except Exception:
        offset = 0

    start_time = time.time()
    print("\n  Waiting for your message...")
    print("  (Checking every 2 seconds, timeout: %d seconds)\n" % timeout)

    while time.time() - start_time < timeout:
        try:
            resp = requests.get(url, params={'offset': offset, 'timeout': 5}, timeout=15)
            data = resp.json()

            if data.get('ok') and data.get('result'):
                for update in data['result']:
                    msg = update.get('message', {})
                    chat = msg.get('chat', {})
                    chat_id = chat.get('id')
                    chat_type = chat.get('type', 'unknown')
                    first_name = chat.get('first_name', '')
                    username = chat.get('username', '')
                    text = msg.get('text', '')

                    if chat_id:
                        return {
                            'chat_id': str(chat_id),
                            'type': chat_type,
                            'first_name': first_name,
                            'username': username,
                            'text': text,
                        }

                    offset = update['update_id'] + 1

        except requests.Timeout:
            pass
        except Exception as e:
            print(f"  Error polling: {e}")

        elapsed = int(time.time() - start_time)
        remaining = timeout - elapsed
        sys.stdout.write(f"\r  Waiting... ({remaining}s remaining)  ")
        sys.stdout.flush()
        time.sleep(2)

    print()
    return None


def send_test_message(token, chat_id):
    """Send a test message to verify everything works."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': "✅ <b>WP-Guardian Connected!</b>\n\nTelegram alerts are working. "
                "You will receive security notifications here.",
        'parse_mode': 'HTML',
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def update_config_file(config_path, token, chat_id):
    """Update wp-guardian.conf with Telegram settings."""
    if not config_path or not os.path.exists(config_path):
        print(f"\n  Config file not found: {config_path}")
        print("  Please manually add these to your wp-guardian.conf:\n")
        print(f"  [telegram]")
        print(f"  enabled = true")
        print(f"  bot_token = {token}")
        print(f"  chat_id = {chat_id}")
        return False

    try:
        with open(config_path, 'r') as f:
            lines = f.readlines()

        # Find and update telegram section
        in_telegram = False
        updated_enabled = False
        updated_token = False
        updated_chat_id = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith('[') and stripped.endswith(']'):
                in_telegram = (stripped == '[telegram]')
                continue

            if in_telegram:
                if stripped.startswith('enabled'):
                    lines[i] = 'enabled = true\n'
                    updated_enabled = True
                elif stripped.startswith('bot_token'):
                    lines[i] = f'bot_token = {token}\n'
                    updated_token = True
                elif stripped.startswith('chat_id'):
                    lines[i] = f'chat_id = {chat_id}\n'
                    updated_chat_id = True

        with open(config_path, 'w') as f:
            f.writelines(lines)

        success = updated_enabled and updated_token and updated_chat_id
        if success:
            print(f"\n  Updated {config_path}")
        else:
            print(f"\n  Partially updated {config_path}")
            if not updated_enabled:
                print("  WARNING: Could not find 'enabled' in [telegram] section")
            if not updated_token:
                print("  WARNING: Could not find 'bot_token' in [telegram] section")
            if not updated_chat_id:
                print("  WARNING: Could not find 'chat_id' in [telegram] section")

        return success

    except Exception as e:
        print(f"\n  Error updating config: {e}")
        return False


def telegram_setup_wizard(config_path=None):
    """Interactive Telegram setup wizard."""
    print()
    print("=" * 55)
    print("  WP-Guardian — Telegram Bot Setup")
    print("=" * 55)
    print()

    if not HAS_REQUESTS:
        print("  ERROR: 'requests' module not installed.")
        print("  Install it with: pip3 install requests")
        return False

    # Step 1: Get bot token
    print("  STEP 1: Bot Token")
    print("  -" * 25)
    print("  If you don't have a bot yet:")
    print("    1. Open Telegram and search for @BotFather")
    print("    2. Send /newbot")
    print("    3. Choose a name (e.g., 'My Server Guardian')")
    print("    4. Choose a username (e.g., 'myserver_guardian_bot')")
    print("    5. BotFather will give you a token")
    print()

    token = _input("  Enter your bot token: ").strip()
    if not token:
        print("  No token provided. Aborting.")
        return False

    # Validate token
    print("\n  Validating token...")
    valid, result = validate_token(token)
    if not valid:
        print(f"  ERROR: Invalid token — {result}")
        return False

    bot_name = result.get('first_name', 'Unknown')
    bot_username = result.get('username', 'unknown')
    print(f"  ✓ Bot verified: {bot_name} (@{bot_username})")

    # Step 2: Get chat_id
    print()
    print("  STEP 2: Your Chat ID")
    print("  -" * 25)
    print(f"  Now send ANY message to your bot: @{bot_username}")
    print("  (Open Telegram, find your bot, and send 'hello' or anything)")
    print()

    proceed = _input("  Press Enter when you've sent a message to the bot...")

    chat_info = poll_for_chat_id(token, timeout=120)

    if not chat_info:
        print("\n  Timed out waiting for a message.")
        print("  Make sure you sent a message to the correct bot.")
        print(f"  Bot username: @{bot_username}")
        print()

        # Offer manual entry
        manual = _input("  Enter chat_id manually (or press Enter to abort): ").strip()
        if manual:
            chat_info = {'chat_id': manual, 'first_name': 'Manual', 'username': ''}
        else:
            return False

    chat_id = chat_info['chat_id']
    print(f"\n  ✓ Found chat_id: {chat_id}")
    if chat_info.get('first_name'):
        print(f"    Name: {chat_info['first_name']}")
    if chat_info.get('username'):
        print(f"    Username: @{chat_info['username']}")

    # Step 3: Test
    print()
    print("  STEP 3: Testing")
    print("  -" * 25)
    print("  Sending test message...")

    if send_test_message(token, chat_id):
        print("  ✓ Test message sent! Check your Telegram.")
    else:
        print("  ✗ Failed to send test message.")
        proceed = _input("  Continue anyway? [y/N]: ").strip().lower()
        if proceed != 'y':
            return False

    # Step 4: Save to config
    print()
    print("  STEP 4: Save Configuration")
    print("  -" * 25)

    save = _input("  Save to wp-guardian.conf? [Y/n]: ").strip().lower()
    if save != 'n':
        update_config_file(config_path, token, chat_id)
    else:
        print(f"\n  Add these to your wp-guardian.conf manually:\n")
        print(f"  [telegram]")
        print(f"  enabled = true")
        print(f"  bot_token = {token}")
        print(f"  chat_id = {chat_id}")

    print()
    print("  " + "=" * 50)
    print("  Telegram setup complete!")
    print()
    print(f"  Bot: @{bot_username}")
    print(f"  Chat ID: {chat_id}")
    print()
    print("  You can test anytime with:")
    print("    python3 wp-guardian.py --telegram-test")
    print("  " + "=" * 50)
    print()
    return True


if __name__ == '__main__':
    # Allow running standalone
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    telegram_setup_wizard(config_path)
