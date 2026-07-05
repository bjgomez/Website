#!/usr/bin/env python3
"""
Security Monitor — bendigosweb.duckdns.org
Monitors Apache, Fail2ban, ModSecurity, and SSH logs.
Sends email alerts via Gmail when threats are detected.
"""

import re
import time
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict

# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────
GMAIL_ADDRESS   = "Email Address to send Alerts"
GMAIL_APP_PASS  = "YOUR_16_CHAR_APP_PASSWORD"
ALERT_TO        = "Email Address to Recieve Alerts"

# Alert thresholds
FAIL2BAN_ALERT    = True    # alert on every new Fail2ban ban
MODSEC_ALERT      = True    # alert on ModSecurity blocks
SSH_ALERT         = True    # alert on SSH failed logins
SPIKE_404_LIMIT   = 20      # alert if this many 404s in the window
SPIKE_WINDOW_MINS = 5       # time window in minutes for 404 spike detection

# Log file paths
APACHE_ACCESS_LOG = "/var/log/apache2/access.log"
FAIL2BAN_LOG      = "/var/log/fail2ban.log"
MODSEC_AUDIT_LOG  = "/var/log/apache2/modsec_audit.log"
AUTH_LOG          = "/var/log/auth.log"

# How often to run checks (seconds)
CHECK_INTERVAL    = 60

# Local log file
MONITOR_LOG       = "/home/bendigo/security_monitor.log"

# ─────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────
seen_fail2ban_bans  = set()
seen_modsec_blocks  = set()
seen_ssh_attempts   = set()
alert_cooldown      = {}
notfound_timestamps = []

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(MONITOR_LOG, "a") as f:
        f.write(line + "\n")


def send_email(subject, body):
    """Send an email alert via Gmail SMTP with cooldown to prevent spam."""
    key = subject[:60]
    now = datetime.now()
    if key in alert_cooldown:
        if now - alert_cooldown[key] < timedelta(minutes=10):
            return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SERVER ALERT] {subject}"
        msg["From"]    = GMAIL_ADDRESS
        msg["To"]      = ALERT_TO

        text_body = (
            f"{body}\n\n"
            f"--\n"
            f"bendigosweb.duckdns.org security monitor\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        html_body = f"""
        <html>
        <body style="font-family:monospace;background:#0a0e0f;color:#c8d8d4;padding:20px;">
          <div style="max-width:500px;margin:0 auto;border:1px solid #1e2d31;border-radius:4px;overflow:hidden;">
            <div style="background:#00ff9d;padding:12px 20px;">
              <strong style="color:#0a0e0f;font-size:16px;">SERVER ALERT</strong>
            </div>
            <div style="padding:20px;background:#0f1518;">
              <h2 style="color:#00ff9d;margin:0 0 16px;">{subject}</h2>
              <pre style="color:#c8d8d4;background:#141c1f;padding:12px;border-radius:4px;white-space:pre-wrap;">{body}</pre>
              <p style="color:#6a8a84;font-size:12px;margin-top:16px;">
                bendigosweb.duckdns.org &middot; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
              </p>
            </div>
          </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASS)
            server.sendmail(GMAIL_ADDRESS, ALERT_TO, msg.as_string())

        alert_cooldown[key] = now
        log(f"Email sent: {subject}")

    except Exception as e:
        log(f"Email failed: {e}")


def read_last_lines(filepath, num_lines=100):
    """Read the last N lines of a file safely."""
    try:
        result = subprocess.run(
            ["tail", f"-{num_lines}", filepath],
            capture_output=True, text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        log(f"Could not read {filepath}: {e}")
        return []


# ─────────────────────────────────────────
#  CHECK FUNCTIONS
# ─────────────────────────────────────────
def check_fail2ban():
    """Detect new IP bans in Fail2ban."""
    lines   = read_last_lines(FAIL2BAN_LOG, 50)
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).+Ban\s+(\S+)")

    for line in lines:
        match = pattern.search(line)
        if match:
            timestamp = match.group(1)
            ip        = match.group(2)
            key       = f"{timestamp}_{ip}"

            if key not in seen_fail2ban_bans:
                seen_fail2ban_bans.add(key)
                jail = "unknown"
                if "sshd" in line:
                    jail = "sshd"
                elif "apache" in line.lower():
                    jail = "apache"

                subject = f"Fail2ban Ban — {ip}"
                body    = (
                    f"A new IP has been banned by Fail2ban.\n\n"
                    f"IP Address : {ip}\n"
                    f"Jail       : {jail}\n"
                    f"Time       : {timestamp}\n\n"
                    f"The IP has been automatically blocked."
                )
                log(f"[FAIL2BAN] New ban — {ip} ({jail})")
                if FAIL2BAN_ALERT:
                    send_email(subject, body)


def check_modsecurity():
    """Detect new ModSecurity blocks."""
    lines     = read_last_lines(MODSEC_AUDIT_LOG, 100)
    full_text = "\n".join(lines)

    ip_pattern   = re.compile(r"\[client (\S+)\]")
    rule_pattern = re.compile(r'\[id "(\d+)"\]')
    msg_pattern  = re.compile(r'\[msg "([^"]+)"\]')

    blocks = re.findall(
        r"ModSecurity: Access denied.+?(?=ModSecurity:|$)",
        full_text, re.DOTALL
    )

    for block in blocks:
        ip_match   = ip_pattern.search(block)
        rule_match = rule_pattern.search(block)
        msg_match  = msg_pattern.search(block)

        ip      = ip_match.group(1)   if ip_match   else "unknown"
        rule_id = rule_match.group(1) if rule_match else "unknown"
        reason  = msg_match.group(1)  if msg_match  else "unknown"

        key = f"{ip}_{rule_id}_{reason[:30]}"
        if key not in seen_modsec_blocks:
            seen_modsec_blocks.add(key)

            subject = f"ModSecurity Block — {ip}"
            body    = (
                f"ModSecurity blocked a suspicious request.\n\n"
                f"IP Address : {ip}\n"
                f"Rule ID    : {rule_id}\n"
                f"Reason     : {reason[:120]}\n\n"
                f"The request was denied before reaching your site."
            )
            log(f"[MODSEC] Block — {ip} rule {rule_id}: {reason[:60]}")
            if MODSEC_ALERT:
                send_email(subject, body)


def check_ssh_attempts():
    """Detect SSH failed login attempts."""
    lines   = read_last_lines(AUTH_LOG, 100)
    pattern = re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+).+Failed password for (\S+) from (\S+)"
    )

    for line in lines:
        match = pattern.search(line)
        if match:
            timestamp = match.group(1)
            user      = match.group(2)
            ip        = match.group(3)
            key       = f"{timestamp}_{ip}_{user}"

            if key not in seen_ssh_attempts:
                seen_ssh_attempts.add(key)

                subject = f"SSH Failed Login — {ip}"
                body    = (
                    f"A failed SSH login attempt was detected.\n\n"
                    f"IP Address : {ip}\n"
                    f"Username   : {user}\n"
                    f"Time       : {timestamp}\n\n"
                    f"If this continues, Fail2ban will automatically ban this IP."
                )
                log(f"[SSH] Failed login — {user}@{ip}")
                if SSH_ALERT:
                    send_email(subject, body)


def check_404_spike():
    """Detect a spike in 404 errors — possible scanner or attack."""
    global notfound_timestamps
    lines   = read_last_lines(APACHE_ACCESS_LOG, 200)
    pattern = re.compile(r'(\S+).+\[(.+?)\].+"[^"]+"\s+404')
    now     = datetime.now()
    window  = now - timedelta(minutes=SPIKE_WINDOW_MINS)

    for line in lines:
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            try:
                ts_str = match.group(2).split()[0]
                ts     = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                if ts > window:
                    notfound_timestamps.append((ts, ip))
            except Exception:
                pass

    notfound_timestamps = [(ts, ip) for ts, ip in notfound_timestamps if ts > window]

    count = len(notfound_timestamps)
    if count >= SPIKE_404_LIMIT:
        ip_counts = defaultdict(int)
        for _, ip in notfound_timestamps:
            ip_counts[ip] += 1
        top_ip    = max(ip_counts, key=ip_counts.get)
        top_count = ip_counts[top_ip]

        subject = f"404 Spike Detected — {count} requests"
        body    = (
            f"An unusual spike in 404 errors was detected.\n\n"
            f"Total 404s   : {count} in {SPIKE_WINDOW_MINS} minutes\n"
            f"Top offender : {top_ip} ({top_count} hits)\n\n"
            f"This may indicate a scanner or brute-force attempt.\n"
            f"Check: /var/log/apache2/access.log"
        )
        log(f"[404 SPIKE] {count} 404s in {SPIKE_WINDOW_MINS} mins — top IP: {top_ip}")
        send_email(subject, body)
        notfound_timestamps.clear()


def run_summary():
    """Log a periodic summary."""
    log("=" * 50)
    log("SECURITY MONITOR — STATUS SUMMARY")
    log(f"Fail2ban bans tracked : {len(seen_fail2ban_bans)}")
    log(f"ModSec blocks tracked : {len(seen_modsec_blocks)}")
    log(f"SSH attempts tracked  : {len(seen_ssh_attempts)}")
    log(f"Recent 404s in window : {len(notfound_timestamps)}")
    log("=" * 50)


# ─────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────
def main():
    log("Security monitor started.")
    send_email(
        "Security Monitor Started",
        "The security monitor is now running on bendigosweb.duckdns.org.\n\n"
        "You will receive alerts for:\n"
        "- Fail2ban IP bans\n"
        "- ModSecurity WAF blocks\n"
        "- SSH failed login attempts\n"
        f"- 404 spikes ({SPIKE_404_LIMIT}+ in {SPIKE_WINDOW_MINS} minutes)"
    )

    cycle = 0
    while True:
        try:
            check_fail2ban()
            check_modsecurity()
            check_ssh_attempts()
            check_404_spike()

            cycle += 1
            if cycle % 10 == 0:
                run_summary()

        except Exception as e:
            log(f"Error during check cycle: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
