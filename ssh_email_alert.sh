#!/bin/sh

SUBJECT="[$(hostname)] SSH notification: successful login from IP ${PAM_RHOST}"

BODY="$(cat <<EOF
<html>
<body style="font: small/ 1.5 Arial,Helvetica,sans-serif;padding: 15px;">
  <h1 style="font: small/ 1.5 Arial,Helvetica,sans-serif;">SSH Login successful</h1>
  <p>The following user signed to your server via SSH, please review the information below:</p>
  <p>
    <table style="font-size: 13px;">
      <tr><td class="key" style="color: #76808f;text-align: right;padding-right: 5px;">User:</td><td>${PAM_USER}</td></tr>
      <tr><td class="key" style="color: #76808f;text-align: right;padding-right: 5px;">IP Address:</td><td>${PAM_RHOST}</td></tr>
      <tr><td class="key" style="color: #76808f;text-align: right;padding-right: 5px;">Service:</td><td>${PAM_SERVICE}</td></tr>
      <tr><td class="key" style="color: #76808f;text-align: right;padding-right: 5px;">Time:</td><td>$(date +'%Y-%m-%d %T (%Z)')</td></tr>
    </table>
  </p>
  <p>
    <h3 style="font: small/ 1.5 Arial,Helvetica,sans-serif;">Whois information</h3>
    <div class="whois" style="display: inline-block;font-family: monospace;line-height: 1.3em;word-spacing: .01em;word-wrap: break-word;padding: 15px;background-color: #f5f5f5;border: 1px solid #e3e3e3;box-shadow: inset 0 1px 1px rgba(0, 0, 0, 0.05);">
$(whois ${PAM_RHOST} | awk '{print $0"<br>"}')
    </div>
  </p>
  <p>If you don't recognize this activity, your server might be compromised.</p>
</body>
</html>
EOF
)"

if [ "${PAM_TYPE}" = "open_session" ]; then
  ( cat <<EOF
Subject:${SUBJECT}
Content-Type: text/html
${BODY}
EOF
) | /usr/sbin/sendmail -t ${EMAIL_RECIPIENTS}
fi

exit 0
