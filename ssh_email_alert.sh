#!/bin/sh

SUBJECT="[$HOSTNAME] SSH notification: successful login from IP ${PAM_RHOST}"

BODY="$(cat <<EOF
<!DOCTYPE html>
<html>
<head>
</head>
<style>
body {
  color: #222;
  font: 13px/18px arial, sans-serif;
}
div {
    display: inline-block;
}

h1,h2,h3,h4,h5,h6 {
  color: #000;
  font: 16px/24px arial, sans-serif normal;
}

a {
  color: #15c;
  cursor: pointer;
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

.whois {
    font-family: monospace;
    line-height: 1.3em;
    word-spacing: .01em;
    word-wrap: break-word;
    padding: 15px;
    background-color: #f5f5f5;
    border: 1px solid #e3e3e3;
    border-radius: 0;
    box-shadow: inset 0 1px 1px rgba(0, 0, 0, 0.05);
}

.key {
  color: #76808f;
  text-align: right;
}
</style>

<body>
    <h1>SSH Login successful</h1>
<p>
The following user signed to your server via SSH, please review the information below:
<table>
  <tr><td class="key">User:</td><td>${PAM_USER}</td></tr>
  <tr><td class="key">IP Address:</td><td>${PAM_RHOST}</td></tr>
  <tr><td class="key">Service:</td><td>${PAM_SERVICE}</td></tr>
  <tr><td class="key">Time:</td><td>$(date +'%Y-%m-%d %T(%Z)')</td></tr>
</table>
</p>
<p>
<h3>Whois information</h3>
<div class="whois">
$(whois ${PAM_RHOST} | awk '{print $0"</br>"}')
</div>
</p>
<p>
If you don't recognize this activity, your server might be compromised.
</p>
</body>
</html>
EOF
)"

if [ "${PAM_TYPE}" = "open_session" ]; then
  echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail -t ${EMAIL_RECIPIENTS}
fi

exit 0
