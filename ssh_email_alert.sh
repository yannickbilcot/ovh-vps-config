#!/bin/sh

SUBJECT="[$(hostname)] SSH notification: successful login from IP ${PAM_RHOST}"

BODY="$(cat <<EOF
<html>
<head>
<style>
body {
  font: small/ 1.5 Arial,Helvetica,sans-serif;
  padding: 15px;
}
h1,h2,h3,h4,h5,h6 {
  font: small/ 1.5 Arial,Helvetica,sans-serif normal;
}
a {
  color: #15c;
  cursor: pointer;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
table {
  font-size: small;
}
.whois {
  display: inline-block;
  font-family: monospace;
  line-height: 1.3em;
  word-spacing: .01em;
  word-wrap: break-word;
  padding: 15px;
  background-color: #f5f5f5;
  border: 1px solid #e3e3e3;
  box-shadow: inset 0 1px 1px rgba(0, 0, 0, 0.05);
}
.key {
  color: #76808f;
  text-align: right;
  padding-right: 5px;
}
</style>
</head>
<body>
  <h1>SSH Login successful</h1>
  <p>The following user signed to your server via SSH, please review the information below:</p>
  <div>
    <table>
      <tr><td class="key">User:</td><td>${PAM_USER}</td></tr>
      <tr><td class="key">IP Address:</td><td>${PAM_RHOST}</td></tr>
      <tr><td class="key">Service:</td><td>${PAM_SERVICE}</td></tr>
      <tr><td class="key">Time:</td><td>$(date +'%Y-%m-%d %T (%Z)')</td></tr>
    </table>
  </div>
  <div>
    <h3>Whois information</h3>
    <div class="whois">
$(whois "${PAM_RHOST}" | awk '{print $0"<br>"}')
    </div>
    <p>If you don't recognize this activity, your server might be compromised.</p>
  </div>
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
) | /usr/sbin/sendmail -t "${EMAIL_RECIPIENTS}"
fi

exit 0
