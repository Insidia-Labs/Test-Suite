#!/usr/bin/env bash
# DVWA setup: create the database, log in with DVWA's documented default account,
# and set the security level. Writes the session to auth.json for the tool.
# Usage: setup.sh <base_url> <level> <input_dir>
set -euo pipefail
base="${1%/}"
level="$2"
out="$3"
jar="$out/cookies.txt"

token() { grep -o "name=.user_token. value=.[0-9a-f]*" | head -1 | sed -E "s/.*value=.//"; }
get() { curl -fsS -c "$jar" -b "$jar" "$base/$1"; }
post() { curl -fsS -o /dev/null -c "$jar" -b "$jar" --data "$2" "$base/$1"; }

for _ in $(seq 1 90); do get setup.php >/dev/null 2>&1 && break; sleep 2; done
for _ in $(seq 1 30); do
  t=$(get setup.php | token)
  post setup.php "create_db=Create+%2F+Reset+Database&user_token=$t" && break
  sleep 3
done
t=$(get login.php | token)
post login.php "username=admin&password=password&Login=Login&user_token=$t"
t=$(get security.php | token)
post security.php "security=$level&seclev_submit=Submit&user_token=$t"

page=$(get security.php)
echo "$page" | grep -qi "security level is currently: <em>$level</em>" \
  || { echo "security level $level was not set" >&2; exit 1; }

session=$(awk '$6=="PHPSESSID"{print $7}' "$jar" | tail -1)
[ -n "$session" ] || { echo "no session cookie" >&2; exit 1; }
cat > "$out/auth.json" <<JSON
{
  "cookies": {"PHPSESSID": "$session", "security": "$level"},
  "login": {"url": "$base/login.php", "username": "admin", "password": "password"},
  "exclude_paths": ["/logout.php", "/setup.php", "/security.php", "/login.php"]
}
JSON
echo "DVWA ready at level $level"
