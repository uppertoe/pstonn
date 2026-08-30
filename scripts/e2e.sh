#!/bin/bash
# End-to-end local verification of pstonn.
#
# Two runs, because the config guards (correctly) refuse to let a production-shaped
# deployment also fake the council:
#   RUN A  dev-shaped   — the full user journey against the sandbox council.
#   RUN B  prod-shaped  — real at-rest key, roster key, status token, proxy identity.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
S="${PSTONN_E2E_TMP:-$(mktemp -d)}"
go build -o "$S/pstonn" . || exit 1

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 — got '$2', want '$3'"; fi; }
# has/hasnt: case-insensitive, and byte-oriented via LC_ALL=C. Without that, BSD grep
# in a UTF-8 locale silently fails to match when the haystack contains a byte sequence
# that is not valid UTF-8 — which an HTML page carrying embedded binary (a QR data URI)
# does. That failure mode is invisible: the text is plainly there and grep just says no,
# so a real assertion reads as a broken feature.
# NOT grep -q: it exits on the first match, closing the pipe, so printf dies with
# SIGPIPE and `set -o pipefail` turns that into a pipeline failure — reporting "not
# found" for text that is plainly there. It only bites when the match comes early in a
# large body, which is exactly the real pages and never the small fixtures you test the
# helper with. Redirecting instead makes grep consume all of its input.
has()  { if printf '%s' "$2" | LC_ALL=C grep -i -- "$3" >/dev/null; then ok "$1"; else bad "$1 — '$3' not found"; fi; }
hasnt(){ if printf '%s' "$2" | LC_ALL=C grep -i -- "$3" >/dev/null; then bad "$1 — '$3' WAS present"; else ok "$1"; fi; }
sec() { printf '\n\033[1m%s\033[0m\n' "$1"; }
# q: run a query and fail loudly if the table/row is missing, so a check can never
# pass merely because the data it inspects does not exist.
q() { python3 - "$1" "$2" <<'PY'
import sqlite3,sys
try:
    rows=list(sqlite3.connect(sys.argv[1]).execute(sys.argv[2]))
except Exception as e:
    print("QUERYERROR:", e); sys.exit(0)
print("EMPTYRESULT" if not rows else rows)
PY
}

KEY=$(openssl rand -hex 32); RKEY=$(openssl rand -hex 32)
SEC=$(openssl rand -hex 32); TOK=$(openssl rand -hex 24)
rm -f "$S"/e2e*.db* "$S"/e2e*.log "$S"/g?.db*

############################  STARTUP GUARDS  ############################
sec "1. Startup guards — the config mistakes that would be catastrophic"
guard(){ env -i PATH="$PATH" HOME="$HOME" "$@" "$S/pstonn" 2>&1 | tail -1; }
has "refuses DEV_IDENTITY_EMAIL beside a production key (A4)" \
    "$(guard DEV_IDENTITY_EMAIL=me@x.com DATA_ENCRYPTION_KEY=$KEY DOMAIN=x.com SQLITE_PATH=$S/g1.db)" "dev_identity"
has "refuses COUNCIL_SANDBOX beside a production key (A4)" \
    "$(guard COUNCIL_SANDBOX=1 DATA_ENCRYPTION_KEY=$KEY DOMAIN=x.com SQLITE_PATH=$S/g2.db)" "council_sandbox"
has "refuses STATUS_TOKEN without ROSTER_KEY (A3)" \
    "$(guard DATA_ENCRYPTION_KEY=$KEY STATUS_TOKEN=$TOK DOMAIN=x.com SQLITE_PATH=$S/g3.db)" "roster"
has "refuses a missing PUBLIC_BASE_URL in production (A5)" \
    "$(guard DATA_ENCRYPTION_KEY=$KEY SQLITE_PATH=$S/g4.db)" "public_base_url\|domain"
has "refuses a missing DATA_ENCRYPTION_KEY" \
    "$(guard DOMAIN=x.com SQLITE_PATH=$S/g5.db)" "data_encryption_key"
has "refuses a short DATA_ENCRYPTION_KEY" \
    "$(guard DATA_ENCRYPTION_KEY=abcd DOMAIN=x.com SQLITE_PATH=$S/g6.db)" "data_encryption_key"
rm -f "$S"/g?.db*

############################  RUN A — dev-shaped  ############################
BA=http://127.0.0.1:8251
H='Content-Type: application/x-www-form-urlencoded'; OA="Origin: $BA"
DEV_IDENTITY_EMAIL=owner@example.com COUNCIL_SANDBOX=1 LISTEN_ADDR=127.0.0.1:8251 \
  DISPLAY_TIMEZONE=Australia/Melbourne PUBLIC_BASE_URL=$BA SQLITE_PATH="$S/e2ea.db" \
  "$S/pstonn" > "$S/e2ea.log" 2>&1 &
APPA=$!
for i in $(seq 1 60); do sleep 0.25; curl -sf $BA/healthz >/dev/null 2>&1 && break; done

sec "2. RUN A — the full household journey (sandbox council)"
eq "app is up" "$(curl -s -o /dev/null -w '%{http_code}' $BA/healthz)" "200"
p(){ curl -s -X POST -H "$H" -H "$OA" "$@"; }
loc(){ curl -s -o /dev/null -D - -X POST -H "$H" -H "$OA" "$@" | grep -i '^location:' | tr -d '\r' | sed 's/[Ll]ocation: //I'; }

N=$(curl -s $BA/schedule | grep -c 'name="agree')
p -o /dev/null -d "$(seq 0 $((N-1)) | awk '{printf "agree%s=1&", $1}')" $BA/terms/accept
has "terms accepted (consent gate passed)" "$(curl -s $BA/schedule)" "council"
p -o /dev/null -d 'council_password=sandbox&save_password=1' $BA/council/link
PC=$(curl -s $BA/permits/new | grep -oE 'value="9[0-9]+"' | head -1 | sed 's/value="//;s/"//')
p -o /dev/null -d "council_permit_id=$PC&permit_type_id=14" $BA/permits
p -o /dev/null -d 'label=Flat 3, 12 Smith St' $BA/permits/1/name
p -o /dev/null -d 'registration=ABC123&label=Blue+hatch' $BA/vehicles
p -o /dev/null -d 'registration=XYZ789&label=Grey+wagon' $BA/vehicles
for wd in 1 3 5; do p -o /dev/null -d "weekday=$wd&vehicle_id=1" $BA/permits/1/rules; done
has "permit claimed, named and rostered" "$(curl -s $BA/schedule)" "ABC123"

# The scheduler must drive the (fake) council THROUGH to success. Two deliberate
# behaviours have to be accommodated rather than worked around: the sandbox fails the
# first write and lands the change a few seconds later, and a failed apply then backs
# off exponentially, so natural convergence would take minutes. Sleep past the
# sandbox's delay, then make a schedule change — which kicks the permit and forces an
# immediate reconcile, exactly as a user edit would.
sleep 6
for i in $(seq 1 40); do
  p -o /dev/null -d "weekday=1&vehicle_id=1" $BA/permits/1/rules
  sleep 0.5
  r=$(q "$S/e2ea.db" "SELECT active_registration FROM permit WHERE id=1")
  printf '%s' "$r" | grep -q ABC123 && break
done
has "the scheduler drove the council through to success" "$r" "ABC123"
has "…and the apply is recorded as success, not just attempted" \
    "$(q "$S/e2ea.db" "SELECT status FROM apply_log WHERE registration='ABC123' ORDER BY id DESC LIMIT 1")" "success"

sec "3. RUN A — guest passes"
gcreate=$(p -L -d 'permit_id=1&label=Neighbour&vehicle_id=1&recipients=guest@example.com' $BA/guests)
GT=$(printf '%s' "$gcreate" | grep -oE '/g/[A-Za-z0-9_-]{20,}' | head -1 | sed 's|/g/||')
has "the grant exists" "$(q "$S/e2ea.db" "SELECT label FROM guest_grant WHERE request_only=0")" "Neighbour"
if [ -n "$GT" ]; then
  eq "the guest page is public" "$(curl -s -o /dev/null -w '%{http_code}' $BA/g/$GT)" "200"
  gp=$(curl -s $BA/g/$GT)
  has "an emailed pass names the household (the recipient is known)" "$gp" "owner@example.com"
  p -o /dev/null -d 'vehicle_id=1' $BA/g/$GT
  ok "guest activation accepted"
else bad "could not mint an emailed guest pass"; fi

p -o /dev/null -d 'permit_id=1' $BA/guests/printed
has "a printed door QR was minted" "$(curl -s $BA/guests)" "door"
DGID=$(curl -s $BA/guests | grep -oE '/guests/door/[0-9]+/view' | head -1 | grep -oE '[0-9]+')
has "the door QR poster renders" "$(curl -s $BA/guests/door/$DGID/view)" "data:image/png"
hasnt "the poster never prints the token as text" "$(curl -s $BA/guests/door/$DGID/view)" "/g/[A-Za-z0-9_-]\{20,\}"

sec "4. RUN A — invites grant nothing until accepted (D1)"
loc -d 'email=partner@example.com' $BA/account/members >/dev/null
inv=$(q "$S/e2ea.db" "SELECT member_email, invite_pending FROM account_member")
has "the invite row is PENDING" "$inv" "partner@example.com', 1"
l1=$(loc -d 'email=partner@example.com' $BA/account/members)
l2=$(loc -d 'email=stranger@example.com' $BA/account/members)
if [ "${l1%%=*}" = "${l2%%=*}" ]; then ok "known and unknown addresses get the same answer (D2)"; else bad "addMember still distinguishes: '$l1' vs '$l2'"; fi

sec "5. RUN A — deleting a rostered car names the days (follow-up)"
# Follow the real redirect the delete issues, rather than a synthesised URL: the
# flash only renders inside the signed-in app shell, so a hand-built URL tests the
# harness's idea of the app state instead of the app's.
# --data (not -X POST) so curl follows the 303 as a GET. -X pins the method across
# redirects, which silently re-POSTs to /vehicles — the add-vehicle route — and
# returns a validation error page instead of the page under test.
dlpage=$(curl -s -L --data '' -H "$H" -H "$OA" $BA/vehicles/1/delete)
dl=$(loc $BA/vehicles/2/delete)
has "the redirect carries counts, not free text" "$dl" "days=\|bookings="
has "the flash names the emptied roster days" "$dlpage" "3 roster days"
has "Activity names which days" "$(curl -s $BA/activity)" "Monday, Wednesday and Friday"
hasnt "a crafted flash param is refused (H3)" "$(curl -s "$BA/vehicles?deleted=Call+0399+to+restore")" "Call 0399"

kill -TERM $APPA 2>/dev/null; wait $APPA 2>/dev/null
has "RUN A shut down cleanly" "$(cat "$S/e2ea.log")" "shutting down"
hasnt "RUN A: no 'did not stop in time'" "$(cat "$S/e2ea.log")" "did not stop in time"
hasnt "RUN A: no panics" "$(cat "$S/e2ea.log")" "panic"

############################  RUN B — production-shaped  ############################
BB=http://127.0.0.1:8252
OB="Origin: $BB"; ID='Remote-Email: owner@example.com'; IDG='Remote-Groups: user,admin'
DATA_ENCRYPTION_KEY=$KEY ROSTER_KEY=$RKEY STATUS_TOKEN=$TOK SESSION_SECRET=$SEC \
  PUBLIC_BASE_URL=$BB LISTEN_ADDR=127.0.0.1:8252 DISPLAY_TIMEZONE=Australia/Melbourne \
  SQLITE_PATH="$S/e2eb.db" "$S/pstonn" > "$S/e2eb.log" 2>&1 &
APPB=$!
for i in $(seq 1 60); do sleep 0.25; curl -sf $BB/healthz >/dev/null 2>&1 && break; done

sec "6. RUN B — boots production-shaped (real council, no dev hatches)"
eq "app is up" "$(curl -s -o /dev/null -w '%{http_code}' $BB/healthz)" "200"
hasnt "no at-rest-key warning" "$(cat "$S/e2eb.log")" "DATA_ENCRYPTION_KEY is unset"
hasnt "no sandbox warning"     "$(cat "$S/e2eb.log")" "COUNCIL_SANDBOX is on"

a(){ curl -s -H "$ID" -H "$IDG" "$@"; }
sec "7. RUN B — identity and authorization"
eq "anonymous cannot reach the app"     "$(curl -s -o /dev/null -w '%{http_code}' $BB/vehicles)" "401"
eq "the proxy's identity is accepted"   "$(curl -s -o /dev/null -w '%{http_code}' -H "$ID" -H "$IDG" $BB/schedule)" "200"
eq "the public landing needs no identity" "$(curl -s -o /dev/null -w '%{http_code}' $BB/)" "200"
eq "a non-admin cannot reach /admin"    "$(curl -s -o /dev/null -w '%{http_code}' -H "$ID" -H 'Remote-Groups: user' $BB/admin)" "403"
eq "an admin can"                       "$(curl -s -o /dev/null -w '%{http_code}' -H "$ID" -H "$IDG" $BB/admin)" "200"
eq "a cross-site POST is refused"       "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$ID" -H "$H" -H 'Origin: https://evil.example' -d 'x=1' $BB/vehicles)" "403"
eq "a POST with no Origin is refused"   "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$ID" -H "$H" -d 'x=1' $BB/vehicles)" "403"

sec "8. RUN B — response headers and CSP"
hdr=$(a -D - -o /dev/null $BB/schedule)
has  "authenticated pages are no-store (H1)"    "$hdr" "cache-control:.*no-store"
has  "Permissions-Policy is set (H6)"           "$hdr" "permissions-policy"
has  "object-src 'none' (H6)"                   "$hdr" "object-src 'none'"
hasnt "no HSTS on a plaintext request (H6)"     "$hdr" "strict-transport-security"
csp=$(printf '%s' "$hdr" | grep -i content-security-policy)
has  "script-src carries a nonce (H7)"          "$csp" "script-src[^;]*nonce-"
hasnt "script-src has no 'unsafe-inline' (H7)"  "$(printf '%s' "$csp" | sed 's/;.*style-src.*//')" "unsafe-inline"
n1=$(a -D - -o /dev/null $BB/schedule | grep -io 'nonce-[A-Za-z0-9_-]*' | head -1)
n2=$(a -D - -o /dev/null $BB/schedule | grep -io 'nonce-[A-Za-z0-9_-]*' | head -1)
if [ -n "$n1" ] && [ "$n1" != "$n2" ]; then ok "the CSP nonce is fresh per response (H7)"; else bad "nonce not fresh ('$n1' / '$n2')"; fi
bd=$(a $BB/); st=$(printf '%s' "$bd" | grep -c '<script'); nn=$(printf '%s' "$bd" | grep -c 'nonce=')
eq "every script tag carries a nonce (H7)" "$st" "$nn"
hasnt "public pages are NOT no-store" "$(curl -s -D - -o /dev/null $BB/security)" "cache-control:.*no-store"

sec "9. RUN B — /status, which holds the roster"
eq "no token is refused"            "$(curl -s -o /dev/null -w '%{http_code}' $BB/status)" "401"
eq "a wrong token is refused"       "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong" $BB/status)" "401"
eq "a bare token (no Bearer) is refused (A9)" "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: $TOK" $BB/status)" "401"
eq "the right token is accepted"    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" $BB/status)" "200"
s1=$(curl -s -H "Authorization: Bearer $TOK" $BB/status)
hasnt "the routine poll carries no roster (A3)" "$s1" "roster_sealed"
s2=$(curl -s -H "Authorization: Bearer $TOK" "$BB/status?roster=1")
has  "the roster is sealed when requested (A3)"  "$s2" "roster_sealed"
hasnt "…and never appears in the clear"          "$s2" "owner@example.com"

sec "10. RUN B — public signed endpoints"
eq "a forged unsubscribe token is refused (G8)" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$OB" $BB/u/b3duZXJAZXhhbXBsZS5jb20/forged)" "200"
sup=$(q "$S/e2eb.db" "SELECT COUNT(*) FROM mail_suppression")
has "…and suppressed nobody" "$sup" "(0,)"
eq "the SES hook 404s when unconfigured" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -d '{}' $BB/hooks/ses)" "404"

sec "11. RUN B — shutdown"
kill -TERM $APPB 2>/dev/null; wait $APPB 2>/dev/null
has "RUN B shut down cleanly" "$(cat "$S/e2eb.log")" "shutting down"
hasnt "RUN B: no 'did not stop in time'" "$(cat "$S/e2eb.log")" "did not stop in time"
hasnt "RUN B: no panics" "$(cat "$S/e2eb.log")" "panic"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
