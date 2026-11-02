#!/bin/sh
# M7 curl functional suite against the deanOS REST server (hostfwd :8080->:80).
set -e
BASE="http://127.0.0.1:8080"
fail() { echo "FAIL: $1"; exit 1; }

# /health
H=$(curl -fsS "$BASE/health")
echo "$H" | grep -q '"status":"ok"' || fail "health body: $H"
echo "$H" | grep -q '"os":"deanOS"' || fail "health os: $H"

# Empty list
L=$(curl -fsS "$BASE/api/items")
[ "$L" = "[]" ] || fail "initial list: $L"

# POST -> 201 with id
C=$(curl -fsS -X POST -d '{"name":"widget","qty":3}' "$BASE/api/items")
echo "$C" | grep -q '"id":1' || fail "create: $C"
echo "$C" | grep -q '"name":"widget"' || fail "create body: $C"

C2=$(curl -fsS -X POST -d '{"name":"gadget","qty":7}' "$BASE/api/items")
echo "$C2" | grep -q '"id":2' || fail "create2: $C2"

# GET by id
G=$(curl -fsS "$BASE/api/items/1")
echo "$G" | grep -q '"name":"widget"' || fail "get1: $G"

# PUT
P=$(curl -fsS -X PUT -d '{"name":"widget","qty":99}' "$BASE/api/items/1")
echo "$P" | grep -q '"qty":99' || fail "put: $P"

# List has 2
L2=$(curl -fsS "$BASE/api/items")
echo "$L2" | grep -q '"id":1' || fail "list ids: $L2"
echo "$L2" | grep -q '"id":2' || fail "list ids2: $L2"

# DELETE -> 204, then 404
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/api/items/2")
[ "$code" = "204" ] || fail "delete code: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/items/2")
[ "$code" = "404" ] || fail "post-delete get code: $code"

# 404 / 400 / 405 handling
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nope")
[ "$code" = "404" ] || fail "404 code: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'not json' "$BASE/api/items")
[ "$code" = "400" ] || fail "bad json code: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/health")
[ "$code" = "405" ] || fail "405 code: $code"

# Keep-alive: 5 requests, total new connections across transfers must be 1.
KA=$(curl -fsS -w '%{num_connects}\n' \
  -o /dev/null -o /dev/null -o /dev/null -o /dev/null -o /dev/null \
  "$BASE/health" "$BASE/health" "$BASE/health" "$BASE/health" "$BASE/health" \
  | awk '{s+=$1} END {print s}')
[ "$KA" = "1" ] || fail "keep-alive total connects: $KA"

echo "M7 CURL SUITE OK"
