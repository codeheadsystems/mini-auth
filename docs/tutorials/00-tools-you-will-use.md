# Stage 0.5 — the tools you'll use

> **Optional pre-reading.** Every lab from here on assumes you're comfortable with `curl`,
> environment variables, running something in the background, and pulling a field out of a JSON
> response. If all of that is already muscle memory, skip straight to
> [`01-resolve-a-principal.md`](01-resolve-a-principal.md). If any of it isn't, five minutes here
> will save you from fighting the terminal instead of learning the auth concepts the labs are
> actually about.

## `curl` — talking to a service by hand

The labs never wrap requests in a script; you type the `curl` command yourself so the shape of the
HTTP call stays visible. The pattern you'll reuse constantly:

```bash
curl -s -XPOST http://127.0.0.1:8466/admin/roles \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id": "reader", "grants": [{"action": "read", "resource": "doc:*"}]}'
```

- `-s` — silent (suppress the progress meter; you still get the response body).
- `-XPOST` — the HTTP method (`-XPOST`, `-XGET` — the default is `GET` if you omit it).
- `-H` — one header per flag; every admin call in this repo needs an `Authorization: Bearer <token>`
  header.
- `-d` — the request body. Single-quote it so your shell doesn't try to expand the `$` or `"`
  inside the JSON.

Add `-i` to see the response status line and headers (useful when a lab asks you to check a status
code, e.g. `302` or `401`), or `-v` when something's failing and you want to see the whole exchange.

## Exporting environment variables

Every admin token in this repo is read from an environment variable — **never** a CLI flag, and
never logged. You'll export one per service you start:

```bash
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

That variable is now set for the rest of *this shell session* — every `curl` and every `server`
process you launch from this same terminal can see it. If you open a new terminal tab, it's gone;
export it again there, or put your exports in a small `.envrc`-style file you `source` at the start
of a session. Check what's set with `echo "$MINIDIR_ADMIN_TOKEN"` (careful — that prints the
secret to your scrollback).

## Running things in the background, and stopping them

Each lab starts one or more long-running servers. You need them running *while* you run `curl`
commands in the same terminal, which means backgrounding them:

```bash
services/mini-directory/build/install/mini-directory/bin/mini-directory \
  --port 8466 --data-dir ~/.mini-directory &   # the trailing & backgrounds it
```

The shell prints a job number and a process id (PID) — `[1] 12345`. Useful commands:

- `jobs` — list what's running in the background in *this* shell.
- `fg %1` — bring job 1 to the foreground (so `Ctrl-C` can stop it).
- `kill 12345` — stop it directly by PID (`kill %1` works too, using the job number).
- `lsof -i :8466` (or `ss -ltnp | grep 8466`) — find out *what* is holding a port, when a lab's
  server won't start because the port's already in use (see [`SETUP.md`](../SETUP.md)'s
  troubleshooting section for the full rescue steps).

If you'd rather not juggle background jobs, open one terminal tab per server instead and run each
one in the foreground — slower to switch between, but nothing to background or kill.

## Reading a token: `jq` or `python`

A JWT is three base64url segments joined by `.` — `header.payload.signature`. The labs ask you to
decode the payload and read the claims (`sub`, `exp`, `grants`, …) by hand. Two ways to do it,
depending on what you have installed:

```bash
# jq (if you have it) — pull the token out of a JSON response and decode the payload
TOKEN=$(curl -s ... | jq -r .access_token)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# python3 (ships on most systems) — no jq required
python3 -c "
import base64, json, sys
payload = sys.argv[1].split('.')[1]
payload += '=' * (-len(payload) % 4)   # restore the base64 padding curl/JWT libs strip
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
" "$TOKEN"
```

The `-r` flag to `jq` strips the surrounding quotes so you get the raw token string, not
`"eyJ..."`. The padding line in the Python version exists because base64url tokens omit the `=`
padding standard base64 expects — you'll hit this exact wrinkle again in lab 02 when you verify a
signature by hand.

---

Ready. Continue to [`01-resolve-a-principal.md`](01-resolve-a-principal.md) — stage 1.
