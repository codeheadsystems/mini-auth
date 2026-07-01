# Before you start / Troubleshooting

> **How-to (task-oriented).** A five-minute preflight and a rescue list for the labs. The tutorials
> are "guaranteed to succeed" — but only once your machine can build the repo and the standard ports
> are free. If a lab dies at step 1, the fix is almost always on this page. Read it once, then get
> back to [`TEACHING.md`](TEACHING.md).

## Preflight (do this once)

**1. JDK 21+ is on your `PATH`.** The Gradle toolchain is pinned to 21.

```bash
java -version      # want: "21" (or higher). 17 or 11 will NOT build.
```

If `java` is missing or older, install a JDK 21 (Temurin, Zulu, Corretto, or your distro's
`openjdk-21`). You don't strictly need to set `JAVA_HOME` — Gradle's foojay toolchain can
auto-download a 21 for the build — but the wrapper itself still needs *some* JVM to launch.

**2. The first build needs network.** `./gradlew build` downloads Gradle, the plugins, and every
dependency from Maven Central (and, for mini-oidc, `pk-auth-core`) on the first run. Do the first
build **online**; after that the Gradle cache lets you work offline (add `--offline` to force it).

```bash
./gradlew build    # first run: online, a few minutes. This IS the CI gate — it must be green.
```

**3. Run every Gradle command from the repo root.** There is one root wrapper (`./gradlew`); there
are no per-module wrappers.

## The standard lab ports

Each service binds a fixed loopback port. If any is already in use, that service won't start.

| Service | Port | Started by |
| --- | --- | --- |
| mini-idp | `8455` | `--port 8455` |
| mini-directory | `8466` | `--port 8466` |
| mini-oidc | `8477` | `--port 8477` |
| mini-gateway | `8488` | `--port 8488` |
| mini-ca | `8499` | `--port 8499` |
| mini-console | `8500` | `--port 8500` |
| mini-kms | `9123` | `--tcp-port 9123` |

## Rescue list

### "Address already in use" / a service won't start

Something is already on that port — usually a service you started in an earlier lab and never
stopped. Find it and stop it:

```bash
lsof -iTCP:8455 -sTCP:LISTEN        # what's holding the port? (swap in the port from the table)
# or, without lsof:
ss -ltnp 'sport = :8455'

kill <pid>                          # stop just that one
```

If you don't want to hunt per-port, see "stray background servers" below.

### Stray background servers from an earlier lab

The labs launch servers in the background (`… &`). When you close a terminal, they can keep running.
To find and stop every mini-service you started this way:

```bash
# List them (they all launch from the installed 'bin/…' launchers under build/install):
pgrep -af 'build/install/.*/bin/'

# Stop them all at once:
pkill -f 'build/install/.*/bin/'
```

The bundled [`docs/examples/run-family.sh`](examples/run-family.sh) avoids this entirely: it tracks
every PID and tears the whole family down on `Ctrl-C` (it traps `INT`/`TERM`/`EXIT`). Prefer it when
you want the whole stack up.

### Wrong JDK picked up mid-lab

A `class file has wrong version` or a toolchain error means Gradle found a JDK older than 21. Confirm
`java -version` is 21+, or point Gradle at a specific JDK:

```bash
./gradlew build -Dorg.gradle.java.home=/path/to/jdk-21
```

### Offline build fails on the first run

You cannot build fully offline the very first time — the Gradle distribution and dependencies aren't
cached yet. Do one online `./gradlew build`, then `--offline` works.

### A build-script change won't take effect

Gradle's configuration cache is on. When iterating on `build-logic` or a `*.gradle.kts`, add
`--no-configuration-cache` until it's stable.

### Reset a lab's on-disk state

The services write to a `--data-dir` (or `--keystore` for mini-kms). If a lab left a store in a
confusing state, stop the service and delete that directory to start clean — e.g. `rm -rf
~/.mini-idp` (use whatever path the lab passed). These are local demo stores; there's nothing to
preserve.

---

**Still stuck?** The deeper reflexes behind secrets and ports are in
[`concepts/secure-design-invariants.md`](concepts/secure-design-invariants.md) and
[`howto/configuration-and-secrets.md`](howto/configuration-and-secrets.md); the full stack in one
command is [`howto/run-the-whole-family.md`](howto/run-the-whole-family.md).
