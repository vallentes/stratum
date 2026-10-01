# Stratum

Metadata analytics for file and object storage. Stratum walks Windows file servers, Dell PowerScale (OneFS) clusters, Linux servers and S3-compatible object stores, builds an index of names, sizes, dates and owners (never file contents), and turns it into answers: what is hot or cold, what is duplicated, who owns what, what is growing, what looks risky, and what would break a migration.

One Go binary. The server keeps its index in SQLite and serves a web UI. Collectors (the same binary) run next to storage the server cannot reach and connect out to it over HTTPS.

## Features

**Index**
- Parallel metadata walk of Windows drives and SMB shares, PowerScale (OneFS RAN API), Linux mount points and S3 / Dell ObjectScale buckets
- A scan only replaces a share's index when it finishes cleanly; failed or cancelled scans keep the last good index
- Crash-resume: an interrupted scan continues from the folders it already finished
- Live index updates from audit events between full scans
- One scan per physical disk at a time (partitions of one drive never fight), separate disks in parallel
- Per-share exclusions with presets (recycle bin and system files, code folders, macOS leftovers, container storage)
- Optional NTFS alternate data stream discovery

**See**
- Dashboard: hot/cold by age, top folders at any depth, growth with a 6-month projection, file types, top owners
- Insights: ranked recommendations with estimated monthly savings (cold data, duplicates, junk, PST files, orphaned owners, stale shares, capacity forecast)
- Risk: ransomware extensions and ransom notes, credentials and keys stored by name, database dumps, VM disks, mass-change bursts from audit
- Owners by account, Active Directory department and OU tree (LDAP)
- Path and scan issues: unreadable folders, links and stubs, Windows path length, illegal and reserved names, with triage
- Audit activity (OneFS protocol audit over syslog, Windows Security log), IOPS diagnostics, device inventory
- Excel and CSV export

**Find and act**
- Search by name, type, age, size, owner, path and tag; plain-English "Ask" box
- In-browser viewer for text, images, PDF, audio/video, Word, RTF and Excel; only indexed files can be opened and every view is logged
- Duplicate sets (name + size + date for files, ETag for objects)
- Auto Tag rules and Automations (copy, move, delete, rename, tag) with dry-run, typed confirmation for destructive runs and a per-item ledger

**Run it**
- Users with roles: viewer (read-only, no file contents), editor (sources, scans, automations, files), admin (users, settings, collectors, auditing)
- Collectors install from a pre-configured download, run as a Windows service and update themselves when the server is upgraded
- HTTPS directly by IP with a self-signed certificate that collectors pin, or behind any reverse proxy

## Quick start

```
go build -o stratum .
./stratum -addr :8470 -data ./data
```

Open http://localhost:8470 and sign in as `admin` / `admin`. You are asked to choose a new password straight away. Add more users under Settings.

To serve HTTPS by IP without a domain or proxy (self-signed, generated once and kept in the data folder):

```
./stratum -addr 127.0.0.1:8470 -tls-addr 203.0.113.10:8443 -data ./data
```

Useful flags: `-syslog :5514` (receive OneFS audit syslog, empty to disable), `-reset-password <pw> -user <name>` (recovery), `-list-shares`, `-delete-share <id>`.

## Collectors

Storage in another network gets a collector. In the UI: Sources, Collectors, New collector, Download Windows installer. Double-click it on a machine that can reach the storage and approve the administrator prompt: it installs the `StratumCollector` service with the server address and its token built in. Then use Add source and pick the collector.

Linux: `./stratum collector -server https://your-server -token stc_...` (run it under systemd).

The service account needs read access to the shares. Running as a Windows service (LocalSystem) also lets the collector read the Security log for audit events and turn file auditing on or off from the UI.

## PowerScale and S3 status

- **S3**: request signing is verified against the AWS Signature Version 4 examples published in the Amazon S3 API reference, and bucket listing, paging, owners and ETag duplicates are tested against a mock S3 endpoint. Not yet run against a live AWS account or ObjectScale cluster.
- **PowerScale**: share discovery across access zones, inventory, the RAN directory walk with resume paging and session authentication are tested against a mock built from the OneFS 9.x API reference. Not yet run against a real cluster; field names, RBAC privileges and the protocol audit syslog format should be checked on first use.

Reports from real systems are welcome as issues.

## Security notes

- Passwords are bcrypt-hashed; sign-in is throttled after repeated failures; sessions expire after 12 hours idle.
- Device credentials are encrypted at rest with a key in the data folder (`secret.key`). Back the data folder up and keep it private.
- Collectors authenticate with per-collector tokens (stored hashed) and can pin the server certificate.
- The file viewer refuses files that look like secrets (keys, `.env`, password stores) and serves active content (HTML, SVG) as plain text in a sandbox.
- Automations change data. Dry-run first; destructive real runs and schedules require typing the automation's name.

## Development

```
go vet ./...
go test ./...
```

Tests cover scanning, publish rules, crash-resume, collectors end to end, S3 signing and listing, PowerScale (mock), live updates, the viewer's path guard, users and roles, exports and exclusions. CI runs them on Windows and Linux; pushing a `v*` tag builds release binaries.

## License

[PolyForm Noncommercial 1.0.0](LICENSE). You may use, study, change and share Stratum for any noncommercial purpose: personal use, research, education, and use by charities, schools and public bodies.

**Commercial use needs a license from the author.** That includes selling Stratum or a product built on it, offering it as a paid or hosted service, and using it inside a business. Get in touch through [github.com/vallentes](https://github.com/vallentes).
