# SIEM forwarding runbook

How the audit journal reaches a SIEM (plan §3.3, §3.9 "Audit forwarding",
WP C.3), what to configure per receiver, and what the failure modes look
like. The configuration keys themselves are in
[`configuration.md`](configuration.md) (the `MCP_AUDIT_FORWARD_*` rows).

## What forwarding is, and is not

The durable journal in `MCP_AUDIT_JOURNAL_DIR` is the evidence. Forwarding
is a **copy** of it, made after the fact by the `control` role (or `all`):
a background shipper reads the journal file from the last sequence the
receiver acknowledged, sends batches through one adapter, and moves its
cursor only once the receiver has taken the batch. Consequences worth
knowing before you rely on it:

- **Nothing on the request path waits on the receiver.** A tool call is
  acknowledged by the journal's own writer, exactly as before; the
  shipper reads the file the writer already synced. A SIEM outage degrades
  the health banner (`audit forwarding is failing; journal retained`) and
  nothing else.
- **At least once.** The cursor is written after acknowledgement, so a
  crash between the two re-sends the last batch. The record's `seq` is the
  deduplication key; every record carries it, and a gap in what the
  receiver holds is a finding (`mcp-devtools audit verify` on the journal
  says whether the gap is in the journal or in the copy).
- **The receiver holds the journal's lines**, byte for byte, not a
  rendering: what `audit verify` hashes is what the SIEM stores. Indexing
  on `seq`, `kind`, `timestamp`, `principal.subject`, and
  `decision.effect` covers the reports Phase B produces.
- **Never a hole.** A journal the shipper cannot read past — a sequence
  gap, an unparseable line — stops forwarding at that point and reports
  `journal_unreadable`; it does not skip. Run `audit verify`.
- **The gateway never forwards.** Its process budget is the request path.
  In `--role all` the one process does both.

## Choosing a receiver

| Receiver | URL | Why |
|---|---|---|
| A **local syslog relay** (rsyslog, syslog-ng) with a disk queue, forwarding on to the SIEM | `syslog+tls://relay:6514` | TCP syslog has no application acknowledgement (see below); a relay on the same node or LAN closes the window to what a `close` can carry, and the relay's own queue and retries cover the WAN hop. This is the recommended shape. |
| Splunk HTTP Event Collector | `https://splunk:8088/services/collector/event` + `MCP_AUDIT_FORWARD_TOKEN` | HEC checks the whole body and answers `2xx` only when it has all of it: a real acknowledgement. |
| Anything with an HTTPS ingest endpoint that takes a JSON array | `https://siem.example/ingest` (+ token) | Elastic, Datadog, a homegrown collector. The body is `[record, record, …]`; a `2xx` acknowledges. |

Plaintext syslog is refused. `http://` is accepted only on loopback (a
local collector, a test). Anything else in the URL is a startup refusal
naming the scheme: a partner who wants Kafka or OTLP gets a new adapter,
not a fork.

### Syslog: what the receiver sees

RFC 5424 over RFC 5425 octet counting, one message per record:

```text
<110>1 2026-09-04T12:00:00.123Z gateway-0 mcp-devtools - tool_call_intent - BOM{"seq":41,"kind":"tool_call_intent",…}
```

- **Facility** 13 (log audit). **Severity** *informational* (6) for a
  record, *warning* (4) for a denial or refusal — an egress denial, a
  `*_rejected` control record, a tool call whose decision is `deny` — so a
  receiver's severity filter sees denials without parsing JSON.
- **HOSTNAME** is `MCP_AUDIT_FORWARD_ORIGIN` (default `$HOSTNAME`); set it
  per gateway when several forward to one relay, because `seq` is per
  journal. **APP-NAME** `mcp-devtools`, **MSGID** the record's `kind`, no
  structured data.
- **MSG** is the UTF-8 BOM and the journal line without its newline.

Receiver-side configuration that works, from the CI job
(`tests/fixtures/syslog-ng/syslog-ng.conf`):

```text
source s_mcp { syslog(port(6514) transport("tls")
  tls(key-file("…/server-key.pem") cert-file("…/server.pem")
      ca-file("…/ca.pem") peer-verify(required-trusted))); };
destination d_mcp { file("/var/log/mcp-audit/messages" template("${MSGID} ${MSG}\n")); };
log { source(s_mcp); destination(d_mcp); };
```

For rsyslog the equivalent is `imtcp` with `StreamDriver.Mode="1"`,
`StreamDriver.AuthMode="x509/name"`, and `SupportOctetCountedFraming="on"`
(the default). Mutual TLS: give the forwarder
`MCP_AUDIT_FORWARD_CLIENT_CERT` / `_CLIENT_KEY`; the receiver's
`peer-verify(required-trusted)` (syslog-ng) or `PermittedPeer` (rsyslog)
names who may send.

**Acknowledgement over TCP syslog.** There is none in the protocol. The
adapter checks that the peer is still there before writing to a reused
connection, and listens for a close or a TLS alert for 50 ms after every
batch (which is also how a receiver that demands a client certificate the
forwarder lacks is detected, since TLS 1.3 reports that after the
handshake). A receiver that takes the bytes and dies inside that window
without writing them loses that batch; the recommendation to relay locally
exists because of it, and RELP — the acknowledged variant — is recorded as
the adapter that would close it (CF-32).

### Splunk HEC: what the collector sees

One HEC event per record, newline-separated in one `POST`:

```json
{"time":1788868800.123,"host":"gateway-0","source":"mcp-devtools","sourcetype":"mcp-devtools:audit","event":{"seq":41,"kind":"tool_call_intent",…}}
```

`time` is the record's own timestamp, so the event is indexed when it
happened, not when it was forwarded. Set `sourcetype` in the token's
configuration if you want another name; the body's value wins where the
collector allows it. A `403 Invalid token` is reported in the operator log
as `receiver_rejected: http 403: Invalid token` — the token itself appears
nowhere.

### Generic JSON

`POST` of a JSON array of the records, `Content-Type: application/json`,
`Authorization: Bearer <token>` when `MCP_AUDIT_FORWARD_TOKEN` is set. Any
`2xx` acknowledges the batch.

## Topology

`--role all` (single host): the shipper reads the process's own journal.
Nothing to mount.

Split (`gateway` + `control` on Kubernetes): the control replica must read
the gateway's journal file. `deploy/k8s/control.yaml` shows the shape —
the gateway's journal volume mounted read-only at `/gateway-journal`, named
by `MCP_AUDIT_FORWARD_JOURNAL_DIR`; a writable `MCP_AUDIT_FORWARD_STATE_DIR`
for the cursor; the receiver's CA and client certificate from a Secret.
That needs the journal volume readable from another pod (`ReadWriteMany`
storage, or a single node). One forwarder ships one journal; with several
gateway replicas each needs its own control-side shipper or a shared
`ReadWriteMany` volume per gateway. The audit *push* from gateway to
control that §3.4 sketches, and pruning a gateway's journal once it is
acknowledged, are not built (CF-33).

## Operating it

| Symptom | Meaning | Do |
|---|---|---|
| Startup: `cannot configure audit forwarding: … no audit forwarder for `x://`` | The URL's scheme has no adapter. | Use `syslog+tls://` or `https://`. |
| Startup: `… plaintext syslog, which is not supported` | `syslog://`, `syslog+tcp://`. | Put TLS on the relay (`syslog+tls://`). |
| Startup: `… is set but neither MCP_AUDIT_FORWARD_JOURNAL_DIR nor MCP_AUDIT_JOURNAL_DIR names a journal` | Forwarding on, nothing to forward. | Set the journal directory. |
| Startup: `MCP_AUDIT_FORWARD_STATE_DIR=…: Permission denied` | The cursor cannot be written where it would live. | Point the state directory at a writable volume. |
| Banner: `audit forwarding is failing; journal retained`; log `audit forwarding failed; journal retained, will retry: delivery failed: receiver_unreachable: …` | The receiver cannot be reached, or the TLS handshake fails (`TLS handshake with …: …`). | Check the relay, the CA file, the client certificate. Records wait; nothing is lost. |
| Log: `… receiver_rejected: http 403: Invalid token` | HEC refused the token. | Rotate `MCP_AUDIT_FORWARD_TOKEN` (a `file://` reference is re-read at the next refresh). |
| Log: `… delivery_interrupted: receiver closed the connection while the batch was in flight` | The relay closed during a batch — restarted, or refused the client certificate. | The batch is re-sent; if it repeats, check the relay's peer verification. |
| Log: `… journal unreadable: expected sequence N, found M` | The journal has a gap at the cursor. | `mcp-devtools audit verify`; forwarding does not skip it. |
| Log: `audit forward cursor is for another journal; forwarding from the start` | The state directory held a cursor for a different journal path. | Expected after moving directories; the receiver deduplicates on `seq`. |
| Log: `audit forwarding recovered` | Delivery is working again. | — |

The cursor is `audit-forward-cursor.json` in the state directory:

```json
{"acknowledged":1204,"offset":611392,"chain":"sha256:…","journal":"/journal/audit-journal.jsonl"}
```

Deleting it re-sends the whole journal (duplicates at the receiver, never a
hole). Editing `acknowledged` down does the same from that point. Do not
edit it up.

## Verifying the copy

`mcp-devtools audit verify` checks the journal. To check the copy against
it, export the receiver's records for the range and compare `seq`
coverage: every sequence from the first forwarded to the cursor's
`acknowledged` must be present at least once, and each record's bytes must
equal the journal line (the receiver may hold a record twice after a
retry; it must never hold one the journal lacks). The `siem` CI job does
exactly this against a real syslog-ng container
(`tests/siem_live_tests.rs`).
