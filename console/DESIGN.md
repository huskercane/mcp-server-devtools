# Governance console design

Adapted from the user-supplied Google Stitch export
`stitch_mcp_devtools_governance_console.zip` on September 6, 2026.
The shield logo uses the export's SVG. The sidebar, blue/slate surfaces,
compact tables, and split policy editor follow its design direction.

The implementation uses Askama templates, the existing pinned htmx, and one
local stylesheet. System sans-serif and monospace fonts replace the export's
remote fonts; SVG navigation icons replace its remote icon font. No Tailwind
runtime, CDN, new JavaScript library, or package-manager dependency is needed.

## Product boundaries

- Navigation names and routes remain the existing console destinations.
- Every displayed value comes from the existing page model or admin API.
  The export's example tenants, users, rule counts, drift metrics, hardware
  signing claims, notifications, and global search are not product features.
- Policy explanation remains a read-only simulation with the existing form
  fields. The policy document is shown as YAML, without inventing a different
  rule language or precedence model from the mockup.
- Authoring retains native text/file inputs, exact-byte download and upload,
  offline signing, structural comparison, and the configured mutation gate.
- Proposal list and detail use one presentation model. An approved proposal
  is labeled Applied only when `applied_seq` is a numeric value. Otherwise it
  is incomplete. Decision forms appear only for pending proposals; the API
  still enforces identity, freshness, expiry and authorization on every action.
- Raw proposal metadata remains available in a disclosure for audit review.
  The interface does not imply in-app access to stored candidate files.

## Layout and access

The desktop sidebar is 240px; it becomes a compact navigation grid on narrow
screens. Editor and review panels stack on tablets. Tables scroll inside their
own keyboard-focusable regions. Forms keep visible labels, focus rings, native
submission, and existing htmx fragment IDs. Status text accompanies color.
Empty states describe the next useful action and never substitute for errors.

Native form submissions require `Referrer-Policy: same-origin`. The former
`no-referrer` setting caused Chrome to send `Origin: null`, so legitimate
upload, decision, and logout forms failed the origin check. Cross-origin
referrers remain suppressed; the guard still rejects null and foreign origins.
See [MDN's Origin behavior documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header).
