Header Analyzer for dns-audit.com, scope, 2026-10-15

Purpose
A page where you paste raw email headers and the first thing you
read is what failed and why. Built first for Neil's own tickets,
then for clients and visitors.

Decision: it runs entirely in the browser
No backend. One static page plus one JS file. Reasons: pasted
headers never leave the visitor's machine, which is a claim none
of the incumbents can make; no rate limiting, no logging policy,
no load on the droplet; and it can be built and tested in the
cloud container now and used today as a published page, then
dropped into static/ on dns-audit.com with one route when you
are ready. Nothing in the first release needs DNS.

First release
1. Paste box and .eml drop. Headers unfolded, encoded words
   decoded, duplicates kept in order.
2. Finding first. One sentence naming the cause, for example:
   DMARC failed because DKIM signed as mailer.example and SPF
   checked bounce.mailer.example, so neither aligned with the
   From domain. Then the fix in plain words.
3. Alignment table. From domain, Return-Path domain, every DKIM
   d= with its selector and result, each marked aligned or not,
   relaxed or strict as the DMARC policy would read it.
4. Authentication-Results and ARC per RFC 8601, broken out per
   method with the host that wrote them, and the ARC chain with
   cv= so forwarded mail reads correctly.
5. Hop timeline. Each Received hop with from, by, protocol, TLS,
   and delay. The slowest hop flagged, total transit time, and
   forwarders named when the chain shows one.
6. Provider decode in one place regardless of who wrote it:
   Microsoft X-Forefront-Antispam-Report (SCL, BCL, CAT, SFV,
   IPV, CIP, DIR) and X-MS-Exchange-Organization-SCL; Google
   X-Google-DKIM-Signature and spam markers; Proofpoint and
   Mimecast score headers when present.
7. Raw headers collapsed under everything, searchable.
8. One line on the page: nothing you paste leaves your browser.

Parked
DKIM public key lookup (needs DNS, can call the audit API later).
Bounce and SMTP code decoding (separate tool).
Shareable result links (conflicts with the privacy claim).
Link from a failing domain to its dns-audit.com audit (cheap, add
once the page lives on the site).

Testing
Node test suite in the container. Synthetic fixtures for every
RFC 8601 result and ARC state, plus real headers Neil pastes from
his own mailboxes, Gmail, Outlook, iCloud, and forwarded mail.
Hostile input: folded garbage, missing Received, no
Authentication-Results, two From headers.

Build plan
Four steps, each published as a page Neil can try that day:
parser and hop timeline; Authentication-Results, ARC, and
alignment; finding sentence and provider decode; copy pass and
mobile. Claude about 25 hours. Neil about 2 hours total: paste
headers, say what reads wrong.

Not touched until Neil says so: GitHub, the droplet, WSL.
