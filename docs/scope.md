Email Header Decoder, scope

Written 2026-10-15 as the Header Analyzer scope; brought up to date
2026-10-25. The repo docs are the only copy.

Purpose
A page where you paste raw email headers and the first thing you
read is what failed and why. Built first for Neil's own tickets,
then for clients and visitors. It is also a portfolio piece: it
should earn a technical reader's respect and still make sense to
the business owner who owns the domain.

Decision: it runs entirely in the browser
No backend. One static page. Reasons: pasted headers never leave
the visitor's machine; no rate limiting, no logging policy, no
load on the droplet. Nothing in the first release needs DNS.

Where it lives
headers.dns-audit.com, a static site on Cloudflare, with the same
site bar and footer as dns-audit.com so the two read as one family.
Its own repo, its own hosting; the droplet never serves it. A link
in the dns-audit.com nav points to it. A subdomain rather than a
path was chosen for simplicity; dns-audit.com/headers through a
Cloudflare route stays possible if search traffic becomes a goal.

First release
1. Paste box and .eml drop. Headers unfolded, encoded words
   decoded, duplicates kept in order.
2. Finding first. One sentence naming the cause, for example:
   DMARC failed because DKIM signed as mailer.example and SPF
   checked bounce.mailer.example, so neither aligned with the
   From domain. Then the fix in plain words, as numbered steps.
3. Four check tiles under the finding: SPF, DKIM, DMARC, and
   delivery time, each with the question it answers. A forward the
   finding blames shows as failed after the forward, passed before.
4. Alignment picture. From domain, Return-Path domain, every DKIM
   d= with its selector and result, each marked aligned or not,
   relaxed or strict as the DMARC policy would read it.
5. Authentication-Results and ARC per RFC 8601, broken out per
   method with the host that wrote them, and the ARC chain with
   cv= so forwarded mail reads correctly.
6. Hop timeline. Each Received hop with from, by, protocol, TLS,
   and delay. The slowest hop flagged, total transit time, and
   forwarders named when the chain shows one.
7. Provider decode in one place regardless of who wrote it:
   Microsoft, Google, Proofpoint, Mimecast, Cisco, Barracuda,
   SpamAssassin, and Rspamd.
8. Raw headers collapsed under everything, searchable.
9. Plain and technical wording, plain first. The switch changes
   every sentence; Copy report carries both headlines.
10. Copy report: the finding, the tiles, and the fixes as plain
    text for a ticket or a client email.
11. (Dropped 2026-10-28.) A line on the page saying nothing you
    paste leaves your browser; Neil does not want it advertised.
12. Static text below the tool for readers and search engines:
    what it reads, how to copy headers in Gmail, Outlook, classic
    Outlook, and Apple Mail, and an FAQ. The JSON-LD FAQ is built
    from the page's own FAQ.
13. Beta label on the page and in the README, with a line asking
    for messages it reads wrong.

Parked
DKIM public key lookup (needs DNS, can call the audit API later).
Bounce and SMTP code decoding (separate tool).
Shareable result links (conflicts with the privacy claim; Copy
report covers the need without a server).
Link from a failing domain to its dns-audit.com audit.
Compare two messages side by side.

Testing
Node test suite. Synthetic fixtures for every RFC 8601 result and
ARC state. Real headers Neil pastes from his own mailboxes, Gmail,
Outlook, iCloud, and forwarded mail, are used for checking and
never committed. Hostile input: folded garbage, missing Received,
no Authentication-Results, two From headers. Browser check with
Playwright at desktop and phone widths, dark and light.

Build plan
Four steps, each a page Neil can try that day: parser and hop
timeline; Authentication-Results, ARC, and alignment; finding
sentence and provider decode; copy pass, design, mobile, and
hosting. Neil's part: paste real headers and say what reads wrong.
