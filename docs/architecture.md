Email Header Decoder, architecture

Shape
One static page. No server of its own and no storage. Pasted
headers are parsed in the visitor's browser and never leave it. The
one network call is a usage note with the finding status only, to
dns-audit.com/api/usage.
The same files run under Node for tests. This is the plan for the
product, not a prototype shortcut: a header analyzer has no reason
to send mail headers anywhere.

Modules, each one file, each a pure function layer over the one
below it, all under the HA namespace:

src/parse.js     Text in, field list out. Finds the header block
                 inside a bare paste, a full .eml, or a copy of a
                 whole Show original page. Unfolds, repairs lost
                 indentation, decodes RFC 2047, parses addresses,
                 dates (RFC 5322 plus the obsolete zones), comments,
                 and tag=value lists. Nothing downstream re-reads
                 raw text.
src/psl.js       Organizational domain from an abbreviated public
                 suffix list (RFC 7489 style). The DMARCbis tree
                 walk needs DNS, so this is the first release
                 approximation and the page says so.
src/received.js  Received fields into a chronological hop chain
                 with per hop delay, slowest hop, clock skew, TLS
                 evidence, and internal relay detection (two hosts
                 of one operator, mapi, private IPs).
src/auth.js      Authentication-Results per RFC 8601 (Google form
                 with authserv-id, Exchange Online form without),
                 Received-SPF, DKIM-Signature, the ARC set per RFC
                 8617 with chain checks, and identifier alignment.
                 Produces reported results and a computed DMARC
                 result side by side.
src/providers.js Decodes filter results (Microsoft SCL, BCL, CAT,
                 SFV, IPV, SFS, PCL, AuthAs, AuthSource,
                 compauth; Google; Proofpoint; Mimecast; Cisco; Barracuda;
                 SpamAssassin; Rspamd) into plain statements with a
                 level, fingerprints the sending platform from
                 headers, DKIM d=, Return-Path and first relay, and
                 reads list and sending headers (RFC 8058 one-click,
                 Message-ID domain).
                 Unknown codes are shown raw, never guessed.
src/finding.js   The finding, the one sentence result. Reads
                 everything above and writes status, headline,
                 cause, policy consequence, details, fixes, flags,
                 and limits. Forwarded mail is
                 recognised from ARC and the pre-forward results are
                 quoted, so the failure is blamed on the forward
                 when the receiver vouched for the ARC seals.
src/analyze.js   analyze(text) returns one plain result object.
                 The page renders it; the tests assert on it.

ui/page.html     Markup and tokens. The dns-audit.com site bar,
                 the paste box, then the results: finding (headline,
                 what to do, the four check tiles, why, what the
                 DMARC setting did, evidence), message, alignment,
                 authentication, path, filter headers, raw headers
                 collapsed. Below the tool, static text for readers
                 and search engines: what it reads, how to copy the
                 headers, and the FAQ. Then the site footer.
ui/app.js        Rendering only. No parsing logic lives here. The
                 tiles and the copied report read values already
                 in the result; they decide nothing new. The raw
                 header list is drawn when opened, 200 fields at a
                 time, and a field over 2,000 characters shows
                 clipped with a button to show all of it.
ui/og-card.png   The share card, 1200 by 630.
build.js         Inlines src and ui into dist/index.html (full
                 document: head with CSP, title, description,
                 canonical, share tags, and JSON-LD whose FAQ is
                 read from the page's own FAQ) and dist/artifact.html
                 (body only, for the claude.ai preview). Also writes
                 what the static host serves beside the page:
                 _headers (the CSP as a real header, with
                 frame-ancestors), robots.txt, sitemap.xml, and the
                 share card.
test/            node:test suite over analyze() with synthetic
                 fixtures and hostile input. Run: node --test test/
scripts/sentences.js  The sentence inventory: drives finding.js
                 through every status and cause with synthetic
                 headers built in the script, adds every filter code
                 meaning, and writes docs/sentences.md. Run: npm run
                 sentences. A test fails when the file is stale, a
                 case throws, a sentence breaks the copy rules, or
                 two cases share a cause.

Rules that keep it honest
No DNS, no signature verification, no guessing. Every sentence is
built from identifiers in the headers. Where the page cannot know
(adkim/aspf, the organizational domain, Gmail's spam decision) it
says so in the output rather than defaulting silently.

Result object (what the page renders)
input, message, finding, alignment (rows per identifier with
aligned, strict, mode), auth (all A-R, primary, spf, dkim, dmarc,
computed, arc, arcResult, compauth), chain (hops, totalSec,
slowestIdx, clockSkew, originIp), decoded (filters, platform,
list, notes), fields, flags.

Parked for later releases
DKIM key lookup through a DNS API. Bounce and SMTP code decoding.
Full public suffix list or a DMARCbis tree walk via DNS. Link from a
failing From domain to its dns-audit.com audit. Compare two messages
side by side.
