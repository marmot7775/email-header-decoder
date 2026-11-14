Email Header Decoder, architecture

Shape
One static page with no server of its own. Pasted headers are
parsed in the visitor's browser. The only thing
stored is the theme choice, in localStorage. There are two kinds of
network call. Usage notes go to dns-audit.com/api/usage: a visit note
when the page opens (tool and linking host only), and after each read the tool
name, the finding status, whether a sample was read, and the host name
of the linking site (ref), with no header text, addresses or domains.
The signature check, when the reader presses its button, sends a TXT
query for each DKIM key name (selector._domainkey.domain) to
cloudflare-dns.com over DNS over HTTPS. Nothing is looked up on
paste, on page load, or for a built-in sample.
The same files run under Node for tests. This is the plan for the
product, not a prototype shortcut.

Modules, each one file, each a pure function layer over the one
below it, all under the HA namespace:

src/parse.js     Text in, field list out. Finds the header block
                 inside a bare paste, a full .eml, or a copy of a
                 whole Show original page. Unfolds, repairs lost
                 indentation, decodes RFC 2047, parses addresses,
                 dates (RFC 5322 plus the obsolete zones), comments,
                 and tag=value lists. Adjacent encoded words in one
                 charset decode as one byte string. Soft hyphens and
                 zero width characters are removed only when they sit
                 inside field names (a rich text copy); otherwise they
                 are kept, so a From domain holding one is read as
                 written. Nothing downstream re-reads raw text.
src/psl.js       Organizational domain from an abbreviated public
                 suffix list (RFC 7489 style). The RFC 9989 tree
                 walk needs DNS, so this is the first release
                 approximation and the page says so. lookup() also
                 gives the A-label forms (key, orgKey) that
                 alignment compares, through the URL parser's IDNA;
                 names with hidden characters or NFKC compatibility
                 forms stay as written.
src/received.js  Received fields into a chronological hop chain
                 with per hop delay, slowest hop, clock skew, TLS
                 evidence, and internal relay detection (two hosts
                 of one operator, mapi, private IPs).
src/auth.js      Authentication-Results per RFC 8601 (Google form
                 with authserv-id, Exchange Online form without),
                 Received-SPF, DKIM-Signature, the ARC set per RFC
                 8617 with chain checks (at most 50 sets), and
                 identifier alignment. SPF is the MAIL FROM result;
                 a HELO result stands in only for a null reverse
                 path. A DKIM result known only by i= has strict
                 alignment null (unknown). Produces reported results
                 and a computed DMARC result side by side.
src/providers.js Decodes filter results (Microsoft SCL, BCL, CAT,
                 SFV, IPV, SFS, PCL, AuthAs, AuthSource,
                 compauth, with Mailbox-Delivery shown as written
                 and its dest I or J read, marked undocumented; Google;
                 Proofpoint; Mimecast; Cisco; Barracuda;
                 SpamAssassin; Rspamd) into plain statements with a
                 level, fingerprints the sending platform from
                 headers, DKIM d=, Return-Path and first relay, and
                 reads list and sending headers (RFC 8058 one-click,
                 Message-ID domain).
                 Unknown codes are shown raw, never guessed.
src/dkimverify.js  Verifies one DKIM signature given its key. Pure,
                 no DOM, no network, no dependencies. SHA-256 written
                 out, base64, simple and relaxed canonicalization of
                 headers and body (RFC 6376 3.4), the hash inputs of
                 RFC 6376 3.7 with l= and with h= names listed more
                 often than they appear (5.4.2), and the RSA public
                 key operation on BigInt. rsaCheck looks inside the
                 PKCS #1 v1.5 padding (RFC 8017 9.2): valid padding
                 around this hash is a pass, valid padding around
                 another hash means the key signed and a signed field
                 changed, and invalid padding means the key in DNS is
                 not the key that signed. Ed25519 (RFC 8463) goes
                 through a WebCrypto object passed in and cannot
                 separate those causes. Hashing reads each field
                 byte for byte as given, from parse.exactLines, not
                 the unfolded and repaired value.
src/dkimkey.js   The signature check. lookup() asks
                 cloudflare-dns.com/dns-query for name and type=TXT
                 with accept: application/dns-json, through a fetch
                 passed in, and reads NXDOMAIN, an empty answer, a
                 CNAME chain with its target, joined TXT strings,
                 SERVFAIL, an HTTP error, and a timeout. parseKey()
                 reads v, k, p, t, h, and s (RFC 6376 3.6.1), an
                 empty p= as revoked, and the RSA size in bits.
                 checkAll(text, fetch, opts) checks every
                 DKIM-Signature and returns one outcome each: pass,
                 no-body, body-mismatch, header-changed,
                 key-mismatch, ed25519-fail, no-key, revoked,
                 malformed, too-short, dns-failed, sha1, unknown-alg,
                 incomplete, or unsupported, with whether the text
                 came from a file or a paste. One query per name. A
                 name that is not DNS labels is never sent.
src/finding.js   The finding, the one sentence result. Reads
                 everything above and writes status, headline,
                 cause, policy consequence, delivery, details, fixes,
                 flags, and limits. delivery (deliveryOf) says what
                 the result means for mail from here on, only where
                 an RFC or a mailbox provider's published sender
                 rules cover it, and is null otherwise. Forwarded mail is
                 recognised from ARC and the pre-forward results are
                 quoted, so the failure is blamed on the forward
                 when the receiver vouched for the ARC seals. A list
                 claim with nothing from before the list and no
                 broken author signature is one possible reason,
                 beside a forgery. STATUS_WORD, the status chip
                 words, lives here so the Simple word test reads it.
                 keyCheckOf turns a signature check into sentences:
                 what the receiver recorded and what the check found
                 as two facts, who fixes it, the steps, and the key
                 size caveat. A verification failure on pasted text
                 becomes could not confirm, and a recorded pass that
                 fails today becomes unknown. When the receiver
                 recorded dkim=fail and a cause was found, the DKIM
                 detail, the cause, and the fix use it, marked as
                 checked today. KEY_UI holds the button's words.
                 signalsOf builds finding.signals, the block under
                 the headline: sender (the DMARC status and the
                 flags) and spam (warn and fail items from filter
                 groups on the receiver's side, without compauth),
                 each with a state, an answer, and its items, plus
                 a scope sentence when nothing fired.
src/analyze.js   analyze(text, opts) returns one plain result object.
                 The page renders it; the tests assert on it.
                 opts.keyCheck is a signature check to state.

ui/page.html     Markup and tokens. The shared site header,
                 the paste box, then the results: finding (headline,
                 the sender and spam questions, what to do, the four check tiles, why, what the
                 DMARC setting did, evidence), message, alignment,
                 authentication, path, filter headers, raw headers
                 collapsed. Below the tool, static text for readers
                 and search engines: what it reads, how to copy the
                 headers, and the FAQ. Then the site footer.
ui/app.js        Rendering only. No parsing logic lives here. The
                 tiles and the copied report read values already
                 in the result; they decide nothing new. Invisible
                 and direction control characters print as <U+XXXX>.
                 A dropped or chosen .eml goes through one reader:
                 the box shows the first 2 MB, and the file's own
                 bytes (up to 25 MB, one character per byte) are
                 kept for the signature check while the box still
                 holds what the file put there. The signature check
                 button calls dkimkey.checkAll, then analyze again
                 with the result. It is the only caller, and it does
                 nothing for a built-in sample. Each result is
                 announced in the polite live region. The raw
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
No guessing. Every sentence in the finding is built from
identifiers in the headers. Where the page cannot know
(adkim/aspf, the organizational domain, Gmail's spam decision) it
says so in the output rather than defaulting silently. The signature
check is the one thing that reaches past the headers, and only when
asked: its result is dated, kept apart from the receiver's, and
never turned into a reason when the two disagree. Only a message
file supports a failure. The DMARC and SPF records are not looked
up.

Result object (what the page renders)
input, message, finding (with keyCheck: null, or the signature check
as intro and per signature results), alignment (rows per identifier with
aligned, strict, mode), auth (all A-R, primary, spf, dkim, dmarc,
computed, arc, arcResult, compauth, unbackedDkim), chain (hops, totalSec,
slowestIdx, clockSkew, originIp), decoded (filters, platform,
list, notes), fields, flags (hidden-characters among them).

Parked for later releases
Bounce and SMTP code decoding.
Full public suffix list or an RFC 9989 tree walk via DNS. Link from a
failing From domain to its dns-audit.com audit. Compare two messages
side by side.
