# Email Header Decoder

A single page email header analyzer. Paste raw headers, a full
.eml, or a copy of a Show original page, and the first thing you
read is the finding: one sentence naming what failed and why, then
the fix in plain words. Built first for Neil's own tickets, then
for clients and visitors.

The repo and directory are email-header-decoder. The display name
is Email Header Decoder. The one sentence result is the finding.
The word verdict is not used in the code, the page, or the docs;
two tests check for it on purpose.

## Hard rules

Everything runs in the visitor's browser. No storage, no analytics
scripts. Pasted headers are never sent anywhere, but the page no
longer advertises that (Neil, 2026-10-28: not a selling point; he
wants usage logs). The one network call is the usage note (Neil,
2026-10-28: he wants to see the tool is used): after each new read,
ui/app.js posts the finding status only to
https://dns-audit.com/api/usage, the CSP's only connect-src. Never
add header text, addresses, or domains to it.

Standalone repo, not a dns-audit.com feature. Hosting comes in
step 4 as a static site; the droplet never serves it.

No DNS lookups, no signature verification, no guessing. Every
sentence on the page is built from identifiers in the headers.
Where the page cannot know something (adkim and aspf, the
organizational domain, Gmail's spam decision, unverified ARC
seals) it says so in the limits list under the finding rather
than defaulting silently. Unknown filter codes show raw, with no
meaning attached. Unnamed beats guessed, for platforms and for
codes alike.

Every sentence is `{ state, technical, plain, src }`: state is
pass, caveat, fail or unknown, and src lists the field indexes it
came from.

No web fonts, no CDN, no external images. Inline SVG for icons.
No color carries meaning alone. Touch targets are 44px; inline
source line chips are 24px, the WCAG 2.2 AA minimum. Works at
375px with no horizontal scroll.

Zero dependencies, Node 18 or later, plain JavaScript.

Samples and fixtures are synthetic. Never commit real mail.

No model name, plan, tier, or model version appears in any file
in the repo: not in docs, comments, commit messages, or the page.
Claude Code as the name of the tool is fine.

Links may point only at dns-audit.com, Neil's LinkedIn, and the
GitHub repo; build.js refuses any other host. The page loads
nothing from anywhere.

Commit each step locally. Publishing was approved on 2026-10-25:
the public GitHub repo, hosting at headers.dns-audit.com on
Cloudflare, and the nav link on dns-audit.com. Push and deploy only
work that passed tests, the build, and the browser check. The
droplet never serves this page.

## Layout

src/parse.js      Text in, field list out. Finds the header block
                  in a bare paste, an .eml, or a Show original
                  copy. Unfolds, repairs lost indentation, decodes
                  RFC 2047, parses addresses, dates, comments, and
                  tag=value lists. Nothing downstream re-reads raw
                  text.
src/psl.js        Organizational domain from an abbreviated public
                  suffix list, RFC 7489 style.
src/received.js   Received fields into a chronological hop chain
                  with per hop delay, slowest hop, clock skew, TLS
                  evidence, internal relay detection, and the
                  trust line.
src/auth.js       Authentication-Results per RFC 8601 (Google form
                  with authserv-id, Exchange Online form without),
                  Received-SPF, DKIM-Signature, the ARC set per RFC
                  8617 with chain checks, identifier alignment, and
                  a computed DMARC result beside the reported one.
src/providers.js  Filter header decode (Microsoft SCL, BCL, CAT,
                  SFV, IPV, compauth; Proofpoint; Mimecast; Cisco;
                  Barracuda; SpamAssassin; Rspamd), platform
                  fingerprint with a confidence, list and sending
                  headers including RFC 8058 one-click.
src/finding.js    The sentence. Status, headline, cause, policy
                  consequence, details, fixes, flags, and limits.
src/analyze.js    analyze(text) returns one plain result object.
                  The page renders it; the tests assert on it.
ui/page.html      Markup and tokens. Site bar, paste box, then
                  finding with the check tiles, message, alignment,
                  authentication, path, filter headers, raw headers
                  collapsed. Static guide and FAQ below the tool.
ui/app.js         Rendering only. No parsing logic lives here.
build.js          Builds dist/index.html (full document with a
                  CSP, title, description, canonical, share tags,
                  and JSON-LD; opens from disk) and
                  dist/artifact.html (body only, for the claude.ai
                  preview), plus _headers, robots.txt, sitemap.xml,
                  and the share card for the static host. dist is
                  gitignored.
ui/og-card.png    The share card, 1200 by 630.
test/             node:test suite over analyze() with synthetic
                  fixtures and hostile input. Fixtures are under
                  test/fixtures.
scripts/sentences.js  Writes docs/sentences.md, every string the
                  finding and the filter decode can show, by case.
                  npm run sentences; commit the file with any
                  wording change.
wrangler.jsonc    Cloudflare static hosting: dist/ on
                  headers.dns-audit.com, workers.dev off.
README.md         The public face of the repo, with the Beta note.
docs/scope.md     What the first release does and what is parked.
docs/architecture.md  The module plan. Keep it true as the code
                  changes; it is the plan, not a snapshot.
docs/plan.md      The build log: decisions with dates, and each
                  step with its status and commit.

Each module is one file and a pure function layer over the one
below it, all under the HA namespace. Each src file attaches to
HA and sets module.exports under Node. build.js SRC lists what
ships; test/load.js loads the same list.

## Commands

Tests: node --test test/
Build: node build.js
Deploy: node build.js, then wrangler deploy (token and account in
~/.config/cloudflare/env; wrangler is in
~/.local/share/wrangler4/node_modules/.bin). Push to GitHub first.

Both must pass before every commit.

Browser check: Playwright from
/home/neil/projects/dns-security-auditor/.venv runs Chromium
headless on this machine; load dist/index.html as file://.

## Settled decisions

Origin IP is the address the receiver saw. X-Originating-IP is
kept separate as the stated origin. A hop via Frontend Transport
is the inbound hop at Exchange Online, not internal.

Statuses are pass, fail, forwarded, none, error, unknown. A
reported pass with nothing aligned is status pass with a caveat,
and the headline says why it passed.

Blame moves to a forward only when the earliest forwarder's
ARC-Authentication-Results show an aligned pass, the chain holds
together, and the receiver reported arc=pass (or Microsoft
compauth reason 130). This page does not verify seals, so a sender
can write an ARC set; without the receiver's word it is not a
forward. An ARC set the final receiver sealed itself is not a
forward.

A filter header below the receiver's first Received stamp is
marked before custody. Microsoft's own fields count as the
receiver's when Microsoft received.

Platform confidence: high for a platform header or two kinds of
evidence, medium for Return-Path or DKIM d= alone, low for the
relay name alone. A fix names the platform only at high
confidence. Platform matches are on label boundaries, not
substrings.

SCL: Microsoft documents -1, 0, 1, 5, 6, and 9. Show 2 to 4 raw;
7 and 8 are a warning. BCL comes from X-Forefront-Antispam-Report
when present, else X-Microsoft-Antispam.

No move to p=quarantine fix when the From domain belongs to a
mailbox provider.

RFC 8058 one-click passes only when a passing DKIM signature
lists both List-Unsubscribe fields in h=.

Palette uses dns-audit.com's tokens with system fonts. Dark and
light both work. No horizontal scroll at 375px.

### Settled by the step 2 check

- Primary Authentication-Results: the topmost field whose
  authserv-id shares an operator with the by host of the last
  Received hop, or, when X-MS-Exchange-Organization-* fields are
  present, the topmost one with no authserv-id. Never one a
  sender could have written.
- Untrusted: every other Authentication-Results field, whether its
  host is missing from the chain or sits on the sender's side. It
  is kept and shown, never used for reported results. RFC 8601
  section 5 only has a receiver strip fields that carry its own
  authserv-id. No trusted field means no primary and computed
  DMARC is none.
- An id-less field without Exchange Online headers is untrusted.
- Received-SPF counts only when it sits above the last sender-side
  Received field, and is the SPF source only when the primary set
  has no spf= result.
- Alignment defaults to relaxed, with strict computed beside it.
  computed.result is pass, fail or none and follows relaxed; adkim
  and aspf are not in the headers, and alignment.modeNote says so.
- One From domain or none: two From fields, or one From field
  naming two domains, leave alignment undefined and nothing is
  computed.
- A DKIM result naming neither s= nor b= when two signatures share
  d= is marked ambiguous, not matched by order.
- Microsoft action=oreject and pct.* keep value empty in
  dmarc.disposition: Microsoft Learn pages contradict each other
  on what those did to the message. raw, policy and sampled are
  kept.

## Copy

Every sentence has two voices. The switch on the page reads Simple
and Technical; in code they stay `plain` and `technical`.

Simple is for the owner of a small business: someone who sells
coffee, knows what their website address is, and may have heard
the word DMARC from their email service. Each Simple sentence says
what happened, whether it matters, and what to do or whom to ask.
Short sentences, no semicolons, nothing they would have to look
up. Name the receiver (Gmail, Microsoft) and the sending service
when known. Fixed words, used the same way everywhere:

- DMARC: the sender check (DMARC), then DMARC.
- DKIM: the digital signature, signed by.
- SPF: the list of servers allowed to send for a domain.
- Return-Path, MAIL FROM: the hidden return address.
- p=: the domain's DMARC setting; none is watch only,
  quarantine is send failures to spam, reject is refuse failures.
- DNS record: a DNS setting for the domain, at the company that
  hosts its DNS (often where the domain was bought).
- TLS: encrypted. A Received hop: a handoff between servers.

Never in Simple: aligned, alignment, bounce, Return-Path,
envelope, HELO, EHLO, selector, d=, s=, header (one named
header; the headers, meaning the pasted text, is fine), field, authserv,
ARC, seal, compauth, SCL, BCL, PCL, organizational domain, relay,
hop, TLS, RFC, policy. A test enforces the list, and no
semicolons, over every fixture and every case in
docs/sentences.md. Contractions in Simple are applied in one place,
P.contract in parse.js, so write Simple strings either way.
A listed word may appear in Simple in brackets right after the
plain words that explain it, as in the sender check (DMARC) or the
hidden return address (Return-Path), so a reader learns the term
their email service uses. The test ignores bracketed text.

Technical is for a deliverability practitioner. Lead with the word
practitioners say, then the RFC identifier in brackets: the
Return-Path domain (RFC5321.MailFrom), the From domain
(RFC5322.From). Use the protocol's own terms exactly: RFC5322.From, RFC5321.MailFrom, the HELO
identity, DKIM d=, s= and i=, relaxed and strict alignment (adkim,
aspf), the organizational domain, p=, sp=, pct=, Gmail's dis=,
Microsoft's action= and compauth reason, ARC i= and cv=, the
authserv-id. Quote result tokens verbatim. Cite the RFC section
when it settles a point (RFC 7208, 6376, 8617, 8058; DMARC is RFC
9989 for the protocol, which obsoletes RFC 7489). Say what the
headers cannot show. Technical carries more detail than Simple,
never less.

Both voices follow Neil's house style (the neil-voice skill):
complete sentences under 25 words with varied length, contractions,
the reader addressed as you where the advice is theirs, AP numbers
(one to nine in words), Oxford comma, no dashes or quotation marks
as punctuation, no filler words (very, really, just, quite,
actually, basically), and none of the banned buzzwords. No em dashes anywhere, in code comments and
UI text included, and no hyphens as punctuation. No exclamation
marks, no emoji, no intensifiers. Oxford comma. Identifiers
verbatim in monospace. Say a thing once.

## Process

One build step per prompt. Finish the step, run tests and build,
commit, then report. The report is one fenced block and covers:
files new, changed, and deleted; test count before and after;
anything reused, dropped, or settled without being asked, each
with the reason; what is not done; the commit SHA. The report ends
with the Decisions and Steps sections of docs/plan.md copied in
full, after updating them for the step, so the next prompt can be
written from the report alone.

Update docs/architecture.md and docs/scope.md in the same commit
whenever a step changes what they describe.
