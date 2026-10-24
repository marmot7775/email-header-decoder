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

Everything runs in the visitor's browser. No server, no network
calls, no storage, no analytics. Pasted headers never leave the
machine, and the page says so in one line.

No DNS lookups, no signature verification, no guessing. Every
sentence on the page is built from identifiers in the headers.
Where the page cannot know something (adkim and aspf, the
organizational domain, Gmail's spam decision, unverified ARC
seals) it says so in the limits list under the finding rather
than defaulting silently. Unknown filter codes show raw, with no
meaning attached. Unnamed beats guessed, for platforms and for
codes alike.

No model name, plan, tier, or model version appears in any file
in the repo: not in docs, comments, commit messages, or the page.
Claude Code as the name of the tool is fine.

Do not push. Commit each step locally and wait for the word.

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
                  evidence, and internal relay detection.
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
ui/page.html      Markup and tokens. Finding first, then message,
                  alignment, authentication, path, filter headers,
                  raw headers collapsed.
ui/app.js         Rendering only. No parsing logic lives here.
build.js          Builds dist/index.html (opens from disk) and
                  dist/artifact.html (body only, for the claude.ai
                  preview). dist is gitignored.
test/             node:test suite over analyze() with synthetic
                  fixtures and hostile input.
docs/scope.md     What the first release does and what is parked.
docs/architecture.md  The module plan. Keep it true as the code
                  changes; it is the plan, not a snapshot.
docs/plan.md      The build log: decisions with dates, and each
                  step with its status and commit.

Each module is one file and a pure function layer over the one
below it, all under the HA namespace.

## Commands

Tests: node --test test/
Build: node build.js

Both must pass before every commit.

## Settled decisions

Origin IP is the address the receiver saw. X-Originating-IP is
kept separate as the stated origin. A hop via Frontend Transport
is the inbound hop at Exchange Online, not internal.

Statuses are pass, fail, forwarded, none, error, unknown. A
reported pass with nothing aligned is status pass with a caveat,
and the headline says why it passed.

Blame moves to a forward only when the earliest forwarder's
ARC-Authentication-Results show an aligned pass, the chain holds
together, and the receiver did not report arc=fail. An ARC set
the final receiver sealed itself is not a forward.

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

## Copy

Plain words, technical wording beside them where a code needs it.
No em dashes anywhere, in code comments and UI text included. No
intensifiers. Say a thing once.

## Process

One build step per prompt. Finish the step, run tests and build,
commit, then report. The report covers: files new, changed, and
deleted; test count before and after; anything reused, dropped,
or settled without being asked, each with the reason; what is not
done; the commit SHA. The report ends with the Decisions and Steps
sections of docs/plan.md copied in full, after updating them for
the step, so the next prompt can be written from the report alone.

Update docs/architecture.md and docs/scope.md in the same commit
whenever a step changes what they describe.
