# Header Verdict

A single page email header analyzer. Paste raw headers, a full .eml, or a
copy of a Show original page, and the first thing you read is what failed
and why. Everything runs in the browser: no server, no network calls, no
storage, no DNS. Standalone repo, not a dns-audit.com feature. Hosting
comes in step 4 as a static site; the droplet never serves it.

## Rules

- No DNS, no signature verification, no guessing. Every sentence is built
  from identifiers in the headers. Where the page cannot know something it
  says so. Unknown codes are shown raw.
- parse.js produces the field list; nothing downstream re-reads raw text.
- Every sentence is `{ state, technical, plain, src }`: state is pass,
  caveat, fail or unknown, src lists the field indexes it came from.
- UI writing: plain words, complete sentences, no em dashes or hyphens as
  punctuation, no exclamation marks, no emoji, Oxford comma. Identifiers
  verbatim in monospace.
- No web fonts, no CDN, no external images. Inline SVG for icons. No color
  carries meaning alone. Touch targets 44px (inline source line chips are
  24px, the WCAG 2.2 AA minimum). Works at 375px with no horizontal scroll.
- Zero dependencies, Node 18 or later, plain JavaScript.
- Samples and fixtures are synthetic. Never commit real mail.
- Do not push, and do not touch GitHub, the droplet, or dns-audit.com
  until Neil says so.

## Settled by the step 2 check

- Primary Authentication-Results: the topmost field whose authserv-id
  shares an operator with the by host of the last Received hop, or, when
  X-MS-Exchange-Organization-* fields are present, the topmost one with
  no authserv-id. Never one a sender could have written.
- Untrusted: every other Authentication-Results field, whether its host
  is missing from the chain or sits on the sender's side. It is kept and
  shown, never used for reported results. RFC 8601 section 5 only has a
  receiver strip fields that carry its own authserv-id. No trusted field
  means no primary and computed DMARC is none.
- An id-less field without Exchange Online headers is untrusted.
- Received-SPF counts only when it sits above the last sender-side
  Received field, and is the SPF source only when the primary set has no
  spf= result.
- Alignment defaults to relaxed, with strict computed beside it.
  computed.result is pass, fail or none and follows relaxed; adkim and
  aspf are not in the headers, and alignment.modeNote says so.
- One From domain or none: two From fields, or one From field naming two
  domains, leave alignment undefined and nothing is computed.
- A DKIM result naming neither s= nor b= when two signatures share d= is
  marked ambiguous, not matched by order.
- Microsoft action=oreject and pct.* keep value empty in
  dmarc.disposition: Microsoft Learn pages contradict each other on what
  those did to the message. raw, policy and sampled are kept.

## Layout

    src/parse.js      text in, field list out
    src/psl.js        organizational domain, abbreviated suffix list
    src/received.js   Received fields into a hop chain and trust line
    src/auth.js       Authentication-Results, ARC, alignment, computed DMARC
    src/providers.js  step 3: filter verdicts, platform, list headers
    src/verdict.js    step 3: the sentence and the fix
    src/analyze.js    analyze(text) returns one plain result object
    ui/page.html      markup and CSS tokens
    ui/app.js         rendering only
    build.js          dist/index.html (full document, CSP, opens from disk)
                      and dist/artifact.html (body only, for claude.ai)
    test/             node:test suite, fixtures under test/fixtures
    wip/step3/        rescued step 3 work; not built, not tested

Each src file attaches to the HA namespace and sets module.exports under
Node. build.js SRC lists what ships; test/load.js loads the same list.

## Commands

    node --test test/        run the suite
    node build.js            write dist/
    HV_SRC=all node --test test/   also load the not yet shipped modules

Browser check: Playwright from /home/neil/projects/dns-security-auditor/.venv
runs Chromium headless on this machine; load dist/index.html as file://.

## Steps

See docs/plan.md. 1 done, 2 done, 3 next, 4 after.

## End of step report

One fenced block: files created or changed, test count and result,
decisions made where the prompt was silent, anything not done, and the
commit SHA. Then stop; the next prompt comes from Cowork.
