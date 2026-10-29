Email Header Decoder, plan

Four steps. Each ends with a report and a commit, and the next prompt
is handed out only after that. Status as of 2026-10-25.

1  Repo, parser, hop timeline, page skeleton, tests, build.    DONE
   parse.js (header block in a bare paste, a full .eml, a Show
   original copy, or Outlook's box; unfolding and lost indentation
   repair; RFC 2047; addresses; RFC 5322 dates), psl.js, received.js
   (hop chain, delays, slowest hop, clock skew, internal groups, TLS
   evidence, trust line, stated origin), analyze.js, the page with
   Message, Path and Headers cards, build.js with a CSP that has no
   connect-src. Commits f54c7bc and 30058f5, then 3535036, the
   step 1 gap fill against Cowork prompt 1.

2  Authentication-Results, ARC, alignment table, computed DMARC. DONE
   auth.js: RFC 8601 per method with the host that wrote each field
   and whether the Received chain backs it; ARC sets per RFC 8617
   with chain checks; alignment per identifier in relaxed and strict
   mode; a DMARC result computed here beside the reported one, and a
   named reason when they disagree. Commits 594feac and 8cf9fa1,
   then the Step 2 check commit against the 2026-10-23 spec: primary
   and untrusted Authentication-Results, Received-SPF as SPF source,
   DKIM matching by s= or b=, HELO identity for a null reverse path,
   computed DMARC as pass, fail or none, two From fields.

3  Finding sentence and provider decode.                    DONE
   finding.js (status pass, fail, forwarded, none, error or unknown;
   headline, cause, policy consequence, details, fixes, flags, and
   limits; forwarded mail from the ARC chain with the pre-forward
   results quoted) and providers.js (Microsoft, Google, Proofpoint,
   Mimecast, Cisco, Barracuda, SpamAssassin, Rspamd; platform with
   a confidence; list and sending headers with RFC 8058), both in
   the build. The product name is Email Header Decoder and the repo
   is email-header-decoder (renamed 24 Oct). wip/step3 and the
   15 Oct verdict.js are gone. Gap check 2026-10-27 against the
   original step 3 prompt, commit bc8930f: Microsoft PCL, AuthSource,
   SFS, AuthAs External and Partner, and the Message-ID domain.

4  Copy pass, design, mobile, hosting.                      IN PROGRESS
   Design pass done 2026-10-25: dns-audit.com site bar and footer,
   Beta label, check tiles, plain first with the technical line
   under it, numbered fixes, evidence folded, quieter line chips,
   filter headers after the path, Copy report, samples labelled,
   static guide and FAQ, head with JSON-LD, share card, host files.
   Published 2026-10-25: public repo marmot7775/email-header-decoder,
   live at headers.dns-audit.com (Workers static assets from dist/,
   wrangler.jsonc, workers.dev off). Nav link on dns-audit.com live
   2026-10-28 (dns-audit #234, 52dbbf5).
   Sentence inventory 2026-10-27, commit 986d7de:
   scripts/sentences.js drives finding.js through 51 synthetic
   cases (every status and cause) and every filter code meaning,
   and writes docs/sentences.md; npm run sentences regenerates it
   and test/sentences.test.js fails on a stale file, a throwing
   case, a dash as punctuation, the word verdict, a double space,
   or two cases with the same cause. Commit 12dc5c8: the
   HELO only and forwarded causes reworded.
   First real headers 2026-10-28 (an IETF mailing list message in
   Outlook, pasted twice): the page called it a two From forgery.
   Fixed: a doubled paste reads once, mailing list mail gets its own
   finding, the full analysis starts closed, the box opens empty.
   Large paste stall 2026-10-28, commit 6a577af. Five synthetic
   pastes (2 MB with 400 Received, a 500 KB value with no spaces,
   a DKIM b= of 100 KB, Outlook rich text with no break spaces and
   soft hyphens, 5000 fields) stayed under 400 ms to the finding,
   so none of them was the stall. A probe of every field name the
   code reads with 25 and 50 KB unbroken runs found three regular
   expressions that rescanned a run from every character: PROP_RE
   in auth.js (Received-SPF and Authentication-Results properties),
   the Proofpoint key=value scan in providers.js, and the List-Id
   angle bracket match in finding.js. 100 KB in Received-SPF took
   38.8 seconds to the finding in Chromium, Proofpoint 13.2, List-Id
   5.7. Each now starts a match only at a token boundary and runs in
   linear time. The Outlook paste was also misread: soft hyphens
   inside field names hid 64 of 67 fields, so parse.js drops soft
   hyphens and zero width characters. The raw header list was drawn
   in full on every read (20,707 nodes for 2 MB, 620 ms to open,
   650 ms per search keystroke); app.js now draws it when opened,
   200 fields at a time, with fields over 2,000 characters clipped
   behind a Show all button. test/large-input.test.js fails if
   analyze() takes 500 ms on any of the five pastes or the three
   runs. Neil's original paste was not available, so the cause is
   the likeliest match, not a confirmed one.
   Copy pass 2026-10-28 over docs/sentences.md: compauth meanings
   now carry the result Microsoft writes with each code (the table
   had paired every code with fail), with a plain line per result
   and the meaning alone on the technical line; a test fails if a
   pass code renders the word fail. A detail that restates the
   cause is dropped. SPF details get one sentence per result. No
   never, no Technical view, fewer metaphors. Commit f03d76b; follow-up a35d376 (no pointer
   line, no SPF detail that repeats the cause).
   Second half the same day: the receiver judging differently and
   strict alignment headlines read passed and aligns with the From
   domain; strict alignment now offers the adkim=s fix (sign with
   the From domain or relax the record) instead of the custom
   return path; DKIM temperror gets its own fix; forwarded and
   mailing list wording cut down; the CAT versus SCL and BCL
   threshold sentences moved off every item into one note on the
   Microsoft card. Commit 2120673.
   Still to do: more real headers from Neil and the copy pass they
   drive.

Decisions

2026-10-15  Runs entirely in the browser. No server, no network
            calls, no DNS, no signature verification.
2026-10-28  One network call after all: a usage note with the
            finding status, posted to dns-audit.com/api/usage, so
            Neil can see the tool is used. Headers still never leave,
            but the page no longer says so: the policy panel and the
            "leave my browser" FAQ are gone.
2026-10-23  Step 2 check rules, as listed in CLAUDE.md under
            Settled by the step 2 check.
2026-10-24  Renamed Header Verdict to Email Header Decoder; the one
            sentence result is the finding.
2026-10-25  Hosted at headers.dns-audit.com as a static site on
            Cloudflare, styled as part of the dns-audit.com family.
            A subdomain, not a path, for simplicity; neither harms
            search.
2026-10-25  Public repo with a Beta label; version stays under 1.0.
2026-10-25  Plain wording first. The plain headline leads and the
            technical one sits under it; the switch changes the rest.
            The voice choice is no longer kept in localStorage, so
            the no storage rule holds.
2026-10-25  Links to dns-audit.com, Neil's LinkedIn, and the GitHub
            repo are allowed on the page. A link sends nothing until
            followed; the CSP still blocks every request the page
            itself could make. The build refuses any other host.
2026-10-25  Static guide and FAQ under the tool, for readers and for
            search and AI crawlers. The JSON-LD FAQ is generated
            from the page's FAQ so the two match; a test checks it.
2026-10-25  The page opens on the forwarded sample, labelled as a
            sample. Reversed 2026-10-28: the box opens empty, as Neil
            found headers already in it that he had to delete first.
            The sample buttons stay.
2026-10-25  Check tiles and Copy report read values already in the
            result. When the finding blames a forward, the tiles say
            failed after the forward and passed before it, from the
            first ARC set.
2026-10-25  X-Microsoft-Antispam-Mailbox-Delivery is shown in the
            Microsoft group as written. Microsoft does not document
            it, so dest, ucf, jmr, OFR, and RF get no meaning, the
            same rule as X-Gm-Spam.
2026-10-25  Audit fixes. A forward is blamed only when the receiver
            reported arc=pass or Microsoft compauth reason 130; the
            page does not verify seals, and a sender can write an i=1
            set. forwarded.txt (no arc=, reason 000) now reads as a
            fail with the forward noted but not relied on. Beside the
            primary, an Authentication-Results field fills methods
            only above the receiver's first Received stamp, and with
            no sender side hop Received-SPF must sit above it too.
            A DKIM result with only header.i is matched by header.b
            or header.s and takes d= from the signature. A subdomain
            From quotes sp= and names the organizational domain. The
            CSP allows the inline script by its sha256 instead of
            'unsafe-inline'.
2026-10-27  The original step 3 prompt came in again after step 3
            was done. Treated it as a gap check, not a redo: the
            finding already covered every case it lists.
2026-10-27  Item levels stay pass, info, warn, fail, not the
            prompt's ok and bad. The page, the tests, and the
            sentence states already use them.
2026-10-27  PCL meanings come from the Exchange Server antispam
            stamps table (1 to 3 Neutral, 4 to 8 Suspicious), the
            only one Microsoft publishes. 0 and other values show
            raw.
2026-10-27  SFS shows raw and is marked as not in the published
            table. Microsoft documents no rule IDs.
2026-10-27  The Message-ID domain is info only, never a warning.
            Sending platforms routinely use their own domain.
2026-10-27  Sentence inventory. Cases are built from synthetic
            headers in the script, not fixtures, all with the same
            domains so a duplicate cause is a real one. Two causes
            count as the same only when both the technical and the
            plain sentence match. Each case lists headline, cause,
            policy, details, fixes, and flags in both voices; limits
            are left out, as the prompt did not list them.
2026-10-27  Causes made distinct where cases collided. causeOfFail
            now names SPF none, neutral, permerror, and temperror,
            DKIM permerror and temperror, and softfail apart from
            fail. The no DMARC record headline keeps would pass or
            would fail, and the reason moves to the cause. A cause
            quotes Microsoft compauth and its meaning when the
            receiver wrote one, since it is Microsoft's own reason.
            No From reads apart from a From naming two domains.
2026-10-27  package.json added for npm run sentences, with test and
            build scripts beside it. Still no dependencies.
2026-10-27  providers.js exports its code tables (TABLES), so the
            inventory lists every code the page knows and drives
            each one through the real decode.
2026-10-28  The paste box opens empty; the sample buttons stay.
            Neil found headers in the box he had to delete first.
2026-10-28  A header block pasted twice, one copy straight after the
            other, is read once with a note. Outlook pastes can
            double, and two From fields read as a forgery.
2026-10-28  Mailing list mail. When List-Id is present and a pass is
            on the list's own organizational domain, the finding
            blames the list, not the sender, unless the list's
            server recorded a failure before the list.
            Authentication-Results-Original or X-Original-
            Authentication-Results is quoted as that record but never
            relied on: the list's server wrote it. Fixes go to the
            list operator (Mailman DMARC mitigation named when
            X-Mailman-Version is present), never domain
            authentication at the sender.
2026-10-28  Everything under the finding (message, alignment,
            authentication, path, filter headers, raw headers) sits
            in one Full analysis section that starts closed. A tile
            or source link opens it. The first real paste ran to
            nearly 6,000 pixels and read as noise.
2026-10-28  The plain voice drops Microsoft compauth when it adds
            nothing (none, or a code with no plain meaning). The
            technical voice still quotes it.
2026-10-28  Plain view no longer repeats the headline in technical
            wording under it, and hides the raw line tags in the
            finding (the evidence fold and Full analysis keep them).
            Tiles say Passed or Passed for another domain, and the
            top line is just the header and hop count. Technical view
            is unchanged. Copy report still carries both headlines.
            Reverses the 2026-10-25 rule that the technical headline
            shows either way: on a real message it read as an echo.
2026-10-28  The wording switch reads Simple and Technical. Simple is
            written for a small business owner, with a fixed word
            list in CLAUDE.md (no aligned, bounce, policy, ARC, and
            the like) that a test enforces over every fixture.
            Technical keeps the protocol's own terms. Both follow
            Neil's house style. Line tags never show in Simple, and
            in Technical only in the evidence fold and Full analysis.
2026-10-28  The finding card reads top down under labels: the
            headline, What to do (Nothing to fix on a pass), The
            checks, Why, What the DMARC setting did, then the
            evidence fold. Copy report follows the same order. Simple
            tiles say Failed, matching the DMARC tile.
2026-10-28  Simple gets its contractions in one place (P.contract,
            run by sentence(), item(), and a last pass in analyze),
            not string by string. Technical keeps long forms because
            it can quote a receiver's words. The Simple word list and
            a no semicolon rule now cover docs/sentences.md too, which
            caught bounce address, policy, and a lowercase sentence
            start. List header notes rewritten in both voices.
            Precedence names bulk, list, and junk as the values
            software acts on. Hops without a time zone share one
            note. Counts under 10 are words.
2026-10-28  Simple may say the headers, meaning the text the reader
            pasted. A single named header and the word field stay
            out, and the test now enforces both. Simple also
            contracts it is, that is, there is, and here is when a
            word follows.
2026-10-28  The guide and FAQ follow house style: the What it reads
            list is full sentences, no semicolons, contractions, no
            quotation marks around aligned. The Full analysis panels
            keep their technical labels in both views, with
            contractions where they read as prose.
2026-10-28  Technical leads with the practitioner's word and puts the
            RFC identifier in brackets: Return-Path domain
            (RFC5321.MailFrom), From domain (RFC5322.From). Simple
            may use a listed term in brackets after its plain
            explanation, such as (Return-Path) and (SPF), so the
            reader learns the word their email service uses.
2026-10-28  The switch reads Summary and Technical. Simple read as
            talking down. Simple headlines split into the result,
            then the reason, so long sentences fell from 13 to four.
            SPF neutral, permerror, and temperror get everyday words.
2026-10-28  One output, no switch. The finding reads in plain words;
            a Technical details fold under it holds the technical
            headline, cause, consequence, fixes, evidence, and limits
            with line tags. Full analysis reads in technical wording.
            Nobody is sorted into a category. A test now parses
            ui/app.js, after a syntax error passed the suite.
2026-10-28  Large pastes. No regular expression may rescan a long
            run from each character: a scan for name=value starts
            only at a token boundary. The raw header list draws when
            opened, 200 fields at a time, and clips a field over
            2,000 characters until expanded. analyze() stays under
            500 ms in Node on the speed test inputs.
2026-10-28  A detail that repeats the cause word for word is dropped,
            and so is the forwarded already failing detail when the
            cause says it. compauth none reads as skipped for 3xx and
            bypassed for 4xx and 9xx. 8xx keeps fail in the inventory.
