# Sentence inventory

## pass by DKIM

Plain headline: This message passed the sender check (DMARC): it was signed by shop.example. That matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed, and it aligns with the RFC5322.From domain shop.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, aligned DKIM carries the pass, and it survives forwarding as long as nothing alters the signed headers or body.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

## pass by SPF

Plain headline: This message passed the sender check (DMARC): it came from a server that shop.example allows. That matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because SPF passed for the RFC5321.MailFrom domain shop.example, and it aligns with the RFC5322.From domain shop.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, only SPF carries the pass. A forward or a mailing list breaks it, because SPF checks whichever server hands the message over; aligned DKIM would keep it.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: DMARC rests on SPF alone, and forwarding breaks SPF. Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## pass by both

Plain headline: This message passed the sender check (DMARC): it was signed by shop.example and it came from a server that shop.example allows. Both match shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=shop.example s=s1 passed and SPF passed for the RFC5321.MailFrom domain shop.example, and both align with the RFC5322.From domain shop.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, both SPF and DKIM carry the pass, so it survives a forward that breaks SPF.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=none, which asks for no action. This message passed, so the policy did not come into play.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Your DMARC setting only watches. It doesn't stop fake mail that uses your domain. Once the DMARC reports show all your real mail passing, ask whoever manages the DNS for shop.example to change it to quarantine.

Fix 1, technical: shop.example publishes p=none, so forged mail is not stopped. Once aggregate reports show every real source passing, move to p=quarantine.

## pass reported with nothing aligned

Plain headline: This message was let through on trust: its own checks don't match shop.example, but the receiving system accepted it under its own rules.

Technical headline: DMARC passed at mx.receiver.example only because of a local policy or a result it did not write into these headers; in these headers there was no DKIM signature and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing aligned with the From domain shop.example.

Cause, plain: The checks don't line up, but the receiving system passed the message anyway, probably because of its own rules.

Cause, technical: No reported pass aligns with shop.example, yet the receiver reported dmarc=pass. A local policy, or a result it did not write into these headers, is the likely reason.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused. This message passed, so the policy did not come into play.

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The checks don't line up, but the receiving system passed the message anyway, probably because of its own rules.

Detail 2, technical: No reported pass aligns with shop.example, yet the receiver reported dmarc=pass. A local policy, or a result it did not write into these headers, is the likely reason.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: DMARC rests on SPF alone, and forwarding breaks SPF. Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## pass computed, no DMARC result reported

Plain headline: The receiving system didn't record the sender check, but working it out from what it did record, this message passed the sender check (DMARC): it was signed by shop.example. That matches shop.example, the domain in the From address.

Technical headline: mx.receiver.example recorded no DMARC result; worked out from the identifiers, DMARC passes because DKIM d=shop.example s=s1 passed, and it aligns with the RFC5322.From domain shop.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For shop.example, aligned DKIM carries the pass, and it survives forwarding as long as nothing alters the signed headers or body. Worked out here; the receiver recorded no DMARC result.

Policy, plain: The headers don't say what shop.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of shop.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Nothing needs fixing. If you want both checks to match, give the service that sends this mail a custom return address on shop.example (often called a custom return path).

Fix 1, technical: Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under shop.example at the sending service.

## fail with no DKIM signature

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server check for shop.example came out neutral, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF was neutral for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The sender's list of approved servers couldn't be read, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The SPF record of shop.example makes no statement about the server that handed the message over (neutral), so SPF did not pass.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out neutral.

Detail 1, technical: SPF was neutral for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## fail with DKIM unaligned

Plain headline: This message failed the sender check (DMARC) because it was signed by mailer.example and it came from a server that bounce.mailer.example allows, but neither of those is shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=mailer.example s=m1 passed and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, but neither aligns with the RFC5322.From domain shop.example.

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender.

Cause, technical: The checks passed, but for mailer.example and bounce.mailer.example, domains that are not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## fail with DKIM broken in transit

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example didn't check out and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example (body hash did not verify): something changed the signed part of the message after signing, or the key in DNS does not match. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example s=s1 (body hash did not verify). Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The signature on this message was damaged on the way. Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That is the usual cause.

Fix 1, technical: The signature from d=shop.example broke between signing and mx.receiver.example. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at s1._domainkey.shop.example is the one it signs with.

## fail with SPF for the bounce domain only

Plain headline: This message failed the sender check (DMARC) because it carried no signature and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender.

Cause, technical: The checks passed, but for bounce.mailer.example, a domain that is not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## fail with SPF for HELO only

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server called itself o1.mailer.example. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF passed for the HELO identity o1.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The message had no hidden return address, so the only check that passed was on the sending server's own name, which doesn't belong to shop.example.

Cause, technical: SPF passed only for the server name o1.mailer.example, which is not shop.example. The bounce address was empty, so SPF checked the name the sending server gave itself (HELO) instead of a sender domain, and nothing else passed for shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The sending server is approved, but by o1.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for the HELO name o1.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## fail with SPF fail

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## fail with SPF softfail

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF soft failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out softfail.

Detail 1, technical: SPF soft failed for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## fail with SPF none

Plain headline: This message failed the sender check (DMARC) because it carried no signature and shop.example publishes no list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF found no record for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The sender's domain publishes no list of approved servers, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. shop.example publishes no SPF record, so SPF could not pass.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out none.

Detail 1, technical: SPF found no record for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: Ask whoever manages the DNS for shop.example to publish an SPF record listing the services that send your mail.

Fix 2, technical: Publish an SPF record for shop.example that lists the servers that send for it.

## fail with SPF permerror

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server check for shop.example came out permerror, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF hit a permanent error in the record for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The sender's list of approved servers couldn't be read, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The SPF record of shop.example could not be evaluated (permerror): it has a syntax error or needs more than 10 DNS lookups.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out permerror.

Detail 1, technical: SPF hit a permanent error in the record for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: The SPF record for shop.example is broken, often because it lists too many services. Ask whoever manages its DNS to check and simplify it.

Fix 2, technical: Repair the SPF record of shop.example: check its syntax and keep it within 10 DNS lookups.

## fail with SPF temperror

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server check for shop.example came out temperror, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because there was no DKIM signature and SPF hit a temporary DNS error for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The sender's list of approved servers couldn't be read, and nothing else proves the mail came from shop.example.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. A temporary DNS error kept mx.receiver.example from evaluating the SPF record of shop.example (temperror).

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The check of the sending server against shop.example came out temperror.

Detail 1, technical: SPF hit a temporary DNS error for shop.example.

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## fail with DKIM permerror

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example couldn't be checked and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM for shop.example returned permerror and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The signature on the message couldn't be checked, and nothing else proves it came from shop.example.

Cause, technical: The DKIM signature from shop.example could not be checked at mx.receiver.example (dkim=permerror): the key at s1._domainkey.shop.example is missing or unreadable, or the signature itself is malformed. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example couldn't be checked.

Detail 1, technical: DKIM returned permerror for d=shop.example s=s1 (no key for signature).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The key that checks this signature couldn't be read. Ask whoever manages the DNS for shop.example to compare the record named s1._domainkey.shop.example with what the service that sends this mail says it should be.

Fix 1, technical: Publish or repair the DKIM key at s1._domainkey.shop.example; mx.receiver.example could not use it.

## fail with DKIM temperror

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example couldn't be checked and it came from a server that bounce.mailer.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM for shop.example returned temperror and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The signature on the message couldn't be checked, and nothing else proves it came from shop.example.

Cause, technical: The DKIM signature from shop.example could not be checked at mx.receiver.example (dkim=temperror): a temporary DNS error kept it from fetching the key. SPF passed only for bounce.mailer.example, which is not shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example couldn't be checked.

Detail 1, technical: DKIM returned temperror for d=shop.example s=s1 (key query timeout).

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: These headers don't show one clear fix. Send the same message to another mailbox, such as Gmail or Outlook, and compare.

Fix 1, technical: Nothing in these headers points at a single change. Compare with a copy of the same message delivered to a different mailbox provider.

## fail computed, no DMARC result reported

Plain headline: The receiving system didn't record the sender check, but working it out from what it did record, this message fails the sender check (DMARC) because it was signed by mailer.example and shop.example publishes no list of approved servers. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: mx.receiver.example recorded no DMARC result; worked out from the identifiers, DMARC fails because DKIM d=mailer.example s=m1 passed and SPF found no record for the RFC5321.MailFrom domain shop.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The sender's domain publishes no list of approved servers, and nothing else proves the mail came from shop.example.

Cause, technical: DKIM passed only for mailer.example, which is not shop.example. shop.example publishes no SPF record, so SPF could not pass.

Policy, plain: The headers don't say what shop.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of shop.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The check of the sending server against shop.example came out none.

Detail 2, technical: SPF found no record for shop.example.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Ask whoever manages the DNS for shop.example to publish an SPF record listing the services that send your mail.

Fix 2, technical: Publish an SPF record for shop.example that lists the servers that send for it.

## fail through a mailing list

Plain headline: This message failed the sender check (DMARC) because it came through the mailing list club.list.example. The list changed the message, which broke the sender's signature, and sent it on under its own domain, list.example, not shop.example.

Technical headline: DMARC failed because the message came through the mailing list club.list.example, which changed it, breaking the DKIM signature from shop.example, and sent it on as list.example, which does not align with the RFC5322.From domain shop.example.

Cause, plain: The headers carry no record of how the message looked before the list, so this page can't confirm the sender's own setup. Lists break these checks by changing the message, for example by adding a footer.

Cause, technical: No record from before the list is in the headers, so this page cannot show that the message passed before the list changed it. Lists break signatures by tagging the subject or adding a footer.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example didn't check out, because the mailing list changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message came through a mailing list, and lists change it enough to break the signature.

Detail 2, plain: The sending server is approved, but by list.example, not by the sender's own domain.

Detail 2, technical: SPF passed for list.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: If you sent this, your setup isn't the problem as far as these headers show. Mailing lists that change messages break these checks. That's a known side effect.

Fix 1, technical: Nothing to change at shop.example on the strength of this message. Mail through a list that changes messages fails DMARC unless the list rewrites the From address or the receiver trusts the list's ARC seal.

Fix 2, plain: If you run the list: have it send under its own address (it can keep the sender's name), or stop it adding a subject tag and a footer.

Fix 2, technical: If you run club.list.example: have the list rewrite the From address to its own; or stop tagging the subject and adding a footer; or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.

## fail through a mailing list that kept its record

Plain headline: This message failed the sender check (DMARC) because it came through the mailing list club.list.example. The list changed the message, which broke the sender's signature, and sent it on under its own domain, list.example, not shop.example.

Technical headline: DMARC failed because the message came through the mailing list club.list.example, which changed it, breaking the DKIM signature from shop.example, and sent it on as list.example, which does not align with the RFC5322.From domain shop.example.

Cause, plain: Before the list, the list's own server recorded that the message passed. The sender's setup looks fine. The list broke the checks by changing the message, for example by adding a footer.

Cause, technical: Before the list, mx.list.example recorded dkim=pass (shop.example), spf=pass (news@shop.example), and dmarc=pass (shop.example) in its Authentication-Results-Original field. The list's own server wrote that record and this page cannot verify it, but it shows the message passed on arrival. Lists break signatures by tagging the subject or adding a footer.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example didn't check out, because the mailing list changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message came through a mailing list, and lists change it enough to break the signature.

Detail 2, plain: The sending server is approved, but by list.example, not by the sender's own domain.

Detail 2, technical: SPF passed for list.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: If you sent this, your setup isn't the problem. Mailing lists that change messages break these checks. That's a known side effect.

Fix 1, technical: Nothing to change at shop.example: its mail passed before the list. Mail through a list that changes messages fails DMARC unless the list rewrites the From address or the receiver trusts the list's ARC seal.

Fix 2, plain: If you run the list: have it send under its own address (it can keep the sender's name), or stop it adding a subject tag and a footer.

Fix 2, technical: If you run club.list.example: have the list rewrite the From address to its own; or stop tagging the subject and adding a footer; or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.

## fail with the receiver judging differently

Plain headline: This message failed the sender check (DMARC), though it was signed for shop.example. The receiving system judged it differently from this page.

Technical headline: DMARC at mx.receiver.example failed at mx.receiver.example even though DKIM d=shop.example s=s1 passed aligns with the From domain shop.example.

Cause, plain: The checks line up, but the receiving system marked the message as failing anyway, probably because of its own rules.

Cause, technical: The identifiers align and the receiver reported them as passing, yet it reported dmarc=fail. A local policy, or a result it did not write into these headers, is the likely reason.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The headers don't say which domain the sending server was checked against.

Detail 2, technical: No SPF domain: there is no smtp.mailfrom, Received-SPF envelope-from or Return-Path to read it from.

Detail 3, plain: The checks line up, but the receiving system marked the message as failing anyway, probably because of its own rules.

Detail 3, technical: The identifiers align and the receiver reported them as passing, yet it reported dmarc=fail. A local policy, or a result it did not write into these headers, is the likely reason.

Fix 1, plain: These headers don't show one clear fix. Send the same message to another mailbox, such as Gmail or Outlook, and compare.

Fix 1, technical: Nothing in these headers points at a single change. Compare with a copy of the same message delivered to a different mailbox provider.

## strict alignment suspected

Plain headline: This message failed the sender check (DMARC) although it was signed by a domain in the same organization as shop.example. The sender's DMARC setting probably demands an exact domain match.

Technical headline: DMARC at mx.receiver.example failed even though DKIM d=mail.shop.example s=s1 passed aligns with shop.example in relaxed mode, so the DMARC record most likely requires strict alignment (adkim=s); the record itself is not in the headers.

Cause, plain: The sending domain's DMARC record probably demands an exact domain match, and this message only matches the wider organization.

Cause, technical: The receiver reported dmarc=fail and the identifiers align only in relaxed mode, so the record most likely sets adkim=s. The DMARC record decides; this page cannot read it without DNS.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The message was signed by mail.shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=mail.shop.example s=s1, which aligns with shop.example in relaxed mode only.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 3, plain: The sending domain's DMARC record probably demands an exact domain match, and this message only matches the wider organization.

Detail 3, technical: The receiver reported dmarc=fail and the identifiers align only in relaxed mode, so the record most likely sets adkim=s. The DMARC record decides; this page cannot read it without DNS.

Fix 1, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 1, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## dmarc none, would pass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would pass.

Technical headline: DMARC did not apply because mx.receiver.example found no DMARC record for shop.example; with one, this message would pass.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message is set up to pass once there is one.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would pass, because DKIM d=shop.example s=s1 passed, and it aligns with the RFC5322.From domain shop.example.

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example s=s1, which aligns with shop.example.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## dmarc none, would fail

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because mx.receiver.example found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 3, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 3, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## dmarc bestguesspass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. The message would pass if the domain had one.

Technical headline: DMARC did not apply: mx.receiver.example reported dmarc=bestguesspass, meaning shop.example has no DMARC record but the message would pass if it had one.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message is set up to pass once there is one.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would pass, because SPF passed for the RFC5321.MailFrom domain shop.example, and it aligns with the RFC5322.From domain shop.example.

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## dmarc permerror

Plain headline: The sender check couldn't run because the DMARC record of shop.example is written wrong.

Technical headline: DMARC could not be evaluated because mx.receiver.example hit a permanent error reading the DMARC record for shop.example (dmarc=permerror).

Cause, plain: The record is there but broken, so mail systems treat the domain as if it had none.

Cause, technical: A permanent error means the record exists but cannot be read: a syntax mistake, a missing v=DMARC1, or more than one record. Computed from the identifiers, the message would pass.

Policy: none written

Detail 1, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 1, technical: SPF passed for shop.example, which aligns with shop.example.

Fix 1, plain: The sender's DMARC record is written wrong, so mail systems ignore it. Ask whoever manages the DNS for shop.example to check the record named _dmarc.shop.example for typos, or for a second copy that should be deleted.

Fix 1, technical: Fix the DMARC record at _dmarc.shop.example: mx.receiver.example could not parse it. Look for a mistyped tag, a missing v=DMARC1 at the start, or two records at the same name.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

## dmarc temperror

Plain headline: The sender check couldn't run because looking up the DMARC record of shop.example failed for a temporary reason.

Technical headline: DMARC could not be evaluated because mx.receiver.example hit a temporary DNS error looking up the DMARC record for shop.example (dmarc=temperror).

Cause, plain: The lookup failed this time. The next one may work.

Cause, technical: A temporary error says nothing about the record itself. Computed from the identifiers, the message would fail.

Policy: none written

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: The check failed for a temporary reason. If it keeps happening, ask whoever hosts the DNS for shop.example whether their servers had trouble.

Fix 1, technical: The DMARC lookup failed for a temporary reason, so there is nothing to fix from these headers. If it repeats, check the DNS hosting of shop.example.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 3, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 3, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## dmarc result outside RFC 7489

Plain headline: The receiving system recorded a sender check result this page doesn't know.

Technical headline: mx.receiver.example reported dmarc=policy, a result outside RFC 7489, so it is shown as written.

Cause, plain: The details below show what was checked.

Cause, technical: The identifiers are in the details below; the page does not guess what the receiver meant.

Policy: none written

Detail 1, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 1, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

## forwarded with arc=pass

Plain headline: This message failed the sender check (DMARC) because it was forwarded by forward.example. It passed before the forward, and the forward broke it.

Technical headline: DMARC at mx.receiver.example failed because the message was forwarded by forward.example: before the forward, mx.forward.example recorded spf=pass (orders@shop.example), dkim=pass (shop.example), and dmarc=pass (shop.example), and after it DKIM d=shop.example s=s1 failed verification and SPF soft failed for the RFC5321.MailFrom domain shop.example.

Cause, plain: The sender set things up correctly. Forwarding changed the message on the way, which is a known side effect of forwarding.

Cause, technical: The failure belongs to the forward, not to the sender. The message passed on arrival at mx.forward.example. The forward broke SPF: it sent the message on from its own server, which the SPF record of shop.example does not authorize (spf=softfail). It also broke the DKIM signature from shop.example by changing the message.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example didn't check out, most likely because the forward changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message was forwarded, and forwarders often change it enough to break the signature.

Detail 2, plain: The check of the sending server against shop.example came out softfail.

Detail 2, technical: SPF soft failed for shop.example. A forward sends from the forwarder's own server, which the sender's SPF record does not list.

Fix 1, plain: The sender did nothing wrong. If you set up this forward, ask whoever runs the receiving mailbox to trust the forwarding service (forward.example). In Microsoft 365, an administrator adds it under Trusted ARC sealers in the Defender portal.

Fix 1, technical: Nothing at the sender fixes a forward. If the forward is yours, have the final mailbox trust the forwarder's ARC seal: Gmail weighs ARC on its own; Microsoft 365 honors it only for sealers an admin adds as trusted ARC sealers in the Defender portal.

Fix 2, plain: If you didn't set up this forward, there is nothing to change. Ask for a copy sent straight to you to check the sender.

Fix 2, technical: If the forward is not yours, authentication worked as designed. Judge the sender by a copy delivered straight to the mailbox.

## forwarded, noted but not relied on

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example didn't check out and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=shop.example s=s1 failed verification and SPF soft failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key.

Cause, technical: The DKIM signature from shop.example did not verify at mx.receiver.example: something changed the signed part of the message after signing, or the key in DNS does not match. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The signature from shop.example didn't check out, most likely because the forward changed the message.

Detail 1, technical: DKIM failed for d=shop.example s=s1. The message was forwarded, and forwarders often change it enough to break the signature.

Detail 2, plain: The check of the sending server against shop.example came out softfail.

Detail 2, technical: SPF soft failed for shop.example. A forward sends from the forwarder's own server, which the sender's SPF record does not list.

Detail 3, plain: The forwarder claims the message passed before it was forwarded, but its record doesn't hold up, so this page doesn't rely on it.

Detail 3, technical: The forwarder's record says before the forward, mx.forward.example recorded spf=pass (orders@shop.example), dkim=pass (shop.example), and dmarc=pass (shop.example), but mx.receiver.example did not report arc=pass, and this page does not verify ARC seals, so that record is not relied on and the failure is not blamed on the forward.

Fix 1, plain: Ask for a copy sent straight to you, without the forward, and check that one. The forwarding service says the message passed before it forwarded it, but nothing here confirms that.

Fix 1, technical: Judge the sender by a copy delivered straight to the mailbox. The forwarder's record shows a pass before the forward, but the receiver did not confirm it, so this failure could come from the forward or from a forgery.

## forwarded, already failing before the forward

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example wasn't checked and it came from a server that forward.example allows. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because the DKIM signature from shop.example has no recorded result and SPF passed for the RFC5321.MailFrom domain forward.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The message failed the check before it was ever forwarded, so the problem is with the sender, not the forward.

Cause, technical: The message was already failing before the forward: mx.forward.example recorded spf=fail (orders@shop.example) and dmarc=fail (shop.example). SPF now passes only for the forwarder's domain forward.example, which does not count for shop.example.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: One signature on the message wasn't checked by the receiver.

Detail 1, technical: DKIM-Signature d=shop.example s=s1 carries no result from the receiver.

Detail 2, plain: The sending server is approved, but by forward.example, not by the sender's own domain.

Detail 2, technical: SPF passed for forward.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 3, plain: The message already failed the check before it was forwarded, so the problem is at the sender.

Detail 3, technical: The forward is not the cause: before the forward, mx.forward.example recorded spf=fail (orders@shop.example) and dmarc=fail (shop.example), so the message was already failing when it arrived there.

Fix 1, plain: The problem started before the forward. If shop.example didn't send this message, it is forged, and the failed check is working as it should.

Fix 1, technical: Look at the sender, not the forward: the message failed before it was forwarded. If shop.example did not send it, it is forged and DMARC did its job.

## no Authentication-Results

Plain headline: The receiving mail system didn't record its checks in these headers.

Technical headline: Nothing can be judged because there is no Authentication-Results field: receiver.example recorded no SPF, DKIM or DMARC result here.

Cause, plain: Without the receiver's own record there is nothing trustworthy to read.

Cause, technical: Some servers skip Authentication-Results, and some mail programs strip it when exporting. Results written by anyone else could be forged, so they are not used.

Policy: none written

Detail 1, plain: The message carries a signature, but no receiver's check of it is recorded.

Detail 1, technical: DKIM signatures present, not checked by any receiver here: d=shop.example (would align).

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

## Authentication-Results with no results

Plain headline: The receiving mail system recorded no checks for this message.

Technical headline: mx.receiver.example wrote Authentication-Results but recorded no SPF, DKIM or DMARC result in it, so there is nothing to judge.

Cause, plain: There is nothing in the record to go on.

Cause, technical: The field is there, but it lists no method this page reads (it reports none).

Policy: none written

Fix 1, plain: Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.

Fix 1, technical: Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.

## untrusted Authentication-Results claims a pass

Plain headline: This message failed the sender check (DMARC) because it was signed by mailer.example and the sending server isn't on shop.example's list of approved servers. Nothing that checked out matches shop.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example failed because DKIM d=mailer.example s=m1 passed and SPF failed for the RFC5321.MailFrom domain shop.example, and nothing that passed aligns with the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers.

Cause, technical: DKIM passed only for mailer.example, which is not shop.example. The server that handed the message over is not authorized by the SPF record of shop.example, as mx.receiver.example reported.

Policy, plain: shop.example's DMARC setting asks providers to refuse fake mail. The recipient's email provider refused this message.

Policy, technical: shop.example publishes p=reject, which asks for failing mail to be refused, and mx.receiver.example refused this message (dis=REJECT).

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example s=m1, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The check of the sending server against shop.example came out fail.

Detail 2, technical: SPF failed for shop.example.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

Flag 1, plain: One set of results in the headers claims the message passed, but the receiving system didn't write it, so it is ignored.

Flag 1, technical: An Authentication-Results field the receiver did not write claims dmarc=pass. It is ignored here: the sender or a hop before the receiver could have written it.

## no Received

Plain headline: This is the sender's own copy, so no mail system has checked it yet.

Technical headline: Nothing was checked because these headers have no Received fields: this is a sent or draft copy, and SPF, DKIM and DMARC are checked only by a receiving server.

Cause, plain: The checks happen when a message arrives, and this copy never arrived anywhere.

Cause, technical: A receiver writes Authentication-Results when it accepts the message. A copy that was never received has none.

Policy: none written

Detail 1, plain: The message carries a signature, but no receiver's check of it is recorded.

Detail 1, technical: DKIM signatures present, not checked by any receiver here: d=shop.example (would align).

Fix 1, plain: These headers come from a sent or draft copy. Open the message in the recipient's mailbox and copy its headers from there.

Fix 1, technical: Paste the headers of the copy the recipient received. This copy never passed through a receiving server, so nothing was checked.

## two From fields

Plain headline: This page can't check who sent the message, because the message names more than one sender.

Technical headline: DMARC cannot be judged because the message carries two From fields, so there is no single author domain to align with.

Cause, plain: The receiving system recorded a result, but the headers don't say which sender it checked.

Cause, technical: DMARC checks one author domain. mx.receiver.example still reported dmarc=pass for header.from=shop.example, but which address it judged is not in the headers.

Policy: none written

Fix 1, plain: Don't trust this message. It names more than one sender, which is a common trick in forged mail.

Fix 1, technical: Treat the message as suspicious: with no single From domain, DMARC cannot protect the recipient.

## From naming two domains

Plain headline: This page can't check who sent the message, because the sender line names addresses at more than one domain.

Technical headline: DMARC cannot be judged because the From field names addresses in two domains (shop.example and bank.example), so there is no single author domain to align with.

Cause, plain: Without one clear sender there is nothing to check.

Cause, technical: DMARC checks one author domain. Nothing is computed from any of the addresses.

Policy: none written

Fix 1, plain: Don't trust this message. It names more than one sender, which is a common trick in forged mail.

Fix 1, technical: Treat the message as suspicious: with no single From domain, DMARC cannot protect the recipient.

## no From

Plain headline: This page can't check who sent the message, because the sender's address is missing.

Technical headline: DMARC cannot be judged because there is no usable From address, so there is no single author domain to align with.

Cause, plain: Without one clear sender there is nothing to check.

Cause, technical: DMARC aligns SPF and DKIM with the author domain, and without one there is nothing to align with. Nothing is computed from any of the addresses.

Policy: none written

Fix 1, plain: The sender's address is missing, so copy the full headers again and make sure the From line is included.

Fix 1, technical: Paste the complete header block; there is no usable From address to check against.

## display name impersonation

Plain headline: This message passed the sender check (DMARC): it was signed by notify.example and it came from a server that notify.example allows. Both match notify.example, the domain in the From address.

Technical headline: DMARC at mx.receiver.example passed because DKIM d=notify.example s=n1 passed and SPF passed for the RFC5321.MailFrom domain notify.example, and both align with the RFC5322.From domain notify.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was.

Cause, technical: For notify.example, both SPF and DKIM carry the pass, so it survives a forward that breaks SPF.

Policy, plain: The headers don't say what notify.example asks mail providers to do with fake mail.

Policy, technical: mx.receiver.example did not quote the DMARC policy of notify.example, so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.

Detail 1, plain: The message was signed by notify.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=notify.example s=n1, which aligns with notify.example.

Detail 2, plain: The sending server is approved by notify.example, which belongs to the sender.

Detail 2, technical: SPF passed for notify.example, which aligns with notify.example.

Flag 1, plain: The name shown for the sender contains an address at bank.example, but the message really comes from notify.example. Forged mail often does this.

Flag 1, technical: The display name shows an address at bank.example, while the real From domain is notify.example. That is a common impersonation layout.

## Microsoft action oreject

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=000, meaning explicit authentication failed: DMARC failed and the policy is quarantine or reject.

Policy, plain: The sender's DMARC setting says to refuse fake mail. Microsoft kept the message but treated it as suspicious instead.

Policy, technical: Microsoft recorded action=oreject: the domain's policy is reject and Microsoft overrode it. Microsoft's own pages disagree on whether that means junk or quarantine, so the page does not say which. The message was not refused outright.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## Microsoft action quarantine

Plain headline: This message failed the sender check (DMARC) because the signature from shop.example didn't check out and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because DKIM d=shop.example failed verification and SPF soft failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The message was changed after it was signed, or the signature doesn't match the sender's published key. Microsoft's own sender check failed it too.

Cause, technical: The DKIM signature from shop.example did not verify at Microsoft 365 (body hash did not verify): something changed the signed part of the message after signing, or the key in DNS does not match. The SPF record of shop.example does not authorize the server that handed the message over and asks receivers to treat it as suspicious rather than fail it outright (softfail), as Microsoft 365 reported. Microsoft recorded compauth=fail reason=000, meaning explicit authentication failed: DMARC failed and the policy is quarantine or reject.

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Detail 1, plain: The signature from shop.example didn't check out.

Detail 1, technical: DKIM failed for d=shop.example (body hash did not verify). Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.

Detail 2, plain: The check of the sending server against shop.example came out softfail.

Detail 2, technical: SPF soft failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: The signature on this message was damaged on the way. Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave the service that sends this mail. That is the usual cause.

Fix 1, technical: The signature from d=shop.example broke between signing and Microsoft 365. Look for anything that edits mail after the sending service signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at <selector>._domainkey.shop.example is the one it signs with.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## Microsoft action none

Plain headline: This message failed the sender check (DMARC) because it was signed by mailer.example and it came from a server that bounce.mailer.example allows, but neither of those is shop.example, the domain in the From address.

Technical headline: DMARC at Microsoft 365 failed because DKIM d=mailer.example passed and SPF passed for the RFC5321.MailFrom domain bounce.mailer.example, but neither aligns with the RFC5322.From domain shop.example.

Cause, plain: The service sending this mail is using its own domain instead of shop.example, so the checks pass for the service but not for the sender. Microsoft's own sender check failed it too.

Cause, technical: The checks passed, but for mailer.example and bounce.mailer.example, domains that are not shop.example. That is what happens when the sending service's own domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain. Microsoft recorded compauth=fail reason=001, meaning implicit authentication failed: no authentication records, or only weak ones (SPF ~all or ?all, DMARC p=none).

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Detail 1, plain: The message was signed, but by mailer.example, not by the sender's own domain.

Detail 1, technical: DKIM passed for d=mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Detail 2, plain: The sending server is approved, but by bounce.mailer.example, not by the sender's own domain.

Detail 2, technical: SPF passed for bounce.mailer.example, which does not align with shop.example. A pass on another domain does not count for DMARC.

Fix 1, plain: In the settings of the service that sends this mail, turn on domain authentication for shop.example. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of mailer.example.

Fix 1, technical: At the sending service, set up domain authentication for shop.example so the DKIM signature carries d=shop.example or a subdomain of it, instead of d=mailer.example.

Fix 2, plain: Once the signature is fixed, you can also give the service that sends this mail a custom return address on shop.example. Services call it a custom return path or sending domain. It's optional.

Fix 2, technical: Second, after DKIM: set a custom Return-Path (bounce) domain under shop.example at the sending service so SPF aligns too.

## compauth 0xx, explicit fail

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=002, meaning the organization prohibits this sender and domain pair from sending spoofed mail.

Policy, plain: Microsoft refused the message because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=reject.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 1xx, pass

Plain headline: This message passed the sender check (DMARC): it was signed by shop.example and it came from a server that shop.example allows. Both match shop.example, the domain in the From address.

Technical headline: DMARC at Microsoft 365 passed because DKIM d=shop.example passed and SPF passed for the RFC5321.MailFrom domain shop.example, and both align with the RFC5322.From domain shop.example.

Cause, plain: A message passes when it is signed by, or sent for, the domain in its From address, and this one was. Microsoft's own sender check still passed it.

Cause, technical: For shop.example, both SPF and DKIM carry the pass, so it survives a forward that breaks SPF. Microsoft recorded compauth=pass reason=100, meaning SPF or DKIM passed and aligns with the From domain.

Policy, plain: The message passed, so the sender's DMARC setting didn't come into play.

Policy, technical: Microsoft recorded action=none; the message passed, so no action was needed.

Detail 1, plain: The message was signed by shop.example, which belongs to the sender.

Detail 1, technical: DKIM passed for d=shop.example, which aligns with shop.example.

Detail 2, plain: The sending server is approved by shop.example, which belongs to the sender.

Detail 2, technical: SPF passed for shop.example, which aligns with shop.example.

## compauth 2xx, soft pass

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because Microsoft 365 found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added. Microsoft's own sender check gave it a soft pass.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example. Microsoft recorded compauth=softpass reason=201, meaning the PTR of the From domain aligns with the subnet of the connecting IP's PTR.

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 3, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 3, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 3xx, not checked

Plain headline: shop.example has no DMARC setting, so the sender check didn't apply. With one, this message would fail.

Technical headline: DMARC did not apply because Microsoft 365 found no DMARC record for shop.example; with one, this message would fail.

Cause, plain: Without a DMARC setting, nothing stops others from sending mail that claims to be from shop.example. This message wouldn't pass if one were added.

Cause, technical: Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put shop.example in a From address without failing a policy. With a record this message would fail, because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example. Microsoft recorded compauth=none reason=300, meaning not checked for composite authentication (code 300 has no entry of its own).

Policy, plain: shop.example has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.

Policy, technical: shop.example publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Ask whoever manages the DNS for shop.example to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.

Fix 1, technical: Publish a DMARC record at _dmarc.shop.example with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.

Fix 2, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 2, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 3, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 3, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 4xx, bypassed

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=none reason=451, meaning bypassed composite authentication (code 451 has no entry of its own).

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 5xx, bounce not enforced

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check still passed it.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=pass reason=501, meaning DMARC not enforced: a valid bounce where sender and recipient had prior contact.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 6xx, implicit fail

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=601, meaning the From domain is one of the organization's accepted domains (self-to-self or intra-org spoofing).

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 7xx, history pass

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check still passed it.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=pass reason=701, meaning DMARC not enforced because the organization has a history of legitimate mail from this infrastructure.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 8xx, not in the table

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers. Microsoft's own sender check failed it too.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=fail reason=801, a code not in its published table.

Policy, plain: Microsoft put the message in junk or quarantine because of the sender's DMARC setting.

Policy, technical: Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## compauth 9xx, complex routing

Plain headline: This message failed the sender check (DMARC) because it carried no signature and the sending server isn't on shop.example's list of approved servers, so nothing proved the mail came from shop.example.

Technical headline: DMARC at Microsoft 365 failed because there was no DKIM signature and SPF failed for the RFC5321.MailFrom domain shop.example, so no identifier passed for the RFC5322.From domain shop.example.

Cause, plain: The server that sent this isn't on the sender's list of approved servers.

Cause, technical: There is no DKIM signature, so DMARC rests on SPF alone. The server that handed the message over is not authorized by the SPF record of shop.example, as Microsoft 365 reported. Microsoft recorded compauth=none reason=905, meaning DMARC not enforced because of complex routing, such as mail through on-premises Exchange or another service first.

Policy, plain: Microsoft took no action over the failure, so it didn't send the message to junk for this reason.

Policy, technical: Microsoft recorded action=none: it applied no DMARC action to this message.

Detail 1, plain: The check of the sending server against shop.example came out fail.

Detail 1, technical: SPF failed for shop.example (sender IP is 198.51.100.44).

Fix 1, plain: Turn on email signing (DKIM) for shop.example in the settings of the service that sends this mail. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.

Fix 1, technical: Turn on DKIM signing for shop.example at the sending service. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.

Fix 2, plain: If you sent this, ask whoever manages the DNS for shop.example to add the service that sends this mail to its list of allowed servers (the SPF record). The service's setup page gives the exact entry. If you didn't send it, someone else used your domain and this check caught it.

Fix 2, technical: If this is your mail, add the sending service to the SPF record of shop.example. If it is not, SPF did its job.

## Filter code meanings

Microsoft CAT NONE (pass). Technical: Threat category: No threat policy applied. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: No threat was detected.

Microsoft CAT SPM (fail). Technical: Threat category: Spam. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Filed as spam.

Microsoft CAT HSPM (fail). Technical: Threat category: High confidence spam. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Filed as spam with high confidence.

Microsoft CAT PHSH (fail). Technical: Threat category: Phishing. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as phishing.

Microsoft CAT HPHSH (fail). Technical: Threat category: High confidence phishing. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as phishing with high confidence.

Microsoft CAT HPHISH (fail). Technical: Threat category: High confidence phishing. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as phishing with high confidence.

Microsoft CAT BULK (warn). Technical: Threat category: Bulk. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as bulk mail, such as a newsletter.

Microsoft CAT SPOOF (fail). Technical: Threat category: Spoofing. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as a forged sender.

Microsoft CAT MALW (fail). Technical: Threat category: Malware. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Malware was found.

Microsoft CAT AMP (fail). Technical: Threat category: Anti-malware policy. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Caught by the malware filter.

Microsoft CAT FTBP (fail). Technical: Threat category: Anti-malware common attachments filter. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Caught by the attachment type filter.

Microsoft CAT SAP (fail). Technical: Threat category: Safe Attachments (Defender for Office 365). In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Caught by attachment scanning.

Microsoft CAT DIMP (fail). Technical: Threat category: Domain impersonation (Defender for Office 365). In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Looked like it was pretending to be a protected domain.

Microsoft CAT UIMP (fail). Technical: Threat category: User impersonation (Defender for Office 365). In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Looked like it was pretending to be a protected person.

Microsoft CAT GIMP (fail). Technical: Threat category: Mailbox intelligence impersonation (Defender for Office 365). In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Looked like it was pretending to be someone the recipient usually hears from.

Microsoft CAT BIMP (fail). Technical: Threat category: Brand impersonation (Defender for Office 365). In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Looked like it was pretending to be a known brand.

Microsoft CAT INTOS (fail). Technical: Threat category: Intra-organization phishing. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as phishing from inside the organization.

Microsoft CAT OSPM (warn). Technical: Threat category: Outbound spam. In cloud organizations CAT, not SCL, says how the message was filtered. Plain: Treated as outgoing spam.

Microsoft SFV NSPM (pass). Technical: Spam filtering marked it as not spam. Plain: Microsoft's spam filter decided this isn't spam.

Microsoft SFV SPM (fail). Technical: Spam filtering marked it as spam. Plain: Microsoft's spam filter decided this is spam.

Microsoft SFV BLK (fail). Technical: Filtering skipped; blocked because the sender is on the user's Blocked Senders list. Plain: The recipient had blocked this sender.

Microsoft SFV SFE (pass). Technical: Filtering skipped; allowed because the sender is on the user's Safe Senders list. Plain: The recipient had marked this sender as safe, so filtering was skipped.

Microsoft SFV SKA (pass). Technical: Filtering skipped: the sender is on an allowed senders or domains list in an anti-spam policy. Plain: An administrator had allowed this sender, so filtering was skipped.

Microsoft SFV SKB (fail). Technical: Marked as spam: the sender matched a blocked senders or domains list in an anti-spam policy. Plain: An administrator had blocked this sender.

Microsoft SFV SKI (pass). Technical: Filtering skipped: the source IP is on the IP Allow List in the connection filter policy. Plain: An administrator had allowed the sending server, so filtering was skipped.

Microsoft SFV SKN (pass). Technical: Filtering bypassed by an Exchange mail flow rule. Plain: A rule set by an administrator let this message skip the spam filter.

Microsoft SFV SKQ (info). Technical: Released from quarantine to the recipients. Plain: The message was held in quarantine and then released.

Microsoft SFV SKS (fail). Technical: Marked as spam before filtering, by a mail flow rule or an on-premises hybrid decision. Plain: A rule set by an administrator marked this message as spam.

Microsoft SCL -1 (pass). Technical: Spam confidence level -1: filtering skipped. In cloud organizations SCL does not decide the filing; CAT does. Plain: Spam filtering was skipped.

Microsoft SCL 0 (pass). Technical: Spam confidence level 0: not spam. In cloud organizations SCL does not decide the filing; CAT does. Plain: Not spam.

Microsoft SCL 1 (pass). Technical: Spam confidence level 1: not spam. In cloud organizations SCL does not decide the filing; CAT does. Plain: Not spam.

Microsoft SCL 2 (info). Technical: Spam confidence level 2 is inside Microsoft's range but has no published meaning, so it is shown as written. In cloud organizations SCL does not decide the filing; CAT does. Plain: Microsoft recorded a spam score this page can't interpret.

Microsoft SCL 5 (fail). Technical: Spam confidence level 5: spam. In cloud organizations SCL does not decide the filing; CAT does. Plain: Rated as spam.

Microsoft SCL 6 (fail). Technical: Spam confidence level 6: spam. In cloud organizations SCL does not decide the filing; CAT does. Plain: Rated as spam.

Microsoft SCL 7 (warn). Technical: Spam confidence level 7. Microsoft gives this value no meaning of its own and says 5 or higher generally means the message is considered bad. In cloud organizations SCL does not decide the filing; CAT does. Plain: Rated as likely spam.

Microsoft SCL 9 (fail). Technical: Spam confidence level 9: high confidence spam. In cloud organizations SCL does not decide the filing; CAT does. Plain: Rated as spam with high confidence.

Microsoft SCL 10 (info). Technical: SCL 10 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It is shown as written.

Microsoft BCL 0 (pass). Technical: Bulk complaint level 0: not from a bulk sender. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Not bulk mail.

Microsoft BCL 1 (info). Technical: Bulk complaint level 1: a bulk sender that generates few complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 2 (info). Technical: Bulk complaint level 2: a bulk sender that generates few complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 3 (info). Technical: Bulk complaint level 3: a bulk sender that generates few complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender with few complaints.

Microsoft BCL 4 (warn). Technical: Bulk complaint level 4: a bulk sender that generates a mixed number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 5 (warn). Technical: Bulk complaint level 5: a bulk sender that generates a mixed number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 6 (warn). Technical: Bulk complaint level 6: a bulk sender that generates a mixed number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 7 (warn). Technical: Bulk complaint level 7: a bulk sender that generates a mixed number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people sometimes complain about.

Microsoft BCL 8 (fail). Technical: Bulk complaint level 8: a bulk sender that generates a high number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people often complain about.

Microsoft BCL 9 (fail). Technical: Bulk complaint level 9: a bulk sender that generates a high number of complaints. The tenant's threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers. Plain: Bulk mail from a sender people often complain about.

Microsoft PCL 1 (pass). Technical: Phishing confidence level 1: Neutral, the content is not likely phishing. Plain: The content didn't look like phishing.

Microsoft PCL 4 (warn). Technical: Phishing confidence level 4: Suspicious, the content is likely phishing. Plain: The content looked like phishing.

Microsoft PCL 9 (info). Technical: PCL 9 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It is shown as written.

Microsoft IPV CAL (pass). Technical: Skipped spam filtering: the source IP is on the IP Allow List. Plain: An administrator had allowed the sending server.

Microsoft IPV NLI (pass). Technical: The IP address was not found on any IP reputation list. Plain: The sending server wasn't on any reputation list Microsoft checks.

Microsoft IPV XYZ (info). Technical: IPV XYZ is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It is shown as written.

Microsoft SRV BULK (warn). Technical: Identified as bulk by spam filtering and the BCL threshold. Plain: Treated as bulk mail.

Microsoft SFTY 9.19 (warn). Technical: Identified as phishing and given the domain impersonation safety tip. Plain: Outlook showed a warning: domain impersonation.

Microsoft SFTY 9.20 (warn). Technical: Identified as phishing and given the user impersonation safety tip. Plain: Outlook showed a warning: user impersonation.

Microsoft SFTY 9.25 (warn). Technical: Identified as phishing and given the first contact safety tip. Plain: Outlook showed a warning: first contact.

Microsoft DIR INB (info). Technical: Direction: inbound message. Plain: Microsoft treated this as inbound mail.

Microsoft DIR OUT (info). Technical: Direction: outbound message. Plain: Microsoft treated this as outbound mail.

Microsoft DIR INT (info). Technical: Direction: internal message. Plain: Microsoft treated this as internal mail.

Microsoft CIP 198.51.100.44 (info). Technical: Connecting IP as Microsoft saw it. Plain: The address of the server that handed the message to Microsoft.

Microsoft CTRY US (info). Technical: Country or region of the connecting IP, which may differ from where the message started. Plain: Where the server that handed it over is.

Microsoft H o1.sender.example (info). Technical: HELO or EHLO name the connecting server gave. Plain: The name the sending server gave itself.

Microsoft PTR o1.sender.example (info). Technical: Reverse DNS of the connecting IP, as Microsoft looked it up. Plain: The name registered for the sending server's address.

Microsoft SFS (13230040) (info). Technical: SFS (13230040) is not in Microsoft's published table, so it is shown as written. Plain: Microsoft recorded a code this page doesn't know. It is shown as written.

Microsoft AuthAs Internal (info). Technical: Treated as internal, authenticated mail. Plain: Microsoft treated this as mail from inside the organization.

Microsoft AuthAs Anonymous (info). Technical: Treated as external, unauthenticated mail. Plain: Microsoft treated this as mail from outside the organization.

Microsoft AuthAs External (info). Technical: Authentication source External. Plain: Microsoft recorded this as authenticated mail from outside the organization.

Microsoft AuthAs Partner (info). Technical: Authentication source Partner. Plain: Microsoft recorded this as mail from a partner organization.

Microsoft AuthSource BN3PEPF0000B077.namprd04.prod.outlook.com (info). Technical: The server that evaluated authentication for the organization. Plain: The Microsoft server that checked who sent this.

Microsoft compauth fail reason=100 (fail). Technical: Composite authentication fail: SPF or DKIM passed and aligns with the From domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=101 (fail). Technical: Composite authentication fail: DKIM signed by the From domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=102 (fail). Technical: Composite authentication fail: SPF passed and the MAIL FROM aligns with the From domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=103 (fail). Technical: Composite authentication fail: the From domain aligns with the PTR record of the source IP. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=104 (fail). Technical: Composite authentication fail: the PTR record of the source IP aligns with the From domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=108 (fail). Technical: Composite authentication fail: DKIM failed because an earlier legitimate hop modified the body. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=109 (fail). Technical: Composite authentication fail: no DMARC record, but the message would pass. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=111 (fail). Technical: Composite authentication fail: DMARC hit an error, but SPF or DKIM aligns with the From domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=112 (fail). Technical: Composite authentication fail: a DNS timeout prevented the DMARC record lookup. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=115 (fail). Technical: Composite authentication fail: sent from a Microsoft 365 organization where the From domain is an accepted domain. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=116 (fail). Technical: Composite authentication fail: the MX record of the From domain aligns with the PTR record of the connecting IP. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=130 (fail). Technical: Composite authentication fail: an ARC result from a trusted ARC sealer overrode the DMARC failure. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=201 (fail). Technical: Composite authentication fail: the PTR of the From domain aligns with the subnet of the connecting IP's PTR. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=202 (fail). Technical: Composite authentication fail: the From domain aligns with the domain of the connecting IP's PTR record. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=501 (fail). Technical: Composite authentication fail: DMARC not enforced: a valid bounce where sender and recipient had prior contact. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=502 (fail). Technical: Composite authentication fail: DMARC not enforced: a valid bounce for a message this organization sent. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=601 (fail). Technical: Composite authentication fail: the From domain is one of the organization's accepted domains (self-to-self or intra-org spoofing). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=905 (fail). Technical: Composite authentication fail: DMARC not enforced because of complex routing, such as mail through on-premises Exchange or another service first. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=000 (fail). Technical: Composite authentication fail: explicit authentication failed: DMARC failed and the policy is quarantine or reject. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=001 (fail). Technical: Composite authentication fail: implicit authentication failed: no authentication records, or only weak ones (SPF ~all or ?all, DMARC p=none). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=002 (fail). Technical: Composite authentication fail: the organization prohibits this sender and domain pair from sending spoofed mail. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=010 (fail). Technical: Composite authentication fail: DMARC failed with quarantine or reject, and the From domain is one of the organization's own accepted domains. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=701 (fail). Technical: Composite authentication fail: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=702 (fail). Technical: Composite authentication fail: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=703 (fail). Technical: Composite authentication fail: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=704 (fail). Technical: Composite authentication fail: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure. Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=299 (fail). Technical: Composite authentication fail: soft-passed implicit authentication (code 299 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=399 (fail). Technical: Composite authentication fail: not checked for composite authentication (code 399 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=499 (fail). Technical: Composite authentication fail: bypassed composite authentication (code 499 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=699 (fail). Technical: Composite authentication fail: failed implicit authentication (code 699 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=799 (fail). Technical: Composite authentication fail: passed implicit authentication (code 799 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=999 (fail). Technical: Composite authentication fail: bypassed composite authentication (code 999 has no entry of its own). Plain: Microsoft's own sender check failed. The Technical view gives its reason.

Microsoft compauth fail reason=801 (fail). Technical: Composite authentication fail. Reason code 801 is not in Microsoft's published table, so it is shown as written. Plain: Microsoft's own sender check failed. Its reason code isn't one Microsoft explains publicly.

Proofpoint rule notspam (pass). Technical: Classification rule notspam: not spam. Plain: Proofpoint decided this isn't spam.

Proofpoint policy default (info). Technical: Policy route applied. Plain: The Proofpoint rule set that handled the message.

Proofpoint score 0 (info). Technical: score 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint spamscore 0 (info). Technical: spamscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint phishscore 0 (info). Technical: phishscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint bulkscore 0 (info). Technical: bulkscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint malwarescore 0 (info). Technical: malwarescore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint suspectscore 0 (info). Technical: suspectscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint impostorscore 0 (info). Technical: impostorscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint adultscore 0 (info). Technical: adultscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint mlxscore 0 (info). Technical: mlxscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint clxscore 0 (info). Technical: clxscore 0. The customer sets the thresholds, which are not in the headers, so the score is shown as written. Plain: A Proofpoint score of 0. What it leads to is set by the receiving organization.

Proofpoint rule spam (fail). Technical: Classification rule spam: spam. Plain: Proofpoint decided this is spam.

Proofpoint rule custom_rule (info). Technical: Classification rule custom_rule. The customer names its own rules, so it is shown as written. Plain: Proofpoint applied a rule named custom_rule.

Mimecast Spam-Score 4 (info). Technical: Mimecast spam score; higher is worse. Mimecast publishes no scale for it and the customer sets the thresholds. Plain: Mimecast's spam score. Higher is worse.

Mimecast Impersonation-Protect Similar Monitored External Domain (warn). Technical: Impersonation Protect (policy Default) flagged: Similar Monitored External Domain. Plain: Mimecast thought the sender might be pretending to be someone.

Mimecast Bulk-Signature yes (info). Technical: Mimecast bulk signature, shown as written. Plain: Mimecast checked whether this is bulk mail.

Mimecast Impersonation-Protect nothing fired (pass). Technical: Impersonation Protect (policy Default): none of its 1 checks fired. Plain: Mimecast found no sign the sender was pretending to be someone.

Mimecast Impersonation-Protect opaque (info). Technical: Impersonation Protect ran; its value is in a form this page does not read, so it is shown as written. Plain: Mimecast checked whether the sender was pretending to be someone.

Mimecast X-Mimecast-Spam-Signature present (info). Technical: Mimecast handled this message; its other fields carry no documented result. Plain: Mimecast handled this message.

Cisco Anti-Spam-Filtered true (info). Technical: Anti-spam scanning ran on this message. Plain: Cisco scanned this message for spam.

Cisco X-IronPort-Anti-Spam-Result opaque (info). Technical: An encoded anti-spam result. Cisco does not publish how to read it. Plain: Cisco recorded a result in a form only Cisco can read.

Cisco X-IPAS-Result opaque (info). Technical: An encoded anti-spam result. Cisco does not publish how to read it. Plain: Cisco recorded a result in a form only Cisco can read.

Cisco Reputation -3.1 (info). Technical: SenderBase reputation score of the connecting IP, from -10 to +10; lower is worse. The customer's mail policies decide what a score does. Plain: Cisco's reputation score for the sending server. Lower is worse.

Cisco AV E=Sophos;i="6.00" (info). Technical: Anti-virus engine stamp, shown as written. Plain: Cisco scanned this message for viruses.

Cisco X-IronPort-MID 12345 (info). Technical: A Cisco Secure Email field with no documented result, shown as written. Plain: Cisco handled this message.

Barracuda Spam-Status Yes (fail). Technical: Classified as spam: score 7.1, tag level 3.5, block level 6.0. Plain: Barracuda decided this is spam.

Barracuda Spam-Status No (pass). Technical: Classified as not spam: score 0.2, tag level 3.5, block level 6.0. Plain: Barracuda decided this isn't spam.

Barracuda Spam-Status Maybe (info). Technical: Spam-Status Maybe is not in Barracuda's published table, so it is shown as written. Plain: Barracuda recorded a code this page doesn't know. It is shown as written.

Barracuda Spam-Score 1.5 (info). Technical: Barracuda score; the customer sets the thresholds. Plain: Barracuda's spam score.

Barracuda Spam-Flag YES (fail). Technical: Flagged as spam. Plain: Barracuda flagged this as spam.

Barracuda Spam-Flag NO (pass). Technical: Not flagged as spam. Plain: Barracuda didn't flag this as spam.

SpamAssassin X-Spam-Status Yes (fail). Technical: Classified as spam: score 6.2 against a threshold of 5.0. Plain: The filter decided this is spam.

SpamAssassin tests BAYES_99,URIBL_BLOCKED (info). Technical: Rules that matched. Plain: The filter rules this message matched.

SpamAssassin X-Spam-Status No (pass). Technical: Classified as not spam: score 0.1 against a threshold of 5.0. Plain: The filter decided this isn't spam.

SpamAssassin X-Spam-Status Unclear (info). Technical: X-Spam-Status Unclear is not in SpamAssassin's published table, so it is shown as written. Plain: SpamAssassin recorded a code this page doesn't know. It is shown as written.

SpamAssassin X-Spam-Flag YES (fail). Technical: Flagged as spam. Plain: The filter flagged this as spam.

SpamAssassin X-Spam-Score 6.2 (info). Technical: Spam score; the threshold is not in the headers. Plain: The filter's spam score.

SpamAssassin X-Spam-Flag NO (pass). Technical: Not flagged as spam. Plain: The filter didn't flag this as spam.

Rspamd X-Rspamd-Action no action (pass). Technical: No action: the message is not spam. Plain: Rspamd decided this isn't spam.

Rspamd X-Rspamd-Action greylist (warn). Technical: Greylisted: delivery was delayed once. Plain: Rspamd delayed the message once as a test.

Rspamd X-Rspamd-Action add header (fail). Technical: Marked as spam with a header. Plain: Rspamd marked this as spam.

Rspamd X-Rspamd-Action rewrite subject (fail). Technical: Marked as spam in the subject line. Plain: Rspamd marked this as spam in its subject.

Rspamd X-Rspamd-Action soft reject (warn). Technical: Temporarily refused. Plain: Rspamd asked the sender to try again later.

Rspamd X-Rspamd-Action reject (fail). Technical: Rejected as spam. Plain: Rspamd refused this as spam.

Rspamd X-Rspamd-Action quarantine (info). Technical: X-Rspamd-Action quarantine is not in Rspamd's published table, so it is shown as written. Plain: Rspamd recorded a code this page doesn't know. It is shown as written.

Rspamd X-Spamd-Result 16.20 / 15.00 (fail). Technical: Score 16.20 against a reject threshold of 15.00: over it. Plain: Rspamd scored this as spam.

Rspamd X-Spamd-Result 2.10 / 15.00 (info). Technical: Score 2.10 against a reject threshold of 15.00: under it. Lower actions, such as adding a spam header, have their own thresholds, which are not in the headers. Plain: Rspamd scored this below its refusal level.

Rspamd X-Spamd-Result unreadable (info). Technical: X-Spamd-Result unreadable is not in Rspamd's published table, so it is shown as written. Plain: Rspamd recorded a code this page doesn't know. It is shown as written.
