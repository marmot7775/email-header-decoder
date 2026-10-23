// psl.js: organizational domain, RFC 7489 style, from an abbreviated
// public suffix list. The full PSL is about 250 KB; this carries the
// multi-label suffixes that show up in mail, plus a rule that any
// unknown two-label name under a ccTLD with a known second level is a
// suffix. RFC 9989 receivers find the organizational domain with a DNS
// tree walk instead; that needs DNS, so this file is the first release
// approximation and the UI says so.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});

  const MULTI = `
ac.uk co.uk gov.uk ltd.uk me.uk net.uk nhs.uk org.uk plc.uk sch.uk police.uk
asn.au com.au edu.au gov.au id.au net.au org.au
ac.nz co.nz govt.nz net.nz org.nz school.nz
ac.jp ad.jp co.jp ed.jp go.jp gr.jp lg.jp ne.jp or.jp
com.br net.br org.br gov.br edu.br
ac.in co.in edu.in firm.in gen.in gov.in ind.in net.in nic.in org.in res.in
ac.za co.za edu.za gov.za net.za org.za web.za
com.mx edu.mx gob.mx net.mx org.mx
ac.cn com.cn edu.cn gov.cn net.cn org.cn
ac.kr co.kr go.kr ne.kr or.kr re.kr
com.tw edu.tw gov.tw net.tw org.tw
com.hk edu.hk gov.hk net.hk org.hk
com.sg edu.sg gov.sg net.sg org.sg
com.my edu.my gov.my net.my org.my
ac.id co.id go.id my.id or.id web.id
com.ph edu.ph gov.ph net.ph org.ph
ac.th co.th go.th in.th or.th
com.vn edu.vn gov.vn net.vn org.vn
com.tr edu.tr gov.tr net.tr org.tr
com.ar edu.ar gob.ar net.ar org.ar
com.co edu.co gov.co net.co org.co
com.pe edu.pe gob.pe net.pe org.pe
com.ve com.ec com.uy com.bo com.py com.gt com.sv com.hn com.ni com.pa com.do com.cu com.pr
com.pl edu.pl gov.pl net.pl org.pl
com.ru net.ru org.ru
com.ua edu.ua gov.ua in.ua net.ua org.ua
ac.il co.il gov.il muni.il net.il org.il
com.eg edu.eg gov.eg org.eg
com.sa edu.sa gov.sa org.sa
ac.ae co.ae gov.ae net.ae org.ae
com.pk edu.pk gov.pk net.pk org.pk
com.bd edu.bd net.bd org.bd
com.ng edu.ng gov.ng net.ng org.ng
ac.ke co.ke go.ke ne.ke or.ke
com.gh edu.gh gov.gh org.gh
co.tz co.ug co.zw co.bw com.na com.et
com.kw com.qa com.om com.bh com.jo com.lb com.cy com.mt
com.es edu.es gob.es nom.es org.es
asso.fr gouv.fr nom.fr
ac.at co.at gv.at or.at
co.hu org.hu
com.ro nom.ro org.ro
com.hr from.hr
com.pt edu.pt gov.pt org.pt
com.gr edu.gr gov.gr net.gr org.gr
`.split(/\s+/).filter(Boolean);

  const SUFFIXES = new Set(MULTI);
  // US state locality rules: k12.ca.us, cc.ca.us, lib.ca.us, state.ca.us
  const US_STATE = /^(k12|cc|lib|state)\.[a-z]{2}\.us$/;
  // Private-section suffixes relevant to mail and hosting.
  const PRIVATE = new Set(['github.io', 'herokuapp.com', 'blogspot.com', 'appspot.com', 'azurewebsites.net', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'myshopify.com']);

  function publicSuffix(domain) {
    const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length < 2) return domain;
    const last3 = labels.slice(-3).join('.');
    const last2 = labels.slice(-2).join('.');
    if (US_STATE.test(last3)) return last3;
    if (SUFFIXES.has(last2)) return last2;
    return labels[labels.length - 1];
  }

  // Organizational domain: public suffix plus one label (RFC 7489 3.2).
  function orgDomain(domain) {
    if (!domain) return '';
    const d = domain.toLowerCase().replace(/\.$/, '');
    const labels = d.split('.');
    if (labels.length <= 2) return d;
    const last2 = labels.slice(-2).join('.');
    if (PRIVATE.has(last2)) return labels.slice(-3).join('.');
    const suffix = publicSuffix(d);
    const n = suffix.split('.').length + 1;
    return labels.slice(-n).join('.');
  }

  HA.psl = { orgDomain, publicSuffix };
})(typeof globalThis !== 'undefined' ? globalThis : this);
