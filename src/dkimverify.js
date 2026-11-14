// dkimverify.js: verify a DKIM signature again, given the key. Pure: no
// DOM, no network, no dependencies. SHA-256 is written out here so the
// hashes run the same in Node and in every browser. RSA runs on BigInt,
// which also lets the page look inside the PKCS #1 v1.5 padding: valid
// padding around a different hash means the key is the one that signed and
// a signed header changed; invalid padding means the key is not the one
// that signed. Ed25519 (RFC 8463) goes through WebCrypto, passed in, and a
// failure there cannot separate those two causes.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});

  // SHA-256, FIPS 180-4. Input and output are Uint8Array.
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  function sha256(bytes) {
    const len = bytes.length;
    const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[len] = 0x80;
    const bits = len * 8;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
    dv.setUint32(padded.length - 4, bits >>> 0);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const W = new Uint32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  // base64 text to bytes; null when the text is not base64. Whitespace is
  // ignored, as RFC 6376 3.5 allows FWS inside b= and bh=.
  function b64decode(text) {
    const s = String(text || '').replace(/[ \t\r\n]/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.replace(/=+$/, '').length % 4 === 1) return null;
    const clean = s.replace(/=+$/, '');
    const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
    let buf = 0, n = 0, j = 0;
    for (let i = 0; i < clean.length; i++) {
      buf = (buf << 6) | B64.indexOf(clean[i]);
      n += 6;
      if (n >= 8) { n -= 8; out[j++] = (buf >> n) & 0xff; }
    }
    return out;
  }
  function b64encode(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
      out += B64[a >> 2] + B64[((a & 3) << 4) | ((b || 0) >> 4)] + (b === undefined ? '=' : B64[((b & 15) << 2) | ((c || 0) >> 6)]) + (c === undefined ? '=' : B64[c & 63]);
    }
    return out;
  }

  // Text to the octets DKIM hashes. Pasted text and a UTF-8 file are UTF-8;
  // a file that is not valid UTF-8 arrives as one character per byte.
  function toBytes(text, encoding) {
    if (encoding === 'latin1') {
      const out = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
      return out;
    }
    return new TextEncoder().encode(text);
  }
  function concat(parts) {
    const n = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  // RFC 6376 3.4.1 and 3.4.2. raw is the field as it stood in the message,
  // folds as CRLF, with no CRLF at the end.
  function canonHeader(raw, mode) {
    if (mode !== 'relaxed') return raw;
    const colon = raw.indexOf(':');
    const name = raw.slice(0, colon).replace(/[ \t]+$/, '').toLowerCase();
    const value = raw.slice(colon + 1).replace(/\r\n(?=[ \t])/g, '').replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').replace(/^ /, '').replace(/ $/, '');
    return name + ':' + value;
  }

  // RFC 6376 3.4.3 and 3.4.4. body has CRLF line ends.
  function canonBody(body, mode) {
    let b = body;
    if (mode === 'relaxed') b = b.split('\r\n').map(l => l.replace(/[ \t]+$/, '').replace(/[ \t]+/g, ' ')).join('\r\n');
    // Empty lines at the end are dropped; one index walk, so a long run of
    // them costs nothing.
    let e = b.length;
    while (e >= 2 && b.charCodeAt(e - 2) === 13 && b.charCodeAt(e - 1) === 10) e -= 2;
    b = b.slice(0, e);
    return mode === 'relaxed' && b === '' ? '' : b + '\r\n';
  }

  // The DKIM-Signature field with the value of b= deleted, everything else
  // as it stood (RFC 6376 3.7, hash step 2).
  function withoutB(raw) {
    const colon = raw.indexOf(':');
    return raw.slice(0, colon + 1) + raw.slice(colon + 1).replace(/((?:^|;)[ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1');
  }

  // The fields h= names, in h= order, each taken from the bottom of the
  // header block up; a name listed more often than it appears adds nothing
  // for the extra listings (RFC 6376 5.4.2).
  function selectHeaders(fields, names) {
    const used = new Set();
    const out = [];
    for (const n of names) {
      for (let i = fields.length - 1; i >= 0; i--) {
        if (used.has(i) || fields[i].lower !== n) continue;
        used.add(i);
        out.push(fields[i]);
        break;
      }
    }
    return out;
  }

  // The header hash input and the body hash for one signature.
  // msg: { fields: [{ lower, exact }], body: string | null, encoding }
  // sig: the DKIM-Signature tags from auth.js plus exact, its raw text.
  function hashes(msg, sig) {
    const [hc, bc] = String(sig.c || 'simple/simple').toLowerCase().split('/');
    const hmode = hc === 'relaxed' ? 'relaxed' : 'simple';
    const bmode = bc === 'relaxed' ? 'relaxed' : 'simple';
    const names = String(sig.h || '').split(':').map(s => s.trim().toLowerCase()).filter(Boolean);
    const picked = selectHeaders(msg.fields, names);
    const text = picked.map(f => canonHeader(f.exact, hmode) + '\r\n').join('') + canonHeader(withoutB(sig.exact), hmode);
    const headerHash = sha256(toBytes(text, msg.encoding));
    let body = null;
    if (msg.body !== null && msg.body !== undefined) {
      let bytes = toBytes(canonBody(msg.body, bmode), msg.encoding);
      let short = false;
      if (sig.l !== null && sig.l !== undefined) {
        if (sig.l > bytes.length) short = true;
        else bytes = bytes.slice(0, sig.l);
      }
      const got = b64encode(sha256(bytes));
      body = { computed: got, matches: !short && got === String(sig.bh || '').replace(/[ \t\r\n]/g, ''), short, length: bytes.length };
    }
    return { headerHash, body, signedCount: picked.length, listed: names.length, hmode, bmode };
  }

  // RSA public key from the DER in p=: SubjectPublicKeyInfo, which keys in
  // DNS use, or a bare RSAPublicKey, which RFC 6376 3.6.1 describes.
  function der(bytes, pos) {
    if (pos + 2 > bytes.length) return null;
    const tag = bytes[pos];
    let len = bytes[pos + 1], p = pos + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 4 || p + n > bytes.length) return null;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + bytes[p + i];
      p += n;
    }
    if (p + len > bytes.length) return null;
    return { tag, start: p, end: p + len };
  }
  const toBig = (bytes) => { let h = '0'; for (const b of bytes) h += b.toString(16).padStart(2, '0'); return BigInt('0x' + h); };
  const RSA_OID = '2a864886f70d010101';
  const hex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  function rsaKey(bytes) {
    let top = der(bytes, 0);
    if (!top || top.tag !== 0x30) return null;
    let first = der(bytes, top.start);
    if (!first) return null;
    let seq = top;
    if (first.tag === 0x30) {
      const oid = der(bytes, first.start);
      if (!oid || oid.tag !== 0x06 || hex(bytes.slice(oid.start, oid.end)) !== RSA_OID) return { notRsa: true };
      const bit = der(bytes, first.end);
      if (!bit || bit.tag !== 0x03 || bytes[bit.start] !== 0) return null;
      seq = der(bytes, bit.start + 1);
      if (!seq || seq.tag !== 0x30) return null;
      first = der(bytes, seq.start);
    }
    if (!first || first.tag !== 0x02) return null;
    const eT = der(bytes, first.end);
    if (!eT || eT.tag !== 0x02) return null;
    const n = toBig(bytes.slice(first.start, first.end)), e = toBig(bytes.slice(eT.start, eT.end));
    if (n <= 0n || e <= 0n) return null;
    const bits = n.toString(2).length;
    if (bits > 16384) return null;
    return { n, e, bits };
  }

  function modPow(b, e, m) {
    let r = 1n;
    b %= m;
    while (e > 0n) {
      if (e & 1n) r = r * b % m;
      e >>= 1n;
      b = b * b % m;
    }
    return r;
  }

  // DigestInfo for SHA-256 (RFC 8017 9.2, note 1), and the form without
  // the NULL parameters that some signers write.
  const DI_SHA256 = '3031300d060960864801650304020105000420';
  const DI_SHA256_NONULL = '302f300b0609608648016503040201' + '0420';
  // The public key operation, then a look inside the padding (RFC 8017
  // 8.2.2 and 9.2). ok: valid padding around this hash. other-hash: valid
  // padding around a different hash, so the key signed and the signed data
  // changed. bad-padding: not this key's signature.
  function rsaCheck(key, sigBytes, hash) {
    const k = Math.ceil(key.bits / 8);
    if (!sigBytes || !sigBytes.length || sigBytes.length > k) return 'bad-padding';
    const s = toBig(sigBytes);
    if (s >= key.n) return 'bad-padding';
    let mh = modPow(s, key.e, key.n).toString(16);
    mh = mh.padStart(k * 2, '0');
    const em = mh.match(/../g).map(x => parseInt(x, 16));
    if (em[0] !== 0 || em[1] !== 1) return 'bad-padding';
    let i = 2;
    while (i < em.length && em[i] === 0xff) i++;
    if (i - 2 < 8 || em[i] !== 0) return 'bad-padding';
    const t = em.slice(i + 1);
    // T must be a DER DigestInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    const tb = Uint8Array.from(t);
    const outer = der(tb, 0);
    if (!outer || outer.tag !== 0x30 || outer.end !== tb.length) return 'bad-padding';
    const alg = der(tb, outer.start);
    const dig = alg && der(tb, alg.end);
    if (!alg || alg.tag !== 0x30 || !dig || dig.tag !== 0x04 || dig.end !== tb.length) return 'bad-padding';
    const prefix = hex(tb.slice(0, dig.start));
    if ((prefix === DI_SHA256 || prefix === DI_SHA256_NONULL) && equal(tb.slice(dig.start), hash)) return 'ok';
    return 'other-hash';
  }

  // Ed25519 over the SHA-256 header hash (RFC 8463 3). subtle is
  // WebCrypto's SubtleCrypto. Resolves true, false, or null when this
  // browser has no Ed25519.
  async function ed25519Check(subtle, pub, sigBytes, hash) {
    let key;
    try { key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']); } catch (e) { return null; }
    try { return await subtle.verify({ name: 'Ed25519' }, key, sigBytes, hash); } catch (e) { return false; }
  }

  HA.dkimverify = { sha256, b64decode, b64encode, toBytes, concat, canonHeader, canonBody, withoutB, selectHeaders, hashes, rsaKey, rsaCheck, ed25519Check, modPow };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.dkimverify;
})(typeof globalThis !== 'undefined' ? globalThis : this);
