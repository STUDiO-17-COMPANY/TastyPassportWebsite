import crypto from 'crypto';

function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function safeEqualHex(a, b) {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { code } = req.body || {};
  const hash = sha256Hex(code || '');
  const passHash = process.env.PASS_HASH;

  if (!passHash) {
    return res.status(500).json({ ok: false, message: 'ENV not set' });
  }

  if (!safeEqualHex(hash, passHash)) {
    return res.status(401).json({ ok: false, message: 'Invalid' });
  }

  return res.status(200).json({ ok: true });
}