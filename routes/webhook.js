const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const SIGNATURE_HEADER = 'x-zenapi-signature';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const TIMESTAMP_TOLERANCE_MIN = process.env.TIMESTAMP_TOLERANCE_MIN || 5;

/* Verify function for body parser to save raw body */
function jsonParserVerify(req, res, buf, encoding) {
  req.rawBodyBuf = buf;
  req.rawBodyBufEncoding = encoding;
}

/* Signature Verify Middleware */
function signatureVerify(req, res, next) {
  // get signature header
  const sigHeader = req.headers[SIGNATURE_HEADER];
  if (!sigHeader) {
    const err = new Error('Signature Error: No signature header');
    err.status = 400;
    throw err;
  }

  // parse signature header
  const data = sigHeader
    .split(',', 6)
    .map(i => {
      const [ name, value ] = i.trim().split('=');
      return { name, value };
    });
  
  // check timestamp
  const timestampData = data.find(i => i.name==='t'); // get first timestamp
  const timestampStr = timestampData ? timestampData.value : undefined;
  if (!timestampStr) {
    const err = new Error('Signature Error: No timestamp field');
    err.status = 400;
    throw err;
  }
  const diffMs = Date.now() - parseInt(timestampStr) * 1000;
  const diffMinutes = diffMs / (1000*60);
  if (diffMinutes > TIMESTAMP_TOLERANCE_MIN || diffMinutes < -TIMESTAMP_TOLERANCE_MIN) {
    const err = new Error('Signature Error: Timestamp out of tolerance');
    err.status = 400;
    throw err;
  }

  // check signature
  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
  hmac.update(`${timestampStr}.`)
  hmac.update(req.rawBodyBuf);
  const signature = hmac.digest('hex');
  const hasValidSignature = data.some(i => i.name==='s' && i.value===signature); // find for some valid signature
  if (!hasValidSignature) {
    const err = new Error('Signature Error: No valid signature found');
    err.status = 400;
    throw err;
  }
  
  next();
}

/* Webhook Activation Middleware */
function activationChallenge(req, res, next) {
  if (req.body.activation && req.body.activation.challenge) {
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    hmac.update(req.body.activation.challenge);
    const challenge_response = hmac.digest('hex');
    res.json({
      activation: {
        challenge_response,
      },
    });
  } else {
    next();
  }
}

/* Webhook Controller */
function controller(req, res, next) {
  res.status(200).send();
}

/* Webhook Endpoint */
router.post(
  '/',
  express.json({ verify: jsonParserVerify }),
  signatureVerify,
  activationChallenge,
  controller);

module.exports = router;
