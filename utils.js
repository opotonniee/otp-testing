function getSecretBytes(secret) {
  let secretBytes = secret;
  if (typeof (secretBytes) == "string") {
    const encoder = new TextEncoder('utf-8');
    secretBytes = encoder.encode(secret);
  }
  return secretBytes;
}

/* -----------------------------------------------------
  Hex encoder/decoder
  ----------------------------------------------------- */

/**
* convert byte array to hexa string
* @param {array} byteArray - a byte array
* @returns {string} the hexadecimal string representation of the array value
*/
function bytesToHex(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('').toUpperCase();
}

/**
* Convert an hexa string to a byte array
* @param {hex} string - the hexadecimal string representation of the array value
* @returns {UInt8Array} the converted array value
*/
function hexToBytes(hex) {
  const isHex = /^[0-9A-Fa-f]+$/.test(hex);
  if (!isHex) throw new Error("Invalid hexa string");
  let bytes = [];
  for (let c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
  return new Uint8Array(bytes);
}

/* -----------------------------------------------------
  Base32 encoder
  Credit: https://github.com/LinusU/base32-encode/blob/master/index.js
  ----------------------------------------------------- */

function base32Encode(secret, padding) {
  let buffer = getSecretBytes(secret);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const length = buffer.byteLength;
  const view = new Uint8Array(buffer);
  let bits = 0;
  let value = 0;
  let output = '';
  for (var i = 0; i < length; i++) {
    value = (value << 8) | view[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  if (padding) {
    while ((output.length % 8) !== 0) {
      output += '=';
    }
  }
  return output;
};

/* -----------------------------------------------------
  OTP generation
  Credit: https://github.com/khovansky-al/web-otp-demo/blob/master/src/hotp.js
  ----------------------------------------------------- */

async function generateKey(secret, algo, counter) {
  const digest = algo.replace("SHA", "SHA-");
  const Crypto = window.crypto.subtle;
  let secretBytes = getSecretBytes(secret);
  const counterArray = this.padCounter(counter);
  const key = await Crypto.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: { name: digest } },
    false,
    ['sign']
  );
  const HS = await Crypto.sign('HMAC', key, counterArray);
  return new Uint8Array(HS);
}

function padCounter(counter) {
  const buffer = new ArrayBuffer(8);
  const bView = new DataView(buffer);
  const byteString = '0'.repeat(64); // 8 bytes
  const bCounter = (byteString + counter.toString(2)).slice(-64);
  for (let byte = 0; byte < 64; byte += 8) {
    const byteValue = parseInt(bCounter.slice(byte, byte + 8), 2);
    bView.setUint8(byte / 8, byteValue);
  }
  return buffer;
}

function DT(HS, bytes) {
  if (HS.length < bytes) {
    throw new Error("Hash length is less than the number of bytes to extract");
  }
  let offset = HS[HS.length - 1] & 0xf;
  if (offset + bytes > HS.length) { // proprietary tweak for bytes > 4 as in alphanumeric HOTP
    offset -= Math.max(4, bytes - (HS.length - offset));
  }
  let P = 0n; // use BigInt in case more than 8 bytes are needed
  for (let i = 0; i < bytes; i++) {
    P = (P << 8n) | BigInt((i == 0) ? HS[offset + i] & 0x7f : HS[offset + i] & 0xff);
  }
  return P;
}

// This implements the standard HOTP algorithm as defined in RFC 4226
async function generateHOTP(secret, algo, digits, counter) {
  const key = await generateKey(secret, algo, counter);
  const Snum = DT(key, digits > 10 ? 7 : 4); // /!\ digits > 10 is not standard
  const padded = ('000000' + (Snum % (10n ** BigInt(digits)))).slice(-digits);
  return padded;
}

// This implements a proprietary variant algorithm as sugggest in appendix E.2 of RFC 4226, 
// using alphanumeric characters instead of digits (base32 characters, with no ambiguous characters).
async function generateAlphanumHOTP(secret, algo, digits, counter) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const key = await generateKey(secret, algo, counter);
  let Snum = DT(key, digits > 10 ? 12 : 8);
  let output = '';
  for (let i = 0; i < digits; i++) {
    const charIndex = Snum & 0x1fn;
    Snum = Snum >> 5n;
    output += alphabet[charIndex];
  }
  return output;
}
