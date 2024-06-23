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
  var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var length = buffer.byteLength;
  var view = new Uint8Array(buffer);
  var bits = 0;
  var value = 0;
  var output = '';
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
  return HS;
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

function DT(HS) {
  const offset = HS[HS.length - 1] & 0xf;
  const P = ((HS[offset] & 0x7f) << 24) | (HS[offset + 1] << 16) | (HS[offset + 2] << 8) | HS[offset + 3];
  return P;
}

async function generateHOTP(secret, algo, digits, counter) {
  const key = await generateKey(secret, algo, counter);
  const uKey = new Uint8Array(key);
  const Snum = DT(uKey);
  const padded = ('000000' + (Snum % (10 ** digits))).slice(-digits);
  return padded;
}
