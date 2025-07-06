/**
 * @param {string} input
 * @returns {Uint8Array}
 */
function base64Decode(input) {
  return Uint8Array.fromBase64(input, {
    alphabet: "base64url",
    lastChunkHandling: "loose",
  });
}

/**
 * @param {Uint8Array} input
 * @returns {string}
 */
function base64Encode(input) {
  return input.toBase64({ alphabet: "base64url", omitPadding: true });
}

export { base64Decode, base64Encode };
