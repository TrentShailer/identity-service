declare global {
  interface Uint8Array<TArrayBuffer extends ArrayBufferLike> {
    toBase64(options?: { alphabet?: "base64" | "base64url"; omitPadding?: boolean }): string;
  }

  interface Uint8ArrayConstructor {
    fromBase64(
      string: string,
      options?: {
        alphabet?: "base64" | "base64url";
        lastChunkHandling?: "loose" | "strict" | "stop-before-partial";
      },
    ): Uint8Array;
  }
}

export function base64Decode(input: string): Uint8Array {
  return Uint8Array.fromBase64(input, {
    alphabet: "base64url",
    lastChunkHandling: "loose",
  });
}

export function base64Encode(input: Uint8Array): string {
  return input.toBase64({ alphabet: "base64url", omitPadding: true });
}
