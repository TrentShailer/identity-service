type TokenDetails = {
  bearer: string;
  sub: string;
  typ: "common" | "consent" | "provisioning";
  exp: string;
  act: string | null;
};

type Challenge = {
  challenge: string;
  identityId: string | null;
  issued: string;
  expires: string;
  origin: string;
};

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
