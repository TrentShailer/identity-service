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
  expires: string; // TODO
  origin: string; // TODO
};

type PublicKey = {
  rawId: string;
  identityId: string;
  displayName: string;
  publicKey: string;
  publicKeyAlgorithm: number;
  transports: string[];
  signatureCounter: number;
  created: string; // TODO
  lastUsed: string | null; // TODO
};

type ServerResponse<T> =
  | { status: "ok"; body: T }
  | { status: "clientError"; problems: Problem[] }
  | {
    status: "serverError";
  }
  | never;

type Problem = {
  pointer: string | null;
  detail: string | null;
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
