export type TokenDetails = {
  bearer: string;
  sub: string;
  typ: "common" | "consent" | "provisioning";
  exp: string;
  act: string | null;
};

export type Challenge = {
  challenge: string;
  identityId: string | null;
  issued: string;
  expires: string;
  origin: string;
};

export type PublicKey = {
  rawId: string;
  identityId: string;
  displayName: string;
  publicKey: string;
  publicKeyAlgorithm: number;
  transports: string[];
  signatureCounter: number;
  created: string;
  lastUsed: string | null;
};

export type Identity = {
  id: string;
  username: string;
  displayName: string;
  expires: string | null;
  created: string;
};
