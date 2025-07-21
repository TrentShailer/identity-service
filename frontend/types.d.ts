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
