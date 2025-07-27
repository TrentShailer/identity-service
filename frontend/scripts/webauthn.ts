import { base64Encode } from "../lib/base64.ts";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { Challenge, Identity, TokenDetails } from "../types.ts";
import { API_KEY, API_URL } from "./config.ts";

type WebAuthNResult<T> =
  | { status: "ok"; data: T }
  | { status: "cancelled" }
  | { status: "unauthenticated" }
  | { status: "error" };

export async function requestPasskeyCreation(
  token: TokenDetails,
  preferResidentKey: boolean,
  displayName: string,
): Promise<WebAuthNResult<object>> {
  const challenge = await getChallenge(token.sub);
  if (challenge.status !== "ok") {
    return challenge;
  }

  const relyingParty = await getRelyingParty();
  if (relyingParty.status !== "ok") {
    return relyingParty;
  }

  const existingCredentials = await getExistingCredentials(token.sub, null);
  if (existingCredentials.status !== "ok") {
    return existingCredentials;
  }

  const identity = await getIdentity(token);
  if (identity.status !== "ok") {
    return identity;
  }

  const publicKeyParameters = await getPublicKeyParameters();
  if (publicKeyParameters.status !== "ok") {
    return publicKeyParameters;
  }

  const jsonOptions: PublicKeyCredentialCreationOptionsJSON = {
    challenge: challenge.data,
    excludeCredentials: existingCredentials.data,
    hints: ["security-key", "hybrid", "client-device"],
    rp: relyingParty.data,
    pubKeyCredParams: publicKeyParameters.data,
    user: {
      displayName: identity.data.displayName,
      id: identity.data.id,
      name: identity.data.username,
    },
    authenticatorSelection: {
      residentKey: preferResidentKey ? "preferred" : "discouraged",
      userVerification: "preferred",
    },
  };

  const options = PublicKeyCredential.parseCreationOptionsFromJSON(jsonOptions);
  const credential = await navigator.credentials.create({ publicKey: options }).catch(() => {
    return null;
  });
  if (!credential) {
    return { status: "cancelled" };
  }
  if (!(credential instanceof PublicKeyCredential)) {
    return { status: "error" };
  }

  return await requestCredentialCreation(credential, displayName);
}

export async function requestCommonToken(
  username: string | null,
): Promise<WebAuthNResult<string>> {
  const challenge = await getChallenge(null);
  if (challenge.status !== "ok") {
    return challenge;
  }

  const relyingParty = await getRelyingParty();
  if (relyingParty.status !== "ok") {
    return relyingParty;
  }

  const existingCredentials = await getExistingCredentials(null, username);
  if (existingCredentials.status !== "ok") {
    return existingCredentials;
  }

  const jsonOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: challenge.data,
    allowCredentials: existingCredentials.data,
    hints: ["security-key", "hybrid", "client-device"],
    rpId: relyingParty.data.id,
    userVerification: "required",
  };

  const options = PublicKeyCredential.parseRequestOptionsFromJSON(jsonOptions);
  const credential = await navigator.credentials.get({ publicKey: options }).catch(() => {
    return null;
  });
  if (!credential) {
    return { status: "cancelled" };
  }
  if (!(credential instanceof PublicKeyCredential)) {
    return { status: "error" };
  }

  return await requestTokenIssued(credential, "common", null);
}
export async function requestConsentToken(
  originalToken: TokenDetails,
  action: string,
): Promise<WebAuthNResult<string>> {
  const challenge = await getChallenge(originalToken.sub);
  if (challenge.status !== "ok") {
    return challenge;
  }

  const relyingParty = await getRelyingParty();
  if (relyingParty.status !== "ok") {
    return relyingParty;
  }

  const existingCredentials = await getExistingCredentials(originalToken.sub, null);
  if (existingCredentials.status !== "ok") {
    return existingCredentials;
  }

  const jsonOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: challenge.data,
    allowCredentials: existingCredentials.data,
    hints: ["security-key", "hybrid", "client-device"],
    rpId: relyingParty.data.id,
    userVerification: "required",
  };

  const options = PublicKeyCredential.parseRequestOptionsFromJSON(jsonOptions);
  const credential = await navigator.credentials.get({ publicKey: options }).catch(() => {
    return null;
  });
  if (!credential) {
    return { status: "cancelled" };
  }
  if (!(credential instanceof PublicKeyCredential)) {
    return { status: "error" };
  }

  const token = await requestTokenIssued(credential, "consent", action);
  localStorage.setItem(TOKEN_KEY, originalToken.bearer);
  return token;
}

async function getRelyingParty(): Promise<WebAuthNResult<PublicKeyCredentialRpEntity>> {
  const response = await new FetchBuilder("GET", API_URL + "/.well-known/relying-party.json")
    .setHeaders([API_KEY])
    .fetch<PublicKeyCredentialRpEntity>();
  if (response.status === "ok") {
    return { status: "ok", data: response.body };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}

async function getExistingCredentials(
  identityId: string | null,
  username: string | null,
): Promise<WebAuthNResult<PublicKeyCredentialDescriptorJSON[]>> {
  let query = "";
  if (identityId) {
    query = `?identityId=${identityId}`;
  }
  else if (username) {
    query = `?username=${username}`;
  }
  const response = await new FetchBuilder("GET", API_URL + `/existing-credentials${query}`)
    .setHeaders([API_KEY])
    .fetch<{ credentials: PublicKeyCredentialDescriptorJSON[] }>();
  if (response.status === "ok") {
    return { status: "ok", data: response.body.credentials };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}

async function getChallenge(
  identityId: string | null,
): Promise<WebAuthNResult<string>> {
  const response = await new FetchBuilder("POST", API_URL + "/challenges")
    .setBody({ identityId: identityId })
    .setHeaders([API_KEY])
    .fetch<Challenge>();
  if (response.status === "ok") {
    return { status: "ok", data: response.body.challenge };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}

async function requestTokenIssued(
  credential: PublicKeyCredential,
  type: "consent" | "common",
  action: string | null,
): Promise<WebAuthNResult<string>> {
  if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
    return { status: "error" };
  }
  const response = await new FetchBuilder("POST", API_URL + "/tokens")
    .setHeaders([API_KEY])
    .setBody({
      credential: {
        id: credential.id,
        authenticatorAttachment: credential.authenticatorAttachment,
        rawId: base64Encode(new Uint8Array(credential.rawId)),
        response: {
          authenticatorData: base64Encode(new Uint8Array(credential.response.authenticatorData)),
          clientDataJSON: base64Encode(new Uint8Array(credential.response.clientDataJSON)),
          signature: base64Encode(new Uint8Array(credential.response.signature)),
          userHandle: credential.response.userHandle
            ? base64Encode(new Uint8Array(credential.response.userHandle))
            : null,
        },
      },
      typ: type,
      act: action,
    })
    .fetch<TokenDetails>();
  if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else if (response.status !== "ok") {
    return { status: "error" };
  }

  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    return { status: "error" };
  }
  return { status: "ok", data: token };
}

async function requestCredentialCreation(
  credential: PublicKeyCredential,
  displayName: string,
): Promise<WebAuthNResult<object>> {
  if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
    return { status: "error" };
  }

  const publicKey = credential.response.getPublicKey();
  if (!publicKey) {
    return { status: "error" };
  }

  const response = await new FetchBuilder("POST", API_URL + "/public-keys")
    .setHeaders([API_KEY])
    .setBody({
      displayName,
      credential: {
        authenticatorAttachment: credential.authenticatorAttachment,
        id: credential.id,
        rawId: base64Encode(new Uint8Array(credential.rawId)),
        response: {
          attestationObject: base64Encode(new Uint8Array(credential.response.attestationObject)),
          clientDataJSON: base64Encode(new Uint8Array(credential.response.clientDataJSON)),
          authenticatorData: base64Encode(
            new Uint8Array(credential.response.getAuthenticatorData()),
          ),
          publicKey: base64Encode(new Uint8Array(publicKey)),
          publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
          transports: credential.response.getTransports(),
        },
      },
    })
    .fetch();

  if (response.status === "ok") {
    return { status: "ok", data: {} };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}

export async function getIdentity(
  token: TokenDetails,
): Promise<WebAuthNResult<Identity>> {
  const response = await new FetchBuilder("GET", API_URL + `/identities/${token.sub}`)
    .setHeaders([API_KEY])
    .fetch<Identity>();
  if (response.status === "ok") {
    return { status: "ok", data: response.body };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}

async function getPublicKeyParameters(): Promise<WebAuthNResult<PublicKeyCredentialParameters[]>> {
  const response = await new FetchBuilder(
    "GET",
    API_URL + `/.well-known/public-key-parameters.json`,
  )
    .setHeaders([API_KEY])
    .fetch<{ publicKeyParameters: PublicKeyCredentialParameters[] }>();
  if (response.status === "ok") {
    return { status: "ok", data: response.body.publicKeyParameters };
  }
  else if (response.status === "unauthenticated") {
    return { status: "unauthenticated" };
  }
  else {
    return { status: "error" };
  }
}
