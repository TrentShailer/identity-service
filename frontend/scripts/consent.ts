import { base64Encode } from "../lib/base64.ts";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { Challenge, Identity, TokenDetails } from "../types.ts";
import { API_KEY, API_URL } from "./config.ts";

type Consent = {
  action: string;
  consentToken: string;
  originalToken: string;
};

export async function getConsent(
  action: string,
): Promise<Consent | "cancelled" | "unexpectedError" | "unauthenticated"> {
  const originalToken = localStorage.getItem(TOKEN_KEY);
  if (!originalToken) {
    return "unauthenticated";
  }

  const tokenDetailsResponse = await new FetchBuilder("GET", API_URL + "/tokens/current")
    .setHeaders([API_KEY])
    .fetch<TokenDetails>();
  if (tokenDetailsResponse.status === "unauthorized") {
    return "unauthenticated";
  }
  else if (tokenDetailsResponse.status !== "ok") {
    return "unexpectedError";
  }
  const tokenDetails = tokenDetailsResponse.body;

  const identityDetailsResponse = await new FetchBuilder(
    "GET",
    API_URL + `/identities/${tokenDetails.sub}`,
  ).setHeaders([API_KEY]).fetch<Identity>();
  if (identityDetailsResponse.status !== "ok") {
    return "unexpectedError";
  }
  const identityDetails = identityDetailsResponse.body;

  const requestOptions = await getCredentialRequestOptions(
    identityDetails.id,
    identityDetails.username,
  );
  console.log(requestOptions);
  if (!requestOptions) {
    return "unexpectedError";
  }

  const credential = await navigator.credentials.get({ publicKey: requestOptions })
    .catch(() => {
      return null;
    });
  if (
    !credential
    || !(credential instanceof PublicKeyCredential)
    || !(credential.response instanceof AuthenticatorAssertionResponse)
  ) {
    return "cancelled";
  }

  const consentToken = await createConsentToken(credential, action);
  localStorage.setItem(TOKEN_KEY, originalToken);
  if (!consentToken) {
    return "unexpectedError";
  }

  return {
    action,
    consentToken,
    originalToken,
  };
}

async function getCredentialRequestOptions(
  identityId: string,
  username: string,
): Promise<PublicKeyCredentialRequestOptions | null> {
  const optionsResponse = await new FetchBuilder("GET", API_URL + "/credential-request-options")
    .setHeaders([API_KEY])
    .fetch<PublicKeyCredentialRequestOptionsJSON>();
  if (optionsResponse.status !== "ok") {
    return null;
  }
  const optionsJson = optionsResponse.body;

  const challengeResponse = await new FetchBuilder("POST", API_URL + "/challenges")
    .setHeaders([API_KEY])
    .setBody({ identityId })
    .fetch<Challenge>();
  if (challengeResponse.status !== "ok") {
    return null;
  }

  optionsJson.challenge = challengeResponse.body.challenge;

  if (username) {
    const allowedCredentialsResponse = await new FetchBuilder(
      "GET",
      API_URL + `/allowed-credentials/${username}`,
    ).setHeaders([API_KEY])
      .fetch<{ allowCredentials: PublicKeyCredentialDescriptorJSON[] }>();
    if (allowedCredentialsResponse.status !== "ok") {
      return null;
    }

    optionsJson
      .allowCredentials = allowedCredentialsResponse.body.allowCredentials;
  }

  return PublicKeyCredential.parseRequestOptionsFromJSON(optionsJson);
}

async function createConsentToken(
  credential: PublicKeyCredential,
  action: string,
): Promise<string | null> {
  if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
    return "clientError";
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
      typ: "consent",
      act: action,
    })
    .fetch<TokenDetails>();
  if (response.status !== "ok") {
    return null;
  }
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    return null;
  }

  return token;
}
