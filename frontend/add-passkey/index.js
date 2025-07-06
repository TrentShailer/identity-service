import { base64Encode } from "../scripts/base64.js";
import { API_KEY, API_KEY_HEADER, API_URL } from "../scripts/config.js";
import { formPreSend, renableForm, setFormError } from "../scripts/form.js";
import { getCurrentToken, logout } from "../scripts/identity.js";

getCurrentToken();

const formElement = document.getElementById("addPasskey");

if (formElement) {
  formElement.addEventListener("submit", async (event) => {
    event.preventDefault();

    const token = await getCurrentToken();

    const values = formPreSend(["displayName"], "form.submit", "form.error");
    const displayName = values.get("displayName") ?? "";

    // TODO form

    const challenge = await getChallenge(token);
    const credentialCreationOptions = await getCredentialCreationOptions(
      token,
      challenge.challenge,
    );

    const credential = await navigator.credentials.create({ publicKey: credentialCreationOptions })
      .catch(() => {
        setFormError(
          "form.error",
          "Could not register a passkey because the prompt was cancelled.",
        );
        renableForm(["username", "displayName"], "form.submit");
      });
    if (!credential || !(credential instanceof PublicKeyCredential)) {
      return;
    }

    await uploadPublicKey(token, credential, displayName);

    renableForm(["username", "displayName"], "form.submit");
  });
}

/**
 * @param {TokenDetails} token
 * @returns {Promise<Challenge | never>}
 */
async function getChallenge(token) {
  const requestBody = JSON.stringify(
    {
      identityId: token.sub,
    },
  );

  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);
  headers.append("Content-Type", "application/json");
  headers.append("Authorization", token.bearer);

  const response = await fetch(API_URL + "/challenges", {
    method: "POST",
    body: requestBody,
    headers,
  });

  if (response.status === 401) {
    return await logout();
  } else if (response.status !== 201) {
    // TODO alert
    return await logout();
  }

  const body = await response.json();
  if (!body.challenge || !body.issued || !body.expires || !body.origin) {
    // TODO alert
    return await logout();
  }

  return body;
}

/**
 * @param {TokenDetails} token
 * @param {string} challenge
 * @returns {Promise<PublicKeyCredentialCreationOptions | never>}
 */
async function getCredentialCreationOptions(token, challenge) {
  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);
  headers.append("Authorization", token.bearer);

  const response = await fetch(API_URL + "/credential-creation-options", {
    method: "GET",
    headers,
  });

  if (response.status === 401) {
    return await logout();
  } else if (response.status !== 200) {
    // TODO alert
    return await logout();
  }

  const body = await response.json();
  body.challenge = challenge;

  return PublicKeyCredential.parseCreationOptionsFromJSON(body);
}

/**
 * @param {TokenDetails} token
 * @param {PublicKeyCredential} credential
 * @param {string} displayName
 */
async function uploadPublicKey(token, credential, displayName) {
  const headers = new Headers();
  headers.append(API_KEY_HEADER, API_KEY);
  headers.append("Authorization", token.bearer);
  headers.append("Content-Type", "application/json");

  let response;
  if (credential.response instanceof AuthenticatorAttestationResponse) {
    const authenticatorData = credential.response.getAuthenticatorData();
    const publicKey = credential.response.getPublicKey();
    const publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
    const transports = credential.response.getTransports();
    if (!publicKey) {
      // TODO
      return;
    }

    response = {
      attestationObject: base64Encode(new Uint8Array(credential.response.attestationObject)),
      clientDataJSON: base64Encode(new Uint8Array(credential.response.clientDataJSON)),
      authenticatorData: base64Encode(new Uint8Array(authenticatorData)),
      publicKey: base64Encode(new Uint8Array(publicKey)),
      publicKeyAlgorithm,
      transports,
    };
  } else {
    // TODO
    return;
  }

  const body = {
    credential: {
      authenticatorAttachment: credential.authenticatorAttachment,
      id: credential.id,
      rawId: base64Encode(new Uint8Array(credential.rawId)),
      response,
    },
    displayName, // TODO
  };

  console.log(JSON.stringify(body));

  const uploadResponse = await fetch(API_URL + "/public-keys", {
    method: "POST",
    body: JSON.stringify(body),
    headers,
  });
}
