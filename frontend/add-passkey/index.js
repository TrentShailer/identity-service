import { base64Encode } from "../scripts/base64.js";
import { fetch } from "../scripts/fetch.js";
import { lockForm, setFormError, setFormInputErrors, unlockForm } from "../scripts/form.js";
import { getCurrentToken } from "../scripts/identity.js";

// Send the user to login if they are not logged in.
getCurrentToken();

const formElement = document.getElementById("addPasskey");

if (formElement) {
  // Listen for submits
  formElement.addEventListener("submit", async (event) => {
    event.preventDefault();

    // Ensure the token is still valid and fetch identity ID.
    const token = await getCurrentToken();

    // Lock the form
    const values = lockForm(["displayName"], "form.submit", "form.error");
    const displayName = values.get("displayName") ?? "";

    // Get the challenge
    const challengeResponse = await getChallenge(token);
    if (challengeResponse.status !== "ok") {
      setFormError(
        "form.error",
        "Could not register a passkey because the server sent an unexpected response.",
      );
      unlockForm(["displayName"], "form.submit");
      return;
    }

    // Get the credential creation options
    const credentialCreationOptions = await getCredentialCreationOptions(
      challengeResponse.body.challenge,
    );
    if (!credentialCreationOptions) {
      setFormError(
        "form.error",
        "Could not register a passkey because the server sent an unexpected response.",
      );
      unlockForm(["displayName"], "form.submit");
      return;
    }

    const credential = await navigator.credentials.create({ publicKey: credentialCreationOptions })
      .catch(null);
    if (!credential || !(credential instanceof PublicKeyCredential)) {
      setFormError(
        "form.error",
        "Could not register a passkey because the prompt was cancelled.",
      );
      unlockForm(["displayName"], "form.submit");
      return;
    }

    const response = await uploadPublicKey(credential, displayName);
    if (!response || response.status === "serverError") {
      setFormError(
        "form.error",
        "Could not register the passkey because something went wrong.",
      );
      unlockForm(["displayName"], "form.submit");
      return;
    } else if (response.status === "clientError") {
      const pointerMap = new Map([["/displayName", "displayName"]]);
      setFormInputErrors(pointerMap, "form.error", response.problems, "Could not register because");
      unlockForm(["displayName"], "form.submit");
      return;
    }

    const params = new URLSearchParams(document.location.search);
    const redirect = params.get("redirect");
    const nextPage = redirect ?? "/identity";
    location.href = nextPage;
  });
}

/**
 * @param {TokenDetails} token
 * @returns {Promise<ServerResponse<Challenge>>}
 */
function getChallenge(token) {
  return fetch("POST", "/challenges", {
    identityId: token.sub,
  });
}

/**
 * @param {string} challenge
 * @returns {Promise<PublicKeyCredentialCreationOptions?>}
 */
async function getCredentialCreationOptions(challenge) {
  const response = await fetch("GET", "/credential-creation-options", null);
  if (response.status !== "ok") {
    return null;
  }

  response.body.challenge = challenge;

  return PublicKeyCredential.parseCreationOptionsFromJSON(response.body);
}

/**
 * @param {PublicKeyCredential} credential
 * @param {string} displayName
 * @returns {Promise<ServerResponse<PublicKey> | null>}
 */
async function uploadPublicKey(credential, displayName) {
  if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
    return null;
  }

  const authenticatorData = credential.response.getAuthenticatorData();
  const publicKey = credential.response.getPublicKey();
  const publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
  const transports = credential.response.getTransports();
  if (!publicKey) {
    return null;
  }

  const attestationResponse = {
    attestationObject: base64Encode(new Uint8Array(credential.response.attestationObject)),
    clientDataJSON: base64Encode(new Uint8Array(credential.response.clientDataJSON)),
    authenticatorData: base64Encode(new Uint8Array(authenticatorData)),
    publicKey: base64Encode(new Uint8Array(publicKey)),
    publicKeyAlgorithm,
    transports,
  };

  return await fetch("POST", "/public-keys", {
    credential: {
      authenticatorAttachment: credential.authenticatorAttachment,
      id: credential.id,
      rawId: base64Encode(new Uint8Array(credential.rawId)),
      response: attestationResponse,
    },
    displayName,
  });
}
