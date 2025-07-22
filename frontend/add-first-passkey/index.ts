import { base64Encode } from "../lib/base64.ts";
import { FetchBuilder } from "../lib/fetch.ts";
import { Form } from "../lib/form.ts";
import { API_KEY, API_URL, LOGOUT_CONFIG } from "../scripts/config.ts";
import { setHref } from "../lib/redirect.ts";
import { requireTokenType } from "../scripts/pageRequirements.ts";

await requireTokenType("provisioning");

const form = new Form("/addPasskey", ["/displayName", "/residentKey"]);
form.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    form.lock();
    form.clearErrors();

    const values = form.getValues();
    const displayName = values.get("/displayName") ?? "";
    const preferResidentKey = values.get("/residentKey") ?? "unchecked";

    // Get token details
    const tokenResponse = await new FetchBuilder("GET", API_URL + "/tokens/current")
      .setHeaders([API_KEY])
      .setLogout(LOGOUT_CONFIG, false)
      .fetch<TokenDetails>();
    if (tokenResponse.status !== "ok") {
      form.formError.unexpectedResponse("register a passkey");
      form.unlock();
      return;
    }
    const token = tokenResponse.body;

    // Get a challenge
    const challengeResponse = await new FetchBuilder("POST", API_URL + "/challenges")
      .setLogout(LOGOUT_CONFIG, false)
      .setHeaders([API_KEY])
      .setBody({ identityId: token.sub })
      .fetch<Challenge>();
    if (challengeResponse.status !== "ok") {
      form.formError.unexpectedResponse("register a passkey");
      form.unlock();
      return;
    }
    const challenge = challengeResponse.body.challenge;

    // Get the credential creation options
    const credentialCreationOptionsResponse = await new FetchBuilder(
      "GET",
      API_URL + "/credential-creation-options",
    ).setHeaders([API_KEY])
      .setLogout(LOGOUT_CONFIG, false)
      .fetch<PublicKeyCredentialCreationOptionsJSON>();
    if (credentialCreationOptionsResponse.status !== "ok") {
      form.formError.unexpectedResponse("register a passkey");
      form.unlock();
      return;
    }
    credentialCreationOptionsResponse.body.challenge = challenge;
    if (
      preferResidentKey === "checked"
      && credentialCreationOptionsResponse.body.authenticatorSelection
    ) {
      credentialCreationOptionsResponse.body.authenticatorSelection.residentKey = "preferred";
    }
    else if (credentialCreationOptionsResponse.body.authenticatorSelection) {
      credentialCreationOptionsResponse.body.authenticatorSelection.residentKey = "discouraged";
    }

    const credentialCreationOptions = PublicKeyCredential.parseCreationOptionsFromJSON(
      credentialCreationOptionsResponse.body,
    );

    console.log(credentialCreationOptions);

    // Get the credentials
    const credential = await navigator.credentials.create({ publicKey: credentialCreationOptions })
      .catch(() => {
        return null;
      });
    if (
      !credential
      || !(credential instanceof PublicKeyCredential)
      || !(credential.response instanceof AuthenticatorAttestationResponse)
    ) {
      form.formError.setError("Could not register a passkey because the prompt was cancelled.");
      form.unlock();
      return;
    }

    const authenticatorData = credential.response.getAuthenticatorData();
    const publicKey = credential.response.getPublicKey();
    const publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
    const transports = credential.response.getTransports();
    if (!publicKey) {
      form.formError.setError("Could not register the passkey because it wasn't created.");
      form.unlock();
      return;
    }

    const attestationResponse = {
      attestationObject: base64Encode(new Uint8Array(credential.response.attestationObject)),
      clientDataJSON: base64Encode(new Uint8Array(credential.response.clientDataJSON)),
      authenticatorData: base64Encode(new Uint8Array(authenticatorData)),
      publicKey: base64Encode(new Uint8Array(publicKey)),
      publicKeyAlgorithm,
      transports,
    };

    const publicKeyResponse = await new FetchBuilder("POST", API_URL + "/public-keys").setLogout(
      LOGOUT_CONFIG,
      false,
    ).setHeaders([API_KEY]).setBody({
      displayName,
      credential: {
        authenticatorAttachment: credential.authenticatorAttachment,
        id: credential.id,
        rawId: base64Encode(new Uint8Array(credential.rawId)),
        response: attestationResponse,
      },
    }).fetch();
    if (publicKeyResponse.status === "ok") {
      const params = new URLSearchParams(document.location.search);
      const redirect = params.get("redirect");
      const nextPage = redirect ? decodeURI(redirect) : "/identity";
      await setHref(nextPage);
    }
    else if (publicKeyResponse.status === "clientError") {
      form.setInputErrors(publicKeyResponse.problems);
    }
    else {
      form.formError.unexpectedResponse("register the passkey");
    }
  }
  finally {
    form.unlock();
  }
});
