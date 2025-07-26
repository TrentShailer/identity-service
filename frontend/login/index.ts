import { base64Encode } from "../lib/base64.ts";
import { FetchBuilder } from "../lib/fetch.ts";
import { Form } from "../lib/form.ts";
import { setHref } from "../lib/redirect.ts";
import { API_KEY, API_URL } from "../scripts/config.ts";
import { getToken } from "../scripts/pageRequirements.ts";
import { Challenge, TokenDetails } from "../types.ts";

const token = await getToken();
if (token) {
  switch (token.typ) {
    case "common":
      await setHref("/identity");
      break;
    case "provisioning":
      await setHref("/add-passkey");
      break;
  }
}

const form = new Form("/login", ["/username"]);

document.getElementById("prompt-resident-key")!.addEventListener("mouseup", async () => {
  form.clearErrors();

  const requestOptions = await getCredentialRequestOptions(null);
  console.log(requestOptions);
  if (!requestOptions) {
    form.formError.unexpectedResponse("get credential request options");
    return;
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
    form.formError.setError("Could not login because the prompt was cancelled.");
    return;
  }

  const response = await login(credential);
  if (response === "clientError") {
    form.formError.setError("Invalid credential.");
  }
  else {
    form.formError.unexpectedResponse("login");
  }
});

form.form.addEventListener("submit", async (event) => {
  try {
    event.preventDefault();

    form.lock();
    form.clearErrors();

    const values = form.getValues();
    const username = values.get("/username") ?? "";

    const requestOptions = await getCredentialRequestOptions(username);
    console.log(requestOptions);
    if (!requestOptions) {
      form.formError.unexpectedResponse("get credential request options");
      form.unlock();
      return;
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
      form.formError.setError("Could not login because the prompt was cancelled.");
      form.unlock();
      return;
    }

    const response = await login(credential);
    if (response === "clientError") {
      form.formError.setError("Invalid credential.");
    }
    else {
      form.formError.unexpectedResponse("login");
    }
  }
  finally {
    form.unlock();
  }
});

async function getCredentialRequestOptions(
  username: string | null,
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
    .setBody({ identityId: null })
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

async function login(
  credential: PublicKeyCredential,
): Promise<never | "serverError" | "clientError"> {
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
      typ: "common",
    })
    .fetch<TokenDetails>();

  if (response.status === "ok") {
    const params = new URLSearchParams(document.location.search);
    const redirect = params.get("redirect");
    const nextPage = redirect ? decodeURI(redirect) : "/identity";
    return await setHref(nextPage);
  }

  if (response.status === "serverError") {
    return "serverError";
  }
  else {
    return "clientError";
  }
}
