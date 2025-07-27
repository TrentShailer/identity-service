import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { setHref } from "../lib/redirect.ts";
import { API_KEY, API_URL } from "../scripts/config.ts";
import { requestConsentToken } from "../scripts/webauthn.ts";
import { Identity, PublicKey } from "../types.ts";
import { formatOptions, parseUtcToLocalDateTime } from "../lib/temporal.ts";
import { FormError } from "../lib/form.ts";
import { getToken, logout } from "../scripts/token.ts";

const token = getToken();
if (!token) {
  await setHref("/login");
  throw new Error();
}
if (token.typ === "provisioning") {
  await setHref("/add-passkey");
}

document.getElementById("logout")!.addEventListener("mouseup", async () => {
  localStorage.removeItem(TOKEN_KEY);
  await logout(false);
});

const deleteIdentityAlert = new FormError("/deleteIdentity", "delete your identity");
document.getElementById("deleteIdentity")!.addEventListener("mouseup", async () => {
  const consent = await requestConsentToken(token, `DELETE /identities/${token.sub}`);
  if (consent.status === "cancelled") {
    deleteIdentityAlert.addError("the consent prompt was cancelled");
    return;
  }
  else if (consent.status === "unauthenticated") {
    await logout(false);
    return;
  }
  else if (consent.status !== "ok") {
    deleteIdentityAlert.panic();
    return;
  }

  const response = await new FetchBuilder("DELETE", API_URL + `/identities/${token.sub}`)
    .setHeaders([API_KEY, ["Authorization", consent.data]])
    .fetch();
  if (response.status === "badRequest" && response.problems.length != 0) {
    for (const problem of response.problems) {
      if (problem.detail) {
        passkeyAlert.addError(problem.detail);
      }
    }
    return;
  }
  else if (response.status !== "ok") {
    deleteIdentityAlert.panic();
    return;
  }

  localStorage.removeItem(TOKEN_KEY);
  await logout(false);
});

const identityResponse = await new FetchBuilder("GET", API_URL + `/identities/${token.sub}`)
  .setHeaders([API_KEY])
  .fetch<Identity>();
const identityAlert = new FormError("/identity", "fetch your identity details");
if (identityResponse.status === "ok") {
  const created = parseUtcToLocalDateTime(identityResponse.body.created)
    .toPlainDate()
    .toLocaleString(formatOptions().locale, { dateStyle: "long" });
  document.getElementById("username")!.textContent = identityResponse.body.username;
  document.getElementById("displayName")!.textContent = identityResponse.body.displayName;
  document.getElementById("created")!.textContent = created;
}
else if (identityResponse.status === "unauthenticated") {
  await logout(false);
}
else {
  identityAlert.panic();
}

type PublicKeysResponse = {
  publicKeys: PublicKey[];
};
const passkeyResponse = await new FetchBuilder(
  "GET",
  API_URL + `/public-keys?identityId=${token.sub}`,
)
  .setHeaders([API_KEY])
  .fetch<PublicKeysResponse>();
const passkeyAlert = new FormError("/passkeys", "fetch your passkey details");
const deletePasskeyAlert = new FormError("/deletePasskey", "delete your passkey");

if (passkeyResponse.status === "ok") {
  const parent = document.getElementById("passkeys")!;
  for (const passkey of passkeyResponse.body.publicKeys) {
    addPasskey(passkey, parent);
  }
}
else if (passkeyResponse.status === "unauthenticated") {
  await logout(false);
}
else {
  passkeyAlert.panic();
}

function addPasskey(passkey: PublicKey, parent: HTMLElement) {
  const deleteButton = document.createElement("button");
  deleteButton.setHTMLUnsafe(
    `<svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M296,64H216a7.91,7.91,0,0,0-8,8V96h96V72A7.91,7.91,0,0,0,296,64Z" style="fill: none" /><path d="M432,96H336V72a40,40,0,0,0-40-40H216a40,40,0,0,0-40,40V96H80a16,16,0,0,0,0,32H97L116,432.92c1.42,26.85,22,47.08,48,47.08H348c26.13,0,46.3-19.78,48-47L415,128h17a16,16,0,0,0,0-32ZM192.57,416H192a16,16,0,0,1-16-15.43l-8-224a16,16,0,1,1,32-1.14l8,224A16,16,0,0,1,192.57,416ZM272,400a16,16,0,0,1-32,0V176a16,16,0,0,1,32,0ZM304,96H208V72a7.91,7.91,0,0,1,8-8h80a7.91,7.91,0,0,1,8,8Zm32,304.57A16,16,0,0,1,320,416h-.58A16,16,0,0,1,304,399.43l8-224a16,16,0,1,1,32,1.14Z" /></svg>`,
  );
  deleteButton.addEventListener("mouseup", () => {
    deletePasskey(passkey.rawId);
  });
  deleteButton.className = "icon-button circle ghost red";
  deleteButton.ariaLabel = `delete '${passkey.displayName}' passkey`;

  const heading = document.createElement("h3");
  heading.innerText = passkey.displayName;

  const firstDiv = document.createElement("div");
  firstDiv.appendChild(heading);
  firstDiv.appendChild(deleteButton);

  const created = document.createElement("small");
  const createdText = parseUtcToLocalDateTime(passkey.created)
    .toPlainDate()
    .toLocaleString(formatOptions().locale, { dateStyle: "long" });
  created.innerText = `Created: ${createdText}`;
  const lastUsed = document.createElement("small");
  const lastUsedText = passkey.lastUsed
    ? parseUtcToLocalDateTime(passkey.lastUsed).toPlainDate()
      .toLocaleString(formatOptions().locale, { dateStyle: "long" })
    : "Never";
  lastUsed.innerText = `Last Used: ${lastUsedText}`;

  const secondDiv = document.createElement("div");
  secondDiv.appendChild(created);
  secondDiv.appendChild(lastUsed);

  const container = document.createElement("div");
  container.className = "passkey";
  container.appendChild(firstDiv);
  container.appendChild(secondDiv);

  parent.prepend(container);
}

async function deletePasskey(id: string) {
  const currentToken = getToken();
  if (!currentToken) {
    await logout(false);
    return;
  }

  const consent = await requestConsentToken(currentToken, `DELETE /public-keys/${id}`);
  if (consent.status === "cancelled") {
    deletePasskeyAlert.addError("the prompt was cancelled");
    return;
  }
  else if (consent.status === "unauthenticated") {
    await logout(false);
    return;
  }
  else if (consent.status !== "ok") {
    deletePasskeyAlert.panic();
    return;
  }

  const response = await new FetchBuilder("DELETE", API_URL + `/public-keys/${id}`)
    .setHeaders([API_KEY, ["Authorization", consent.data]])
    .fetch();
  if (response.status === "badRequest" && response.problems.length != 0) {
    for (const problem of response.problems) {
      if (problem.detail) {
        deletePasskeyAlert.addError(problem.detail);
      }
    }
    return;
  }
  else if (response.status !== "ok") {
    deletePasskeyAlert.panic();
    return;
  }

  location.reload();
}
