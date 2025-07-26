import { FetchBuilder, logout } from "../lib/fetch.ts";
import { setHref } from "../lib/redirect.ts";
import { API_KEY, API_URL, LOGOUT_CONFIG } from "../scripts/config.ts";
import { getToken } from "../scripts/pageRequirements.ts";
import { Identity, PublicKey } from "../types.ts";
import { formatOptions, Intl, parseUtcToLocalDateTime } from "../lib/temporal.ts";

const token = await getToken();
if (!token) {
  await setHref("/login");
  throw new Error();
}
if (token.typ === "provisioning") {
  await setHref("/add-passkey");
}

document.getElementById("deleteAccount")!.addEventListener("mouseup", async () => {
  // deleteAccountAlert

  // TODO consent flow must be in-page
  // TODO old token must be preserved in case of failure to perform action.
  // TODO get consent
  // TODO perform action
  // TODO logout
});

const identityResponse = await new FetchBuilder("GET", API_URL + `/identities/${token.sub}`)
  .setHeaders([API_KEY])
  .setLogout(LOGOUT_CONFIG, false)
  .fetch<Identity>();
const identityAlert = document.getElementById("/identity/error/content")!;
switch (identityResponse.status) {
  case "clientError":
  case "serverError": {
    identityAlert.textContent =
      "Could not fetch identity details, the server sent an unexpected response.";
    identityAlert.classList.remove("collapse");
    break;
  }
  case "unauthorized":
  case "notFound": {
    await logout(LOGOUT_CONFIG, false);
    break;
  }
  case "ok": {
    const created = parseUtcToLocalDateTime(identityResponse.body.created)
      .toPlainDate()
      .toLocaleString(formatOptions().locale, { dateStyle: "long" });
    document.getElementById("username")!.textContent = identityResponse.body.username;
    document.getElementById("displayName")!.textContent = identityResponse.body.displayName;
    document.getElementById("created")!.textContent = created;
    break;
  }
}

type PublicKeysResponse = {
  publicKeys: PublicKey[];
};
const passkeyResponse = await new FetchBuilder(
  "GET",
  API_URL + `/public-keys?identityId=${token.sub}`,
).setLogout(LOGOUT_CONFIG, false)
  .setHeaders([API_KEY])
  .fetch<PublicKeysResponse>();
const passkeyAlert = document.getElementById("/passkeys/error/content")!;
switch (passkeyResponse.status) {
  case "clientError":
  case "serverError": {
    passkeyAlert.textContent =
      "Could not fetch the passkey details, the server sent an unexpected response.";
    passkeyAlert.classList.remove("collapse");
    break;
  }
  case "unauthorized":
  case "notFound": {
    await logout(LOGOUT_CONFIG, false);
    break;
  }
  case "ok": {
    const parent = document.getElementById("passkeys")!;
    for (const passkey of passkeyResponse.body.publicKeys) {
      addPasskey(passkey, parent);
    }
    break;
  }
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
  // TODO
}
