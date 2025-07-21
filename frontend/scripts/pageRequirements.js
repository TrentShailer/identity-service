import { FetchBuilder, logout } from "../lib/fetch.js";
import { setHref } from "../lib/redirect.js";
import { API_KEY, API_URL, LOGOUT_CONFIG } from "./config.js";

/**
 * @param { "common" | "provisioning" | "none" } requiredType
 */
export async function requireTokenType(requiredType) {
  /** @type import("../lib/fetch.js").ServerResponse<TokenDetails> */
  const response = await new FetchBuilder("GET", API_URL + "/tokens/current").setHeaders([API_KEY])
    .fetch();
  if (response.status !== "ok" && response.status !== "notFound") {
    console.error(
      `recieved unexpected response from server when fetching current token: ${response.status}`,
    );
    return;
  }

  const token = response.status === "ok" ? response.body : null;

  switch (requiredType) {
    case "common":
      return await requireCommonToken(token);
    case "provisioning":
      return await requireProvisioningToken(token);
    case "none":
      return await requireNoToken(token);
  }
}

/** @param { TokenDetails | null } token */
async function requireCommonToken(token) {
  if (!token) {
    const redirect = encodeURI(location.href);
    return await setHref(`/login?redirect=${redirect}`);
  }

  switch (token.typ) {
    case "common":
      return;
    case "provisioning": {
      const redirect = encodeURI(location.href);
      return await setHref(`/add-first-passkey?redirect=${redirect}`);
    }
    default:
      return await logout(LOGOUT_CONFIG, true);
  }
}

/** @param { TokenDetails | null } token */
async function requireProvisioningToken(token) {
  if (!token) {
    return await setHref(`/register`);
  }

  switch (token.typ) {
    case "provisioning":
      return;
    case "common": {
      const params = new URLSearchParams(document.location.search);
      const redirect = params.get("redirect");
      const nextPage = redirect ? decodeURI(redirect) : "/identity";
      return await setHref(nextPage);
    }
    default:
      return await logout(LOGOUT_CONFIG, false);
  }
}

/** @param { TokenDetails | null } token */
async function requireNoToken(token) {
  if (!token) {
    return;
  }

  switch (token.typ) {
    case "common": {
      const params = new URLSearchParams(document.location.search);
      const redirect = params.get("redirect");
      const nextPage = redirect ? decodeURI(redirect) : "/identity";
      return await setHref(nextPage);
    }
    case "provisioning":
      return await setHref(`/add-first-passkey`);
    default:
      return await logout(LOGOUT_CONFIG, false);
  }
}
