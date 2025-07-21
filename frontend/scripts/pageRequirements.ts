import { FetchBuilder, logout, TOKEN_KEY } from "../lib/fetch.ts";
import { setHref } from "../lib/redirect.ts";
import { API_KEY, API_URL, LOGOUT_CONFIG } from "./config.ts";

/**
 * @param { "common" | "provisioning" | "none" } requiredType
 */
export async function requireTokenType(requiredType: "common" | "provisioning" | "none") {
  const response = await new FetchBuilder("GET", API_URL + "/tokens/current")
    .setHeaders([API_KEY])
    .fetch<TokenDetails>();

  let token = null;

  if (response.status === "serverError" || response.status === "clientError") {
    console.error(
      `recieved unexpected response from server when fetching current token: ${response.status}`,
    );
    return;
  }

  if (response.status === "unauthorized") {
    localStorage.removeItem(TOKEN_KEY);
  }

  if (response.status === "ok") {
    token = response.body;
  }

  switch (requiredType) {
    case "common":
      return await requireCommonToken(token);
    case "provisioning":
      return await requireProvisioningToken(token);
    case "none":
      return await requireNoToken(token);
  }
}

async function requireCommonToken(token: TokenDetails | null) {
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

async function requireProvisioningToken(token: TokenDetails | null) {
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

async function requireNoToken(token: TokenDetails | null) {
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
