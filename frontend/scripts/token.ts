import { base64Decode } from "../lib/base64.ts";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { setHref } from "../lib/redirect.ts";
import { TokenDetails } from "../types.ts";
import { API_KEY, API_URL } from "./config.ts";

export function getToken(): TokenDetails | null {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    localStorage.removeItem(TOKEN_KEY);
    return null;
  }

  const decoder = new TextDecoder();
  const claims = JSON.parse(decoder.decode(base64Decode(parts[1])));

  return {
    bearer: token,
    act: claims.act ?? null,
    exp: claims.exp,
    sub: claims.sub,
    typ: claims.typ,
    tid: claims.tid,
  };
}

export async function logout(should_return: boolean): Promise<never> {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    await new FetchBuilder("POST", API_URL + "/revoked-tokens").setHeaders([API_KEY]).fetch();
    alert("Your session has expired");
  }
  localStorage.removeItem(TOKEN_KEY);

  const href = should_return ? `/login?redirect=${encodeURI(location.href)}` : "/login";
  return await setHref(href);
}
