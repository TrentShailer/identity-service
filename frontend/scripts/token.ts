import { deleteToken, FetchBuilder, getToken as retrieveToken } from "../lib/fetch.ts";
import { setHref } from "../lib/redirect.ts";
import { TokenDetails } from "../types.ts";
import { API_KEY, API_URL } from "./config.ts";

export async function getToken(): Promise<TokenDetails | null> {
  const token = await retrieveToken();
  if (!token) {
    return null;
  }

  return {
    bearer: token.bearer,
    act: token.claims.act ?? null,
    exp: token.claims.exp,
    sub: token.claims.sub,
    typ: token.claims.typ,
    tid: token.claims.tid,
  };
}

export async function logout(should_return: boolean): Promise<never> {
  const token = await getToken();
  if (token) {
    await new FetchBuilder("POST", API_URL + "/revoked-tokens").setHeaders([API_KEY]).fetch();
    alert("Your session has expired");
  }
  await deleteToken();

  const href = should_return ? `/login?redirect=${encodeURI(location.href)}` : "/login";
  return await setHref(href);
}
