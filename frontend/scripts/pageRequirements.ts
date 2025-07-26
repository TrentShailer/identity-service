import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { TokenDetails } from "../types.ts";
import { API_KEY, API_URL } from "./config.ts";

export async function getToken(): Promise<TokenDetails | null> {
  const response = await new FetchBuilder("GET", API_URL + "/tokens/current")
    .setHeaders([API_KEY])
    .fetch<TokenDetails>();

  if (
    response.status === "serverError"
    || response.status === "clientError"
    || response.status === "unauthorized"
  ) {
    localStorage.removeItem(TOKEN_KEY);
    return null;
  }

  if (response.status === "ok") {
    return response.body;
  }
  else {
    localStorage.removeItem(TOKEN_KEY);
    return null;
  }
}
