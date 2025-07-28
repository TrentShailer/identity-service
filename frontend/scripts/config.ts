import { Header, setConfig as setFetchConfig } from "../lib/fetch.ts";

export const API_URL = "http://localhost:8081";
export const API_KEY: Header = ["X-TS-API-Key", "identity-site"];
// TODO could API Key be moved to fetch config
// TODO handle dev config vs prod config?

export function setConfig() {
  setFetchConfig("");
}
