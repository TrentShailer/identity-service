import { Form } from "../lib/form.js";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.js";
import { API_KEY, API_URL } from "../scripts/config.js";
import { setHref } from "../lib/redirect.js";
import { requireTokenType } from "../scripts/pageRequirements.js";

await requireTokenType("none");

const form = new Form("/register", ["/username", "/displayName"]);
form.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  form.lock();
  form.clearErrors();

  const values = form.getValues();
  const username = values.get("/username") ?? "";
  const displayName = values.get("/displayName") ?? "";

  /** @type import("../lib/fetch.js").ServerResponse<any> */
  const response = await new FetchBuilder("POST", API_URL + "/identities").setHeaders([API_KEY])
    .setBody({ username, displayName }).fetch();

  if (response.status === "ok" && localStorage.getItem(TOKEN_KEY)) {
    const params = new URLSearchParams(document.location.search);
    const redirect = params.get("redirect");
    const nextPage = redirect ? `/add-first-passkey?redirect=${redirect}` : `/add-first-passkey`;
    await setHref(nextPage);
  } else if (response.status === "clientError") {
    form.setInputErrors(response.problems);
  } else {
    form.formError.unexpectedResponse("register");
  }

  form.unlock();
});
