import { Form } from "../lib/form.js";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.js";
import { API_KEY, API_URL, LOGOUT_CONFIG } from "../scripts/config.js";
import { setHref } from "../lib/redirect.js";

// TODO if valid token, should redirect to ?redirect or /identity

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
    .setBody({ username, displayName }).setLogout(LOGOUT_CONFIG).fetch();

  if (response.status === "ok" && localStorage.getItem(TOKEN_KEY)) {
    const params = new URLSearchParams(document.location.search);
    const redirect = params.get("redirect");
    let nextPage = "/add-passkey";
    if (redirect) {
      nextPage += `?redirect=${redirect}`;
    }
    await setHref(nextPage);
  } else if (response.status === "clientError") {
    form.setInputErrors(response.problems);
  } else {
    form.formError.unexpectedResponse("register");
  }

  form.unlock();
});
