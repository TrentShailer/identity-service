import { Form } from "../lib/form.ts";
import { FetchBuilder, TOKEN_KEY } from "../lib/fetch.ts";
import { API_KEY, API_URL } from "../scripts/config.ts";
import { setHref } from "../lib/redirect.ts";
import { getToken } from "../scripts/token.ts";

const token = getToken();
if (token) {
  switch (token.typ) {
    case "common":
      await setHref("/identity");
      break;
    case "provisioning":
      await setHref("/add-passkey");
      break;
  }
}

const form = new Form("/register", ["/username", "/displayName"], "register");
form.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  form.setLock(true);
  form.clearErrors();

  const values = form.getValues();
  const username = values.get("/username") ?? "";
  const displayName = values.get("/displayName") ?? "";

  const response = await new FetchBuilder("POST", API_URL + "/identities")
    .setHeaders([API_KEY])
    .setBody({ username, displayName })
    .fetch<unknown>();

  if (response.status === "ok" && localStorage.getItem(TOKEN_KEY)) {
    const params = new URLSearchParams(document.location.search);
    const redirect = params.get("redirect");
    const nextPage = redirect ? `/add-passkey?redirect=${redirect}` : `/add-passkey`;
    await setHref(nextPage);
  }
  else if (response.status === "badRequest") {
    form.setInputErrors(response.problems);
  }
  else {
    form.formError.panic();
  }

  form.setLock(false);
});
