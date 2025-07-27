import { Form } from "../lib/form.ts";
import { setHref } from "../lib/redirect.ts";
import { setConfig } from "../scripts/config.ts";
import { getToken, logout } from "../scripts/token.ts";
import { requestPasskeyCreation } from "../scripts/webauthn.ts";

setConfig();

const token = await getToken();
if (!token) {
  await setHref("/login");
  throw new Error();
}

document.getElementById("cancel")?.addEventListener("mouseup", async (event) => {
  event.preventDefault();

  if (token.typ === "provisioning") {
    await logout(false);
  }
  else {
    await setHref("/identity");
  }
});

const form = new Form("/addPasskey", ["/displayName", "/residentKey"], "register a passkey");
form.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    form.setLock(true);
    form.clearErrors();

    const values = form.getValues();
    const displayName = values.get("/displayName") ?? "";
    const preferResidentKey = values.get("/residentKey") ?? "unchecked";

    const currentToken = await getToken();
    if (!currentToken) {
      await setHref("/login");
      throw new Error();
    }

    const result = await requestPasskeyCreation(
      currentToken,
      preferResidentKey === "checked",
      displayName,
    );
    if (result.status === "ok") {
      const params = new URLSearchParams(document.location.search);
      const redirect = params.get("redirect");
      const nextPage = redirect ? decodeURI(redirect) : "/identity";
      await setHref(nextPage);
    }
    else if (result.status === "cancelled") {
      form.formError.addError("the prompt was cancelled");
      form.setLock(false);
      return;
    }
    else if (result.status === "unauthenticated") {
      await logout(false);
    }
    else {
      form.formError.panic();
      form.setLock(false);
      return;
    }
  }
  finally {
    form.setLock(false);
  }
});
