import { Form } from "../lib/form.ts";
import { setHref } from "../lib/redirect.ts";
import { getToken } from "../scripts/token.ts";
import { requestCommonToken } from "../scripts/webauthn.ts";

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

const form = new Form("/login", ["/username"], "login");
document.getElementById("prompt-resident-key")!.addEventListener("mouseup", async () => {
  form.clearErrors();

  const result = await requestCommonToken(null);
  if (result.status === "ok") {
    await goToNextPage();
  }
  else if (result.status === "cancelled") {
    form.formError.addError("the prompt was cancelled");
    return;
  }
  else {
    form.formError.panic();
    return;
  }
});

form.form.addEventListener("submit", async (event) => {
  try {
    event.preventDefault();

    form.setLock(true);
    form.clearErrors();

    const values = form.getValues();
    const username = values.get("/username") ?? "";

    const result = await requestCommonToken(username);
    if (result.status === "ok") {
      await goToNextPage();
    }
    else if (result.status === "cancelled") {
      form.formError.addError("the prompt was cancelled");
      form.setLock(false);
      return;
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

async function goToNextPage(): Promise<never> {
  const params = new URLSearchParams(document.location.search);
  const redirect = params.get("redirect");
  const nextPage = redirect ? decodeURI(redirect) : "/identity";
  return await setHref(nextPage);
}
