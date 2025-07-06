import { formPreSend, renableForm, setFormError, setFormInputErrors } from "../scripts/form.js";
import { API_KEY, API_KEY_HEADER, API_URL } from "../scripts/config.js";

const registerElement = document.getElementById("register");

if (registerElement) {
  registerElement.addEventListener("submit", async (event) => {
    event.preventDefault();

    const values = formPreSend(["username", "displayName"], "form.submit", "form.error");
    const username = values.get("username");
    const displayName = values.get("displayName");

    const body = JSON.stringify(
      {
        username,
        displayName,
      },
    );

    const headers = new Headers();
    headers.append(API_KEY_HEADER, API_KEY);
    headers.append("content-type", "application/json");

    const response = await fetch(API_URL + "/identities", {
      method: "POST",
      body,
      headers,
    });

    if (response.status === 201) {
      const token = response.headers.get("authorization");
      if (!token) {
        setFormError(
          "form.error",
          "Could not register because the server sent an invalid response.",
        );
        renableForm(["username", "displayName"], "form.submit");
        return;
      }

      localStorage.setItem("token", token);
      location.href = "/add-passkey";

      // TODO preserve current redirect target
    } else if (response.status === 409 || response.status === 400) {
      const body = await response.json();
      const pointerMap = new Map();
      pointerMap.set("/username", "username");
      pointerMap.set("/displayName", "displayName");
      setFormInputErrors(pointerMap, "form.error", body.problems, "Could not register because");
    } else {
      setFormError(
        "form.error",
        "Could not register because the server sent an unexpected response.",
      );
    }

    renableForm(["username", "displayName"], "form.submit");
  });
}
