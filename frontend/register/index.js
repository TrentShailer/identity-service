import { lockForm, setFormError, setFormInputErrors, unlockForm } from "../scripts/form.js";
import { fetch } from "../scripts/fetch.js";

const registerElement = document.getElementById("register");

if (registerElement) {
  // Listen for submits
  registerElement.addEventListener("submit", async (event) => {
    event.preventDefault();

    // Reset the form and get the values
    const values = lockForm(["username", "displayName"], "form.submit", "form.error");
    const username = values.get("username");
    const displayName = values.get("displayName");

    // Try create the identity
    const response = await fetch("POST", "/identities", {
      username,
      displayName,
    });

    // If the identity was created and the server sent a token, move to next stage
    if (response.status === "ok" && localStorage.getItem("token")) {
      const params = new URLSearchParams(document.location.search);
      const redirect = params.get("redirect");
      let nextPage = "/add-passkey";
      if (redirect) {
        nextPage += `?redirect=${redirect}`;
      }
      location.href = nextPage;
    } // Else if the server sent back client errors, set the form error fields accordingly.
    else if (response.status === "clientError") {
      const pointerMap = new Map([["/username", "username"], ["/displayName", "displayName"]]);
      setFormInputErrors(pointerMap, "form.error", response.problems, "Could not register because");
    } // Else set the form error
    else {
      setFormError(
        "form.error",
        "Could not register because the server sent an unexpected response.",
      );
    }

    // Re-enable the form
    unlockForm(["username", "displayName"], "form.submit");
  });
}
