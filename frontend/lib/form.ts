import { Problem } from "./fetch.ts";

export class FormError {
  element: HTMLElement;
  contents: HTMLElement;

  constructor(formId: string) {
    this.element = getElementById<HTMLElement>(`${formId}/error`, HTMLElement);
    this.contents = getElementById<HTMLElement>(`${formId}/error/content`, HTMLElement);
  }

  clearError() {
    this.element.classList.add("collapse");
    this.element.ariaHidden = "true";
    this.contents.textContent = "";
  }

  addError(error: string) {
    if (this.contents.textContent === "") {
      this.setError(`Invalid form: ${error}`);
      return;
    }

    this.contents.textContent += `, ${error}`;
  }

  setError(error: string) {
    this.element.classList.remove("collapse");
    this.element.ariaHidden = "false";
    this.contents.textContent = error;
  }

  unexpectedResponse(action: string) {
    this.setError(`Could not ${action} because the server sent an unexpected response.`);
  }
}

export class Input {
  input: HTMLInputElement;
  error: HTMLElement;

  constructor(formId: string, inputId: string) {
    this.input = getElementById<HTMLInputElement>(`${formId}${inputId}/input`, HTMLInputElement);
    this.error = getElementById<HTMLElement>(`${formId}${inputId}/error`, HTMLElement);

    this.input.addEventListener("input", () => {
      this.input.setCustomValidity("");
    });
  }

  getValue(): string {
    if (this.input.type === "checkbox") {
      if (this.input.checked) {
        return "checked";
      } else {
        return "unchecked";
      }
    } else {
      return this.input.value;
    }
  }

  lock() {
    this.input.disabled = true;
  }

  unlock() {
    this.input.disabled = false;
  }

  clearError() {
    this.input.setCustomValidity("");
    this.error.classList.add("hidden");
    this.error.ariaHidden = "true";
    this.error.textContent = "!";
  }

  addError(error: string) {
    if (this.error.textContent === "!") {
      this.setError(`Invalid value: ${error}`);
      return;
    }
    this.error.textContent += `, ${error}`;
    this.input.setCustomValidity(this.error.textContent ?? "Invalid value");
  }

  setError(error: string) {
    this.input.setCustomValidity(error);
    this.error.classList.remove("hidden");
    this.error.ariaHidden = "false";
    this.error.textContent = error;
  }
}

export class Form {
  form: HTMLFormElement;
  formError: FormError;
  submitButton: HTMLButtonElement;
  inputs: Map<string, Input>;

  constructor(formId: string, inputIds: string[]) {
    this.form = getElementById<HTMLFormElement>(formId, HTMLFormElement);
    this.formError = new FormError(formId);
    this.submitButton = getElementById<HTMLButtonElement>(`${formId}/submit`, HTMLButtonElement);

    const inputs = new Map<string, Input>();
    for (const inputId of inputIds) {
      inputs.set(inputId, new Input(formId, inputId));
    }
    this.inputs = inputs;
  }

  clearErrors() {
    this.formError.clearError();
    for (const input of this.inputs.values()) {
      input.clearError();
    }
  }

  lock() {
    this.submitButton.disabled = true;
    for (const input of this.inputs.values()) {
      input.lock();
    }
  }

  unlock() {
    this.submitButton.disabled = false;
    for (const input of this.inputs.values()) {
      input.unlock();
    }
  }

  setInputErrors(problems: Problem[] | null) {
    if (!problems || problems.length === 0) {
      this.formError.addError("an unknown field is invalid");
      return;
    }

    for (const problem of problems) {
      let input: Input | null = null;
      if (problem.pointer) {
        input = this.inputs.get(problem.pointer) ?? null;
      }

      if (input && problem.detail) {
        input.addError(problem.detail);
      } else if (input && !problem.detail) {
        input.addError("unknown reason");
      } else if (!input && problem.detail) {
        this.formError.addError(problem.detail);
      } else {
        this.formError.addError("an unknown field is invalid");
      }
    }
  }

  getValues(): Map<string, string> {
    const map = new Map();
    for (const [id, input] of this.inputs) {
      map.set(id, input.getValue());
    }
    return map;
  }
}

// deno-lint-ignore no-explicit-any
type Class<T> = new (...args: any[]) => T;

/**
 * # Panics
 * If element does not exist or is not an instance of the expected type.
 */
function getElementById<T extends HTMLElement>(id: string, expected: Class<T>): T {
  const element = document.getElementById(id);
  if (!element || !(element instanceof expected)) {
    throw `element '${id}' does not exist`;
  }
  return element;
}
