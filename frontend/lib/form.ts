import { Problem } from "./fetch.ts";

export class FormError {
  element: HTMLElement;
  contents: HTMLElement;
  action: string;

  constructor(formId: string, action: string) {
    this.element = getElementById<HTMLElement>(`${formId}/error`, HTMLElement);
    this.contents = getElementById<HTMLElement>(`${formId}/error/content`, HTMLElement);
    this.action = action;
  }

  clearError() {
    this.element.classList.add("collapse");
    this.element.ariaHidden = "true";
    this.contents.textContent = "";
  }

  addError(error: string) {
    if (this.contents.textContent === "") {
      this.element.classList.remove("collapse");
      this.element.ariaHidden = "false";
      this.contents.textContent = `Could not ${this.action}: ${error}`;
      return;
    }

    this.contents.textContent += `, ${error}`;
  }

  panic() {
    this.element.classList.remove("collapse");
    this.element.ariaHidden = "false";
    this.contents.textContent =
      `Something went wrong while trying to ${this.action}. Try again later.`;
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

  setLock(lock: boolean) {
    this.input.disabled = lock;
  }

  clearError() {
    this.input.setCustomValidity("");
    this.error.classList.add("hidden");
    this.error.ariaHidden = "true";
    this.error.textContent = "!";
  }

  addError(error: string) {
    if (this.error.textContent === "!") {
      this.input.setCustomValidity(error);
      this.error.classList.remove("hidden");
      this.error.ariaHidden = "false";
      this.error.textContent = `Invalid value: ${error}`;
      return;
    }
    this.error.textContent += `, ${error}`;
    this.input.setCustomValidity(this.error.textContent ?? "Invalid value");
  }
}

export class Form {
  form: HTMLFormElement;
  formError: FormError;
  submitButton: HTMLButtonElement;
  inputs: Map<string, Input>;

  constructor(formId: string, inputIds: string[], action: string) {
    this.form = getElementById<HTMLFormElement>(formId, HTMLFormElement);
    this.formError = new FormError(formId, action);
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

  setLock(lock: boolean) {
    this.submitButton.disabled = lock;
    for (const input of this.inputs.values()) {
      input.setLock(lock);
    }
  }

  setInputErrors(problems: Problem[] | null) {
    if (!problems || problems.length === 0) {
      this.formError.addError("an unknown field is invalid");
      return;
    }

    for (const problem of problems) {
      const input = this.inputs.get(problem.pointer) ?? null;

      if (input) {
        input.addError(problem.detail);
      } else {
        this.formError.addError(`field ${problem.pointer} ${problem.detail}`);
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
