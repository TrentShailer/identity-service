export type Problem = {
  pointer: string;
  detail: string;
};

export type ServerResponse<T> =
  | { status: "ok"; body: T }
  | { status: "badRequest"; problems: Problem[] }
  | { status: "unauthenticated" }
  | { status: "error" }
  | never;

export type Header = [string, string];

export const TOKEN_KEY = "token";

export class FetchBuilder {
  #method: "GET" | "POST" | "PUT" | "DELETE";
  #url: string;
  #additionalHeaders: Header[] | null = null;
  #body: object | null = null;

  constructor(method: "GET" | "POST" | "PUT" | "DELETE", url: string) {
    this.#method = method;
    this.#url = url;
  }

  setBody(body: object | null): FetchBuilder {
    this.#body = body;
    return this;
  }

  setHeaders(headers: Header[] | null): FetchBuilder {
    this.#additionalHeaders = headers;
    return this;
  }

  async fetch<T>(): Promise<ServerResponse<T>> {
    return await fetch(
      this.#method,
      this.#url,
      this.#additionalHeaders,
      this.#body,
    );
  }
}

export async function fetch<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  url: string,
  additionalHeaders: Header[] | null,
  body: object | null,
): Promise<ServerResponse<T>> {
  const headers = new Headers();

  if (additionalHeaders) {
    for (const header of additionalHeaders) {
      headers.append(header[0], header[1]);
    }
  }

  if (body) {
    headers.append("content-type", "application/json");
  }

  const token = localStorage.getItem(TOKEN_KEY);
  if (token && !headers.has("Authorization")) {
    headers.append("Authorization", token);
  }

  let bodyContent = null;
  if (body) {
    bodyContent = JSON.stringify(body);
  }

  const response = await self.fetch(url, {
    method,
    body: bodyContent,
    headers,
  }).catch((ex) => {
    console.warn(ex);
    return new Response(null, { status: 500 });
  });

  if (response.ok) {
    const bearer = response.headers.get("Authorization");
    if (bearer) {
      localStorage.setItem(TOKEN_KEY, bearer);
    }

    const body = await response.json().catch((ex) => {
      console.warn(ex);
      return {};
    });

    return {
      status: "ok",
      body,
    };
  }

  switch (response.status) {
    case 400: {
      const body = await response.json().catch((ex) => {
        console.warn(ex);
        return { problems: [] };
      });

      return {
        status: "badRequest",
        problems: body.problems ?? [],
      };
    }
    case 401:
    case 403: {
      return { status: "unauthenticated" };
    }
  }

  return { status: "error" };
}
