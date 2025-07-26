# API Style Guide

## Errors

- 400 Bad Request **MUST** be used for 'business exceptions' such as a form request where the
  username is too long. It **MUST** be accompanied with a JSON body containing problems that conform
  to the following schema:

```json
{
  "type": "object",
  "required": ["pointer", "detail"],
  "properties": {
    "pointer": {
      "type": "string",
      "description": "a JSON pointer to the field in the request body that violates a condition",
      "format": "rfc6901"
    },
    "detail": {
      "type": "string",
      "description": "a short description of the condition the pointer violated",
      "examples": ["must be less than 64 characters", "contains invalid character `&`"]
    }
  }
}
```

- 422 Unprocessable Content **MUST** be used for malformed requests such as invalid base-64 encoded
  value. The server **MUST NOT** provide further details or a response body.

- 409 Conflict **SHOULD NOT** be used for POST requests, instead 400 Bad Request **SHOULD** be
  preferred to standardise client-side error handling.

- 401 Unauthorized **MUST** be returned if the request contains no valid authorization such as no
  API key, no token, malformed token, expired token, or the subject of the token does not exist. The
  server **MUST NOT** provide further details or a response body.

- 403 Forbidden **MUST** be returned if the request contains valid authorization but is not allowed
  to access the given resource. Such as the API key is not allowed for this API, the token is not
  the correct consent, or the subject does not have permission to access the resource. The server
  **MUST NOT** provide further details or a response body.

- 404 Not Found **SHOULD NOT** be returned, instead the server **SHOULD** prefer 403 forbidden.

- 500 Internal Server Error **MUST** be returned for any server-side errors where there is no direct
  problem with the request. The server **MUST NOT** provide further details or a response body.

## Authorization

- Sensitive actions **MUST** require a token where the `typ` is `consent` and the `act` is the
  specific action that is being performed. The `act` claim must be in the form:
  `METHOD /path/to/specific/resource`. For example: `DELETE /identities/abc`,
  `DELETE /public-keys/xyz`.

- The server **MUST** revoke a consent token as soon at it receives it, before any further
  authorization or action is taken.
