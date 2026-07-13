---
source: https://tinker-docs.thinkingmachines.ai/api-reference/exceptions
scraped: 2026-03-08
---

# Exceptions

## Exception Hierarchy

### `TinkerError`

Base exception for all Tinker-related errors. Root exception class from which all others inherit.

### `APIError`

Base class for all API-related errors. Extends `TinkerError`.

The `body` attribute contains the API response body. When available, this holds either decoded JSON data or raw response content. Returns `None` if no response was associated with the error.

### `APIResponseValidationError`

Triggered when an API response fails to match the expected data schema.

### `APIStatusError`

Raised when the API returns a 4xx or 5xx status code.

### `APIConnectionError`

Occurs during connection failures while attempting API requests.

### `APITimeoutError`

Extends `APIConnectionError`. Raised when API requests exceed the timeout threshold.

## HTTP Status Code Exceptions

- **BadRequestError** -- HTTP 400: Malformed or invalid request
- **AuthenticationError** -- HTTP 401: Missing or invalid authentication credentials
- **PermissionDeniedError** -- HTTP 403: Lack of permissions to access the requested resource
- **NotFoundError** -- HTTP 404: Requested resource does not exist
- **ConflictError** -- HTTP 409: Request conflicts with current resource state
- **UnprocessableEntityError** -- HTTP 422: Well-formed request with semantic issues
- **RateLimitError** -- HTTP 429: Request rate limit exceeded
- **InternalServerError** -- HTTP 500+: Server-side errors

### `RequestFailedError`

Raised when asynchronous requests complete unsuccessfully.
