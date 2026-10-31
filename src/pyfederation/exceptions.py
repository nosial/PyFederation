import httpx

#: The status codes of a request the server rejected without performing it (OFD 2.2 "Rate Limiting")
RETRYABLE_STATUS_CODES = (429, 503)


class FederationClientException(Exception):
    """Raised when a request to the Federation server fails.

    Attributes:
        status_code: The HTTP status code of the response, or 0 if no response was received.
        retry_after: The delay in seconds after which the server expects to accept the request
            again, from a response with HTTP 429 or 503, or None when it gave none. The client
            does not retry by itself.
    """

    def __init__(self, message: str, status_code: int = 0, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after

    @property
    def is_retryable(self) -> bool:
        """Whether the server rejected the request without performing it, with HTTP 429 or 503, so
        that it may be repeated after `retry_after`, or after a backoff when that is None."""
        return self.status_code in RETRYABLE_STATUS_CODES

    @classmethod
    def from_response(cls, response: httpx.Response, message: str) -> "FederationClientException":
        """Builds an exception from an error response, including the server's error message."""
        try:
            error = response.json()
        except ValueError:
            error = None

        reason = error.get("message") if isinstance(error, dict) else None
        if reason is None:
            reason = response.reason_phrase

        return cls(f"{message}, {reason}", response.status_code, _retry_after(response, error))


def _retry_after(response: httpx.Response, error: object) -> int | None:
    """Returns the delay of a response with HTTP 429 or 503, from the retry_after member of its
    error response or else its Retry-After header in seconds."""
    if response.status_code not in RETRYABLE_STATUS_CODES:
        return None

    member = error.get("retry_after") if isinstance(error, dict) else None
    if isinstance(member, int) and not isinstance(member, bool) and member >= 0:
        return member

    header = response.headers.get("Retry-After", "").strip()
    if header.isascii() and header.isdecimal() and len(header) <= 10:
        return int(header)

    return None
