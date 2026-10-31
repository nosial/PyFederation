import httpx
import pytest

from pyfederation.exceptions import FederationClientException


def test_status_code_defaults_to_no_response() -> None:
    exception = FederationClientException("Failed to get entity: connection refused")
    assert str(exception) == "Failed to get entity: connection refused"
    assert exception.status_code == 0


def test_from_response_includes_the_server_message() -> None:
    response = httpx.Response(
        403, json={"success": False, "code": 403, "message": "Forbidden: Insufficient permissions"}
    )

    exception = FederationClientException.from_response(response, "Failed to delete entity")

    assert str(exception) == "Failed to delete entity, Forbidden: Insufficient permissions"
    assert exception.status_code == 403


def test_from_response_falls_back_to_the_reason_phrase() -> None:
    response = httpx.Response(502, text="<html>Bad Gateway</html>")

    exception = FederationClientException.from_response(response, "Failed to delete entity")

    assert str(exception) == "Failed to delete entity, Bad Gateway"
    assert exception.status_code == 502


def test_from_response_reads_the_delay_of_a_rate_limited_request() -> None:
    response = httpx.Response(
        429,
        json={"success": False, "code": 429, "message": "Too Many Requests", "retry_after": 30},
        headers={"Retry-After": "60"},
    )

    exception = FederationClientException.from_response(response, "Failed to scan content")

    assert exception.retry_after == 30
    assert exception.is_retryable


def test_from_response_falls_back_to_the_retry_after_header() -> None:
    response = httpx.Response(503, text="Service Unavailable", headers={"Retry-After": " 120 "})

    exception = FederationClientException.from_response(response, "Failed to scan content")

    assert exception.retry_after == 120
    assert exception.is_retryable


@pytest.mark.parametrize(
    ("status_code", "error", "header"),
    [
        (429, {"message": "Too Many Requests"}, None),
        (429, {"message": "Too Many Requests", "retry_after": -1}, "Wed, 21 Oct 2026 07:28:00 GMT"),
        (429, {"message": "Too Many Requests", "retry_after": True}, None),
        (503, {"message": "Service Unavailable", "retry_after": "30"}, "12.5"),
        (403, {"message": "Forbidden", "retry_after": 30}, "30"),
    ],
)
def test_from_response_without_a_usable_delay(
    status_code: int, error: dict[str, object], header: str | None
) -> None:
    headers = {"Retry-After": header} if header is not None else {}
    response = httpx.Response(status_code, json=error, headers=headers)

    exception = FederationClientException.from_response(response, "Failed to scan content")

    assert exception.retry_after is None
    assert exception.is_retryable is (status_code != 403)
