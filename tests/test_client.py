import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from pyfederation import (
    AsyncFederationClient,
    ContentInput,
    ContentType,
    FederationClient,
    FederationClientException,
    IncidentType,
    RecordType,
    SuggestedAction,
)
from pyfederation.records import EntityRecord, EvidenceRecord

from . import payloads
from .utils import ACCESS_TOKEN, multipart_parts, run

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("client_type", [FederationClient, AsyncFederationClient])
def test_endpoint_trailing_slashes_are_removed(client_type: type) -> None:
    federation_client = client_type("https://federation.example/api//")
    assert federation_client.endpoint == "https://federation.example/api"


@pytest.mark.parametrize("client_type", [FederationClient, AsyncFederationClient])
def test_endpoint_must_be_a_url(client_type: type) -> None:
    with pytest.raises(ValueError, match="valid URL"):
        client_type("federation.example")


@pytest.mark.parametrize("access_token", ["", "abc def"])
def test_invalid_access_tokens_are_rejected(access_token: str) -> None:
    with pytest.raises(ValueError, match="Access token"):
        FederationClient("https://federation.example", access_token)


async def test_requests_are_authenticated(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/info").respond(json=payloads.server_information())

    await run(client.get_server_information())

    assert route.calls.last.request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


async def test_requests_are_anonymous_without_an_access_token(
    client: Any, api: respx.MockRouter
) -> None:
    route = api.get("/info").respond(json=payloads.server_information())

    client.access_token = None
    await run(client.get_server_information())

    assert "Authorization" not in route.calls.last.request.headers


async def test_get_server_information(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(json=payloads.server_information())

    information = await run(client.get_server_information())

    assert information.name == "Federation Server"
    assert information.public_search_types == [RecordType.ENTITY]


async def test_get_specification(client: Any, api: respx.MockRouter) -> None:
    api.get("/specification").respond(json={"openapi": "3.2.0"})

    assert await run(client.get_specification()) == {"openapi": "3.2.0"}


async def test_error_responses_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(
        503,
        json={
            "success": False,
            "code": 503,
            "message": "Service Unavailable: Database unavailable",
        },
    )

    with pytest.raises(FederationClientException) as raised:
        await run(client.get_server_information())

    assert raised.value.status_code == 503
    assert str(raised.value) == (
        "Failed to get server information, Service Unavailable: Database unavailable"
    )


async def test_rate_limited_requests_raise_with_their_delay(
    client: Any, api: respx.MockRouter
) -> None:
    api.post("/scan").respond(
        429,
        json={"success": False, "code": 429, "message": "Too Many Requests", "retry_after": 12},
        headers={"Retry-After": "12"},
    )

    with pytest.raises(FederationClientException) as raised:
        await run(client.scan_content("spam"))

    assert raised.value.status_code == 429
    assert raised.value.retry_after == 12
    assert raised.value.is_retryable


async def test_transport_errors_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").mock(side_effect=httpx.ConnectError("Connection refused"))

    with pytest.raises(FederationClientException) as raised:
        await run(client.get_server_information())

    assert raised.value.status_code == 0
    assert str(raised.value) == "Failed to get server information: Connection refused"


async def test_search(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/search").respond(
        json=[
            {"type": "ENTITY", "record": payloads.entity()},
            {"type": "EVIDENCE", "record": payloads.evidence()},
        ]
    )

    results = await run(client.search("example", [RecordType.ENTITY, RecordType.EVIDENCE], 2, 5))

    assert dict(route.calls.last.request.url.params) == {
        "q": "example",
        "type": "ENTITY,EVIDENCE",
        "page": "2",
        "limit": "5",
    }
    assert isinstance(results[0].record, EntityRecord)
    assert isinstance(results[1].record, EvidenceRecord)


async def test_search_leaves_out_unrecognized_record_types(
    client: Any, api: respx.MockRouter
) -> None:
    api.get("/search").respond(
        json=[{"type": "NEW", "record": {}}, {"type": "ENTITY", "record": payloads.entity()}]
    )

    results = await run(client.search("example"))

    assert [result.type for result in results] == [RecordType.ENTITY]


async def test_search_all_types(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/search").respond(json=[])

    await run(client.search("example"))

    assert dict(route.calls.last.request.url.params) == {"q": "example", "page": "1", "limit": "10"}


async def test_request_a_route_without_a_method(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/my-plugin/status").respond(json={"enabled": True})

    response = await run(client.request("get", "/my-plugin/status/", {"verbose": "true"}))

    assert response == {"enabled": True}
    assert dict(route.calls.last.request.url.params) == {"verbose": "true"}
    assert route.calls.last.request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


async def test_request_sends_parameters_as_json(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/my-plugin/rules").respond(204)

    response = await run(client.request("POST", "my-plugin/rules", {"rule": "block"}))

    assert response is None
    assert json.loads(route.calls.last.request.content) == {"rule": "block"}


def scan_response() -> dict[str, Any]:
    return {
        "author_entity": None,
        "resolved_entities": [],
        "classification": {
            "classification_flag": "MALICIOUS",
            "confidence": 0.93,
            "detected_language": "en",
        },
        "suggested_action": "BLOCK_CONTENT",
        "suggested_lift_timestamp": None,
        "scan_results": {"classification": 42.5},
        "risk_score": 42.5,
    }


async def test_scan_content_text(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/scan").respond(json=scan_response())

    scanned = await run(client.scan_content("Buy cheap watches"))

    assert json.loads(route.calls.last.request.content) == {
        "evidence": {"text_content": "Buy cheap watches", "confidential": False}
    }
    assert scanned.classification.confidence == 0.93
    assert scanned.suggested_action is SuggestedAction.BLOCK_CONTENT
    assert scanned.risk_score == 42.5


async def test_scan_content_inputs(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/scan").respond(json=scan_response())

    await run(
        client.scan_content(
            [ContentInput("First message"), ContentInput("Second message", tag="spam")],
            author="john@example.com",
            top_k=3,
            threshold=0.5,
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "evidence": [
            {"text_content": "First message", "confidential": False},
            {"text_content": "Second message", "tag": "spam", "confidential": False},
        ],
        "author": "john@example.com",
        "top_k": 3,
        "threshold": 0.5,
    }


async def test_scan_typed_content_with_concerns(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/scan").respond(json=scan_response())

    await run(
        client.scan_content(
            [
                ContentInput("Your account is locked", content_type=ContentType.TEXT),
                ContentInput(
                    "Verify it now",
                    content_type=ContentType.EMAIL,
                    context={"subject": "Account locked", "sender": "security@example.com"},
                ),
            ],
            concerns=[IncidentType.PHISHING, IncidentType.SPAM],
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        # TEXT is the default content type, which is not sent
        "evidence": [
            {"text_content": "Your account is locked", "confidential": False},
            {
                "text_content": "Verify it now",
                "confidential": False,
                "content_type": "EMAIL",
                "context": {"subject": "Account locked", "sender": "security@example.com"},
            },
        ],
        "concerns": ["PHISHING", "SPAM"],
    }


async def test_scan_content_with_files(client: Any, api: respx.MockRouter, tmp_path: Path) -> None:
    route = api.post("/scan").respond(json=scan_response())
    parcel = tmp_path / "parcel.jpg"
    parcel.write_bytes(b"JPEG")
    qr = tmp_path / "qr.png"
    qr.write_bytes(b"PNG")

    await run(
        client.scan_content(
            [ContentInput("Your parcel is on hold", content_type=ContentType.SMS), ContentInput()],
            author="15550123456@e164.arpa",
            top_k=3,
            concerns=[IncidentType.PHISHING],
            files={0: [parcel], 1: [str(qr)]},
        )
    )

    parts = multipart_parts(route.calls.last.request)
    assert parts.pop("file_0_0") == ("parcel.jpg", b"JPEG")
    assert parts.pop("file_1_0") == ("qr.png", b"PNG")
    # Every other parameter is carried in a part without a file
    assert {name: file_name for name, (file_name, _) in parts.items()} == dict.fromkeys(
        ["evidence", "author", "top_k", "concerns"]
    )
    assert json.loads(parts["evidence"][1]) == [
        {
            "text_content": "Your parcel is on hold",
            "confidential": False,
            "content_type": "SMS",
            "files": ["file_0_0"],
        },
        {"confidential": False, "files": ["file_1_0"]},
    ]
    assert parts["author"][1] == b"15550123456@e164.arpa"
    assert parts["top_k"][1] == b"3"
    assert json.loads(parts["concerns"][1]) == ["PHISHING"]


async def test_scan_content_with_files_of_one_input(
    client: Any, api: respx.MockRouter, tmp_path: Path
) -> None:
    route = api.post("/scan").respond(json=scan_response())
    photos = [tmp_path / "first.jpg", tmp_path / "second.jpg"]
    for photo in photos:
        photo.write_bytes(b"JPEG")

    await run(client.scan_content("Look at these", files={0: photos}))

    parts = multipart_parts(route.calls.last.request)
    assert json.loads(parts["evidence"][1]) == {
        "text_content": "Look at these",
        "confidential": False,
        "files": ["file_0_0", "file_0_1"],
    }
    assert parts["file_0_1"] == ("second.jpg", b"JPEG")


async def test_scan_content_with_file_urls_only_is_a_json_request(
    client: Any, api: respx.MockRouter
) -> None:
    route = api.post("/scan").respond(json=scan_response())

    await run(
        client.scan_content(
            ContentInput(content_type=ContentType.SMS),
            file_urls={0: ["https://carrier.example/mms/1.jpg"]},
        )
    )

    request = route.calls.last.request
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.content)["evidence"]["file_urls"] == [
        "https://carrier.example/mms/1.jpg"
    ]


async def test_scan_content_with_files_and_file_urls(
    client: Any, api: respx.MockRouter, tmp_path: Path
) -> None:
    route = api.post("/scan").respond(json=scan_response())
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(b"JPEG")

    await run(
        client.scan_content(
            "Look at these",
            files={0: [photo]},
            file_urls={0: ["https://example.com/a.jpg", "https://example.com/b.jpg"]},
        )
    )

    parts = multipart_parts(route.calls.last.request)
    assert json.loads(parts["evidence"][1]) == {
        "text_content": "Look at these",
        "confidential": False,
        "files": ["file_0_0"],
        "file_urls": ["https://example.com/a.jpg", "https://example.com/b.jpg"],
    }


async def test_non_json_responses_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(content=b"<html></html>", headers={"Content-Type": "text/html"})

    with pytest.raises(FederationClientException, match="Expected JSON response") as error:
        await run(client.get_server_information())

    assert error.value.status_code == 200


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (
            lambda client: client.search("a"),
            "Search query must contain at least 2 non-whitespace characters",
        ),
        (
            lambda client: client.search(" a "),
            "Search query must contain at least 2 non-whitespace characters",
        ),
        (lambda client: client.search("spam", page=0), "Page must be greater than 0"),
        (lambda client: client.scan_content([]), "Evidence cannot be empty"),
        (lambda client: client.scan_content("spam", concerns=[]), "Concerns cannot be empty"),
        (
            lambda client: client.scan_content(""),
            "At least one evidence record must contain text content",
        ),
        (
            lambda client: client.scan_content([ContentInput(note="Seen in a group")]),
            "At least one evidence record must contain text content, a file or a file URL",
        ),
        (
            lambda client: client.scan_content("spam", files={1: ["photo.jpg"]}),
            "The files are keyed by an evidence index that does not exist: 1",
        ),
        (
            lambda client: client.scan_content("spam", files={0: []}),
            "The files of the evidence at index 0 must be a non-empty sequence of paths",
        ),
        (
            lambda client: client.scan_content("spam", files={0: "photo.jpg"}),
            "The files of the evidence at index 0 must be a non-empty sequence of paths",
        ),
        (
            lambda client: client.scan_content("spam", files={0: ["does-not-exist.jpg"]}),
            "File does not exist: does-not-exist.jpg",
        ),
        (
            lambda client: client.scan_content(
                "spam", file_urls={1: ["https://example.com/a.jpg"]}
            ),
            "The file URLs are keyed by an evidence index that does not exist: 1",
        ),
        (
            lambda client: client.scan_content("spam", file_urls={0: "https://example.com/a.jpg"}),
            "The file URLs of the evidence at index 0 must be a non-empty sequence of URLs",
        ),
        (
            lambda client: client.scan_content("spam", file_urls={0: [""]}),
            "The file URLs of the evidence at index 0 must be a non-empty sequence of URLs",
        ),
        (
            lambda client: client.request("TRACE", "my-plugin"),
            "Method must be one of GET, POST, PUT, PATCH or DELETE",
        ),
        (lambda client: client.request("GET", "/"), "Path must be a non-empty path"),
        (lambda client: client.request("GET", "../info"), "Path must be a non-empty path"),
        (
            lambda client: client.request("GET", "https://example.com/info"),
            "Path must be a non-empty path",
        ),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
