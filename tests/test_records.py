from typing import Any

import pytest

from pyfederation.enums import AuditLogType, ContentType, IncidentType, NamedEntityType, RecordType
from pyfederation.records import (
    AuditLog,
    BlacklistRecord,
    EntityQueryResult,
    EntityRecord,
    EvidenceRecord,
    FileAttachmentRecord,
    OperatorCreated,
    OperatorRecord,
    ResolvedEntityPosition,
    ScannedContent,
    SearchResult,
    ServerInformation,
)

from . import payloads


def test_entity_metadata_is_decoded_from_json_string() -> None:
    record = EntityRecord.model_validate(payloads.entity(metadata='{"platform": "telegram"}'))
    assert record.metadata == {"platform": "telegram"}


def test_entity_metadata_accepts_an_object() -> None:
    record = EntityRecord.model_validate(payloads.entity(metadata={"platform": "telegram"}))
    assert record.metadata == {"platform": "telegram"}


@pytest.mark.parametrize(
    ("host", "id", "telephone"),
    [
        ("e164.arpa", "14155550123", True),
        ("E164.ARPA", "14155550123", True),
        ("e164.arpa", None, False),
        ("example.com", "14155550123", False),
    ],
)
def test_entity_is_telephone(host: str, id: str | None, telephone: bool) -> None:
    assert EntityRecord.model_validate(payloads.entity(host=host, id=id)).is_telephone is telephone


def test_unknown_fields_are_ignored() -> None:
    record = EntityRecord.model_validate(payloads.entity(introduced_later=True))
    assert not hasattr(record, "introduced_later")


@pytest.mark.parametrize(
    ("record_type", "payload", "expected"),
    [
        (RecordType.ENTITY, payloads.entity(), EntityRecord),
        (RecordType.EVIDENCE, payloads.evidence(), EvidenceRecord),
        (RecordType.AUDIT_LOG, payloads.audit_log(), AuditLog),
        (RecordType.OPERATOR, payloads.operator(), OperatorRecord),
    ],
)
def test_search_result_record_is_typed_by_record_type(
    record_type: RecordType, payload: dict[str, Any], expected: type
) -> None:
    result = SearchResult.model_validate({"type": record_type, "record": payload})
    assert isinstance(result.record, expected)


def test_scanned_content_resolves_nested_entities() -> None:
    content = ScannedContent.model_validate(
        {
            "author_entity": None,
            "resolved_entities": [
                {
                    "entity": payloads.entity(host="spam.example"),
                    "entity_position": {"offset": 10, "length": 12, "type": "domain"},
                    "active_blacklists": [],
                    "parent_entity": {
                        "entity": payloads.entity(),
                        "entity_position": None,
                        "active_blacklists": [],
                        "parent_entity": None,
                    },
                }
            ],
            "classification": None,
            "scan_results": {},
            "risk_score": 0,
        }
    )

    resolved = content.resolved_entities[0]
    assert resolved.entity_position is not None
    assert resolved.entity_position.type is NamedEntityType.DOMAIN
    assert resolved.parent_entity is not None
    assert resolved.parent_entity.entity.host == "example.com"


@pytest.mark.parametrize(("evidence", "expected"), [("", None), (None, None), ("e", "e")])
def test_attachment_without_evidence(evidence: str | None, expected: str | None) -> None:
    attachment = FileAttachmentRecord.model_validate(payloads.attachment(evidence=evidence))
    assert attachment.evidence == expected


def test_scanned_content_detections() -> None:
    content = ScannedContent.model_validate(
        {
            "resolved_entities": [],
            "scan_results": {},
            "risk_score": 75,
            "detections": [
                {
                    "concern": "SPAM",
                    "content_index": 1,
                    "entity": payloads.ENTITY_UUID,
                    "source": "blacklist",
                    "confidence": None,
                    "verified": True,
                },
                {
                    "concern": "TRACKING",
                    "content_index": 0,
                    "file_index": 2,
                    "entity": None,
                    "source": "filter_list",
                    "confidence": 0.5,
                    "verified": False,
                },
            ],
        }
    )

    assert [detection.concern for detection in content.detections] == [
        IncidentType.SPAM,
        IncidentType.TRACKING,
    ]
    assert content.detections[0].entity == payloads.ENTITY_UUID
    # Servers before OFD 2.1 do not relate detections to files
    assert content.detections[0].file_index is None
    assert content.detections[1].file_index == 2
    assert not content.detections[1].verified


def test_operator_configuration() -> None:
    operator = OperatorRecord.model_validate(
        payloads.operator(
            configuration={
                "auto_assign_reports": False,
                "auto_assign_automated_reports": True,
                "is_bot": True,
            }
        )
    )

    assert not operator.auto_assign_reports
    assert operator.auto_assign_automated_reports
    assert operator.auto_assigned
    assert operator.is_bot


def test_operator_with_undisclosed_configuration() -> None:
    operator = OperatorRecord.model_validate(payloads.operator(configuration=None))

    assert not operator.auto_assigned
    assert not operator.is_bot


def test_unrecognized_incident_and_audit_log_types_are_read_as_other() -> None:
    assert BlacklistRecord.model_validate(payloads.blacklist(type="NEW")).type is IncidentType.OTHER
    assert AuditLog.model_validate(payloads.audit_log(type="NEW")).type is AuditLogType.OTHER


def test_other_unrecognized_values_are_read_as_none() -> None:
    entity = EntityRecord.model_validate(payloads.entity(relationship_type="NEW"))
    position = ResolvedEntityPosition.model_validate({"offset": 0, "length": 4, "type": "new"})
    query = EntityQueryResult.model_validate(
        {
            "entity_record": payloads.entity(),
            "related_entities": [],
            "active_blacklists": [],
            "suggested_action": "NEW",
        }
    )

    assert entity.relationship_type is None
    assert position.type is None
    assert query.suggested_action is None


def test_unrecognized_values_are_left_out_of_lists() -> None:
    payload = payloads.server_information()
    payload["search_types"] = ["ENTITY", "NEW"]
    payload["scan_content_types"] = ["EMAIL", "NEW"]
    payload["concerns"] = ["SPAM", "NEW"]

    information = ServerInformation.model_validate(payload)

    assert information.search_types == [RecordType.ENTITY]
    assert information.scan_content_types == [ContentType.TEXT, ContentType.EMAIL]
    # An unrecognized incident type is read as OTHER
    assert information.concerns == [IncidentType.SPAM, IncidentType.OTHER]


def test_server_information_capabilities() -> None:
    payload = payloads.server_information()
    payload.update(
        collects_public_scan_content=True,
        allow_url_uploads=True,
        scan_content_types=["TEXT", "EMAIL", "SMS", "WEB_PAGE", "HOSTNAME", "URL"],
        concerns=["SPAM", "SCAM", "ADVERTISING", "TRACKING", "OTHER"],
        default_concerns=["SPAM", "SCAM", "OTHER"],
        max_scan_files=4,
        max_scan_file_size=10_485_760,
    )

    information = ServerInformation.model_validate(payload)

    assert information.api_major_version == 2
    assert information.max_scan_files == 4
    assert information.max_scan_file_size == 10_485_760
    assert information.collects_public_scan_content
    assert information.url_uploads_allowed
    assert information.scan_content_types == list(ContentType)
    assert information.default_concerns == [
        IncidentType.SPAM,
        IncidentType.SCAM,
        IncidentType.OTHER,
    ]


def test_server_information_capabilities_that_are_not_published() -> None:
    information = ServerInformation.model_validate(payloads.server_information())

    assert information.collects_public_scan_content is None
    assert not information.url_uploads_allowed
    # Content scanning always interprets text
    assert information.scan_content_types == [ContentType.TEXT]
    assert information.concerns == information.default_concerns == []
    # Servers before OFD 2.1 do not publish the limits on scanned files
    assert information.max_scan_files == information.max_scan_file_size == 0


@pytest.mark.parametrize(
    ("api_version", "major"), [("2.0", 2), ("2", 2), ("10.1", 10), ("v2", -1), ("", -1)]
)
def test_api_major_version(api_version: str, major: int) -> None:
    payload = payloads.server_information()
    payload["api_version"] = api_version

    assert ServerInformation.model_validate(payload).api_major_version == major


@pytest.mark.parametrize(
    ("api_version", "minor"),
    [("2.2", 2), ("2", 0), ("2.10", 10), ("2.x", -1), ("2.2.1", -1), ("", -1)],
)
def test_api_minor_version(api_version: str, minor: int) -> None:
    payload = payloads.server_information()
    payload["api_version"] = api_version

    assert ServerInformation.model_validate(payload).api_minor_version == minor


@pytest.mark.parametrize(
    ("api_version", "at_least"),
    [("2.2", True), ("2.10", True), ("3.0", True), ("2.1", False), ("1.9", False), ("v2.2", False)],
)
def test_is_api_version_at_least(api_version: str, at_least: bool) -> None:
    payload = payloads.server_information()
    payload["api_version"] = api_version

    assert ServerInformation.model_validate(payload).is_api_version_at_least(2, 2) is at_least


@pytest.mark.parametrize(("published", "allowed"), [(None, True), (True, True), (False, False)])
def test_illegal_content_is_allowed_unless_the_server_declines_it(
    published: bool | None, allowed: bool
) -> None:
    payload = payloads.server_information()
    if published is not None:
        payload["allow_illegal_content"] = published

    assert ServerInformation.model_validate(payload).illegal_content_allowed is allowed


def test_access_tokens_are_left_out_of_the_representation() -> None:
    created = OperatorCreated.model_validate(
        {"uuid": payloads.OPERATOR_UUID, "access_token": "secret-token"}
    )

    assert "secret-token" not in repr(created)
