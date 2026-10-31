"""Records exchanged with a Federation server. All timestamps are Unix epoch seconds."""

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, ClassVar, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    OnErrorOmit,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapValidator,
    field_validator,
)

from .enums import (
    AuditLogType,
    ClassificationFlag,
    ContentType,
    EntityRelationshipType,
    IncidentType,
    NamedEntityType,
    RecordType,
    SuggestedAction,
)

_E = TypeVar("_E", bound=StrEnum)


def _unrecognized_as_none(value: Any, handler: ValidatorFunctionWrapHandler) -> Any:
    try:
        return handler(value)
    except ValidationError:
        return None


# A later minor version of OFD may add values to a set of values. Values this client does not
# recognize are read as None, or left out of lists with OnErrorOmit.
_Lenient = Annotated[_E | None, WrapValidator(_unrecognized_as_none)]


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True)


@dataclass(frozen=True)
class ContentInput:
    """A piece of content submitted for scanning or attached to a report submission.

    The context describes the content as the client observed it, its keys are defined per content
    type. It is an assertion of the client, which the server does not verify.
    """

    text_content: str | None = None
    note: str | None = None
    tag: str | None = None
    confidential: bool = False
    metadata: dict[str, Any] | None = None
    content_type: ContentType = ContentType.TEXT
    context: dict[str, str] | None = None


class AuditLog(_Record):
    """An entry of the audit log, referencing the records affected by the operation."""

    uuid: str
    operator: str | None = None
    entity: str | None = None
    blacklist: str | None = None
    evidence: str | None = None
    file_attachment: str | None = None
    report: str | None = None
    type: AuditLogType
    message: str
    timestamp: int


class BlacklistRecord(_Record):
    """A decision to block an entity, either permanently or until it expires."""

    uuid: str
    operator: str
    entity: str
    report: str | None = None
    type: IncidentType
    lifted: bool
    lifted_by: str | None = None
    expires: int | None = None
    created: int


class ContentClassification(_Record):
    """The classification of scanned content."""

    classification_flag: _Lenient[ClassificationFlag]
    confidence: float
    detected_language: str | None = None


class Detection(_Record):
    """A finding of the server about scanned content with respect to one of the concerns of a scan.

    A detection that is not verified relies on context or other assertions of the client, and
    should be weighed as no stronger than them. file_index is the position of the file, among the
    files of the content input, that the detection relates to, and None when it relates to none.
    """

    concern: IncidentType
    content_index: int
    file_index: int | None = None
    entity: str | None = None
    source: str
    confidence: float | None = None
    verified: bool


class EntityRecord(_Record):
    """An entity known to the server, such as a domain, email address or IP address."""

    uuid: str
    hash: str
    host: str
    id: str | None = None
    metadata: dict[str, Any] | None = None
    whitelisted: bool
    reputation: int
    reputation_last_updated: int | None = None
    relationship_entity: str | None = None
    relationship_type: _Lenient[EntityRelationshipType] = None
    created: int
    updated: int

    TELEPHONE_ENTITY_HOST: ClassVar[str] = "e164.arpa"
    """The host of telephone entities."""

    @field_validator("metadata", mode="before")
    @classmethod
    def _decode_metadata(cls, value: Any) -> Any:
        # FederationLib serializes entity metadata as a JSON encoded string
        return json.loads(value) if isinstance(value, str) else value

    @property
    def is_telephone(self) -> bool:
        """Whether the entity is a telephone number, <E.164 number>@e164.arpa."""
        return self.host.lower() == self.TELEPHONE_ENTITY_HOST and self.id is not None


class EntityQueryResult(_Record):
    """An entity together with its relationship group, active blacklists and suggested action."""

    entity_record: EntityRecord
    related_entities: list[EntityRecord]
    active_blacklists: list[BlacklistRecord]
    suggested_action: _Lenient[SuggestedAction] = None
    suggested_lift_timestamp: int | None = None


class EvidenceRecord(_Record):
    """Information collected about an entity.

    Evidence is automated when the server created it or a bot operator submitted it, and automated
    evidence is created confidential.
    """

    uuid: str
    entity: str
    operator: str
    confidential: bool
    automated: bool
    text_content: str | None = None
    content_type: _Lenient[ContentType] = ContentType.TEXT
    context: dict[str, str] | None = None
    note: str | None = None
    tag: str | None = None
    report: str | None = None
    metadata: dict[str, Any] | None = None
    classification_flag: _Lenient[ClassificationFlag] = None
    created: int
    updated: int


class FileAttachmentRecord(_Record):
    """A file uploaded as part of an evidence record."""

    uuid: str
    evidence: str | None = None
    file_name: str
    file_size: int
    file_mime: str
    created: int

    @field_validator("evidence", mode="before")
    @classmethod
    def _no_evidence(cls, value: Any) -> Any:
        # An empty evidence UUID means the attachment is not associated with evidence
        return value or None


class OperatorCreated(_Record):
    """The UUID and access token of a newly created operator."""

    uuid: str
    access_token: str = Field(repr=False)


class OperatorPermissions(_Record):
    """The permission groups of an operator.

    Management permissions inherit client permissions, so client is True whenever management is.
    """

    client: bool
    management: bool
    operator: bool


class OperatorConfiguration(_Record):
    """The settings of an operator.

    A server only discloses them to the operator itself and to operators with operator permissions.
    """

    auto_assign_reports: bool
    auto_assign_automated_reports: bool
    is_bot: bool


class OperatorRecord(_Record):
    """An account of the Federation server, its permissions and its settings.

    The configuration is None when the server did not disclose it, and the properties reading it
    are then False.
    """

    uuid: str
    name: str
    disabled: bool
    permissions: OperatorPermissions = OperatorPermissions(
        client=False, management=False, operator=False
    )
    configuration: OperatorConfiguration | None = None
    created: int
    updated: int

    @property
    def auto_assign_reports(self) -> bool:
        """Whether reports that are not automated are automatically assigned to the operator."""
        return self.configuration is not None and self.configuration.auto_assign_reports

    @property
    def auto_assign_automated_reports(self) -> bool:
        """Whether automated reports are automatically assigned to the operator."""
        return self.configuration is not None and self.configuration.auto_assign_automated_reports

    @property
    def auto_assigned(self) -> bool:
        """Whether reports of either kind are automatically assigned to the operator."""
        return self.auto_assign_reports or self.auto_assign_automated_reports

    @property
    def is_bot(self) -> bool:
        """Whether the operator is a bot, whose evidence and reports are automated."""
        return self.configuration is not None and self.configuration.is_bot


class ReportRecord(_Record):
    """An incident reported against an entity."""

    uuid: str
    submitting_operator: str
    reporting_entity: str | None = None
    assigned_operator: str | None = None
    automated: bool
    incident_type: IncidentType
    opened: bool
    message: str | None = None
    created: int
    updated: int | None = None


class ReportSubmission(_Record):
    """A submitted report together with the evidence records created for it."""

    report: ReportRecord
    evidence: list[EvidenceRecord]


class ResolvedEntityPosition(_Record):
    """The location of a named entity within scanned content."""

    offset: int
    length: int
    type: _Lenient[NamedEntityType]


class ResolvedEntity(_Record):
    """An entity resolved from scanned content."""

    entity: EntityRecord
    entity_position: ResolvedEntityPosition | None = None
    active_blacklists: list[BlacklistRecord]
    parent_entity: "ResolvedEntity | None" = None


class ScannedContent(_Record):
    """The result of a content scan, with the risk score and suggested action derived from it."""

    resolved_entities: list[ResolvedEntity]
    author_entity: ResolvedEntity | None = None
    classification: ContentClassification | None = None
    suggested_action: _Lenient[SuggestedAction] = None
    suggested_lift_timestamp: int | None = None
    scan_results: dict[str, float]
    risk_score: float
    detections: list[Detection] = []


class ServerInformation(_Record):
    """The identity, capabilities, public accessibility and record counts of a server.

    Unless public_telephone_entities is True, telephone entities are hidden from unauthenticated
    requests that do not identify them by their address or SHA-256 hash.
    collects_public_scan_content tells whether the server may store content that unauthenticated
    requests submit for scanning, and is None when the server does not publish it.
    max_scan_files and max_scan_file_size are the maximum number of files a scan request may carry
    and the maximum size of each in bytes, 0 when the server ignores the files of every request or
    predates OFD 2.1.
    """

    name: str
    api_version: str
    public_audit_logs: bool
    public_evidence: bool
    public_blacklist: bool
    public_entities: bool
    public_reports: bool
    public_entity_metadata: bool
    public_telephone_entities: bool
    public_scan_content: bool
    collects_public_scan_content: bool | None = None
    public_query_entity: bool
    search_enabled: bool
    public_search: bool
    search_types: list[OnErrorOmit[RecordType]]
    public_search_types: list[OnErrorOmit[RecordType]]
    allow_illegal_content: bool | None = None
    allow_url_uploads: bool | None = None
    scan_content_types: list[OnErrorOmit[ContentType]] = [ContentType.TEXT]
    max_scan_files: int = 0
    max_scan_file_size: int = 0
    concerns: list[OnErrorOmit[IncidentType]] = []
    default_concerns: list[OnErrorOmit[IncidentType]] = []
    public_audit_logs_visibility: list[AuditLogType] | None = None
    audit_log_records: int | None = None
    blacklist_records: int | None = None
    known_entities: int | None = None
    evidence_records: int | None = None
    file_attachment_records: int | None = None
    operators: int | None = None
    reports: int | None = None

    @field_validator("scan_content_types")
    @classmethod
    def _scan_text(cls, value: list[ContentType]) -> list[ContentType]:
        # Content scanning always interprets text
        return value if ContentType.TEXT in value else [ContentType.TEXT, *value]

    @property
    def illegal_content_allowed(self) -> bool:
        """Whether the server accepts reports with the ILLEGAL_CONTENT incident type.

        A server that declines them rejects such reports with HTTP 403. Servers that predate
        allow_illegal_content do not publish it and accept every incident type.
        """
        return self.allow_illegal_content is not False

    @property
    def url_uploads_allowed(self) -> bool:
        """Whether the server accepts attachments uploaded by URL.

        Servers that do not publish allow_url_uploads are treated as not accepting them.
        """
        return self.allow_url_uploads is True

    @property
    def api_major_version(self) -> int:
        """The major version of the OFD interface the server implements, -1 if it is unreadable."""
        major = self.api_version.split(".", 1)[0].strip()
        return int(major) if major.isascii() and major.isdecimal() else -1

    @property
    def api_minor_version(self) -> int:
        """The minor version of the OFD interface the server implements, 0 if the version has none
        and -1 if it is unreadable."""
        parts = self.api_version.split(".")
        if len(parts) > 2 or self.api_major_version < 0:
            return -1
        minor = parts[1].strip() if len(parts) == 2 else "0"
        return int(minor) if minor.isascii() and minor.isdecimal() else -1

    def is_api_version_at_least(self, major: int, minor: int = 0) -> bool:
        """Whether the server implements at least the given version of the OFD interface, e.g.
        `is_api_version_at_least(2, 2)` before naming the files of scanned content by URL."""
        if self.api_minor_version < 0:
            return False
        return (self.api_major_version, self.api_minor_version) >= (major, minor)


class UploadResult(_Record):
    """The UUID and download URL of an uploaded file attachment."""

    uuid: str
    url: str


_SEARCH_RECORD_TYPES: dict[RecordType, type[_Record]] = {
    RecordType.ENTITY: EntityRecord,
    RecordType.EVIDENCE: EvidenceRecord,
    RecordType.BLACKLIST: BlacklistRecord,
    RecordType.REPORT: ReportRecord,
    RecordType.ATTACHMENT: FileAttachmentRecord,
    RecordType.AUDIT_LOG: AuditLog,
    RecordType.OPERATOR: OperatorRecord,
}


class SearchResult(_Record):
    """A record matched by a search, typed according to its record type."""

    type: RecordType
    record: (
        EntityRecord
        | EvidenceRecord
        | BlacklistRecord
        | ReportRecord
        | FileAttachmentRecord
        | AuditLog
        | OperatorRecord
    )

    @field_validator("record", mode="before")
    @classmethod
    def _parse_record(cls, value: Any, info: ValidationInfo) -> Any:
        return _SEARCH_RECORD_TYPES[info.data["type"]].model_validate(value)
