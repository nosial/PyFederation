# Generated from async_client.py by scripts/unasync.py, do not edit.
"""Synchronous client for Federation servers."""

import json
import logging
import os
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from os import PathLike
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Any, BinaryIO, Self

import httpx

from ._utils import (
    attachment_file_name,
    compact,
    entity_path,
    evidence_payload,
    page_params,
    parse_list,
    path_segment,
    readable_file,
    require,
    scan_file_urls,
    scan_files,
    search_params,
)
from .enums import (
    ClassificationFlag,
    ContentType,
    EntityRelationshipType,
    IncidentType,
    RecordType,
)
from .exceptions import FederationClientException
from .records import (
    AuditLog,
    BlacklistRecord,
    ContentInput,
    EntityQueryResult,
    EntityRecord,
    EvidenceRecord,
    FileAttachmentRecord,
    OperatorConfiguration,
    OperatorCreated,
    OperatorPermissions,
    OperatorRecord,
    ReportRecord,
    ReportSubmission,
    ScannedContent,
    SearchResult,
    ServerInformation,
    UploadResult,
)

log = logging.getLogger(__name__)

DEFAULT_MAX_FILE_SIZE = 52_428_800


class FederationClient:
    """Synchronous API client for a Federation server.

    Every public method corresponds to an endpoint of the server and handles serialization,
    authentication and error mapping, raising FederationClientException when a request fails.

    List and search methods are paginated with a 1-based page and a limit of items per page, which
    the server caps at its configured maximum. Most of them also accept a category filter, a field
    to sort by and a sort order (ASC or DESC); the accepted values of each are listed in the server
    specification.

    Entities are identified by their UUID, SHA-256 hash or address, such as a domain, an email
    address or an IP address.

    Invalid arguments, such as an empty UUID or a page below 1, raise ValueError before any request
    is sent.

    To release the underlying connection pool, close the client with close() or use it as a
    context manager.
    """

    def __init__(
        self,
        endpoint: str,
        access_token: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        """
        Args:
            endpoint: The base URL of the Federation server.
            access_token: The access token used for authentication, or None for anonymous access.
            http_client: The HTTP client used for all requests, closed together with this client.

        Raises:
            ValueError: If the endpoint is not a valid URL or the access token is invalid.
        """
        if not httpx.URL(endpoint).host:
            raise ValueError(f"Endpoint must be a valid URL: {endpoint}")

        self._endpoint = endpoint.rstrip("/")
        self._http_client = http_client or httpx.Client(timeout=httpx.Timeout(30, write=60))
        self.access_token = access_token

    @property
    def endpoint(self) -> str:
        """The base URL of the Federation server."""
        return self._endpoint

    @property
    def access_token(self) -> str | None:
        """The access token used for authentication, or None for anonymous access."""
        return self._access_token

    @access_token.setter
    def access_token(self, access_token: str | None) -> None:
        if access_token is not None and (not access_token or any(map(str.isspace, access_token))):
            raise ValueError("Access token cannot be empty or contain whitespace")

        self._access_token = access_token

    def close(self) -> None:
        """Closes the underlying HTTP client."""
        self._http_client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _send(
        self,
        method: str,
        path: str,
        error_message: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        headers = {"Accept": "application/json"}
        if self._access_token is not None:
            headers["Authorization"] = f"Bearer {self._access_token}"

        request = self._http_client.build_request(
            method,
            f"{self._endpoint}/{path}",
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
        )
        log.debug("%s request to %s", method, request.url)

        try:
            response = self._http_client.send(request, stream=stream)
            if response.is_error:
                response.read()
                raise FederationClientException.from_response(response, error_message)
        except httpx.HTTPError as e:
            raise FederationClientException(f"{error_message}: {e}") from e

        return response

    def _request(
        self,
        method: str,
        path: str,
        error_message: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        response = self._send(
            method, path, error_message, params=params, json=json, data=data, files=files
        )
        if not response.content:
            return None

        try:
            return response.json()
        except ValueError as e:
            raise FederationClientException(
                f"{error_message}: Expected JSON response but received Content-Type: "
                f"{response.headers.get('Content-Type')}",
                response.status_code,
            ) from e

    def get_server_information(self) -> ServerInformation:
        """Returns the server information including version, feature flags and record counts."""
        data = self._request("GET", "info", "Failed to get server information")
        return ServerInformation.model_validate(data)

    def get_specification(self) -> dict[str, Any]:
        """Returns the OpenAPI specification of the server."""
        spec: dict[str, Any] = self._request("GET", "specification", "Failed to get specification")
        return spec

    def request(self, method: str, path: str, parameters: dict[str, Any] | None = None) -> Any:
        """Sends a request to a route this client has no method for, such as a route a plugin of
        the server provides, authenticated with the access token of the client.

        Args:
            method: The HTTP method: GET, POST, PUT, PATCH or DELETE.
            path: The path of the route relative to the endpoint, such as "my-plugin/status".
            parameters: The parameters, sent as the query string of a GET or DELETE request and as
                a JSON body otherwise.

        Returns:
            The decoded JSON response, or None if the response is empty.
        """
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError("Method must be one of GET, POST, PUT, PATCH or DELETE")
        path = path.strip("/")
        if not path or "://" in path or any(part in (".", "..") for part in path.split("/")):
            raise ValueError(f"Path must be a non-empty path relative to the endpoint: {path}")

        query = method in ("GET", "DELETE")
        return self._request(
            method,
            path,
            f"Failed to request {method} /{path}",
            params=parameters if query else None,
            json=None if query else parameters,
        )

    def search(
        self,
        query: str,
        types: Sequence[RecordType] | None = None,
        page: int = 1,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Searches across all record types.

        Args:
            query: The search query, with at least 2 non-whitespace characters.
            types: The record types to restrict the search to, or None for all types.
            page: The page number.
            limit: The number of results per record type.
        """
        params = search_params(query, page, limit, type=",".join(types) if types else None)
        data = self._request("GET", "search", f"Failed to search, query: {query}", params=params)
        # Records of a type added by a later minor version of OFD are left out
        record_types = set(RecordType)
        return parse_list(SearchResult, [item for item in data if item["type"] in record_types])

    def scan_content(
        self,
        evidence: str | ContentInput | Sequence[ContentInput],
        author: str | None = None,
        top_k: int | None = None,
        threshold: float | None = None,
        concerns: Sequence[IncidentType] | None = None,
        files: Mapping[int, Sequence[str | PathLike[str]]] | None = None,
        file_urls: Mapping[int, Sequence[str]] | None = None,
    ) -> ScannedContent:
        """Scans content for entities and blacklist records, and classifies it.

        Args:
            evidence: The text, content input or content inputs to scan.
            author: The UUID, SHA-256 hash or address of the author entity.
            top_k: The number of top classifications to return.
            threshold: The confidence threshold for classification.
            concerns: The incident types to assess, among the concerns the server publishes, or
                None for its default concerns. Only these affect the classification, risk score,
                suggested action and detections of the result.
            files: The local paths of the files of each content input, such as the images of a
                message, keyed by the position of the input in the evidence, e.g.
                {0: ["photo.jpg"]}. A content input with files may omit its text. Files are sent
                in a multipart/form-data request, which a server that does not scan files accepts
                and ignores, but which a server before OFD 2.1 may reject.
            file_urls: The absolute HTTP or HTTPS URLs of further files of each content input,
                keyed by its position in the evidence, which the server retrieves itself, e.g.
                {0: ["https://example.com/photo.jpg"]}. A content input with file URLs may omit its
                text. A server that does not retrieve them, or a file it cannot retrieve, is
                treated like a file it does not interpret. Only name file URLs to a server for
                which `is_api_version_at_least(2, 2)`, earlier servers reject them. The file index
                of a retrieved file follows those of the files of its input.
        """
        payload = evidence_payload(evidence)
        items = payload if isinstance(payload, list) else [payload]
        parts = scan_files(items, files or {})
        scan_file_urls(items, file_urls or {})
        if not parts and not any(
            item.get("text_content") or item.get("file_urls") for item in items
        ):
            raise ValueError(
                "At least one evidence record must contain text content, a file or a file URL"
            )
        if concerns is not None and not concerns:
            raise ValueError("Concerns cannot be empty")

        body = compact(
            evidence=payload,
            author=author,
            top_k=top_k,
            threshold=threshold,
            concerns=concerns,
        )
        if not parts:
            data = self._request("POST", "scan", "Failed to scan content", json=body)
            return ScannedContent.model_validate(data)

        # A multipart request carries the evidence and the concerns as the JSON text of their
        # values, and the other parameters as their text
        fields = {
            key: value if isinstance(value, str) else json.dumps(value)
            for key, value in body.items()
        }
        with ExitStack() as stack:
            data = self._request(
                "POST",
                "scan",
                "Failed to scan content",
                data=fields,
                files={
                    part: (path.name, stack.enter_context(path.open("rb")))
                    for part, path in parts.items()
                },
            )
        return ScannedContent.model_validate(data)

    def list_audit_logs(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists audit log entries."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "", f"Failed to list audit logs, page: {page}, limit: {limit}", params=params
        )
        return parse_list(AuditLog, data)

    def get_audit_log_record(self, audit_log_uuid: str) -> AuditLog:
        """Returns an audit log entry by its UUID."""
        require(audit_log_uuid, "Audit log UUID")
        data = self._request(
            "GET",
            f"audit/{path_segment(audit_log_uuid)}",
            f"Failed to get audit log record for UUID {audit_log_uuid}",
        )
        return AuditLog.model_validate(data)

    def search_audit_logs(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Searches audit log entries."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "audit/search", f"Failed to search audit logs, query: {query}", params=params
        )
        return parse_list(AuditLog, data)

    def create_operator(self, operator_name: str) -> OperatorCreated:
        """Creates an operator, returning its UUID and access token."""
        require(operator_name, "Operator name")
        data = self._request(
            "POST",
            "operators",
            f"Failed to create operator with name {operator_name}",
            json={"name": operator_name},
        )
        return OperatorCreated.model_validate(data)

    def delete_operator(self, operator_uuid: str) -> None:
        """Deletes an operator."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "DELETE",
            f"operators/{path_segment(operator_uuid)}",
            f"Failed to delete operator with UUID {operator_uuid}",
        )

    def disable_operator(self, operator_uuid: str) -> None:
        """Disables an operator, preventing it from authenticating."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/disable",
            f"Failed to disable operator with UUID {operator_uuid}",
        )

    def enable_operator(self, operator_uuid: str) -> None:
        """Enables a disabled operator."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/enable",
            f"Failed to enable operator with UUID {operator_uuid}",
        )

    def get_operator(self, operator_uuid: str) -> OperatorRecord:
        """Returns an operator by its UUID."""
        require(operator_uuid, "Operator UUID")
        data = self._request(
            "GET", f"operators/{path_segment(operator_uuid)}", "Failed to get operator"
        )
        return OperatorRecord.model_validate(data)

    def get_self(self) -> OperatorRecord:
        """Returns the operator the client is authenticated as."""
        data = self._request("GET", "operators/self", "Failed to get self operator")
        return OperatorRecord.model_validate(data)

    def list_operators(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[OperatorRecord]:
        """Lists operators."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "operators",
            f"Failed to list operators, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(OperatorRecord, data)

    def list_operator_audit_logs(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists the audit log entries of an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/audit",
            f"Failed to list audit logs for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(AuditLog, data)

    def list_operator_evidence(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records submitted by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(
            page, limit, include_confidential=include_confidential, by=by, order=order
        )
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/evidence",
            f"Failed to list evidence records for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def list_operator_blacklist(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Lists the blacklist records created by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, include_lifted=include_lifted, by=by, order=order)
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/blacklist",
            f"Failed to list operator blacklist records with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def update_operator_permissions(
        self,
        operator_uuid: str,
        client: bool | None = None,
        management: bool | None = None,
        operator: bool | None = None,
    ) -> OperatorPermissions:
        """Grants or revokes permission groups of an operator, returning its updated permissions.

        Groups given as None are left unchanged. Management permissions inherit client permissions,
        so the server rejects revoking client permissions from an operator that keeps management
        permissions with HTTP 409.
        """
        require(operator_uuid, "Operator UUID")
        payload = compact(client=client, management=management, operator=operator)
        if not payload:
            raise ValueError("At least one permission group must be given")

        data = self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/permissions",
            f"Failed to update the permissions of operator {operator_uuid}",
            json=payload,
        )
        return OperatorPermissions.model_validate(data)

    def update_operator_configuration(
        self,
        operator_uuid: str,
        auto_assign_reports: bool | None = None,
        auto_assign_automated_reports: bool | None = None,
        is_bot: bool | None = None,
    ) -> OperatorConfiguration:
        """Changes the settings of an operator, returning its updated configuration.

        Settings given as None are left unchanged. An operator may change its own configuration,
        changing that of another operator requires operator permissions.

        Args:
            operator_uuid: The operator to change.
            auto_assign_reports: Whether reports that are not automated are automatically
                assigned to the operator.
            auto_assign_automated_reports: Whether automated reports are automatically assigned
                to the operator.
            is_bot: Whether the operator is a bot, whose evidence and reports are automated and
                whose evidence is created confidential.
        """
        require(operator_uuid, "Operator UUID")
        payload = compact(
            auto_assign_reports=auto_assign_reports,
            auto_assign_automated_reports=auto_assign_automated_reports,
            is_bot=is_bot,
        )
        if not payload:
            raise ValueError("At least one setting must be given")

        data = self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/configuration",
            f"Failed to update the configuration of operator {operator_uuid}",
            json=payload,
        )
        return OperatorConfiguration.model_validate(data)

    def set_operator_permissions(self, operator_uuid: str, has_operator_permissions: bool) -> None:
        """Grants or revokes the permission to manage other operators."""
        self.update_operator_permissions(operator_uuid, operator=has_operator_permissions)

    def set_client_permissions(self, operator_uuid: str, has_client_permissions: bool) -> None:
        """Grants or revokes the permission to submit data as a client.

        Client permissions can't be revoked from an operator that holds management permissions.
        """
        self.update_operator_permissions(operator_uuid, client=has_client_permissions)

    def set_management_permissions(
        self, operator_uuid: str, has_management_permissions: bool
    ) -> None:
        """Grants or revokes the permission to manage the database.

        Granting management permissions also grants client permissions, which revoking them leaves
        in place.
        """
        self.update_operator_permissions(
            operator_uuid,
            client=True if has_management_permissions else None,
            management=has_management_permissions,
        )

    def set_auto_assign(self, operator_uuid: str, auto_assign: bool) -> None:
        """Sets whether reports of every kind are automatically assigned to an operator.

        Use update_operator_configuration() to opt in to ordinary or automated reports only.
        """
        self.update_operator_configuration(operator_uuid, auto_assign, auto_assign)

    def set_bot(self, operator_uuid: str, is_bot: bool) -> None:
        """Sets whether an operator is a bot, whose evidence and reports are automated."""
        self.update_operator_configuration(operator_uuid, is_bot=is_bot)

    def generate_access_token(self, update: bool = True) -> str:
        """Generates a new access token for the authenticated operator, revoking the current one.

        Args:
            update: Whether the client should use the new access token from now on.
        """
        access_token: str = self._request(
            "POST", "operators/refresh", "Failed to generate access token"
        )
        if update:
            self.access_token = access_token

        return access_token

    def generate_operator_access_token(self, operator_uuid: str) -> str:
        """Generates a new access token for an operator, revoking its current one."""
        require(operator_uuid, "Operator UUID")
        access_token: str = self._request(
            "POST",
            f"operators/{path_segment(operator_uuid)}/refresh",
            f"Failed to generate access token for operator with UUID {operator_uuid}",
        )
        return access_token

    def search_operators(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[OperatorRecord]:
        """Searches operators."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "operators/search", f"Failed to search operators, query: {query}", params=params
        )
        return parse_list(OperatorRecord, data)

    def update_operator_name(self, operator_uuid: str, new_name: str) -> None:
        """Renames an operator."""
        require(operator_uuid, "Operator UUID")
        require(new_name, "Operator name")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/update-name",
            f"Failed to update name for operator with UUID {operator_uuid}",
            json={"name": new_name},
        )

    def list_operator_reports(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports submitted by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports",
            f"Failed to list reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def list_assigned_operator_reports(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports assigned to an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports/assigned",
            f"Failed to list assigned reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def delete_entity(self, entity_identifier: str) -> None:
        """Deletes an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "DELETE",
            entity_path(entity_identifier),
            f"Failed to delete the entity {entity_identifier}",
        )

    def get_entity_record(self, entity_identifier: str) -> EntityRecord:
        """Returns an entity."""
        require(entity_identifier, "Entity identifier")
        data = self._request(
            "GET",
            entity_path(entity_identifier),
            f"Failed to get the entity record for {entity_identifier}",
        )
        return EntityRecord.model_validate(data)

    def query_entity(
        self, entity_identifier: str, concerns: Sequence[IncidentType] | None = None
    ) -> EntityQueryResult:
        """Returns an entity with its relationship group, active blacklists and suggested action.

        Args:
            entity_identifier: The entity to query.
            concerns: The incident types to suggest an action for, among the concerns the server
                publishes, or None for its default concerns. The active blacklists are returned
                regardless of the concerns.
        """
        require(entity_identifier, "Entity identifier")
        if concerns is not None and not concerns:
            raise ValueError("Concerns cannot be empty")

        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/query",
            f"Failed to query entity {entity_identifier}",
            params={"concerns": ",".join(concerns)} if concerns is not None else None,
        )
        return EntityQueryResult.model_validate(data)

    def list_entities(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EntityRecord]:
        """Lists entities."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "entities",
            f"Failed to list entities, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(EntityRecord, data)

    def get_top_threats(self, limit: int = 10) -> list[EntityRecord]:
        """Returns the entities with the lowest reputation."""
        if limit < 1:
            raise ValueError("Limit must be greater than 0")

        data = self._request(
            "GET",
            "entities/top-threats",
            f"Failed to retrieve top threats, limit: {limit}",
            params={"limit": limit},
        )
        return parse_list(EntityRecord, data)

    def list_entity_audit_logs(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists the audit log entries of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/audit",
            f"Failed to list audit logs for entity {entity_identifier}",
            params=params,
        )
        return parse_list(AuditLog, data)

    def list_entity_blacklist_records(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Lists the blacklist records of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, include_lifted=include_lifted, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/blacklist",
            f"Failed to list blacklist records for entity {entity_identifier}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def list_entity_evidence_records(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(
            page, limit, include_confidential=include_confidential, by=by, order=order
        )
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/evidence",
            f"Failed to list evidence records for entity {entity_identifier}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def list_entity_reports(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports made against an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/reports",
            f"Failed to list reports for entity {entity_identifier}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def push_entity(
        self, host: str, id: str | None = None, metadata: dict[str, Any] | None = None
    ) -> str:
        """Registers an entity, returning its UUID. Pushing a known entity returns its UUID.

        Args:
            host: The domain or IP address of the entity.
            id: The local part of the entity address, such as the username of an email address.
            metadata: Arbitrary metadata to associate with the entity.
        """
        require(host, "Host")
        if id is not None:
            require(id, "Entity ID")

        entity_uuid: str = self._request(
            "POST",
            "entities",
            f"Failed to push entity with domain {host}",
            json=compact(host=host, id=id, metadata=metadata),
        )
        return entity_uuid

    def update_entity(self, entity_identifier: str, metadata: dict[str, Any]) -> None:
        """Replaces the metadata of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            entity_path(entity_identifier),
            f"Failed to update entity {entity_identifier}",
            json={"metadata": metadata},
        )

    def set_entity_whitelist(self, entity_identifier: str, whitelisted: bool) -> None:
        """Sets whether an entity is whitelisted."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/whitelist",
            f"Failed to set whitelist state for entity {entity_identifier}",
            json={"whitelisted": whitelisted},
        )

    def clear_entity_reputation(self, entity_identifier: str) -> None:
        """Resets the reputation of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/clear-reputation",
            f"Failed to clear reputation for entity {entity_identifier}",
        )

    def set_entity_relationship(
        self,
        entity_identifier: str,
        related_entity_identifier: str,
        relationship_type: EntityRelationshipType,
    ) -> None:
        """Relates an entity to another entity, given by its UUID, SHA-256 hash or address."""
        require(entity_identifier, "Entity identifier")
        require(related_entity_identifier, "Related entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/relationship",
            f"Failed to set relationship for entity {entity_identifier}",
            json={
                "target_identifier": related_entity_identifier,
                "relationship_type": relationship_type,
            },
        )

    def clear_entity_relationship(self, entity_identifier: str) -> None:
        """Removes the relationship of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "DELETE",
            f"{entity_path(entity_identifier)}/relationship",
            f"Failed to clear relationship for entity {entity_identifier}",
        )

    def search_entities(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EntityRecord]:
        """Searches entities."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "entities/search", f"Failed to search entities, query: {query}", params=params
        )
        return parse_list(EntityRecord, data)

    def delete_evidence(self, evidence_uuid: str) -> None:
        """Deletes an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        self._request(
            "DELETE",
            f"evidence/{path_segment(evidence_uuid)}",
            f"Failed to delete evidence with UUID {evidence_uuid}",
        )

    def get_evidence_record(self, evidence_uuid: str) -> EvidenceRecord:
        """Returns an evidence record by its UUID."""
        require(evidence_uuid, "Evidence UUID")
        data = self._request(
            "GET",
            f"evidence/{path_segment(evidence_uuid)}",
            f"Failed to get evidence record with UUID {evidence_uuid}",
        )
        return EvidenceRecord.model_validate(data)

    def get_evidence_attachments(self, evidence_uuid: str) -> list[FileAttachmentRecord]:
        """Returns the file attachments of an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        data = self._request(
            "GET",
            f"evidence/{path_segment(evidence_uuid)}/attachments",
            f"Failed to get evidence attachments for evidence with UUID {evidence_uuid}",
        )
        return parse_list(FileAttachmentRecord, data)

    def list_evidence(
        self,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists evidence records."""
        params = page_params(
            page,
            limit,
            include_confidential=include_confidential,
            category=category,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            "evidence",
            f"Failed to list evidence records, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def submit_evidence(
        self,
        entity_identifier: str,
        text_content: str | None = None,
        note: str | None = None,
        tag: str | None = None,
        confidential: bool = False,
        metadata: dict[str, Any] | None = None,
        classification: ClassificationFlag | None = None,
        content_type: ContentType = ContentType.TEXT,
        context: dict[str, str] | None = None,
    ) -> str:
        """Submits evidence about an entity, returning the UUID of the evidence record.

        Evidence submitted by a bot operator is automated and created confidential, and evidence
        about a telephone entity is always confidential.

        Args:
            entity_identifier: The entity the evidence is about.
            text_content: The observed content, in the form its content type defines.
            note: A note by the operator.
            tag: A tag to categorize the evidence with.
            confidential: Whether the evidence is hidden from the public.
            metadata: Arbitrary metadata to associate with the evidence.
            classification: A classification of the evidence, which requires management
                permissions and trains the server's classifier with the text content.
            content_type: The type of the content.
            context: The context of the content, whose keys are defined per content type.
        """
        require(entity_identifier, "Entity identifier")
        payload = compact(
            entity_identifier=entity_identifier,
            text_content=text_content,
            note=note,
            tag=tag,
            confidential=confidential,
            metadata=metadata,
            classification=classification,
            # TEXT is the default content type, which is not sent
            content_type=content_type if content_type is not ContentType.TEXT else None,
            context=context,
        )
        evidence_uuid: str = self._request(
            "POST",
            "evidence",
            f"Failed to submit evidence for entity {entity_identifier}",
            json=payload,
        )
        return evidence_uuid

    def update_evidence_confidentiality(self, evidence_uuid: str, confidential: bool) -> None:
        """Sets whether an evidence record is hidden from the public."""
        require(evidence_uuid, "Evidence UUID")
        action = "set" if confidential else "unset"
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/update-confidentiality",
            f"Failed to {action} confidentiality for evidence with UUID {evidence_uuid}",
            json={"confidential": confidential},
        )

    def update_evidence_tag(self, evidence_uuid: str, tag: str) -> None:
        """Sets the tag of an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        require(tag, "Tag")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/update-tag",
            f"Failed to update tag for evidence with UUID {evidence_uuid}",
            json={"tag": tag},
        )

    def classify_evidence(self, evidence_uuid: str, classification: ClassificationFlag) -> None:
        """Classifies an evidence record, training the server's classifier with its content.

        A classification replaces the previous classification of the evidence.
        """
        require(evidence_uuid, "Evidence UUID")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/classify",
            f"Failed to classify evidence with UUID {evidence_uuid}",
            json={"classification_flag": classification},
        )

    def search_evidence(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Searches evidence records."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "evidence/search", f"Failed to search evidence, query: {query}", params=params
        )
        return parse_list(EvidenceRecord, data)

    def add_evidence_to_report(self, evidence_uuid: str, report_uuid: str) -> None:
        """Links an evidence record to a report."""
        require(evidence_uuid, "Evidence UUID")
        require(report_uuid, "Report UUID")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/link-report",
            f"Failed to link evidence {evidence_uuid} to report {report_uuid}",
            json={"report_uuid": report_uuid},
        )

    def delete_report(self, report_uuid: str) -> None:
        """Deletes a report."""
        require(report_uuid, "Report UUID")
        self._request(
            "DELETE",
            f"reports/{path_segment(report_uuid)}",
            f"Failed to delete report {report_uuid}",
        )

    def submit_report(
        self,
        reporting_entity: str,
        evidence: str | ContentInput | Sequence[ContentInput],
        incident_type: IncidentType,
        report_message: str | None = None,
    ) -> ReportSubmission:
        """Reports an entity, creating an evidence record for each piece of evidence.

        Args:
            reporting_entity: The entity being reported.
            evidence: The text, content input or content inputs documenting the incident.
            incident_type: The type of the incident.
            report_message: A description of the incident.
        """
        require(reporting_entity, "Reporting entity identifier")
        if isinstance(evidence, str):
            require(evidence, "Content")

        payload = compact(
            reporting_entity=reporting_entity,
            evidence=evidence_payload(evidence),
            incident_type=incident_type,
            report_message=report_message,
        )
        data = self._request("POST", "reports", "Failed to submit report", json=payload)
        return ReportSubmission.model_validate(data)

    def list_reports(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists reports."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "reports",
            f"Failed to list reports, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def list_opened_reports(
        self,
        page: int = 1,
        limit: int = 100,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the opened reports assigned to the authenticated operator."""
        params = page_params(page, limit, by=by, order=order)
        data = self._request(
            "GET",
            "reports/opened",
            f"Failed to list opened reports, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def get_report(self, report_uuid: str) -> ReportRecord:
        """Returns a report by its UUID."""
        require(report_uuid, "Report UUID")
        data = self._request(
            "GET", f"reports/{path_segment(report_uuid)}", f"Failed to get report {report_uuid}"
        )
        return ReportRecord.model_validate(data)

    def list_report_evidence_records(
        self,
        report_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records of a report."""
        require(report_uuid, "Report UUID")
        params = page_params(
            page,
            limit,
            include_confidential=include_confidential,
            category=category,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            f"reports/{path_segment(report_uuid)}/evidence",
            f"Failed to list evidence records for report {report_uuid}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def close_report(
        self,
        report_uuid: str,
        classification: ClassificationFlag | None = None,
        blacklist_incident_type: IncidentType | None = None,
        blacklist_expires: int | None = None,
    ) -> None:
        """Closes a report assigned to the authenticated operator.

        Args:
            report_uuid: The report to close.
            classification: A classification to assign to the evidence records of the report.
            blacklist_incident_type: The incident type to blacklist the reported entity with, or
                None to close the report without blacklisting it.
            blacklist_expires: When the blacklist expires, or None for a permanent blacklist.
        """
        require(report_uuid, "Report UUID")
        payload = compact(
            classification_flag=classification,
            blacklist_incident_type=blacklist_incident_type,
            blacklist_expires=blacklist_expires,
        )
        self._request(
            "PATCH",
            f"reports/{path_segment(report_uuid)}/close",
            f"Failed to close report {report_uuid}",
            json=payload,
        )

    def assign_operator_to_report(self, report_uuid: str, operator_uuid: str | None = None) -> None:
        """Assigns a report to an operator, or to the authenticated operator if none is given."""
        require(report_uuid, "Report UUID")
        if operator_uuid is not None:
            require(operator_uuid, "Operator UUID")

        self._request(
            "PATCH",
            f"reports/{path_segment(report_uuid)}/assign",
            f"Failed to assign an operator to report {report_uuid}",
            json=compact(operator=operator_uuid),
        )

    def search_reports(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Searches reports."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "reports/search", f"Failed to search reports, query: {query}", params=params
        )
        return parse_list(ReportRecord, data)

    def blacklist_entity(
        self,
        entity_identifier: str,
        incident_type: IncidentType,
        report_uuid: str | None = None,
        expires: int | None = None,
    ) -> str:
        """Blacklists an entity, returning the UUID of the blacklist record.

        Args:
            entity_identifier: The entity to blacklist.
            incident_type: The type of the incident the entity is blacklisted for.
            report_uuid: The report supporting the decision, which may concern another entity,
                such as the domain a reported account advertised.
            expires: When the blacklist expires, or None for a permanent blacklist.
        """
        require(entity_identifier, "Entity identifier")
        if report_uuid is not None:
            require(report_uuid, "Report UUID")
        if expires is not None and expires < 0:
            raise ValueError("The expires parameter must be a positive integer or None")

        payload = compact(
            entity_identifier=entity_identifier,
            type=incident_type,
            report_uuid=report_uuid,
            expires=expires,
        )
        blacklist_uuid: str = self._request(
            "POST", "blacklist", f"Failed to blacklist entity {entity_identifier}", json=payload
        )
        return blacklist_uuid

    def delete_blacklist_record(self, blacklist_record_uuid: str) -> None:
        """Deletes a blacklist record."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        self._request(
            "DELETE",
            f"blacklist/{path_segment(blacklist_record_uuid)}",
            f"Failed to delete blacklist record with UUID {blacklist_record_uuid}",
        )

    def get_blacklist_record(self, blacklist_record_uuid: str) -> BlacklistRecord:
        """Returns a blacklist record by its UUID."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        data = self._request(
            "GET",
            f"blacklist/{path_segment(blacklist_record_uuid)}",
            f"Failed to get blacklist record with UUID {blacklist_record_uuid}",
        )
        return BlacklistRecord.model_validate(data)

    def lift_blacklist_record(self, blacklist_record_uuid: str) -> None:
        """Lifts a blacklist record, ending it before it expires."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        self._request(
            "PATCH",
            f"blacklist/{path_segment(blacklist_record_uuid)}/lift",
            f"Failed to lift blacklist record with UUID {blacklist_record_uuid}",
        )

    def extend_blacklist_record(self, blacklist_record_uuid: str, seconds: int) -> None:
        """Extends the expiry of a temporary blacklist record by a number of seconds."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        if seconds <= 0:
            raise ValueError("Extension seconds must be positive")

        self._request(
            "PATCH",
            f"blacklist/{path_segment(blacklist_record_uuid)}/extend",
            f"Failed to extend blacklist record with UUID {blacklist_record_uuid}",
            json={"seconds": seconds},
        )

    def list_blacklist_records(
        self,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
        types: Sequence[IncidentType] | None = None,
    ) -> list[BlacklistRecord]:
        """Lists blacklist records, of the given incident types only if any are given."""
        params = page_params(
            page,
            limit,
            include_lifted=include_lifted,
            category=category,
            type=",".join(types) if types else None,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            "blacklist",
            f"Failed to list blacklist records, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def search_blacklist(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
        types: Sequence[IncidentType] | None = None,
    ) -> list[BlacklistRecord]:
        """Searches blacklist records, of the given incident types only if any are given."""
        params = search_params(
            query,
            page,
            limit,
            category=category,
            type=",".join(types) if types else None,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            "blacklist/search",
            f"Failed to search blacklist records, query: {query}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def get_attachment_info(self, attachment_uuid: str) -> FileAttachmentRecord:
        """Returns the information of a file attachment."""
        require(attachment_uuid, "Attachment UUID")
        data = self._request(
            "GET",
            f"attachments/{path_segment(attachment_uuid)}/info",
            f"Failed to get attachment information with UUID {attachment_uuid}",
        )
        return FileAttachmentRecord.model_validate(data)

    def list_attachments(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[FileAttachmentRecord]:
        """Lists file attachments."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "attachments",
            f"Failed to list attachments, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(FileAttachmentRecord, data)

    def delete_attachment(self, attachment_uuid: str) -> None:
        """Deletes a file attachment."""
        require(attachment_uuid, "Attachment UUID")
        self._request(
            "DELETE",
            f"attachments/{path_segment(attachment_uuid)}",
            f"Failed to delete attachment with UUID {attachment_uuid}",
        )

    def download_attachment(
        self, attachment_uuid: str, directory_path: str | PathLike[str]
    ) -> Path:
        """Downloads a file attachment into a directory, returning the path of the file.

        The file is named after the attachment. An existing file or symbolic link of the same name
        is never replaced, and a download that fails leaves no partial file behind.

        Raises:
            ValueError: If the directory is not usable or the file already exists.
        """
        require(attachment_uuid, "Attachment UUID")
        require(os.fspath(directory_path), "Directory path")
        directory = Path(directory_path)
        if not directory.is_dir():
            raise ValueError(f"Directory does not exist: {directory_path}")
        if not os.access(directory, os.W_OK):
            raise ValueError(f"Directory is not writable: {directory_path}")

        error_message = f"Failed to download attachment with UUID {attachment_uuid}"
        response = self._send(
            "GET", f"attachments/{path_segment(attachment_uuid)}", error_message, stream=True
        )

        try:
            file_path = directory / attachment_file_name(response, attachment_uuid)
            try:
                file = file_path.open("xb")
            except FileExistsError as e:
                raise ValueError(f"File already exists: {file_path}") from e
            try:
                with file:
                    for chunk in response.iter_bytes():
                        file.write(chunk)
            except BaseException:
                file_path.unlink(missing_ok=True)
                raise
        except httpx.HTTPError as e:
            raise FederationClientException(f"{error_message}: {e}") from e
        finally:
            response.close()

        return file_path

    def upload_file_attachment(
        self,
        evidence_uuid: str,
        local_file_path: str | PathLike[str],
        file_name: str | None = None,
    ) -> UploadResult:
        """Uploads a file as an attachment of an evidence record.

        Args:
            evidence_uuid: The evidence record to attach the file to.
            local_file_path: The path of the file to upload.
            file_name: The name to upload the file as, defaulting to its local name.
        """
        require(evidence_uuid, "Evidence UUID")
        path = readable_file(local_file_path)
        with path.open("rb") as file:
            return self._upload_attachment(evidence_uuid, file_name or path.name, file)

    def upload_note_attachment(
        self, evidence_uuid: str, file_name: str, content: str
    ) -> UploadResult:
        """Uploads text as a .txt attachment of an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        require(file_name, "File name")
        require(content, "Content")
        if not file_name.endswith(".txt"):
            file_name += ".txt"

        return self._upload_attachment(evidence_uuid, file_name, content.encode())

    def upload_file_attachment_from_url(
        self,
        evidence_uuid: str,
        file_url: str,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> UploadResult:
        """Downloads a file and uploads it as an attachment of an evidence record.

        The file is requested from this machine, following redirects, so only pass a URL you
        trust.

        Args:
            evidence_uuid: The evidence record to attach the file to.
            file_url: The URL to download the file from, which is requested without credentials.
            max_file_size: The maximum size of the file in bytes.
        """
        require(evidence_uuid, "Evidence UUID")
        if not file_url:
            raise ValueError(f"Invalid URL provided: {file_url}")
        if max_file_size <= 0:
            raise ValueError("Maximum file size must be greater than 0")

        error_message = f"Failed to download file from URL: {file_url}"
        content = bytearray()

        try:
            with self._http_client.stream("GET", file_url, follow_redirects=True) as response:
                if response.is_error:
                    raise FederationClientException(
                        f"{error_message}, {response.reason_phrase}", response.status_code
                    )

                for chunk in response.iter_bytes():
                    content += chunk
                    if len(content) > max_file_size:
                        raise FederationClientException(
                            f"File exceeds maximum file size limit of {max_file_size} bytes", 413
                        )
        except httpx.HTTPError as e:
            raise FederationClientException(f"{error_message}: {e}") from e

        file_name = PurePosixPath(httpx.URL(file_url).path).name or "downloaded_file"
        return self._upload_attachment(evidence_uuid, file_name, bytes(content))

    def upload_file_attachment_by_url(self, evidence_uuid: str, file_url: str) -> UploadResult:
        """Uploads a file as an attachment of an evidence record, which the server retrieves itself.

        Unlike upload_file_attachment_from_url(), which downloads the file and uploads it, only the
        URL is sent. The server must be able to reach it, and servers reject URLs that resolve to
        non-public addresses unless configured otherwise. Only use it with a server that publishes
        allow_url_uploads as true.

        Args:
            evidence_uuid: The evidence record to attach the file to.
            file_url: The HTTP or HTTPS URL of the file.
        """
        require(evidence_uuid, "Evidence UUID")
        if not file_url:
            raise ValueError(f"Invalid URL provided: {file_url}")
        try:
            url = httpx.URL(file_url)
        except httpx.InvalidURL as e:
            raise ValueError(f"URL must be a valid HTTP or HTTPS URL: {file_url}") from e
        if url.scheme not in ("http", "https") or not url.host:
            raise ValueError(f"URL must be a valid HTTP or HTTPS URL: {file_url}")

        data = self._request(
            "POST",
            "attachments",
            f"Failed to upload attachment from URL {file_url}",
            json={"evidence_uuid": evidence_uuid, "url": file_url},
        )
        return UploadResult.model_validate(data)

    def _upload_attachment(
        self, evidence_uuid: str, file_name: str, content: bytes | BinaryIO
    ) -> UploadResult:
        data = self._request(
            "POST",
            "attachments",
            f"Failed to upload file attachment for evidence with UUID {evidence_uuid}",
            data={"evidence_uuid": evidence_uuid},
            files={"file": (file_name, content)},
        )
        return UploadResult.model_validate(data)

    def search_attachments(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[FileAttachmentRecord]:
        """Searches file attachments."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "attachments/search",
            f"Failed to search attachments, query: {query}",
            params=params,
        )
        return parse_list(FileAttachmentRecord, data)
