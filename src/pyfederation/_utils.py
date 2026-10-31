import os
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from email.message import Message
from os import PathLike
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from .enums import ContentType
from .records import ContentInput

M = TypeVar("M", bound=BaseModel)


def compact(**values: Any) -> dict[str, Any]:
    """Returns the given values without the ones that are unset."""
    return {key: value for key, value in values.items() if value is not None}


def require(value: str | None, name: str) -> None:
    """Raises a ValueError if the value is empty."""
    if not value:
        raise ValueError(f"{name} cannot be empty")


def page_params(
    page: int, limit: int, by: str | None = None, order: str | None = None, **filters: Any
) -> dict[str, Any]:
    """Returns the query parameters of a paginated request.

    The sort field and the sort order are uppercased, as OFD 2.0 defines them.
    """
    if page < 1:
        raise ValueError("Page must be greater than 0")
    if limit < 1:
        raise ValueError("Limit must be greater than 0")

    return compact(
        page=page,
        limit=limit,
        **filters,
        by=by.upper() if by is not None else None,
        order=order.upper() if order is not None else None,
    )


def search_params(query: str, page: int, limit: int, **params: Any) -> dict[str, Any]:
    """Returns the query parameters of a paginated search."""
    if sum(not character.isspace() for character in query) < 2:
        raise ValueError("Search query must contain at least 2 non-whitespace characters")

    return {"q": query, **page_params(page, limit, **params)}


def path_segment(value: str) -> str:
    """Returns an identifier percent-encoded as one path segment, so it cannot address another
    endpoint."""
    if value in (".", ".."):
        raise ValueError("Identifier cannot be '.' or '..'")

    return quote(value, safe="")


def entity_path(entity_identifier: str) -> str:
    """Returns the path of an entity, percent-encoding its identifier as one path segment."""
    return f"entities/{path_segment(entity_identifier)}"


def parse_list(model: type[M], data: list[Any]) -> list[M]:
    return [model.model_validate(item) for item in data]


def content_payload(content: ContentInput) -> dict[str, Any]:
    payload = compact(**asdict(content))
    # TEXT is the default content type, which is not sent
    if content.content_type is ContentType.TEXT:
        del payload["content_type"]

    return payload


def evidence_payload(
    evidence: str | ContentInput | Sequence[ContentInput],
) -> dict[str, Any] | list[dict[str, Any]]:
    if isinstance(evidence, str):
        evidence = ContentInput(evidence)

    if isinstance(evidence, ContentInput):
        return content_payload(evidence)

    if not evidence:
        raise ValueError("Evidence cannot be empty")

    return [content_payload(item) for item in evidence]


def readable_file(local_file_path: str | PathLike[str]) -> Path:
    """Returns the path of a local file, raising a ValueError unless it is a readable, non-empty
    file."""
    path = Path(local_file_path)
    if not path.is_file():
        raise ValueError(f"File does not exist: {local_file_path}")
    if not os.access(path, os.R_OK):
        raise ValueError(f"File is not readable: {local_file_path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Invalid file or empty file: {local_file_path}")

    return path


def scan_files(
    items: list[dict[str, Any]], files: Mapping[int, Sequence[str | PathLike[str]]]
) -> dict[str, Path]:
    """Names the files of each content input, keyed by the position of the input, in its files
    member, and returns the files by the name of the multipart part that carries each."""
    parts = {}
    for index, paths in files.items():
        if not 0 <= index < len(items):
            raise ValueError(
                f"The files are keyed by an evidence index that does not exist: {index}"
            )
        if isinstance(paths, str | PathLike) or not paths:
            raise ValueError(
                f"The files of the evidence at index {index} must be a non-empty sequence of paths"
            )

        for file_index, local_file_path in enumerate(paths):
            part = f"file_{index}_{file_index}"
            parts[part] = readable_file(local_file_path)
            items[index].setdefault("files", []).append(part)

    return parts


def scan_file_urls(items: list[dict[str, Any]], file_urls: Mapping[int, Sequence[str]]) -> None:
    """Names the URLs of the further files of each content input, keyed by the position of the
    input, in its file_urls member."""
    for index, urls in file_urls.items():
        if not 0 <= index < len(items):
            raise ValueError(
                f"The file URLs are keyed by an evidence index that does not exist: {index}"
            )
        if (
            isinstance(urls, str)
            or not urls
            or not all(isinstance(url, str) and url for url in urls)
        ):
            raise ValueError(
                f"The file URLs of the evidence at index {index} must be a non-empty sequence "
                "of URLs"
            )

        items[index]["file_urls"] = list(urls)


def attachment_file_name(response: httpx.Response, default: str) -> str:
    """Returns the file name given by the Content-Disposition header, without directories or a
    drive letter.

    Falls back to the default when the header names no usable file.
    """
    message = Message()
    message["Content-Disposition"] = response.headers.get("Content-Disposition", "")
    file_name = message.get_filename(default)
    file_name = file_name[max(map(file_name.rfind, "/\\:")) + 1 :]
    return file_name if file_name not in ("", ".", "..") else default
