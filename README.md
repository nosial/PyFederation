# PyFederation

PyFederation is a Python client library for the Federated Database protocol. It implements the
[Open Federated Database](https://github.com/nosial/OFD-Specification) specification and follows the design of the
reference implementation, [FederationLib](https://github.com/nosial/FederationLib), and of its Java counterpart,
[JFederation](https://github.com/nosial/JFederation), from which it is ported.

## Features

- Works with any Federation server implementing OFD 2.x
- Content scanning with entity resolution, classification, risk assessment, content types, concerns,
  detections, and files such as the images of a message
- Every method of the server API: operators, records, evidence, reports, blacklist records, file
  attachments, audit logs, search, and server information
- Pagination, category filters, and sorting on every listing and search endpoint
- Synchronous and asynchronous clients, `FederationClient` and `AsyncFederationClient`, with the same methods
- All errors are mapped to a single exception carrying the HTTP status code and server message

## Table of Contents

<!-- TOC -->
* [PyFederation](#pyfederation)
  * [Features](#features)
  * [Table of Contents](#table-of-contents)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
    * [Via PyPI](#via-pypi)
    * [From source](#from-source)
  * [Usage](#usage)
    * [Connecting to a server](#connecting-to-a-server)
    * [Asynchronous client](#asynchronous-client)
    * [Content scanning](#content-scanning)
    * [Searching records](#searching-records)
    * [Operators](#operators)
    * [Entities](#entities)
    * [Evidence](#evidence)
    * [Reports](#reports)
    * [Blacklist records](#blacklist-records)
    * [File attachments](#file-attachments)
    * [Pagination and sorting](#pagination-and-sorting)
  * [Error handling](#error-handling)
  * [Testing](#testing)
* [License](#license)
<!-- TOC -->

## Prerequisites

- **Python 3.11 or newer**
- **A running Federation server** for anything other than constructing a client, the reference
  implementation is [FederationLib](https://github.com/nosial/FederationLib), which includes a
  dockerized server deployment

Dependencies are HTTPX for HTTP transport and Pydantic for the records.

## Installation

### Via PyPI

The library is published on [PyPI](https://pypi.org/project/pyfederation/):

```sh
pip install pyfederation
```

### From source

To use an unreleased version, install the library from a clone of the repository:

```sh
git clone https://github.com/nosial/PyFederation.git
cd PyFederation
pip install .
```

## Usage

All functionality is exposed through the `FederationClient` class. Each method maps to a REST endpoint of the
Federation server and handles serialization, authentication, and error mapping.

### Connecting to a server

A client is constructed with the base URL of the Federation server and an optional operator access
token. A client without a token operates anonymously against the server's public endpoints:

```python
from pyfederation import FederationClient

# Anonymous client
client = FederationClient("https://federation.example.com")

# Authenticated client with an operator access token
client = FederationClient("https://federation.example.com", "access-token")
```

The access token can be changed at any time during the lifetime of the client:

```python
client.access_token = "new-token"  # switch authentication
client.access_token = None  # revert to anonymous access
```

Clients should be closed when no longer needed to release the underlying HTTP connection pool, or
used as a context manager:

```python
client.close()

with FederationClient("https://federation.example.com", "access-token") as client:
    ...
```

For custom HTTP settings (timeouts, proxies, TLS, etc.) an existing `httpx.Client` can be passed to
the constructor instead:

```python
import httpx

http_client = httpx.Client(timeout=15)

client = FederationClient("https://federation.example.com", "access-token", http_client)
```

Server information, including the server name, API version, feature flags (which record types are
publicly visible), and total record counts, is available through `get_server_information()`, the raw
OpenAPI specification of the server is available through `get_specification()`:

```python
info = client.get_server_information()
print(f"Server {info.name}, API version {info.api_version}")
print(f"Known entities: {info.known_entities}, reports: {info.reports}")
```

A client should check the major version of the interface with `info.api_major_version`, this release
implements OFD 2.2. Features of a minor version are checked with `info.is_api_version_at_least(2, 2)`
(or `info.api_minor_version`). The server information also publishes what content scanning supports
(`scan_content_types`, `concerns` and `default_concerns`, and the limits on scanned files,
`max_scan_files` and `max_scan_file_size`), whether URL uploads are accepted
(`url_uploads_allowed`), whether telephone entities are public (`public_telephone_entities`) and
whether content scanned anonymously may be stored (`collects_public_scan_content`). Values a newer
server publishes that this client does not recognize are read as `None` or left out of lists, and an
unrecognized incident type is read as `OTHER`.

### Asynchronous client

`AsyncFederationClient` has the same methods as `FederationClient`, as coroutines, and is closed with
`aclose()` or used as an async context manager:

```python
from pyfederation import AsyncFederationClient

async with AsyncFederationClient("https://federation.example.com", "access-token") as client:
    info = await client.get_server_information()
```

Routes the client has no method for, such as the routes a plugin of the server provides, are reached
with `request()`, which sends the parameters as the query string of a `GET` or `DELETE` request and
as a JSON body otherwise, and returns the decoded response:

```python
status = client.request("GET", "my-plugin/status", {"verbose": "true"})
```

### Content scanning

Content scanning accepts text, a `ContentInput`, or a list of inputs. Each input can carry text, a
content type and its context, an operator note, tag, confidentiality flag, metadata, and files; at
least one input must contain text or a file:

| Method                                                              | Return Type      | Description                      |
|---------------------------------------------------------------------|------------------|----------------------------------|
| `scan_content(evidence, author, top_k, threshold, concerns, files)` | `ScannedContent` | Scans one or more content inputs |

The content type (`TEXT`, `EMAIL`, `SMS`, `WEB_PAGE`, `HOSTNAME` or `URL`) determines the form of the
text and the keys its context may contain, such as `subject` and `sender` for an `EMAIL`, `region`
for an `SMS`, and the required `url` for a `WEB_PAGE`. The context is an assertion of the client, a
detection that is not `verified` relies on it. Only the requested concerns (the server's
`default_concerns` when none are given, which exclude `ADVERTISING` and `TRACKING`) affect the
classification, risk score, suggested action, and `detections` of the result:

```python
from pyfederation import ContentInput, ContentType, IncidentType

scan = client.scan_content(
    [
        ContentInput(
            "Your account is locked, verify it now",
            content_type=ContentType.EMAIL,
            context={"subject": "Account locked", "sender": "security@example.com"},
        ),
        ContentInput("https://login.example.com/verify", content_type=ContentType.URL),
    ],
    concerns=[IncidentType.PHISHING, IncidentType.SPAM],
)

for detection in scan.detections:
    print(
        f"{detection.concern} in input {detection.content_index} by {detection.source} "
        f"(verified: {detection.verified})"
    )
```

The files of each input, such as the images of a message, are given as local paths keyed by the
position of the input, and an input with files may omit its text. The server determines the media
type of each file from its content, interprets the ones it supports, and ignores the others, as it
ignores every file when `max_scan_files` is 0; servers before OFD 2.1 may reject files. A detection
that relates to a file carries its position among the files of the input in `file_index`:

```python
scan = client.scan_content(
    [
        ContentInput("Your parcel is on hold", content_type=ContentType.SMS),
        ContentInput(),  # an image sent on its own
    ],
    files={0: ["parcel.jpg"], 1: ["qr.png"]},
)
```

Files the server records as evidence are kept as attachments of that evidence, and many files carry
metadata, such as the location a photograph was taken at, that the server does not need.

Files can also be named by URL, keyed the same way, for the server to retrieve itself, such as the
media of an MMS message held by the carrier. A request that only names file URLs is sent as JSON.
Servers before OFD 2.2 reject file URLs, and a server that does not retrieve them, or cannot retrieve
a file, treats it like a file it does not interpret, so the result does not depend on whether it
does. Retrieved files follow the files of their input in `file_index`:

```python
if info.is_api_version_at_least(2, 2):
    scan = client.scan_content(
        ContentInput(content_type=ContentType.SMS),
        file_urls={0: ["https://carrier.example/mms/1.jpg"]},
    )
```

Scanning content and inspecting the classification result:

```python
from pyfederation import ContentInput

scan = client.scan_content(ContentInput("Suspicious message to inspect"), "author@example.com")

classification = scan.classification
print(
    f"Classification {classification.classification_flag} with "
    f"{classification.confidence:.1%} confidence, detected language: {classification.detected_language}"
)
```

### Searching records

The global search queries all record types with an optional type filter. The search query must
contain at least 2 non-whitespace characters:

```python
from pyfederation import RecordType

# Search all record types
results = client.search("author@example.com")

# Search only entity and blacklist records, page 1, 25 per page
results = client.search("author@example.com", [RecordType.ENTITY, RecordType.BLACKLIST], 1, 25)
```

`SearchResult` records carry the matched `type` and the `record`, resolved to the record class of
the matched type.

### Operators

Operators are the accounts of the Federation server. Every change to the data is made by an
operator, and each operator holds permissions that decide what it may do.

| Method                                                                           | Description                                                                          |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `create_operator(name)`                                                          | Creates a new operator, returns the raw access token (only exposed at creation time) |
| `get_operator(uuid)` / `get_self()`                                              | Returns an operator record / the currently authenticated operator                    |
| `list_operators(page, limit, category, by, order)`                               | Lists operators with optional filters                                                |
| `search_operators(query, page, limit, category, by, order)`                      | Searches operators by name                                                           |
| `update_operator_name(uuid, name)`                                               | Updates the display name of an operator                                              |
| `delete_operator(uuid)`                                                          | Deletes an operator                                                                  |
| `disable_operator(uuid)` / `enable_operator(uuid)`                               | Disables / enables an operator account                                               |
| `update_operator_permissions(uuid, client, management, operator)`               | Grants or revokes permission groups, `None` leaves a group unchanged                 |
| `set_operator_permissions(uuid, enabled)`                                        | Sets whether the operator has operator-level permissions                             |
| `set_client_permissions(uuid, enabled)`                                          | Sets whether the operator has client-level permissions                               |
| `set_management_permissions(uuid, enabled)`                                      | Sets whether the operator has management-level permissions                           |
| `update_operator_configuration(uuid, ...)`                                       | Changes the auto assignment and bot settings, `None` leaves a setting unchanged      |
| `set_auto_assign(uuid, enabled)`                                                 | Sets whether reports of every kind are automatically assigned to the operator        |
| `set_bot(uuid, is_bot)`                                                          | Sets whether the operator is a bot, whose evidence and reports are automated         |
| `generate_access_token(update)`                                                  | Refreshes the current operator's token, optionally updating the client               |
| `generate_operator_access_token(uuid)`                                           | Refreshes another operator's token                                                   |
| `list_operator_audit_logs(uuid, ...)`                                            | Lists the audit log entries of an operator                                           |
| `list_operator_evidence(uuid, ...)`                                              | Lists the evidence an operator submitted                                             |
| `list_operator_blacklist(uuid, ...)`                                             | Lists the blacklist records created by an operator                                   |
| `list_operator_reports(uuid, ...)` / `list_assigned_operator_reports(uuid, ...)` | Lists the reports submitted by / assigned to an operator                             |

Creating an operator and generating a new token:

```python
created = client.create_operator("my-application")
print(f"Operator UUID: {created.uuid}")

# The raw token is only returned once at creation time, store it securely
token = created.access_token

refreshed = client.generate_access_token(True)  # refresh and update this client
```

An `OperatorRecord` carries its permission groups in `permissions` and its settings in
`configuration`. Management permissions inherit client permissions, so revoking client permissions
from an operator that keeps management permissions is rejected with HTTP 409. The configuration is
only disclosed to the operator itself and to operators with operator permissions, anyone else
receives `None`; an operator may change its own configuration:

```python
operator = client.get_operator(uuid)
if operator.permissions.management and operator.configuration is not None:
    print(f"Bot: {operator.is_bot}, auto assigned: {operator.auto_assigned}")

# Opt in to automated reports only
client.update_operator_configuration(uuid, False, True)
```

### Entities

Entities are the subjects tracked by the federation: users, domains, IP addresses, or any other
identifier present in scanned content.

| Method                                                     | Description                                                       |
|------------------------------------------------------------|-------------------------------------------------------------------|
| `get_entity_record(identifier)`                            | Returns the record of an entity by identifier                     |
| `query_entity(identifier, concerns)`                       | Returns an entity's relationship group and active blacklist state |
| `search_entities(query, page, limit, category, by, order)` | Searches entities by identifier                                   |
| `list_entities(page, limit, category, by, order)`          | Lists entities                                                    |
| `get_top_threats(limit)`                                   | Lists the highest-risk entities                                   |
| `update_entity(identifier, metadata)`                      | Updates the metadata of an entity                                 |
| `delete_entity(identifier)`                                | Deletes an entity                                                 |
| `set_entity_whitelist(identifier, whitelisted)`            | (Un)whitelists an entity                                          |
| `clear_entity_reputation(identifier)`                      | Clears the accumulated reputation of an entity                    |
| `set_entity_relationship(identifier, related_id, type)`    | Sets the relationship between two entities                        |
| `clear_entity_relationship(identifier)`                    | Clears the relationship of an entity                              |
| `push_entity(host, id, metadata)`                          | Registers an entity with the server                               |
| `list_entity_audit_logs(identifier, ...)`                  | Lists the audit log entries involving an entity                   |
| `list_entity_blacklist_records(identifier, ...)`           | Lists the blacklist records against an entity                     |
| `list_entity_evidence_records(identifier, ...)`            | Lists the evidence submitted against an entity                    |
| `list_entity_reports(identifier, ...)`                     | Lists the reports submitted against an entity                     |

Entities are identified by their UUID, SHA-256 hash, or address, such as `example.com` or
`john@example.com`. Entity identifiers are percent-encoded in request paths, so addresses such as
`user+tag@example.com` can be passed as they are.

A telephone number is the entity `<E.164 number>@e164.arpa`, whose local part is the international
number without `+` or separators (`EntityRecord.is_telephone`). Unless the server publishes
`public_telephone_entities`, unauthenticated requests only see a telephone entity they identify by
its address or SHA-256 hash.

### Evidence

Evidence records are the supporting data attached to entities, either when submitting a report or
manually by operators, and can hold text content, attachments, tags, notes, and confidentiality
flags:

| Method                                                                                         | Description                                          |
|------------------------------------------------------------------------------------------------|------------------------------------------------------|
| `submit_evidence(identifier, text_content, note, tag, confidential, metadata, classification)` | Submits evidence with all optional fields            |
| `submit_evidence(..., content_type, context)`                                                  | Submits evidence with a content type and its context |
| `list_evidence(page, limit, include_confidential, category, by, order)`                        | Lists evidence records                               |
| `search_evidence(query, page, limit, category, by, order)`                                     | Searches evidence records                            |
| `get_evidence_record(uuid)`                                                                    | Returns a single evidence record                     |
| `get_evidence_attachments(uuid)`                                                               | Lists the attachments of an evidence record          |
| `update_evidence_confidentiality(uuid, confidential)`                                          | Updates the confidentiality flag of evidence         |
| `update_evidence_tag(uuid, tag)`                                                               | Updates the tag of evidence                          |
| `classify_evidence(uuid, classification)`                                                      | Classifies evidence, replacing its classification    |
| `add_evidence_to_report(evidence_uuid, report_uuid)`                                           | Attaches evidence to a report                        |
| `delete_evidence(uuid)`                                                                        | Deletes an evidence record                           |

Confidential evidence is hidden from unauthenticated clients by default, listing endpoints
support an `include_confidential` parameter to include them when the operator has the appropriate
permissions. Evidence the server creates itself or a bot operator submits is `automated` and created
confidential, the `AUTOMATED` and `NOT_AUTOMATED` categories select it, and evidence about a
telephone entity is always confidential.

### Reports

Reports are the central mechanism of the federation server. A report is submitted against an entity,
groups one or more pieces of evidence, and can be classified, assigned to operators, and closed:

| Method                                                                           | Description                                                                      |
|----------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `submit_report(entity, evidence, incident_type, report_message)`                 | Submits one or more evidence items with a report                                 |
| `list_reports(page, limit, category, by, order)`                                 | Lists reports                                                                    |
| `list_opened_reports(page, limit, by, order)`                                    | Lists the opened reports assigned to the current operator                        |
| `search_reports(query, page, limit, category, by, order)`                        | Searches reports by content                                                      |
| `get_report(uuid)`                                                               | Returns a single report                                                          |
| `list_report_evidence_records(report_uuid, ...)`                                 | Lists evidence associated with a report                                          |
| `close_report(uuid, classification, blacklist_incident_type, blacklist_expires)` | Closes a report, optionally classifying its evidence and blacklisting the entity |
| `assign_operator_to_report(report_uuid, operator_uuid)`                          | Assigns an operator to a report                                                  |
| `delete_report(uuid)`                                                            | Deletes a report                                                                 |

`submit_report` returns a `ReportSubmission` object with the created `report` and its list of
`evidence` records. Upload attachments separately against an evidence record.

### Blacklist records

Blacklist records are the server's mitigation mechanism. An operator blacklists an entity with an
incident type and, optionally, the report backing the decision, which may concern another entity,
such as the domain a reported account advertised:

| Method                                                                            | Description                                                            |
|-----------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `blacklist_entity(identifier, incident_type, report_uuid)`                        | Blacklists an entity permanently                                       |
| `blacklist_entity(identifier, incident_type, report_uuid, expires)`               | Blacklists an entity with an expiration timestamp (Unix epoch seconds) |
| `list_blacklist_records(page, limit, include_lifted, category, by, order, types)` | Lists blacklist entries, optionally of the given incident types only   |
| `search_blacklist(query, page, limit, category, by, order, types)`                | Searches blacklist entries, optionally of the given incident types     |
| `get_blacklist_record(uuid)`                                                      | Returns a single blacklist record                                      |
| `lift_blacklist_record(uuid)`                                                     | Lifts the blacklist entry of an entity                                 |
| `extend_blacklist_record(uuid, seconds)`                                          | Extends the blacklist of an entity by the given seconds                |
| `delete_blacklist_record(uuid)`                                                   | Deletes a blacklist record                                             |

### File attachments

Evidence records support file attachments with uploads from disk or URL, and note attachments (plain-text content):

| Method                                                                    | Description                                        |
|---------------------------------------------------------------------------|----------------------------------------------------|
| `upload_file_attachment(evidence_uuid, local_file_path)`                  | Uploads a local file attachment                    |
| `upload_file_attachment(evidence_uuid, local_file_path, file_name)`       | Uploads a local file attachment with a custom name |
| `upload_file_attachment_from_url(evidence_uuid, file_url)`                | Uploads an attachment from a reachable URL         |
| `upload_file_attachment_from_url(evidence_uuid, file_url, max_file_size)` | Uploads an attachment from a URL with a size limit |
| `upload_file_attachment_by_url(evidence_uuid, file_url)`                  | Server retrieves the attachment from a URL         |
| `upload_note_attachment(evidence_uuid, file_name, content)`               | Uploads a plain-text note attachment               |
| `download_attachment(attachment_uuid, directory_path)`                    | Downloads an attachment into the given directory   |
| `get_attachment_info(uuid)`                                               | Returns the metadata of an attachment              |
| `list_attachments(page, limit, category, by, order)`                      | Lists attachments                                  |
| `search_attachments(query, page, limit, category, by, order)`             | Searches attachments                               |
| `delete_attachment(uuid)`                                                 | Deletes an attachment                              |

URL uploads default to a maximum file size of 50 MB, matching the FederationLib client default, the
limit can be raised per request.

`upload_file_attachment_from_url` downloads the file and uploads it, while
`upload_file_attachment_by_url` sends only the URL and the server retrieves the file itself. The URL
must then be reachable by the server, and servers reject URLs that resolve to private, loopback or
other non-public addresses unless configured otherwise.

### Pagination and sorting

Every listing and search endpoint accepts the same pagination and sorting arguments: `page` (1-based)
and `limit` (minimum 1), followed by an optional category filter, `by` (the field to sort by,
case-insensitive, sent uppercase as OFD 2.0 defines), and `order` (`"ASC"` or `"DESC"`), for example:

```python
# Defaults: page 1, limit 100
entities = client.list_entities()

# Explicit pagination
entities = client.list_entities(2, 50)

# Pagination with a category filter, sorted by reputation ascending
entities = client.list_entities(2, 50, "WHITELISTED", "reputation", "ASC")
```

The argument order is the same for every endpoint.

## Error handling

All failures are raised as `FederationClientException`, carrying the HTTP status code of the
response and, when the server returns one, its error message:

```python
from pyfederation import FederationClientException

try:
    client.get_entity_record("non-existent-entity")
except FederationClientException as e:
    print(f"Request failed with status {e.status_code}: {e}")
```

A server may limit the rate of requests. A request it rejects with HTTP 429, or with 503 while it is
unavailable, was not performed and may be repeated, including one that is not idempotent:
`e.is_retryable` tells so, and `e.retry_after` holds the delay in seconds the server asked for, or
`None`, in which case back off exponentially. The client does not retry by itself:

```python
import time

for attempt in range(5):
    try:
        scan = client.scan_content("Suspicious message to inspect")
        break
    except FederationClientException as e:
        if not e.is_retryable:
            raise
        time.sleep(e.retry_after if e.retry_after is not None else 2**attempt)
```

Failures without a response, such as connection errors, have a status code of 0. Invalid arguments,
such as an empty UUID, a page below 1, a search query with fewer than 2 non-whitespace characters,
or an access token that is empty or contains whitespace, are rejected by the client immediately with
a `ValueError`.

## Testing

The unit tests run without a server:

```sh
pip install -e . --group dev
pytest
```

The integration tests run against a live Federation server, and the repository includes a
[docker-compose.yml](docker-compose.yml) that brings up the reference
[FederationLib](https://github.com/nosial/FederationLib) server, MariaDB, and Redis on `http://localhost:7000`:

```sh
docker compose up -d
pytest -m integration
```

By default the tests expect the server at `http://localhost:7000` with access token
`abcdefghijklmnopqrstuvwxyz123456` (matching the compose defaults). To test against a different
server, set the `SERVER_ENDPOINT` and `SERVER_ACCESS_TOKEN` environment variables:

```sh
SERVER_ENDPOINT=http://localhost:7000 SERVER_ACCESS_TOKEN=my-token pytest -m integration
```

The synchronous client, `client.py`, is generated from the asynchronous client, `async_client.py`,
run `python scripts/unasync.py` after changing it.

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
