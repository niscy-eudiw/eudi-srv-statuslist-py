# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import hmac
import logging
import re
from datetime import datetime
from urllib.parse import unquote

from flask import Blueprint, jsonify, request, send_from_directory

from app import list_management
from app.config import CONFIGURATION
from app.list_management import REF_ERRORS, ConflictingRef, IndexOutOfRange, Ref, UnknownEntry, UnknownIdentifier
from app.log_utils import safe
from app.storage import LIST_KINDS, CorruptList, ListNotFound

token = Blueprint("token_status_list", __name__, url_prefix="/token_status_list")
logger = logging.getLogger(__name__)

_LIST_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


#: Longest identifier list ``id`` accepted (the service hands out 32 characters).
MAX_IDENTIFIER = 64

#: Largest body of a batch request, in bytes.
MAX_BATCH_BODY = 1024 * 1024

#: Error answered (401) when ``X-Api-Key`` is missing or wrong.
INCORRECT_API_KEY = "Incorrect API key"


class BadRequest(ValueError):
    """A request value the service rejects with 400."""


class TooLarge(ValueError):
    """A batch the service rejects with 413."""


def api_key_valid() -> bool:
    """Tells whether the request carries the configured ``X-Api-Key``.

    The comparison takes constant time.
    """
    sent = request.headers.get("X-Api-Key", "")
    return hmac.compare_digest(sent.encode(), CONFIGURATION["api_key"].encode())


def validate_doctype(user_input):
    """Validate doctype and return the allowed value"""
    if user_input not in CONFIGURATION["allowed_doctypes"]:
        raise ValueError("Invalid document type")

    return next(dt for dt in CONFIGURATION["allowed_doctypes"] if dt == user_input)


def validate_country(user_input):
    """Validate country code and return clean value"""
    if user_input not in CONFIGURATION["countries"]:
        raise ValueError("Invalid country")

    return next(key for key in CONFIGURATION["countries"].keys() if key == user_input)


def validate_expiry_date(user_input):
    """Validate and sanitize expiry date"""
    try:
        parsed_date = datetime.strptime(user_input, "%Y-%m-%d")
    except (ValueError, TypeError):
        raise ValueError("Invalid expiry date format. Use YYYY-MM-DD.")

    if parsed_date.date() < datetime.now().date():
        raise ValueError("Expiry date must be in the future.")

    # Return clean date string from parsed date
    return parsed_date.strftime("%Y-%m-%d")


def parse_list_uri(uri) -> tuple[str, str, str, str]:
    """Splits a list URI handed out by this service.

    It must be ``<service_url><kind>/<CC>/<doctype>/<id>``: a configured
    country, an allowed doctype and a list id, nothing else.

    Returns:
        ``(kind, country, doctype, list_id)``.

    Raises:
        BadRequest: Any other URI.
    """
    prefix = CONFIGURATION["service_url"]
    if not isinstance(uri, str) or not uri.startswith(prefix) or "?" in uri or "#" in uri:
        raise BadRequest("uri is not a list of this service")
    parts = [unquote(part) for part in uri[len(prefix):].split("/")]
    if len(parts) != 4 or parts[0] not in LIST_KINDS or not _LIST_ID.match(parts[3]):
        raise BadRequest("uri is not a list of this service")
    kind, country, doctype, list_id = parts
    try:
        return kind, validate_country(country), validate_doctype(doctype), list_id
    except ValueError as e:
        raise BadRequest(str(e)) from e


def parse_index(value) -> int:
    """A non-negative integer index (the upper bound is checked against the list)."""
    try:
        index = int(value)
    except (TypeError, ValueError):
        raise BadRequest("'id' or 'idx' unkown") from None
    if index < 0:
        raise BadRequest("index must not be negative")
    return index


def parse_identifier(value) -> str:
    """An identifier list ``id``: an opaque string, not an index."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_IDENTIFIER:
        raise BadRequest(f"'id' must be a string of 1 to {MAX_IDENTIFIER} characters")
    return value


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _entry_error(error: Exception) -> tuple[str, int]:
    """Message and status code of an error naming an entry."""
    if isinstance(error, (BadRequest, IndexOutOfRange, ConflictingRef)):
        return str(error), 400
    if isinstance(error, ListNotFound):
        return "Unknown list", 404
    if isinstance(error, (UnknownIdentifier, UnknownEntry)):
        return str(error), 404
    return "List unavailable", 500


def _form_pointer(values) -> tuple[int | None, str | None]:
    """``idx`` and ``id`` of a form or query (empty values count as absent)."""
    index = values.get("idx") or None
    identifier = values.get("id") or None
    return None if index is None else parse_index(index), None if identifier is None else parse_identifier(identifier)


def _batch_body() -> dict:
    """The JSON object of a batch request (at most :data:`MAX_BATCH_BODY` bytes, else 413)."""
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json")
    request.max_content_length = MAX_BATCH_BODY
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")
    return body


def _batch_size(size: int, name: str) -> None:
    """Rejects an empty batch (400) or one over ``batch_max_size`` (413)."""
    if size < 1:
        raise BadRequest(f"{name} must be at least 1")
    if size > CONFIGURATION["batch_max_size"]:
        raise TooLarge(f"{name} must be at most {CONFIGURATION['batch_max_size']}")


def _take_fields(values) -> tuple[str, str, str]:
    """``(doctype, country, expiry_date)`` of a take request, validated.

    Raises:
        ValueError: A missing or invalid field.
    """
    fields = []
    for name in ("doctype", "country", "expiry_date"):
        value = values.get(name)
        if not isinstance(value, str):
            raise ValueError(f"Missing {name}")
        fields.append(value)
    doctype, country, expiry_date = fields
    return validate_doctype(doctype), validate_country(country), validate_expiry_date(expiry_date)


@token.route("/take", methods=["POST"])
def take_index():

    logger.info("Take request, payload: %s", safe(request.form.to_dict()))

    if not api_key_valid():
        logger.error(INCORRECT_API_KEY)
        return _error(INCORRECT_API_KEY, 401)

    try:
        doctype, country, expiry_date = _take_fields(request.form)
    except ValueError as e:
        logger.warning(str(e))
        return _error(str(e), 400)

    status_info = list_management.take(country, doctype, expiry_date)
    logger.debug("Status info: %s", status_info)
    return jsonify(status_info)


@token.route("/take/batch", methods=["POST"])
def take_batch():
    """Takes ``count`` indices of one country, doctype and expiry date (JSON body)."""
    if not api_key_valid():
        logger.error(INCORRECT_API_KEY)
        return _error(INCORRECT_API_KEY, 401)

    try:
        body = _batch_body()
        logger.info("Take batch request, payload: %s", safe(body))
        doctype, country, expiry_date = _take_fields(body)
        count = body.get("count")
        if isinstance(count, bool) or not isinstance(count, int):
            raise BadRequest("count must be an integer")
        _batch_size(count, "count")
    except TooLarge as e:
        return _error(str(e), 413)
    except ValueError as e:
        logger.warning(str(e))
        return _error(str(e), 400)

    items = list_management.take_many(country, doctype, expiry_date, count)
    logger.debug("Took %s indices", len(items))
    return jsonify({"items": items})


@token.route("/get", methods=["GET"])
def get_index():

    logger.debug("Get request, args: %s", safe(request.args.to_dict()))

    uri = request.args.get("uri")
    if uri is None or not (request.args.get("id") or request.args.get("idx")):
        return _error("Missing URI or idx/id", 400)

    try:
        index, identifier = _form_pointer(request.args)
        kind, country, doctype, list_id = parse_list_uri(uri)
        return str(list_management.read_status(kind, country, doctype, list_id, index, identifier))
    except (BadRequest, *REF_ERRORS) as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list %s", safe(uri))
        return _error(message, status)


@token.route("/set", methods=["POST"])
def set_index():
    if not api_key_valid():
        return jsonify({"message": "Unauthorized access"}), 401

    uri = request.form.get("uri")
    status = request.form.get("status")
    if uri is None or not (request.form.get("id") or request.form.get("idx")) or status is None:
        return _error("Missing URI/index/status", 400)

    try:
        index, identifier = _form_pointer(request.form)
        try:
            status = int(status)
        except ValueError:
            return _error(" status unkown", 400)
        if status != 1:
            return _error("Wrong Status Change", 400)
        # Either URI of a list (token or identifier list) names the same entries.
        _, country, doctype, list_id = parse_list_uri(uri)
        list_management.revoke(country, doctype, list_id, index, identifier)
    except (BadRequest, *REF_ERRORS) as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list %s", safe(uri))
        else:
            logger.warning(message)
        return _error(message, status)

    return "Status Changed\n"


def _parse_ref(ref) -> Ref:
    """The entry one ref of a revoke batch names."""
    if not isinstance(ref, dict):
        raise BadRequest("must be an object with 'uri' and 'idx' or 'id'")
    uri, index, identifier = ref.get("uri"), ref.get("idx"), ref.get("id")
    if uri is None or (index is None and identifier is None):
        raise BadRequest("Missing URI or idx/id")
    if index is not None:
        if isinstance(index, bool) or not isinstance(index, (int, str)):
            raise BadRequest("'id' or 'idx' unkown")
        index = parse_index(index)
    if identifier is not None:
        identifier = parse_identifier(identifier)
    # Either URI of a list (token or identifier list) names the same entries.
    _, country, doctype, list_id = parse_list_uri(uri)
    return Ref(country, doctype, list_id, index, identifier)


@token.route("/set/batch", methods=["POST"])
def set_batch():
    """Revokes every entry of ``refs``, all or none (JSON body)."""
    if not api_key_valid():
        return _error(INCORRECT_API_KEY, 401)

    try:
        refs = _batch_body().get("refs")
        if not isinstance(refs, list):
            raise BadRequest("refs must be a list")
        _batch_size(len(refs), "refs")
        parsed = []
        for position, ref in enumerate(refs):
            try:
                parsed.append(_parse_ref(ref))
            except BadRequest as e:
                raise BadRequest(f"refs[{position}]: {e}") from e
        revoked = list_management.revoke_many(parsed)
    except TooLarge as e:
        return _error(str(e), 413)
    except BadRequest as e:
        logger.warning(str(e))
        return _error(str(e), 400)
    except REF_ERRORS as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list in refs[%s]", e.position)
        else:
            logger.warning("refs[%s]: %s", e.position, message)
        return _error(f"refs[{e.position}]: {message}", status)

    return jsonify({"revoked": revoked})


@token.route("/static/swagger.json", methods=["GET"])
def swagger_static():
    return send_from_directory("static", "swagger.json")
