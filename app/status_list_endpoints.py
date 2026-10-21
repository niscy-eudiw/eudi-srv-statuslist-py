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
from app.list_management import IndexOutOfRange
from app.log_utils import safe
from app.storage import LIST_KINDS, CorruptList, ListNotFound

token = Blueprint("token_status_list", __name__, url_prefix="/token_status_list")
logger = logging.getLogger(__name__)

_LIST_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class BadRequest(ValueError):
    """A request value the service rejects with 400."""


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


def _error(message: str, status: int):
    return jsonify({"error": message}), status


@token.route("/take", methods=["POST"])
def take_index():

    logger.info("Take request, payload: %s", safe(request.form.to_dict()))

    if not api_key_valid():
        logger.error("Incorrect API key")
        return jsonify({"error": "Incorrect API key"}), 401

    try:
        doctype = validate_doctype(request.form["doctype"])
        country = validate_country(request.form["country"])
        expiry_date = validate_expiry_date(request.form["expiry_date"])
    except ValueError as e:
        logger.warning(str(e))
        return _error(str(e), 400)

    status_info = list_management.take(country, doctype, expiry_date)
    logger.debug("Status info: %s", status_info)
    return jsonify(status_info)


@token.route("/get", methods=["GET"])
def get_index():

    logger.debug("Get request, args: %s", safe(request.args.to_dict()))

    uri = request.args.get("uri")
    index = request.args.get("id") or request.args.get("idx")
    if uri is None or index is None:
        return _error("Missing URI or idx/id", 400)

    try:
        index = parse_index(index)
        kind, country, doctype, list_id = parse_list_uri(uri)
        return str(list_management.read_status(kind, country, doctype, list_id, index))
    except (BadRequest, IndexOutOfRange) as e:
        return _error(str(e), 400)
    except ListNotFound:
        return _error("Unknown list", 404)
    except CorruptList:
        logger.exception("Unreadable list %s", safe(uri))
        return _error("List unavailable", 500)


@token.route("/set", methods=["POST"])
def set_index():
    if not api_key_valid():
        return jsonify({"message": "Unauthorized access"}), 401

    uri = request.form.get("uri")
    index = request.form.get("id") or request.form.get("idx")
    status = request.form.get("status")
    if uri is None or index is None or status is None:
        return _error("Missing URI/index/status", 400)

    try:
        index = parse_index(index)
        try:
            status = int(status)
        except ValueError:
            return _error(" status unkown", 400)
        if status != 1:
            return _error("Wrong Status Change", 400)
        # Either URI of a list (token or identifier list) revokes the same entry.
        _, country, doctype, list_id = parse_list_uri(uri)
        list_management.revoke(country, doctype, list_id, index)
    except (BadRequest, IndexOutOfRange) as e:
        logger.warning(str(e))
        return _error(str(e), 400)
    except ListNotFound:
        return _error("Unknown list", 404)
    except CorruptList:
        logger.exception("Unreadable list %s", safe(uri))
        return _error("List unavailable", 500)

    return "Status Changed\n"


@token.route("/static/swagger.json", methods=["GET"])
def swagger_static():
    return send_from_directory("static", "swagger.json")
