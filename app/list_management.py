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
"""Taking, revoking and reading list entries.

Every operation works on the files of :mod:`app.storage`, under the lock of
the list's country and doctype, so concurrent requests, several service
processes and restarts all see the same lists.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app import storage
from app.status_list import NoMoreIndices
from app.storage import IDENTIFIER_LIST, TOKEN_LIST, CorruptList, ListNotFound

logger = logging.getLogger(__name__)


class IndexOutOfRange(ValueError):
    """An index outside the list."""


def _later(a: str | None, b: str) -> str:
    """The later of two ``YYYY-MM-DD`` dates (``a`` may be unset)."""
    if a is None:
        return b
    return b if datetime.strptime(b, "%Y-%m-%d") > datetime.strptime(a, "%Y-%m-%d") else a


def _current_entry(country: str, doctype: str) -> dict[str, Any]:
    """The list new indices come from; a new one when there is none (call under the lock)."""
    list_id = storage.current_list_id(country, doctype)
    if list_id:
        try:
            return storage.load_entry(country, doctype, list_id)
        except (ListNotFound, CorruptList):
            logger.warning("Current list %s/%s/%s unusable, starting a new one", country, doctype, list_id, exc_info=True)
    return storage.new_entry(country, doctype)


def take(country: str, doctype: str, expiry_date: str) -> dict[str, Any]:
    """Takes a free index for a credential about to be issued.

    When the current list is full a new one is started; the index and the
    URIs returned always belong to the same list.

    Args:
        country: Country code.
        doctype: Doctype (or vct) of the credential.
        expiry_date: Expiry of the credential, ``YYYY-MM-DD``; the list is
            kept at least until then.

    Returns:
        The ``status_list`` and ``identifier_list`` pointers for the issuer.
    """
    with storage.country_doctype_lock(country, doctype):
        entry = _current_entry(country, doctype)
        try:
            index = entry["token_status_list"].allocator.take()
        except NoMoreIndices:
            logger.info("List %s/%s/%s is full, starting a new one", country, doctype, entry["rand"])
            entry = storage.new_entry(country, doctype)
            index = entry["token_status_list"].allocator.take()
        entry["expires"] = _later(entry["expires"], expiry_date)
        # The statuses are unchanged: a new list is published, an existing one only stored.
        storage.save_entry(entry, publish=_is_new(entry))
        if storage.current_list_id(country, doctype) != entry["rand"]:
            storage.set_current_list_id(country, doctype, entry["rand"])
    return {
        "status_list": {"uri": entry["status_list_uri"], "idx": index},
        "identifier_list": {"uri": entry["identifier_list_uri"], "id": str(index)},
    }


def _is_new(entry: dict[str, Any]) -> bool:
    """Whether the list has no published files yet."""
    token_dir = storage.list_dir(TOKEN_LIST, entry["country"], entry["doctype"], entry["rand"])
    return not (token_dir / "token_status_list.jwt").exists()


def _check_index(entry: dict[str, Any], index: int) -> None:
    size = entry["token_status_list"].status_list.size
    if not 0 <= index < size:
        raise IndexOutOfRange(f"index must be between 0 and {size - 1}")


def revoke(country: str, doctype: str, list_id: str, index: int) -> None:
    """Revokes one entry: sets its status to 1 and adds it to the identifier list.

    Raises:
        ListNotFound: No such list.
        CorruptList: The list cannot be read.
        IndexOutOfRange: ``index`` is outside the list.
    """
    with storage.country_doctype_lock(country, doctype):
        entry = storage.load_entry(country, doctype, list_id)
        _check_index(entry, index)
        entry["token_status_list"].status_list.set(index, 1)
        entry["identifier_list"]["identifiers"][str(index)] = {}
        storage.save_entry(entry)
    logger.info("Revoked index %s of list %s/%s/%s", index, country, doctype, list_id)


def read_status(kind: str, country: str, doctype: str, list_id: str, index: int) -> int:
    """Status of one entry: the status list value, or 1 when the identifier list holds it.

    Files are replaced atomically, so no lock is needed.

    Raises:
        ListNotFound, CorruptList, IndexOutOfRange: As for :func:`revoke`.
    """
    entry = storage.load_entry(country, doctype, list_id)
    _check_index(entry, index)
    if kind == TOKEN_LIST:
        return entry["token_status_list"].status_list.get(index)
    if kind == IDENTIFIER_LIST:
        return 1 if str(index) in entry["identifier_list"]["identifiers"] else 0
    raise ValueError(f"unknown list kind {kind}")
