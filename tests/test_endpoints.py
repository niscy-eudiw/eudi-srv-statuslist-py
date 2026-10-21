"""HTTP endpoints: /take, /get and /set."""

from __future__ import annotations

import json
import os
from datetime import date, timedelta
from urllib.parse import urlparse

import pytest

from tests.conftest import MDL, PID

FUTURE = (date.today() + timedelta(days=365)).isoformat()
UNKNOWN_ID = "00000000-0000-0000-0000-000000000000"


def take(client, headers, doctype=PID, country="FC", expiry_date=FUTURE):
    return client.post(
        "/token_status_list/take",
        headers=headers,
        data={"doctype": doctype, "country": country, "expiry_date": expiry_date},
    )


def get(client, uri, idx):
    return client.get("/token_status_list/get", query_string={"uri": uri, "idx": idx})


def revoke(client, headers, uri, idx, status=1):
    return client.post("/token_status_list/set", headers=headers, data={"uri": uri, "idx": idx, "status": status})


class TestTake:
    def test_returns_both_list_pointers(self, client, headers):
        response = take(client, headers)
        assert response.status_code == 200
        body = response.json
        status, identifier = body["status_list"], body["identifier_list"]
        assert status["uri"].startswith(f"https://statuslist.test/token_status_list/FC/{PID}/")
        assert identifier["uri"].startswith(f"https://statuslist.test/identifier_list/FC/{PID}/")
        assert identifier["id"] == str(status["idx"])
        assert 0 <= status["idx"] < 10000

    def test_writes_signed_lists(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        directory = configuration["status_list_dir"] + urlparse(uri).path
        assert sorted(os.listdir(directory)) == ["full_list.json", "token_status_list.cwt", "token_status_list.jwt"]

    def test_same_list_for_same_country_and_doctype(self, client, headers):
        first = take(client, headers).json["status_list"]
        second = take(client, headers).json["status_list"]
        assert first["uri"] == second["uri"]
        assert first["idx"] != second["idx"]

    def test_other_doctype_gets_another_list(self, client, headers):
        assert take(client, headers).json["status_list"]["uri"] != take(client, headers, MDL).json["status_list"]["uri"]

    def test_list_expiry_follows_the_latest_credential(self, client, headers, configuration):
        later = (date.today() + timedelta(days=700)).isoformat()
        uri = take(client, headers).json["status_list"]["uri"]
        take(client, headers, expiry_date=later)
        take(client, headers)
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as f:
            assert json.load(f)["expires"] == later

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_api_key_required(self, client, key):
        response = take(client, {"X-Api-Key": key} if key else {})
        assert response.status_code == 401
        assert response.json == {"error": "Incorrect API key"}

    @pytest.mark.parametrize(
        "field,value,error",
        [
            ("doctype", "unknown.doctype", "Invalid document type"),
            ("country", "XX", "Invalid country"),
            ("expiry_date", "01-01-2030", "Invalid expiry date format. Use YYYY-MM-DD."),
            ("expiry_date", "2000-01-01", "Expiry date must be in the future."),
        ],
    )
    def test_invalid_input(self, client, headers, field, value, error):
        response = take(client, headers, **{field: value})
        assert response.status_code == 400
        assert response.json == {"error": error}

    @pytest.mark.parametrize("field", ["doctype", "country", "expiry_date"])
    def test_missing_field(self, client, headers, field):
        data = {"doctype": PID, "country": "FC", "expiry_date": FUTURE}
        del data[field]
        assert client.post("/token_status_list/take", headers=headers, data=data).status_code == 400


class TestGet:
    def test_status_and_identifier_lists(self, client, headers):
        body = take(client, headers).json
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"0"
        assert get(client, body["identifier_list"]["uri"], body["identifier_list"]["id"]).data == b"0"

    @pytest.mark.parametrize("query", [{}, {"uri": "x"}, {"idx": "1"}])
    def test_missing_parameters(self, client, query):
        response = client.get("/token_status_list/get", query_string=query)
        assert response.status_code == 400
        assert response.json == {"error": "Missing URI or idx/id"}

    def test_index_not_a_number(self, client):
        assert get(client, "https://statuslist.test/token_status_list/FC/x/y", "a").status_code == 400

    def test_uri_of_another_kind(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        other = uri.replace("/token_status_list/", "/other_list/")
        directory = configuration["status_list_dir"] + urlparse(other).path
        os.makedirs(directory)
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as src:
            open(directory + "/full_list.json", "w").write(src.read())
        response = get(client, other, 1)
        assert response.status_code == 400
        assert response.json == {"error": "uri is not a list of this service"}

    def test_accepts_id_parameter(self, client, headers):
        body = take(client, headers).json
        response = client.get(
            "/token_status_list/get", query_string={"uri": body["status_list"]["uri"], "id": body["status_list"]["idx"]}
        )
        assert response.data == b"0"

    def test_unknown_list(self, client):
        response = get(client, f"https://statuslist.test/token_status_list/FC/{PID}/{UNKNOWN_ID}", 1)
        assert response.status_code == 404
        assert response.json == {"error": "Unknown list"}

    def test_identifier_list_shows_revocations(self, client, headers):
        """Before, /get on the identifier list always answered 0."""
        body = take(client, headers).json
        revoke(client, headers, body["status_list"]["uri"], body["status_list"]["idx"])
        assert get(client, body["identifier_list"]["uri"], body["identifier_list"]["id"]).data == b"1"

    @pytest.mark.parametrize("idx", ["-1", "10000", str(10**12)])
    def test_index_out_of_range(self, client, headers, idx):
        uri = take(client, headers).json["status_list"]["uri"]
        response = get(client, uri, idx)
        assert response.status_code == 400
        assert response.is_json

    def test_corrupt_list(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json", "w").write("{")
        response = get(client, uri, 1)
        assert response.status_code == 500
        assert response.json == {"error": "List unavailable"}

    def test_uri_cannot_leave_status_list_dir(self, client, configuration, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "full_list.json").write_text(json.dumps({"token_status_list": None, "identifier_list": {"1": 1}}))
        response = get(client, "https://statuslist.test/identifier_list/../../outside", 1)
        assert response.status_code in (400, 404)


class TestSet:
    def test_revokes(self, client, headers, configuration):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        response = revoke(client, headers, uri, idx)
        assert response.status_code == 200
        assert response.data == b"Status Changed\n"
        assert get(client, uri, idx).data == b"1"
        assert get(client, body["identifier_list"]["uri"], idx).data == b"1"

    def test_revocation_survives_the_next_take(self, client, headers):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        revoke(client, headers, uri, idx)
        take(client, headers)
        assert get(client, uri, idx).data == b"1"

    def test_api_key_required(self, client):
        response = revoke(client, {"X-Api-Key": "wrong"}, "u", 1)
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}

    @pytest.mark.parametrize(
        "idx,status,error",
        [("a", 1, "'id' or 'idx' unkown"), (1, "x", " status unkown"), (1, 0, "Wrong Status Change"), (1, 2, "Wrong Status Change")],
    )
    def test_invalid_input(self, client, headers, idx, status, error):
        response = revoke(client, headers, "https://statuslist.test/token_status_list/FC/x/y", idx, status)
        assert response.status_code == 400
        assert response.json == {"error": error}

    @pytest.mark.parametrize("field", ["uri", "status"])
    def test_missing_field(self, client, headers, field):
        data = {"uri": "u", "idx": 1, "status": 1}
        del data[field]
        assert client.post("/token_status_list/set", headers=headers, data=data).status_code == 400

    def test_missing_index(self, client, headers):
        response = client.post("/token_status_list/set", headers=headers, data={"uri": "u", "status": 1})
        assert response.status_code == 400
        assert response.json == {"error": "Missing URI/index/status"}

    @pytest.mark.parametrize("part,error", [(2, "Invalid country"), (3, "Invalid document type")])
    def test_uri_with_unknown_country_or_doctype(self, client, headers, configuration, part, error):
        uri = take(client, headers).json["status_list"]["uri"]
        path = urlparse(uri).path.split("/")
        path[part] = "XX"
        bad = "https://statuslist.test" + "/".join(path)
        os.makedirs(configuration["status_list_dir"] + "/".join(path))
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as src:
            open(configuration["status_list_dir"] + "/".join(path) + "/full_list.json", "w").write(src.read())
        response = revoke(client, headers, bad, 1)
        assert response.status_code == 400
        assert response.json == {"error": error}

    def test_takes_after_a_revocation(self, client, headers):
        """issue 1: the second take after a revocation failed with a 500."""
        body = take(client, headers).json
        revoke(client, headers, body["status_list"]["uri"], body["status_list"]["idx"])
        assert take(client, headers).status_code == 200
        assert take(client, headers).status_code == 200


class TestSetValidation:
    """issues 6, 12 and 13."""

    @pytest.mark.parametrize("idx", ["-1", "10000", str(10**12)])
    def test_index_out_of_range(self, client, headers, idx):
        body = take(client, headers).json
        uri = body["status_list"]["uri"]
        response = revoke(client, headers, uri, idx)
        assert response.status_code == 400
        assert response.is_json
        assert get(client, uri, 9999).data == b"0"  # -1 used to revoke the last entry

    @pytest.mark.parametrize(
        "make_uri",
        [
            lambda uri: uri.replace("https://statuslist.test", "https://other.host"),
            lambda uri: urlparse(uri).path,
            lambda uri: uri + "/",
            lambda uri: uri + "?x=1",
            lambda uri: uri.rsplit("/", 1)[0] + "/../../../../x",
            lambda uri: uri.rsplit("/", 1)[0] + "/not-a-list-id",
            lambda uri: uri.replace("/token_status_list/", "/token_status_list/FC/"),
        ],
    )
    def test_uri_must_be_a_list_of_this_service(self, client, headers, make_uri):
        body = take(client, headers).json
        bad = make_uri(body["status_list"]["uri"])
        response = revoke(client, headers, bad, body["status_list"]["idx"])
        assert response.status_code == 400
        assert response.json == {"error": "uri is not a list of this service"}
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"0"

    def test_unknown_list(self, client, headers):
        response = revoke(client, headers, f"https://statuslist.test/token_status_list/FC/{PID}/{UNKNOWN_ID}", 1)
        assert response.status_code == 404

    def test_corrupt_list(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json", "w").write("{")
        assert revoke(client, headers, uri, 1).status_code == 500

    def test_identifier_list_uri_revokes_the_same_entry(self, client, headers):
        body = take(client, headers).json
        response = client.post(
            "/token_status_list/set",
            headers=headers,
            data={"uri": body["identifier_list"]["uri"], "id": body["identifier_list"]["id"], "status": 1},
        )
        assert response.status_code == 200
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"1"

    def test_revoking_twice(self, client, headers):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        assert revoke(client, headers, uri, idx).status_code == 200
        assert revoke(client, headers, uri, idx).status_code == 200


class TestErrors:
    def test_unknown_route_is_json(self, client):
        response = client.get("/token_status_list/nothing")
        assert response.status_code == 404
        assert response.is_json

    def test_unhandled_error_is_json(self, client, headers, monkeypatch):
        from app import list_management

        def boom(*_):
            raise RuntimeError("boom")

        monkeypatch.setattr(list_management, "take", boom)
        response = take(client, headers)
        assert response.status_code == 500
        assert response.json == {"error": "Internal server error"}
