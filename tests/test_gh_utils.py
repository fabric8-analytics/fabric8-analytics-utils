"""Test file for all the github utils functions."""

from f8a_utils.gh_utils import GithubUtils
from unittest.mock import patch
import os


def test_get_verion_list():
    """Test _get_verion_list."""
    gh = GithubUtils()
    ver = gh._get_verion_list("", "")
    assert ver is None

    ver = gh._get_verion_list("qor", "admin")
    assert "1.0" in ver


def test_get_hash_from_semver():
    """Test _get_hash_from_semver."""
    gh = GithubUtils()
    sv = gh._get_hash_from_semver("wiuroruw", "gshfkjlsdjkh", "v1.19.1")
    assert sv is None
    sv = gh._get_hash_from_semver("", "gshfkjlsdjkh", "v1.19.1")
    assert sv is None
    sv = gh._get_hash_from_semver("fdf", "", "v1.19.1")
    assert sv is None
    sv = gh._get_hash_from_semver("ff", "gshfkjlsdjkh", "")
    assert sv is None


def test_get_date_from_tag_sha():
    """Test _get_date_from_tag_sha."""
    gh = GithubUtils()
    dt = gh._get_date_from_tag_sha("wiuroruw", "gshfkjlsdjkh", "v1.19.1")
    assert dt is None
    sv = gh._get_date_from_tag_sha("", "gshfkjlsdjkh", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_tag_sha("fdf", "", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_tag_sha("ff", "gshfkjlsdjkh", "")
    assert sv is None


def test_get_date_from_commit_sha():
    """Test _get_date_from_commit_sha."""
    gh = GithubUtils()
    dt = gh._get_date_from_commit_sha("wiuroruw", "gshfkjlsdjkh", "v1.19.1")
    assert dt is None
    sv = gh._get_date_from_commit_sha("", "gshfkjlsdjkh", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_commit_sha("fdf", "", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_commit_sha("ff", "gshfkjlsdjkh", "")
    assert sv is None


def test_get_date_from_semver():
    """Test _get_date_from_semver."""
    gh = GithubUtils()
    dt = gh._get_date_from_semver("wiuroruw", "gshfkjlsdjkh", "v1.19.1")
    assert dt is None
    sv = gh._get_date_from_semver("", "gshfkjlsdjkh", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_semver("fdf", "", "v1.19.1")
    assert sv is None
    sv = gh._get_date_from_semver("ff", "gshfkjlsdjkh", "")
    assert sv is None


def test_get_commit_date():
    """Test _get_commit_date."""
    gh = GithubUtils()
    dt = gh._get_commit_date("kubernetes", "kubernetes", "v1.19.1")
    assert dt == "2020-09-09T11:17:20Z"

    dt = gh._get_commit_date("kubernetes", "kubernetes", "0d4799964558b1e96587737613d6e79e1679cb82")
    assert dt == "2020-09-17T13:19:13Z"

    dt = gh._get_commit_date("kubernetes", "kubernetes", "95b5b7d61338aa0f4c601e820e1d8f3e45696bbc")
    assert dt == "2020-09-09T11:17:20Z"


@patch.dict(os.environ, {'GITHUB_TOKEN': 'some-junk-data'})
def test_get_date_from_semver1():
    """Test _get_date_from_semver failure."""
    gh = GithubUtils()
    dt = gh._get_date_from_semver("kubernetes", "kubernetes", "v1.19.1")
    assert dt is None


def test_is_commit_in_date_range():
    """Test _is_commit_in_date_range."""
    gh = GithubUtils()
    res = gh._is_commit_in_vuln_range("", "", "", "")
    assert res is None

    res = gh._is_commit_in_vuln_range("kubernetes", "kubernetes",
                                      "0d4799964558",
                                      ">#2020-09-15T13:19:13Z&<=#2020-09-16T13:19:13Z,"
                                      ">=#2020-09-16T13:19:13Z&<#2020-09-17T13:19:13Z,"
                                      "=#2020-09-17T13:19:13Z")
    assert res is True
    res = gh._is_commit_in_vuln_range("kubernetes", "kubernetes",
                                      "0d4799964558", "*")
    assert res is True

    res = gh._is_commit_in_vuln_range("kubernetes", "kubernetes",
                                      "0d4799964558", "$%#2020-09-17T13:19:13Z")
    assert res is False

    res = gh._is_commit_in_vuln_range("kubernetes", "kubernetes",
                                      "0d4799964558",
                                      "$#2020-09-17T13:19:13Z,%#2020-09-17T13:19:13Z")
    assert res is False

    gh.GITHUB_API = "http://www.gibberish_my_data.com/"
    res = gh._is_commit_in_vuln_range("kubernetes", "kubernetes",
                                      "0d4799964558", "*")
    assert res is None


def test_is_commit_date_in_vuln_range():
    """Test _is_commit_date_in_vuln_range."""
    gh = GithubUtils()
    res = gh._is_commit_date_in_vuln_range("", "")
    assert res is None

    res = gh._is_commit_date_in_vuln_range("20200916101010",
                                           ">#2020-09-15T13:19:13Z&<=#2020-09-16T13:19:13Z,"
                                           ">=#2020-09-16T13:19:13Z&<#2020-09-17T13:19:13Z,"
                                           "=#2020-09-17T13:19:13Z")
    assert res is True

    res = gh._is_commit_date_in_vuln_range("20190916101010",
                                           ">#2020-09-15T13:19:13Z&<=#2020-09-16T13:19:13Z,"
                                           ">=#2020-09-16T13:19:13Z&<#2020-09-17T13:19:13Z,"
                                           "=#2020-09-17T13:19:13Z")
    assert res is False

    res = gh._is_commit_date_in_vuln_range("0d4799964558", "*")
    assert res is None


def test_is_pseudo_version():
    """Test is_pseudo_version."""
    test_data = {
        "1.3.4": False,
        "v2.3.7": False,
        "1.3.4-alpha": False,
        "v.4.3.2-alpha": False,
        "v2.5.4+incompatible": False,
        "v0.0.0-20201010233445-abcd4321dcba": True,
        "0.0.0-20201010233445-abcd4321dcba": True,
        "20201010233445-abcd4321dcba": False,
        "v0.0.0-20201010233445abcd4321dcba": False,
        "v0.0.0-20201010233445-abcd4321": False,
        "v0.0.0-202010102345-abcd4321dcba": False,
        "v0.0.0-20201010233445-abcd4321dcba-alpha3.4": True,
        "v0.0.0-20201010233445-abcd4321dcba+incompatible": True,
        "v0.0.0-abcd4321dcba-20201010233445": False
    }

    gh = GithubUtils()
    for version, expected_value in test_data.items():
        res = gh.is_pseudo_version(version)
        assert res == expected_value, f"For {version} expected value: {expected_value}"


def test_extract_timestamp():
    """Test extract_timestamp."""
    test_data = {
        "1.3.4": None,
        "v2.3.7": None,
        "1.3.4-alpha": None,
        "v.4.3.2-alpha": None,
        "v2.5.4+incompatible": None,
        "v0.0.0-20201010233445-abcd4321dcba": "20201010233445",
        "0.0.0-20201010233445-abcd4321dcba": "20201010233445",
        "20201010233445-abcd4321dcba": "20201010233445",
        "v0.0.0-20201010233445abcd4321dcba": "20201010233445",
        "v0.0.0-20201010233445-abcd4321": "20201010233445",
        "v0.0.0-202010102345-abcd4321dcba": None,
        "v0.0.0-20201010233445-abcd4321dcba-alpha3.4": "20201010233445",
        "v0.0.0-20201010233445-abcd4321dcba+incompatible": "20201010233445",
        "v0.0.0-abcd4321dcba-20201010233445": "20201010233445",
    }

    gh = GithubUtils()
    for version, expected_value in test_data.items():
        res = gh.extract_timestamp(version)
        assert res == expected_value, f"For {version} expected value: {expected_value}"
