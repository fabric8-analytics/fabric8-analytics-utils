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
