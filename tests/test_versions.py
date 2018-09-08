"""Test the code to retrieve package version from online sources."""

from unittest.mock import patch

from f8a_utils.versions import (
    get_versions_for_npm_package,
    get_versions_for_pypi_package,
    get_versions_for_maven_package
)


def test_get_versions_for_npm_package():
    """Test basic behavior of the function get_versions_for_npm_package."""
    package_versions = get_versions_for_npm_package("array")
    assert package_versions is not None

    # good old version 0.4.0 should be reported
    assert "0.4.0" in package_versions

    package_versions = get_versions_for_npm_package(
        "it is hard to specify package that does not exist"
    )
    assert package_versions is not None

    # we expect empty list there
    assert not package_versions


def test_get_versions_for_npm_package_deprecated_package():
    """Test basic behavior of the function get_versions_for_npm_package."""
    package_versions = get_versions_for_npm_package("nsp")
    assert package_versions is not None


class _response_no_json:

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

    def json(self):
        return None


class _response_json_value_error:

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

    def json(self):
        raise ValueError(self.text)


def mocked_requests_get_no_json(url):
    """Implement mocked function requests.get()."""
    assert url
    return _response_no_json(200, """no JSON here""")


def mocked_requests_get_value_error(url):
    """Implement mocked function requests.get()."""
    assert url
    return _response_json_value_error(200, """no JSON here""")


@patch("requests.get", side_effect=mocked_requests_get_no_json)
def test_get_javascript_versions_empty_server_response(_mocked_get):
    """Test the behavior of function get_versions_for_npm_package for empty server response."""
    package_versions = get_versions_for_npm_package("array")
    # empty list is expected
    assert package_versions is not None
    assert not package_versions


@patch("requests.get", side_effect=mocked_requests_get_value_error)
def test_get_javascript_versions_server_response_without_json(_mocked_get):
    """Test get_versions_for_npm_package for server response w/o proper JSON."""
    package_versions = get_versions_for_npm_package("array")
    # empty list is expected
    assert package_versions is not None
    assert not package_versions


def test_get_python_versions():
    """Test basic behavior of function get_versions_for_pypi_package."""
    package_versions = get_versions_for_pypi_package("numpy")
    assert package_versions is not None

    # good old version 1.3.0 should be reported
    assert "1.3.0" in package_versions

    package_versions = get_versions_for_pypi_package(
        "it is hard to specify package that does not exist"
    )
    assert package_versions is not None

    # we expect empty list there
    assert not package_versions


def test_get_java_versions():
    """Test basic behavior of function get_versions_for_maven_package."""
    package_versions = get_versions_for_maven_package("tomcat:catalina")
    assert package_versions is not None

    # good old version 4.0.4 should be reported
    assert "4.0.4" in package_versions

    package_versions = get_versions_for_maven_package(
        "it is hard to specify package that does not exist:foobar"
    )
    assert package_versions is not None

    # we expect empty list there
    assert not package_versions

    package_versions = get_versions_for_maven_package("there's missing comma")
    assert package_versions is not None

    # we expect empty list there
    assert not package_versions
