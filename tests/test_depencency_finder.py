"""Tests for classes from depencency_finder module."""

from f8a_utils.dependency_finder import DependencyFinder
from pathlib import Path
import pytest


def test_scan_and_find_dependencies_npm():
    """Test scan_and_find_dependencies function for NPM."""
    manifests = [{
        "filename": "npmlist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/npmlist.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests, "true")
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "body-parser"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 2


def test_scan_and_find_dependencies_npm_npm_list_as_bytes():
    """Test scan_and_find_dependencies function for NPM."""
    manifests = [{
        "filename": "npmlist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/npmlist.json"), "rb").read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests, "false")
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "body-parser"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 0


def test_scan_and_find_dependencies_pypi():
    """Test scan_and_find_dependencies function for PyPi."""
    manifests = [{
        "filename": "pylist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/pylist.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("pypi", manifests, "false")
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "django"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 1


def test_scan_and_find_dependencies_pypi_pylist_as_bytes():
    """Test scan_and_find_dependencies function for PyPi."""
    manifests = [{
        "filename": "pylist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/pylist.json"), "rb").read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("pypi", manifests, "true")
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "django"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 1


def test_scan_and_find_dependencies_maven_with_transitives():
    """Test scan_and_find_dependencies function for Maven."""
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/dependencies.txt")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, "true")
    assert "result" in res
    resolved = res['result'][0]['details'][0]['_resolved'][0]
    assert resolved['package'] == "io.vertx:vertx-core"
    assert len(resolved['deps']) == 15


def test_scan_and_find_dependencies_maven_without_transitives():
    """Test scan_and_find_dependencies function for Maven."""
    # file containing content should be opened as binary stream
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/dependencies.txt"), "rb").read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, "false")
    assert "result" in res
    resolved = res['result'][0]['details'][0]['_resolved'][0]
    assert resolved['package'] == "io.vertx:vertx-core"
    assert len(resolved['deps']) == 0


def test_scan_and_find_dependencies_maven_various_ncols():
    """Test scan_and_find_dependencies function for Maven."""
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/dependencies_various_ncols.txt")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, "true")
    assert "result" in res
    resolved = res['result'][0]['details'][0]['_resolved'][0]
    assert resolved['package'] == "io.vertx:vertx-core"
    assert len(resolved['deps']) == 15


def test_scan_and_find_dependencies_maven_invalid_coordinates():
    """Test scan_and_find_dependencies function for Maven."""
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content":
        open(str(Path(__file__).parent / "data/dependencies_invalid_coordinates.txt")).read()
    }]
    with pytest.raises(ValueError):
        res = DependencyFinder().scan_and_find_dependencies("maven", manifests, "true")
        assert res


def test_scan_and_find_dependencies_maven_ignore_test_deps():
    """Test scan_and_find_dependencies function for Maven."""
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/dependencies.txt")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, "true")
    assert "result" in res

    # There are total 9 packages, but 4 are mandatory packages.
    assert 4 == len(res['result'][0]['details'][0]['_resolved'])

    # Packages expected are
    mandatory_packages = [
        'io.vertx:vertx-core',
        'io.vertx:vertx-web',
        'io.vertx:vertx-health-check',
        'io.vertx:vertx-web-client'
    ]

    # Pacakge not expected are
    test_packages = [
        'io.vertx:vertx-unit',
        'junit:junit',
        'org.assertj:assertj-core',
        'io.rest-assured:rest-assured',
        'org.arquillian.cube:arquillian-cube-openshift-starter'
    ]

    # Check that only non-test packages are present.
    for package in res['result'][0]['details'][0]['_resolved']:
        assert package['package'] in mandatory_packages
        assert package['package'] not in test_packages


if __name__ == '__main__':
    test_scan_and_find_dependencies_npm()
    test_scan_and_find_dependencies_npm_npm_list_as_bytes()
    test_scan_and_find_dependencies_pypi()
    test_scan_and_find_dependencies_pypi_pylist_as_bytes()
    test_scan_and_find_dependencies_maven_with_transitives()
    test_scan_and_find_dependencies_maven_without_transitives()
    test_scan_and_find_dependencies_maven_invalid_coordinates()
    test_scan_and_find_dependencies_maven_various_ncols()
    test_scan_and_find_dependencies_maven_ignore_test_deps()
