"""Tests for classes from depencency_finder module."""
import json
import unittest

from f8a_utils.dependency_finder import DependencyFinder
from pathlib import Path
import pytest

from f8a_utils.tree_generator import GolangDependencyTreeGenerator, MavenDependencyTreeGenerator


def test_scan_and_find_dependencies_npm():
    """Test scan_and_find_dependencies function for NPM."""
    manifests = [{
        "filename": "npmlist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/npmlist.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests, True)
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
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests, False)
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
    res = DependencyFinder().scan_and_find_dependencies("pypi", manifests, False)
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "django"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 1


def test_scan_and_find_dependencies_golang():
    """Test scan_and_find_dependencies function for golang."""
    manifests = [{
        "filename": "gograph.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/gograph.txt")).read()
    }]
    with open(str(Path(__file__).parent / "data/golang_dep_tree.json")) as fp:
        dep_tree = json.load(fp)
    res = DependencyFinder().scan_and_find_dependencies("golang", manifests, True)
    assert res == dep_tree


class TestDependencyFinder(unittest.TestCase):
    """Test class."""

    def test_scan_and_find_dependencies_golang_empty_input(self):
        """Test scan_and_find_dependencies function for golang Empty."""
        file = open(str(Path(__file__).parent / "data/gograph_empty.txt"))
        manifests = [{
            "filename": "gograph.txt",
            "filepath": "/bin/local",
            "content": file.read()
        }]
        file.close()
        res = DependencyFinder().scan_and_find_dependencies
        self.assertRaises(ValueError, res, "golang", manifests, True)

    def test_scan_and_find_dependencies_golang_only_direct(self):
        """Test scan_and_find_dependencies function for golang Only Direct Deps."""
        file = open(str(Path(__file__).parent / "data/gograph_only_direct.txt"))
        manifests = [{
            "filename": "gograph.txt",
            "filepath": "/bin/local",
            "content": file.read()
        }]
        file.close()
        with open(str(Path(__file__).parent / "data/golist_response_only_direct.json")) as fp:
            ideal_response = json.load(fp)
        res = DependencyFinder().scan_and_find_dependencies("golang", manifests, True)
        self.assertEqual(res, ideal_response)

    def test_parse_go_string(self):
        """Test for Parse go string."""
        ideal_res = {'from': 'github.com/hashicorp/consul/sdk@v0.1.1',
                     'package': 'github.com/hashicorp/consul/sdk',
                     'given_version': 'v0.1.1',
                     'is_semver': True,
                     'version': '0.1.1'}
        res = GolangDependencyTreeGenerator()._parse_string(
            'github.com/hashicorp/consul/sdk@v0.1.1')
        assert res == ideal_res

    def test_parse_go_string_error(self):
        """Test for Parse go string Raise Error."""
        res = GolangDependencyTreeGenerator()._parse_string
        self.assertRaises(ValueError, res, "github.com/hashicorp/consul/sdk@v0.1.1@bla")

    def test_parse_string(self):
        """Test Maven Package String."""
        res = MavenDependencyTreeGenerator()._parse_string("io.vertx:vertx-web")
        self.assertEqual(res['groupId'], 'io.vertx')
        res = MavenDependencyTreeGenerator()._parse_string("io.vertx:vertx-web:3.5.4.redhat-00002")
        self.assertEqual(res['groupId'], 'io.vertx')
        self.assertEqual(res['version'], '3.5.4.redhat-00002')


def test_clean_version():
    """Test clean version."""
    is_semver, cleaned_vr = DependencyFinder().clean_version('v0.0.0-20190718012654-fb15b899a751')
    assert is_semver
    assert cleaned_vr == '0.0.0-20190718012654-fb15b899a751'
    is_semver, cleaned_vr = DependencyFinder().clean_version('v2.1.4+incompatible')
    assert is_semver
    assert cleaned_vr == '2.1.4'
    is_semver, cleaned_vr = DependencyFinder().clean_version('v0.20.1-beta')
    assert is_semver
    assert cleaned_vr == '0.20.1-beta'
    is_semver, cleaned_vr = DependencyFinder().clean_version('v32$@12')
    assert not is_semver
    assert cleaned_vr == '32$@12'
    is_semver, cleaned_vr = DependencyFinder().clean_version('v1.1.1-dev1')
    assert is_semver
    assert cleaned_vr == '1.1.1-dev1'


def test_scan_and_find_dependencies_pypi_pylist_as_bytes():
    """Test scan_and_find_dependencies function for PyPi."""
    manifests = [{
        "filename": "pylist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/pylist.json"), "rb").read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("pypi", manifests, True)
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
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, True)
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
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, False)
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
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, True)
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
        res = DependencyFinder().scan_and_find_dependencies("maven", manifests, True)
        assert res


def test_scan_and_find_dependencies_maven_ignore_test_deps():
    """Test scan_and_find_dependencies function for Maven."""
    manifests = [{
        "filename": "dependencies.txt",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/dependencies.txt")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("maven", manifests, True)
    assert "result" in res

    # There are total 9 packages, but 4 are mandatory packages.
    assert 9 == len(res['result'][0]['details'][0]['_resolved'])


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
