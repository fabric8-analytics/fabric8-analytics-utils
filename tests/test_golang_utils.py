"""Test file for all the golang utils functions."""

from f8a_utils.golang_utils import GolangUtils


def test_golang_utils_with_valid_pkg():
    """Test golang functions with a valid pkg."""
    go_obj = GolangUtils("github.com/grafana/grafana")
    assert go_obj.mode == "mod"
    assert "6.1.4" in go_obj.get_all_versions()
    assert "v6.1.4" not in go_obj.get_all_versions()
    assert go_obj.get_latest_version() is not None
    assert go_obj.get_gh_link() == "https://github.com/grafana/grafana"
    assert go_obj.get_license()[0] == "Apache-2.0"
    assert go_obj.get_module()[0] == "github.com/grafana/grafana"

    go_obj = GolangUtils("k8s.io/kubelet")
    assert go_obj.mode == "mod"
    assert go_obj.get_license()[0] == "Apache-2.0"
    assert go_obj.get_gh_link() == "https://github.com/kubernetes/kubelet"
    assert go_obj.get_module()[0] == "k8s.io/kubelet"
    assert go_obj.get_module()[1] == "github.com/kubernetes/kubelet"


def test_golang_utils_with_valid_pkg2():
    """Test golang functions with a valid pkg."""
    go_obj = GolangUtils("github.com/containous/traefik/api")
    assert go_obj.mode == "pkg"
    assert "1.7.26" in go_obj.get_all_versions()
    assert go_obj.get_latest_version() is not None
    assert go_obj.get_license()[0] == "MIT"
    assert go_obj.get_gh_link() == "https://github.com/containous/traefik"

    go_obj = GolangUtils("github.com/ryanuber/columnize")
    assert go_obj.mode == "mod"
    assert go_obj.get_gh_link() == "https://github.com/ryanuber/columnize"
    assert go_obj.get_license()[0] == "MIT"

    go_obj = GolangUtils("github.com/qor/admin")
    assert go_obj.mode == "mod"
    assert go_obj.get_gh_link() == "https://github.com/qor/admin"
    assert str(go_obj.get_license()[0]) == "not legal advice"

    go_obj = GolangUtils("code.cloudfoundry.org/gorouter/proxy/handler")
    assert len(go_obj.get_license()) == 4
    assert go_obj.get_module()[0] == "code.cloudfoundry.org/gorouter"
    assert go_obj.get_module()[1] == "github.com/cloudfoundry/gorouter"


def test_golang_utils_with_invalid_pkg():
    """Test golang functions with a invalid pkg."""
    go_obj = GolangUtils("some_junk_name")
    assert go_obj.mode == "Not Found"
    assert not go_obj.get_all_versions()
    assert not go_obj.get_latest_version()
    assert not go_obj.get_gh_link()
    assert not go_obj.get_license()
