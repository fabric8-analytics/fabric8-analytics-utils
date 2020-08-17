"""Helper functions related to versions."""

import requests
import logging
from urllib.request import urlopen
from lxml import etree
from f8a_version_comparator.comparable_version import ComparableVersion
from f8a_utils.golang_utils import GolangUtils

_logger = logging.getLogger(__name__)


def get_versions_and_latest_for_ep(ecosystem, package_name):
    """Get all versions for given (ecosystem, package).

    :param ecosystem: str, ecosystem name
    :param package_name: str, package name
    :return json, list of versions and latest version
    """
    if package_name is None:
        raise ValueError('Package name is not provided')

    # check against the supported ecosystems
    if ecosystem == 'npm':
        return get_versions_for_npm_package(package_name, dual_values=True)
    if ecosystem == 'pypi':
        return get_versions_for_pypi_package(package_name, dual_values=True)
    if ecosystem == 'maven':
        return get_versions_for_maven_package(package_name, dual_values=True)
    if ecosystem == 'golang':
        return get_versions_for_golang_package(package_name, dual_values=True)
    else:
        raise ValueError('Unsupported ecosystem: {e}'.format(e=ecosystem))


def get_versions_for_ep(ecosystem, package_name):
    """Get all versions for given (ecosystem, package).

    :param ecosystem: str, ecosystem name
    :param package_name: str, package name
    :return list, list of versions
    """
    if package_name is None:
        raise ValueError('Package name is not provided')

    # check against the supported ecosystems
    if ecosystem == 'npm':
        return get_versions_for_npm_package(package_name)
    if ecosystem == 'pypi':
        return get_versions_for_pypi_package(package_name)
    if ecosystem == 'maven':
        return get_versions_for_maven_package(package_name)
    if ecosystem == 'golang':
        return get_versions_for_golang_package(package_name)
    else:
        raise ValueError('Unsupported ecosystem: {e}'.format(e=ecosystem))


def is_pkg_public(ecosystem, package_name):
    """Check if a pkg is publicly available."""
    version = get_versions_for_ep(ecosystem, package_name)
    if version:
        return True
    return False


def get_latest_versions_for_ep(ecosystem, package_name):
    """Get all versions for given (ecosystem, package).

    :param ecosystem: str, ecosystem name
    :param package_name: str, package name
    :return version
    """
    if package_name is None:
        raise ValueError('Package name is not provided')

    # check against the supported ecosystems
    if ecosystem == 'npm':
        version = get_versions_for_npm_package(package_name, True)
    elif ecosystem == 'pypi':
        version = get_versions_for_pypi_package(package_name, True)
    elif ecosystem == 'maven':
        version = get_versions_for_maven_package(package_name, True)
    elif ecosystem == 'golang':
        version = get_versions_for_golang_package(package_name, True)
    else:
        raise ValueError('Unsupported ecosystem: {e}'.format(e=ecosystem))
    return version


def get_versions_for_golang_package(package_name, latest=False, dual_values=False):
    """Get all versions for given golang package.

    :param package_name: str, package name
    :param latest: boolean value, to return only the latest version
    :param dual_values: boolean value, to return both version list and latest version
    :return list, list of versions
    """
    go_util = GolangUtils(package_name)
    latest_ver = go_util.get_latest_version()
    all_ver = go_util.get_all_versions()
    if latest:
        return latest_ver
    if dual_values:
        return {'versions': all_ver,
                'latest_version': latest_ver}
    return all_ver


def get_versions_for_npm_package(package_name, latest=False, dual_values=False):
    """Get all versions for given NPM package.

    :param package_name: str, package name
    :param latest: boolean value, to return only the latest version
    :param dual_values: boolean value, to return both version list and latest version
    :return list, list of versions
    """
    url = 'https://registry.npmjs.org/{pkg_name}'.format(
        pkg_name=package_name
    )

    response = requests.get(url)

    if response.status_code != 200:
        _logger.info(
            'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
        )
        return []

    response_json = {}
    try:
        response_json = response.json()
    except ValueError:
        pass
    finally:
        if not response_json:
            return []
    ver_list = []
    if response_json.get('versions'):
        ver_list = list({x for x in response_json.get('versions', {})})
    if response_json.get('time'):
        for x in response_json.get('time'):
            if x != "modified" and x != "created":
                ver_list.append(x)
    ver_list = list(set(ver_list))
    if dual_values:
        version = response_json.get('dist-tags', {})['latest'] if \
            'latest' in response_json.get('dist-tags', {}) else select_latest_version(ver_list)
        return {'versions': ver_list,
                'latest_version': version}
    if latest:
        version = response_json.get('dist-tags', {})['latest'] if \
            'latest' in response_json.get('dist-tags', {}) else select_latest_version(ver_list)
        return version
    return ver_list


def get_versions_for_pypi_package(package_name, latest=False, dual_values=False):
    """Get all versions for given PyPI package.

    :param package_name: str, package name
    :param latest: boolean value, to return only the latest version
    :param dual_values: boolean value, to return both version list and latest version
    :return list, list of versions
    """
    pypi_package_url = 'https://pypi.python.org/pypi/{pkg_name}/json'.format(
        pkg_name=package_name
    )

    response = requests.get(pypi_package_url)
    if response.status_code != 200:
        _logger.info(
            'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
        )
        return []

    ver_list = list({x for x in response.json().get('releases', {})})

    if dual_values:
        version = response.json().get('info', {})['version'] if \
            'version' in response.json().get('info', {}) else select_latest_version(ver_list)
        return {'versions': ver_list,
                'latest_version': version}

    if latest:
        version = response.json().get('info', {})['version'] if \
            'version' in response.json().get('info', {}) else select_latest_version(ver_list)
        return version
    return ver_list


def get_versions_for_maven_package(package_name, latest=False, dual_values=False):
    """Get all versions for given package from Maven Central.

    :param package_name: str, package name
    :param latest: boolean value, to return only the latest version
    :param dual_values: boolean value, to return both version list and latest version
    :return list, list of versions
    """
    try:
        g, a = package_name.split(':')
        g = g.replace('.', '/')

        filenames = {'maven-metadata.xml', 'maven-metadata-local.xml'}

        versions = set()
        version = ""
        ok = False
        for filename in filenames:

            url = 'https://repo.maven.apache.org/maven2/{g}/{a}/{f}'.format(g=g, a=a, f=filename)
            try:
                metadata_xml = etree.parse(urlopen(url))
                ok = True  # We successfully downloaded the file
                version_elements = metadata_xml.findall('.//version')
                version = metadata_xml.find('.//release').text if \
                    metadata_xml.find('.//release') is not None else None
                versions = versions.union({x.text for x in version_elements})
            except (OSError, etree.XMLSyntaxError):
                # Not both XML files have to exist, so don't freak out yet
                pass

        if not ok:
            _logger.info(
                'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
            )

        if dual_values:
            version = version if version else select_latest_version(list(versions))
            return {'versions': list(versions),
                    'latest_version': version}
        if latest:
            version = version if version else select_latest_version(list(versions))
            return version
        return list(versions)
    except ValueError:
        # wrong package specification etc.
        return []


def select_latest_version(versions=[]):
    """Select latest version from list."""
    if len(versions) == 0:
        return ""
    version_arr = []
    for x in versions:
        version_arr.append(ComparableVersion(x))
    version_arr.sort()
    return str(version_arr[-1])
