"""Helper functions related to versions."""

import requests
import logging
from urllib.request import urlopen
from lxml import etree

_logger = logging.getLogger(__name__)


def get_versions_for_npm_package(package_name):
    """Get all versions for given NPM package.

    :param package_name: str, package name
    :return list, list of versions
    """
    url = 'https://registry.npmjs.org/{pkg_name}'.format(
        pkg_name=package_name
    )

    response = requests.get(url)

    if response.status_code != 200:
        _logger.error(
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

    versions = {x for x in response_json.get('versions', {})}

    return list(versions)


def get_versions_for_pypi_package(package_name):
    """Get all versions for given PyPI package.

    :param package_name: str, package name
    :return list, list of versions
    """
    pypi_package_url = 'https://pypi.python.org/pypi/{pkg_name}/json'.format(
        pkg_name=package_name
    )

    response = requests.get(pypi_package_url)
    if response.status_code != 200:
        _logger.error(
            'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
        )
        return []

    return list({x for x in response.json().get('releases', {})})


def get_versions_for_maven_package(package_name):
    """Get all versions for given package from Maven Central.

    :param package_name: str, package name
    :return list, list of versions
    """
    try:
        g, a = package_name.split(':')
        g = g.replace('.', '/')

        filenames = {'maven-metadata.xml', 'maven-metadata-local.xml'}

        versions = set()
        ok = False
        for filename in filenames:

            url = 'https://repo.maven.apache.org/maven2/{g}/{a}/{f}'.format(g=g, a=a, f=filename)
            try:
                metadata_xml = etree.parse(urlopen(url))
                ok = True  # We successfully downloaded the file
                version_elements = metadata_xml.findall('.//version')
                versions = versions.union({x.text for x in version_elements})
            except (OSError, etree.XMLSyntaxError) as e:
                # Not both XML files have to exist, so don't freak out yet
                pass

        if not ok:
            _logger.error(
                'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
            )

        return list(versions)
    except ValueError:
        # wrong package specification etc.
        return []
