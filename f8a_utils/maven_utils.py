#!/usr/bin/env python3
# Copyright © 2021 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: Yusuf Zainee <yzainee@redhat.com>
#

"""Utility file Maven versions."""

from lxml import etree
import logging
from urllib.request import urlopen
from f8a_version_comparator.comparable_version import ComparableVersion
from f8a_utils.web_scraper import Scraper

_logger = logging.getLogger(__name__)


class MavenUtils:
    """Maven utils class."""

    def __fetch_data(self, url, all_ver):
        """Fetch the data via web scraping."""
        scraper = Scraper(url)
        versions = scraper.get_value_from_list('a', None, {'class': 'vbtn release'})
        if versions:
            all_ver.extend(versions)
        return all_ver

    def get_versions_from_other_source(self, package_name):
        """Get all versions via web scraping from mvnrepository."""
        all_ver = []
        pkg = package_name.replace(":", "/")
        pkg_url = "https://mvnrepository.com/artifact/{}".format(pkg)
        scraper = Scraper(pkg_url)
        sub_obj = scraper.get_sub_data('div', {'id': 'snippets'})
        tab_list = scraper.get_value_from_list('li', 'a', None, None, 'href', sub_obj)
        for tab in tab_list:
            repo_val = ""
            if "?repo=" in tab:
                repo_val = tab.split("?repo=")[1]
            ver_url = pkg_url + "?repo={}".format(repo_val)
            all_ver = self.__fetch_data(ver_url, all_ver)
        all_ver = set(all_ver)
        return all_ver

    def get_versions_for_maven_package(self, package_name, latest=False,
                                       dual_values=False, multi_source=False):
        """Get all versions for given package from Maven Central.

        :param package_name: str, package name
        :param latest: boolean value, to return only the latest version
        :param dual_values: boolean value, to return both version list and latest version
        :param multi_source: boolean, to fetch data from mvnrepository as well
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

                url = 'https://repo.maven.apache.org/maven2/{g}/{a}/{f}'.format(
                    g=g, a=a, f=filename)
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

            if not ok and multi_source:
                try:
                    versions = self.get_versions_from_other_source(package_name)
                    ok = True
                except Exception:
                    pass

            if not ok:
                _logger.info(
                    'Unable to fetch versions for package {pkg_name}'.format(pkg_name=package_name)
                )

            if dual_values:
                version = version if version else self.select_latest_version(list(versions))
                return {'versions': list(versions),
                        'latest_version': version}
            if latest:
                version = version if version else self.select_latest_version(list(versions))
                return version
            return list(versions)
        except ValueError:
            # wrong package specification etc.
            return []

    def select_latest_version(self, versions=[]):
        """Select latest version from list."""
        if len(versions) == 0:
            return ""
        version_arr = []
        for x in versions:
            version_arr.append(ComparableVersion(x))
        version_arr.sort()
        return str(version_arr[-1])
