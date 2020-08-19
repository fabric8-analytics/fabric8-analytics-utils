#!/usr/bin/env python3
# Copyright © 2020 Red Hat Inc.
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

"""Utility file to fetch golang details."""

from f8a_utils.web_scraper import Scraper
import logging


_logger = logging.getLogger(__name__)


class GolangUtils:
    """Golang utils class."""

    def __init__(self, pkg):
        """Init method for GolangUtils class."""
        self.version_list = []
        self.mode = None
        self.latest_version = "-1"
        self.gh_link = None
        self.license = None
        self.url = self.__populate_data(pkg)

    def __fetch_all_versions(self, obj):
        """Fetch all the versions of a pkg."""
        ver_list = obj.get_value_from_list('li', 'a', {'class': 'Versions-item'})
        if len(ver_list) != 0:
            final_list = []
            for ver in ver_list:
                if "+incompatible" in ver:
                    intermediate_value = ver.split('+incompatible')[0]
                    if "v" in intermediate_value:
                        version = intermediate_value.split('v')[1]
                    else:
                        version = intermediate_value
                    final_list.append(version)
                else:
                    if "v" in ver:
                        version = ver.split('v')[1]
                    else:
                        version = ver
                    final_list.append(version)
            return final_list
        return ver_list

    def __fetch_latest_version(self, obj):
        """Fetch the latest version of a pkg."""
        latest_ver = obj.get_value('div', {'class': 'DetailsHeader-version'})
        if "+incompatible" in latest_ver:
            intermediate_value = latest_ver.split('+incompatible')[0]
            if "v" in intermediate_value:
                latest_ver = intermediate_value.split('v')[1]
            else:
                latest_ver = intermediate_value
        else:
            if "v" in latest_ver:
                latest_ver = latest_ver.split('v')[1]
        return latest_ver

    def __fetch_license(self, obj):
        """Fetch the github link of a pkg."""
        return obj.get_value(
            'a', None, None,
            obj.get_sub_data('span', {'data-test-id': 'DetailsHeader-infoLabelLicense'}))

    def __fetch_gh_link(self, obj):
        """Fetch the github link of a pkg."""
        return obj.get_value(
            'a', None, 'href',
            obj.get_sub_data('p', {'class': 'Overview-sourceCodeLink'}))

    def __populate_data(self, pkg):
        """Set the data for the golang pkg."""
        _logger.info("Populating the data object for {}".format(pkg))
        pkg_url = "https://pkg.go.dev/{}".format(pkg)
        mod_url = "https://pkg.go.dev/mod/{}".format(pkg)
        scraper = Scraper(pkg_url + "?tab=versions")
        self.version_list = self.__fetch_all_versions(scraper)
        if len(self.version_list) == 0:
            _logger.info("Fetching the details from mod.")
            scraper = Scraper(mod_url + "?tab=versions")
            self.version_list = self.__fetch_all_versions(scraper)
            if len(self.version_list) != 0:
                self.mode = "mod"
                self.latest_version = self.__fetch_latest_version(scraper)
            else:
                self.mode = "Not Found"
            return mod_url
        else:
            _logger.info("Fetching the details from pkg.")
            self.mode = "pkg"
            self.latest_version = self.__fetch_latest_version(scraper)
            return pkg_url

    def get_all_versions(self):
        """Return all the versions of a pkg."""
        if self.mode == "Not Found":
            return None
        return self.version_list

    def get_latest_version(self):
        """Return the latest versions of a pkg."""
        if self.mode == "Not Found":
            return None
        return self.latest_version

    def get_gh_link(self):
        """Return the gh link of a pkg."""
        if self.mode == "Not Found":
            return None
        if not self.gh_link:
            if self.mode == "pkg":
                url = self.url + "?tab=overview"
            else:
                url = self.url + "?tab=Overview"
            scraper_ov = Scraper(url)
            self.gh_link = self.__fetch_gh_link(scraper_ov)
            self.license = self.__fetch_license(scraper_ov)
        return self.gh_link

    def get_license(self):
        """Return declared license of a pkg."""
        if self.mode == "Not Found":
            return None
        if not self.license:
            if self.mode == "pkg":
                url = self.url + "?tab=overview"
            else:
                url = self.url + "?tab=Overview"
            scraper_ov = Scraper(url)
            self.gh_link = self.__fetch_gh_link(scraper_ov)
            self.license = self.__fetch_license(scraper_ov)
        return self.license
