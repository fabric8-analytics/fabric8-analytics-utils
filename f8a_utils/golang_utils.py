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
from f8a_utils.gh_utils import GithubUtils
from f8a_version_comparator.comparable_version import ComparableVersion


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
        self.module = []
        self.gh = GithubUtils()
        self.__populate_data(pkg)

    def __fetch_all_versions(self, obj):
        """Fetch all the versions of a pkg."""
        page_exist = obj.get_sub_data('div', {'data-test-id': 'UnitHeader-breadcrumb'})
        ver_list = obj.get_value_from_list('li', 'a', {'class': 'Versions-item'})
        final_list = []
        if len(ver_list) != 0:
            for ver in ver_list:
                if ver.startswith('v0.0.0-'):
                    continue
                elif "+incompatible" in ver:
                    intermediate_value = ver.split('+incompatible')[0]
                    if "v" in intermediate_value:
                        version = intermediate_value.split('v')[1]
                    else:
                        version = intermediate_value
                    final_list.append(version)
                else:
                    if ver.startswith('v'):
                        version = ver.split('v')[1]
                    else:
                        version = ver
                    final_list.append(version)
        # The tab exist logic is added because in some cases, you wont find any versions under tab.
        if ver_list or page_exist:
            link = self.get_gh_link()
            if link and "https://github.com/" in link:
                org_name = self.get_gh_link().split("https://github.com/")[1].split("/")
                all_ver = self.gh._get_verion_list(org_name[0], org_name[1])
                if all_ver:
                    if final_list:
                        all_ver.extend(final_list)
                    return list(set(all_ver))
                elif len(final_list) == 0:
                    return ['none']
            else:
                return []
        return ver_list

    def __select_latest_version(self, versions=[]):
        """Select latest version from list."""
        if len(versions) == 0:
            return ""
        version_arr = []
        for x in versions:
            version_arr.append(ComparableVersion(x))
        version_arr.sort()
        return str(version_arr[-1])

    def __fetch_latest_version(self, obj):
        """Fetch the latest version of a pkg."""
        all_ver = self.get_all_versions()
        if all_ver:
            return self.__select_latest_version(all_ver)
        else:
            return ""

    def __fetch_license(self, obj):
        """Fetch the github link of a pkg."""
        sub_obj = obj.get_sub_data('span', {'data-test-id': 'UnitHeader-licenses'})
        lic_list = obj.get_value_from_list('a', None, None, None, None, sub_obj)
        final_lic_list = []
        for lic in lic_list or []:
            if ', ' in lic:
                lics = lic.split(', ')
                final_lic_list.extend(lics)
            elif ',' in lic:
                lics = lic.split(', ')
                final_lic_list.extend(lics)
            else:
                final_lic_list.append(lic)
        return final_lic_list

    def __fetch_gh_link(self, obj):
        """Fetch the github link of a pkg."""
        return obj.get_value(
            'a', None, 'href',
            obj.get_sub_data('div', {'class': 'UnitMeta'}))

    def __fetch_module(self, obj, mod_val=None):
        """Fetch the module of a pkg."""
        module_lst = []
        if not mod_val:
            # mod_val = obj.get_value('a', {'data-test-id': 'DetailsHeader-infoLabelModule'})
            sub_obj = obj.get_sub_data('div', {'data-test-id': 'UnitHeader-breadcrumb'})
            mod_list = obj.get_value_from_list('a', None, None, None, None, sub_obj)
            if len(mod_list) == 1 and mod_list[0] == 'Discover Packages':
                mod_val = obj.get_value('span', {'data-test-id': 'UnitHeader-breadcrumbCurrent'})
                self.mode = "mod"
            if len(mod_list) >= 2:
                mod_val = mod_list[1]
        if mod_val:
            module_lst.append(mod_val)
            if "github" not in mod_val:
                gh_link = self.get_gh_link()
                if "https" in gh_link:
                    module_lst.append(gh_link.split('https://')[1])
        return module_lst

    def __populate_data(self, pkg):
        """Set the data for the golang pkg."""
        _logger.info("Populating the data object for {}".format(pkg))
        pkg_url = "https://pkg.go.dev/{}".format(pkg)
        mod_url = "https://pkg.go.dev/mod/{}".format(pkg)
        scraper = Scraper(pkg_url + "?tab=versions")
        self.mode = "pkg"
        self.url = pkg_url
        self.version_list = self.__fetch_all_versions(scraper)
        if len(self.version_list) == 0:
            _logger.info("Fetching the details from mod.")
            scraper = Scraper(mod_url + "?tab=versions")
            self.mode = "mod"
            self.url = mod_url
            self.version_list = self.__fetch_all_versions(scraper)
            if len(self.version_list) != 0:
                self.latest_version = self.__fetch_latest_version(scraper)
                self.module = self.__fetch_module(scraper, pkg)
            else:
                self.mode = "Not Found"
        else:
            _logger.info("Fetching the details from pkg.")
            self.latest_version = self.__fetch_latest_version(scraper)
            self.module = self.__fetch_module(scraper)

    def get_module(self):
        """Return module name of a pkg."""
        if self.module == "Not Found":
            return None
        return self.module

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
