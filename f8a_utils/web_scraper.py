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

"""Functionality to fetch details from HTML pages."""


from bs4 import BeautifulSoup
import requests


class Scraper:
    """Scraper class to fetch data from HTML."""

    def __init__(self, url):
        """Init method for Scraper class."""
        html_content = requests.get(url).text
        self.DATA = BeautifulSoup(html_content, "lxml")

    def get_data(self):
        """Get data function to return the entire content."""
        return self.DATA

    def get_sub_data(self, tag, attrs=None, obj=None):
        """Fetch the sub object of a tag from HTML content."""
        if not obj:
            obj = self.DATA
        return obj.find(tag, attrs=attrs)

    def get_value(self, tag, attrs=None, param=None, obj=None):
        """Fetch the text value or param value of a tag from HTML content."""
        val = None
        if not obj:
            obj = self.DATA
        if not param:
            obj_val = obj.find(tag, attrs=attrs)
            if obj_val:
                val = obj_val.text
        else:
            obj_val = obj.find(tag, attrs=attrs)
            if obj_val:
                val = obj_val[param]
        return val

    def get_list(self, tag, attrs=None, obj=None):
        """Fetch the details and return a list."""
        if not obj:
            obj = self.DATA
        return obj.find_all(tag, attrs=attrs)

    def get_value_from_list(self, list_tag, data_tag, list_attrs=None,
                            data_attrs=None, param=None, obj=None):
        """Fetch the value from inside the list items."""
        list_data = self.get_list(list_tag, list_attrs, obj)
        results = []
        for li in list_data:
            if data_tag:
                results.append(self.get_value(data_tag, data_attrs, param, li))
            else:
                if param:
                    results.append(li[param])
                else:
                    results.append(li.text)
        return results


"""
This code is kept commented with purpose: If anyone wants to try out scraper.
Its easier to follow these examples
if __name__ == '__main__':

    url = "https://pkg.go.dev/github.com/kubernetes/kubernetes/pkg/volume/scaleio?tab=versions"
    scraper = Scraper(url)
    print("--all--")
    print(scraper.get_value_from_list('li', 'a', {'class': 'Versions-item'}))
    print("--latest--")
    print(scraper.get_value('div', {'class': 'DetailsHeader-version'}))

    url = "https://pkg.go.dev/github.com/kubernetes/kubernetes/pkg/volume/scaleio?tab=overview"
    scraper = Scraper(url)
    print("--gh link--")
    print(scraper.get_value(
        'a', None, 'href',
        scraper.get_sub_data('p', {'class': 'Overview-sourceCodeLink'})))
    print("--license--")
    print(scraper.get_value(
        'a', None, None,
        scraper.get_sub_data('span', {'data-test-id': 'DetailsHeader-infoLabelLicense'})))

    url = "https://pkg.go.dev/mod/k8s.io/kubelet?tab=versions"
    scraper = Scraper(url)
    print("--all--")
    print(scraper.get_value_from_list('li', 'a', {'class': 'Versions-item'}))
    print("--latest--")
    print(scraper.get_value('div', {'class': 'DetailsHeader-version'}))

    url = "https://pkg.go.dev/mod/github.com/Rican7/retry?tab=Overview" #Overview for mod
    scraper = Scraper(url)
    print("--gh link--")
    print(scraper.get_value(
        'a', None, 'href',
        scraper.get_sub_data('p', {'class': 'Overview-sourceCodeLink'})))
    print("--license--")
    print(scraper.get_value(
        'a', None, None,
        scraper.get_sub_data('span', {'data-test-id': 'DetailsHeader-infoLabelLicense'})))

    url = "https://mvnrepository.com/artifact/org.jenkins-ci.main/jenkins-core"
    scraper = Scraper(url)
    print("--versions--")
    print(scraper.get_value_from_list('a', None, {'class': 'vbtn release'}, None, 'href'))
"""
