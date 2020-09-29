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

"""Utility file to fetch github details."""

import random
import logging
import requests
from os import environ
from datetime import datetime

_logger = logging.getLogger(__name__)


class GithubUtils:
    """Github utils class."""

    def __init__(self):
        """Init method for GithubUtils class."""

        self.GITHUB_TOKEN = environ.get('GITHUB_TOKEN', 'not-set').split(',')
        self.GITHUB_API = "https://api.github.com/"

    def __select_gh_token(self):
        """Randomly select and return a gh token."""
        if 'not-set' not in self.GITHUB_TOKEN and len(self.GITHUB_TOKEN) > 0:
            return random.choice(self.GITHUB_TOKEN)
        _logger.info("Could not select a gh token.")
        return None

    def __make_get_call(self, url):
        """Make an api call and return results."""
        token = self.__select_gh_token()
        headers = None
        if token:
            headers = {
                'Authorization': 'token {t}'.format(t=token)
            }
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            _logger.error(
                'Unable to fetch details for package {u}'.format(u=url)
            )
            return None
        return response.json()

    def _get_hash_from_semver(self, org, name, version):
        """Return the commit hash from the semver."""
        try:
            assert org
            assert name
            assert version
        except AssertionError as e:
            _logger.error("Input data is not valid. {}".format(e))
            return None
        url = self.GITHUB_API + "repos/{o}/{n}/git/refs/tags/{v}".format(
            o=org, n=name, v=version)

        data = self.__make_get_call(url)
        if not data:
            _logger.info("No commit hash found for the url {}".format(url))
            return None
        sha = data.get('object', {}).get('sha', '')
        return sha

    def _get_date_from_commit_sha(self, org, name, sha):
        """Return the commit date for the commit hash."""
        try:
            assert org
            assert name
            assert sha
        except AssertionError as e:
            _logger.error("Input data is not valid. {}".format(e))
            return None
        url = self.GITHUB_API + "repos/{o}/{n}/commits/{s}".format(
            o=org, n=name, s=sha)

        data = self.__make_get_call(url)
        if not data:
            _logger.info("No details found for the url {}".format(url))
            return None
        commit = data.get('commit', {})
        if commit:
            date = commit.get('committer', {}).get('date', '')
        else:
            date = None
        return date

    def _get_date_from_tag_sha(self, org, name, sha):
        """Return the commit tag date for the tag hash."""
        try:
            assert org
            assert name
            assert sha
        except AssertionError as e:
            _logger.error("Input data is not valid. {}".format(e))
            return None

        url = self.GITHUB_API + "repos/{o}/{n}/git/tags/{s}".format(
            o=org, n=name, s=sha)
        data = self.__make_get_call(url)
        if not data:
            _logger.info("No details found for the url {}".format(url))
            return None
        date = data.get('tagger', {}).get('date', '')
        return date

    def _get_date_from_semver(self, org, name, version):
        """Get the commit date from the version."""
        tag_sha = self._get_hash_from_semver(org, name, version)
        if not tag_sha:
            _logger.info("Not able to fetch details for the version.")
            return None
        dt = self._get_date_from_commit_sha(org, name, tag_sha)
        if not dt:
            dt = self._get_date_from_tag_sha(org, name, tag_sha)
        return dt

    def __check_for_date_rule(self, comm_date, date_rule):
        """Check if the committed date falls in the date rule."""
        if date_rule == "*":
            return True
        if '&' in date_rule:
            date_rules_splitted = date_rule.split('&')
            return self.__check_for_date_rule(comm_date, date_rules_splitted[0]) and \
                self.__check_for_date_rule(comm_date, date_rules_splitted[1])
        operator = date_rule.split('#')[0]
        operand = datetime.strptime(date_rule.split('#')[1], '%Y-%m-%dT%H:%M:%SZ')
        if operator == "<":
            return comm_date < operand
        elif operator == "<=":
            return comm_date <= operand
        elif operator == ">":
            return comm_date > operand
        elif operator == ">=":
            return comm_date >= operand
        elif operator == "=":
            return comm_date == operand
        else:
            return False

    def _is_commit_in_date_range(self, org, name, sha, date_range_rules):
        """Returns True or False if the date of commit sha lies within the date range rules.
        rules can be provided in the following format:
        >#2020-09-17T13:19:13Z,>=#2020-09-17T13:19:13Z&<2020-09-20T13:19:13Z and so on."""
        comm_date = self._get_date_from_commit_sha(org, name, sha)
        if not comm_date:
            comm_date = self._get_date_from_tag_sha(org, name, sha)
        if not comm_date:
            _logger.info("No info on the commit hash {h} for {o}/{n} found.".format(
                h=sha, o=org, n=name
            ))
            return None
        comm_date = datetime.strptime(comm_date, '%Y-%m-%dT%H:%M:%SZ')
        if ',' in date_range_rules:
            rules = date_range_rules.split(',')
            for rule in rules:
                val = self.__check_for_date_rule(comm_date, rule)
                if val:
                    return True
            return False
        else:
            return self.__check_for_date_rule(comm_date, date_range_rules)
