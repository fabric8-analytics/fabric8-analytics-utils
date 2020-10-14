"""Definition of a Tree Generator Modal of All Ecosystems."""

import json
from abc import ABC
from collections import defaultdict
import semver


class DependencyTreeGenerator(ABC):
    """Abstract class for Dependency Finderq."""

    @staticmethod
    def get_dependencies(manifests, show_transitive):
        """Make Ecosystem Tree."""
        pass

    @staticmethod
    def _parse_transitives(*args):                # noqa
        """func. for calculating transitives."""
        pass


class MavenDependencyTreeGenerator(DependencyTreeGenerator):
    """Generate Maven Dependency Tree."""

    def get_dependencies(self, manifests: list, show_transitive: bool) -> dict:
        """Scan the maven dependencies files and fetch transitive deps."""
        deps = {}
        result = []
        details = []
        for manifest in manifests:
            dep = {
                "ecosystem": "maven",
                "manifest_file_path": manifest['filepath'],
                "manifest_file": manifest['filename']
            }
            resolved = []
            data = manifest['content']

            if isinstance(data, bytes):
                data = data.decode("utf-8")

            tree = self._get_tree(data)
            for direct, transitives in tree.items():
                # Add meta data to generated tree.
                parsed_json = self._parse_string(direct)
                trans_list = []
                if show_transitive:
                    trans_list = self._parse_transitives(transitives)
                tmp_json = {
                    "package": parsed_json['groupId'] + ":" + parsed_json['artifactId'],
                    "version": parsed_json['version'],
                    "deps": trans_list
                }
                resolved.append(tmp_json)
            dep['_resolved'] = resolved
            details.append(dep)
            details_json = {"details": details}
            result.append(details_json)

        deps['result'] = result
        return deps

    def _parse_transitives(self, transitives: list) -> list:
        """Scan the maven transitives."""
        trans_list = []
        for transitive in transitives:
            parsed_json = self._parse_string(transitive)
            tmp_json = {
                "package": parsed_json['groupId'] + ":" + parsed_json['artifactId'],
                "version": parsed_json['version']
            }
            trans_list.append(tmp_json)
        return trans_list

    def _get_tree(self, content: str) -> dict:
        """Build Dependency Tree.

        :param content: file contents from dependency.txt
        :return: Tree in format ({d1:[t1, t2]})
        """
        final_map = {}
        intermediate_map = defaultdict(list)
        module = ''
        for line in content.split("\n"):
            if '->' in line:
                # line = line.replace('"', '').replace(';', '').strip()
                prefix, suffix = line.split('->')
                prefix = prefix.replace('"', '').replace(';', '').strip()
                suffix = suffix.replace('"', '').replace(';', '').strip()

                prefix, suffix = prefix, suffix.strip('\n')
                if prefix == module:
                    final_map[suffix] = []
                else:
                    intermediate_map[prefix].append(suffix)
            else:
                module = line[line.find('"') + 1:line.rfind('"')]

        for key in final_map.keys():
            values = intermediate_map[key]
            while len(values) != 0:
                next_key = values.pop()
                final_map[key].append(next_key)
                values.extend(intermediate_map[next_key])
        return final_map

    @staticmethod
    def _parse_string(coordinates_str):
        """Parse string representation into a dictionary."""
        a = {'groupId': '',
             'artifactId': '',
             'packaging': '',
             'version': '',
             'classifier': '',
             'scope': ''}

        ncolons = coordinates_str.count(':')
        if ncolons == 1:
            a['groupId'], a['artifactId'] = coordinates_str.split(':')
        elif ncolons == 2:
            a['groupId'], a['artifactId'], a['version'] = coordinates_str.split(':')
        elif ncolons == 3:
            a['groupId'], a['artifactId'], a['packaging'], a['version'] = coordinates_str.split(':')
        elif ncolons == 4:
            # groupId:artifactId:packaging:version:scope
            a['groupId'], a['artifactId'], a['packaging'], a['version'], a['scope'] = \
                coordinates_str.split(':')
        elif ncolons == 5:
            # groupId:artifactId:packaging:classifier:version:scope
            a['groupId'], a['artifactId'], a['packaging'], a['classifier'], a['version'], \
                a['scope'] = coordinates_str.split(':')
        else:
            raise ValueError('Invalid Maven coordinates %s', coordinates_str)

        return a


class NpmDependencyTreeGenerator(DependencyTreeGenerator):
    """Generate NPM Dependency Tree."""

    def get_dependencies(self, manifests, show_transitive):
        """Scan the npm dependencies files to fetch transitive deps."""
        deps = {}
        result = []
        details = []
        for manifest in manifests:
            dep = {
                "ecosystem": "npm",
                "manifest_file_path": manifest['filepath'],
                "manifest_file": manifest['filename']
            }

            data = manifest['content']

            if isinstance(data, bytes):
                data = data.decode("utf-8")

            dependencies = json.loads(data).get('dependencies')
            resolved = []
            if dependencies:
                for key, val in dependencies.items():
                    version = val.get('version') or val.get('required').get('version')
                    if version:
                        transitive = []
                        if show_transitive is True:
                            tr_deps = val.get('dependencies') or \
                                      val.get('required', {}).get('dependencies')
                            if tr_deps:
                                transitive = self._parse_transitives(transitive, tr_deps)
                        tmp_json = {
                            "package": key,
                            "version": version,
                            "deps": transitive
                        }
                        resolved.append(tmp_json)
            dep['_resolved'] = resolved
            details.append(dep)
            details_json = {"details": details}
            result.append(details_json)
        deps['result'] = result
        return deps

    def _parse_transitives(self, transitive, content):
        """Scan the npm dependencies recursively to fetch transitive deps."""
        if content:
            for key, val in content.items():
                version = val.get('version') or val.get('required').get('version')
                if version:
                    tmp_json = {
                        "package": key,
                        "version": version
                    }
                    transitive.append(tmp_json)
                    tr_deps = val.get('dependencies') or val.get('required', {}).get('dependencies')
                    if tr_deps:
                        transitive = self._parse_transitives(transitive, tr_deps)
        return transitive


class PypiDependencyTreeGenerator(DependencyTreeGenerator):
    """Generate Pypi Dependency Tree."""

    def get_dependencies(self, manifests, show_transitive):
        """Scan the Pypi dependencies files to fetch transitive deps."""
        result = []
        details = []
        deps = {}
        for manifest in manifests:
            dep = {
                "ecosystem": "pypi",
                "manifest_file_path": manifest['filepath'],
                "manifest_file": manifest['filename']
            }
            data = manifest['content']

            if isinstance(data, bytes):
                data = data.decode("utf-8")
            content = json.loads(data)
            dep['_resolved'] = content
            details.append(dep)
            details_json = {"details": details}
            result.append(details_json)
        deps['result'] = result
        return deps


class GolangDependencyTreeGenerator(DependencyTreeGenerator):
    """Generate Golang Dependency Tree."""

    def get_dependencies(self, manifests, show_transitive):
        """Check Go Lang Dependencies."""
        details = []
        final = {}
        result = []
        for manifest in manifests:
            dep = {
                "ecosystem": "golang",
                "manifest_file_path": manifest['filepath'],
                "manifest_file": manifest['filename']
            }
            resolved = []
            direct_dep_list = []
            dependencies = self._clean_dependencies(manifest['content'])
            for dependency in dependencies:
                # Find out Direct Dependencies listed against Module Package.
                prefix, direct_dep = dependency.strip().split(" ")
                if '@' not in prefix and (direct_dep not in direct_dep_list):
                    # Only Module Packages have no @ in Prefix.
                    parsed_json = self._parse_string(direct_dep)
                    transitive_list = []
                    trans = []
                    if show_transitive:
                        transitive_list = self._parse_transitives(
                            dependencies, transitive_list, direct_dep, trans)
                    parsed_json["deps"] = transitive_list
                    resolved.append(parsed_json)
            dep['_resolved'] = resolved
            details.append(dep)
        result.append({"details": details})
        final["result"] = result
        return final

    def _parse_transitives(self, data, transitive, suffix, trans):
        """Scan the golang transitive deps."""
        for line in data:
            pref, suff = line.strip().split(" ")
            if pref == suffix and suff not in trans:
                trans.append(suff)
                parsed_json = self._parse_string(suff)
                transitive.append(parsed_json)
                transitive = self._parse_transitives(data, transitive, suff, trans)
        return transitive

    def _parse_string(self, deps_string):
        """Parse string representation into a dictionary."""
        a = {
            'from': deps_string,
            'package': '',
            'given_version': '',
            'is_semver': False,
            'version': ''
        }

        ncolons = deps_string.count('@')
        if ncolons == 0:
            a['package'] = deps_string
        elif ncolons == 1:
            a['package'], a['given_version'] = deps_string.split('@')
        else:
            raise ValueError('Invalid Golang Pkg %s', deps_string)

        a['is_semver'], a['version'] = self.clean_version(a['given_version'])
        return a

    @staticmethod
    def _clean_dependencies(dependencies) -> list:
        """Clean Golang Dep."""
        if isinstance(dependencies, bytes):
            dependencies = dependencies.decode("utf-8")
        dependencies = dependencies[:dependencies.rfind('\n')]
        if not dependencies:
            raise ValueError('Dependency list cannot be empty')
        return dependencies.split('\n')

    @staticmethod
    def clean_version(version):
        """Clean Version."""
        version = version.replace('v', '', 1)
        is_semver = semver.VersionInfo.isvalid(version)
        if is_semver:
            version = str(semver.VersionInfo.parse(version))
        version = version.split('+')[0]
        return is_semver, version
