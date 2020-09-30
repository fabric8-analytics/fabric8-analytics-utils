"""Definition of a Tree Generator Modal of All Ecosystems."""

import json
from abc import ABC

import semver


class DependencyTreeGenerator(ABC):
    """Abstract class for Dependency Finderq."""

    @staticmethod
    def get_dependencies(manifests, show_transitive):
        """Make Ecosystem Tree."""
        pass

    @staticmethod
    def _get_transitives(*args):                # noqa
        """func. for calculating transitives."""
        pass


class MavenDependencyTreeGenerator(DependencyTreeGenerator):
    """Generate Maven Dependency Tree."""

    def get_dependencies(self, manifests, show_transitive):
        """Scan the maven dependencies files to fetch transitive deps."""
        deps = {}
        result = []
        details = []
        direct = []
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

            module = ''
            for line in data.split("\n"):
                if "->" in line:
                    line = line.replace('"', '')
                    line = line.replace(' ;', '')
                    prefix, suffix = line.strip().split(" -> ")
                    parsed_json = self._parse_string(suffix)
                    if prefix == module and suffix not in direct and parsed_json['scope'] != 'test':
                        transitive = []
                        trans = []
                        direct.append(suffix)
                        if show_transitive is True:
                            transitive = self._get_transitives(data, transitive, suffix, trans)
                        tmp_json = {
                            "package": parsed_json['groupId'] + ":" + parsed_json['artifactId'],
                            "version": parsed_json['version'],
                            "deps": transitive
                        }
                        resolved.append(tmp_json)
                else:
                    module = line[line.find('"') + 1:line.rfind('"')]
            dep['_resolved'] = resolved
            details.append(dep)
            details_json = {"details": details}
            result.append(details_json)

        deps['result'] = result
        return deps

    def _get_transitives(self, data, transitive, suffix, trans):
        """Scan the maven dependencies files to fetch transitive deps."""
        for line in data.split("\n"):
            if suffix in line:
                line = line.replace('"', '')
                line = line.replace(' ;', '')
                pref, suff = line.strip().split(" -> ")
                parsed_json = self._parse_string(suff)
                if pref == suffix and suff not in trans and parsed_json['scope'] != 'test':
                    trans.append(suff)
                    tmp_json = {
                        "package": parsed_json['groupId'] + ":" + parsed_json['artifactId'],
                        "version": parsed_json['version']
                    }
                    transitive.append(tmp_json)
                    transitive = self._get_transitives(data, transitive, suff, trans)
        return transitive

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
                                transitive = self._get_transitives(transitive, tr_deps)
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

    def _get_transitives(self, transitive, content):
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
                        transitive = self._get_transitives(transitive, tr_deps)
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
                        transitive_list = self._get_transitives(
                            dependencies, transitive_list, direct_dep, trans)
                    parsed_json["deps"] = transitive_list
                    resolved.append(parsed_json)
            dep['_resolved'] = resolved
            details.append(dep)
        result.append({"details": details})
        final["result"] = result
        return final

    def _get_transitives(self, data, transitive, suffix, trans):
        """Scan the golang transitive deps."""
        for line in data:
            pref, suff = line.strip().split(" ")
            if pref == suffix and suff not in trans:
                trans.append(suff)
                parsed_json = self._parse_string(suff)
                transitive.append(parsed_json)
                transitive = self._get_transitives(data, transitive, suff, trans)
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
    def _clean_dependencies(dependencies: str) -> list:
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
