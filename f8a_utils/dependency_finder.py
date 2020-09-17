"""Definition of a class to find dependencies from an input manifest file."""

import json
import semver


class DependencyFinder():
    """Implementation of methods to find dependencies from manifest file."""

    @staticmethod
    def scan_and_find_dependencies(ecosystem, manifests, show_transitive):
        """Scan the dependencies files to fetch transitive deps."""
        show_transitive = show_transitive == "true"
        deps = dict()
        if ecosystem == "npm":
            deps = DependencyFinder.get_npm_dependencies(ecosystem, manifests, show_transitive)
        elif ecosystem == "pypi":
            deps = DependencyFinder.get_pypi_dependencies(ecosystem, manifests)
        elif ecosystem == "maven":
            deps = DependencyFinder.get_maven_dependencies(ecosystem, manifests, show_transitive)
        elif ecosystem == "golang":
            deps = DependencyFinder.get_golang_dependencies(ecosystem, manifests, show_transitive)
        return deps

    @staticmethod
    def get_maven_dependencies(ecosystem, manifests, show_transitive):
        """Scan the maven dependencies files to fetch transitive deps."""
        deps = {}
        result = []
        details = []
        direct = []
        for manifest in manifests:
            dep = {
                "ecosystem": ecosystem,
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
                    parsed_json = DependencyFinder._parse_string(suffix)
                    if prefix == module and suffix not in direct and parsed_json['scope'] != 'test':
                        transitive = []
                        trans = []
                        direct.append(suffix)
                        if show_transitive is True:
                            transitive = DependencyFinder.get_maven_transitives(data,
                                                                                transitive,
                                                                                suffix,
                                                                                trans)
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

    @staticmethod
    def get_maven_transitives(data, transitive, suffix, trans):
        """Scan the maven dependencies files to fetch transitive deps."""
        for line in data.split("\n"):
            if suffix in line:
                line = line.replace('"', '')
                line = line.replace(' ;', '')
                pref, suff = line.strip().split(" -> ")
                parsed_json = DependencyFinder._parse_string(suff)
                if pref == suffix and suff not in trans and parsed_json['scope'] != 'test':
                    trans.append(suff)
                    tmp_json = {
                        "package": parsed_json['groupId'] + ":" + parsed_json['artifactId'],
                        "version": parsed_json['version']
                    }
                    transitive.append(tmp_json)
                    transitive = DependencyFinder.get_maven_transitives(data,
                                                                        transitive,
                                                                        suff,
                                                                        trans)
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

    @staticmethod
    def get_npm_dependencies(ecosystem, manifests, show_transitive):
        """Scan the npm dependencies files to fetch transitive deps."""
        deps = {}
        result = []
        details = []
        for manifest in manifests:
            dep = {
                "ecosystem": ecosystem,
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
                                transitive = DependencyFinder.get_npm_transitives(transitive,
                                                                                  tr_deps)
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

    @staticmethod
    def get_npm_transitives(transitive, content):
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
                        transitive = DependencyFinder.get_npm_transitives(transitive, tr_deps)
        return transitive

    @staticmethod
    def get_pypi_dependencies(ecosystem, manifests):
        """Scan the pypi dependencies files to fetch transitive deps."""
        result = []
        details = []
        deps = {}
        for manifest in manifests:
            dep = {
                "ecosystem": ecosystem,
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

    @staticmethod
    def get_golang_dependencies(ecosystem, manifests, show_transitive):
        """Check Go Lang Dependencies."""
        details = []
        final = {}
        result = []
        for manifest in manifests:
            dep = {
                "ecosystem": ecosystem,
                "manifest_file_path": manifest['filepath'],
                "manifest_file": manifest['filename']
            }
            resolved = []
            direct_dep_list = []
            dependencies = DependencyFinder.clean_golang_dependencies(manifest['content'])
            for dependency in dependencies:
                # Find out Direct Dependencies listed against Module Package.
                prefix, direct_dep = dependency.strip().split(" ")
                if '@' not in prefix and (direct_dep not in direct_dep_list):
                    # Only Module Packages have no @ in Prefix.
                    parsed_json = DependencyFinder.parse_go_string(direct_dep)
                    transitive_list = []
                    trans = []
                    if show_transitive:
                        transitive_list = DependencyFinder.get_go_transitives(
                            dependencies, transitive_list, direct_dep, trans)
                    parsed_json["deps"] = transitive_list
                    resolved.append(parsed_json)
            dep['_resolved'] = resolved
            details.append(dep)
        result.append({"details": details})
        final["result"] = result
        return final

    @staticmethod
    def get_go_transitives(data, transitive, suffix, trans):
        """Scan the golang transitive deps."""
        for line in data:
            pref, suff = line.strip().split(" ")
            if pref == suffix and suff not in trans:
                trans.append(suff)
                parsed_json = DependencyFinder.parse_go_string(suff)
                transitive.append(parsed_json)
                transitive = DependencyFinder.get_go_transitives(data, transitive, suff, trans)
        return transitive

    @staticmethod
    def parse_go_string(deps_string):
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

        a['is_semver'], a['version'] = DependencyFinder.clean_version(a['given_version'])
        return a

    @staticmethod
    def clean_golang_dependencies(dependencies: str) -> list:
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
