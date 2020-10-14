"""Definition of a class to find dependencies from an input manifest file."""

from f8a_utils.tree_generator import \
    MavenDependencyTreeGenerator as MvnTree, \
    NpmDependencyTreeGenerator as NpmTree, \
    PypiDependencyTreeGenerator as PyTree, \
    GolangDependencyTreeGenerator as GoTree


def get_dependency_tree_generator(eco):
    """Get Dependency Tree class.

    :param eco: Ecosystem
    :return: func. to execute.
    """
    func_dict = {
        "npm": NpmTree,
        "maven": MvnTree,
        "pypi": PyTree,
        "golang": GoTree,
    }
    assert eco in func_dict, "Ecosystem not supported."
    return func_dict.get(eco)


class DependencyFinder():
    """Implementation of methods to find dependencies from manifest file."""

    @staticmethod
    def scan_and_find_dependencies(ecosystem, manifests, show_transitive):
        """Scan the dependencies files to fetch transitive deps."""
        if type(show_transitive) is not bool:
            show_transitive = show_transitive == "true"
        dependency_tree_generator = get_dependency_tree_generator(ecosystem)()
        return dependency_tree_generator.get_dependencies(manifests, show_transitive)

    @staticmethod
    def clean_version(version):
        """Clean Version."""
        # TODO: Remove caller from Component Analyses for Golang.
        return GoTree.clean_version(version)
