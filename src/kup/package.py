from typing import Optional


class GithubPackage:
    __slots__ = ['org', 'repo', 'package', 'branch', 'private']

    def __init__(self, org: str, repo: str, package: str, branch: Optional[str] = None, private: bool = False):
        self.org = org
        self.repo = repo
        self.package = package
        self.branch = branch
        self.private = private


class ConcretePackage(GithubPackage):
    __slots__ = ['org', 'repo', 'package', 'status', 'version', 'immutable', 'index', 'branch', 'private']

    def __init__(
        self,
        org: str,
        repo: str,
        package: str,
        status: str,
        version: str = '-',
        immutable: bool = True,
        index: int = -1,
        branch: Optional[str] = None,
        private: bool = False,
    ):
        self.version = version
        self.status = status
        self.immutable = immutable
        self.index = index
        super().__init__(org, repo, package, branch, private)


class PackageVersion:
    __slots__ = ['sha', 'message', 'tag', 'merged_at']

    def __init__(self, sha: str, message: str, tag: Optional[str], merged_at: str):
        self.sha = sha
        self.message = message
        self.tag = tag
        self.merged_at = merged_at
