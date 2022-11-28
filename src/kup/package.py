from typing import Optional


class AvailablePackage:
    __slots__ = ['repo', 'package']

    def __init__(self, repo: str, package: str):
        self.repo = repo
        self.package = package


class ConcretePackage:
    __slots__ = ['repo', 'package', 'status', 'version', 'immutable', 'index']

    def __init__(
        self,
        repo: str,
        package: str,
        status: str,
        version: str = '-',
        immutable: bool = True,
        index: int = -1,
    ):
        self.repo = repo
        self.package = package
        self.version = version
        self.status = status
        self.immutable = immutable
        self.index = index


class PackageVersion:
    __slots__ = ['sha', 'message', 'tag', 'merged_at']

    def __init__(self, sha: str, message: str, tag: Optional[str], merged_at: str):
        self.sha = sha
        self.message = message
        self.tag = tag
        self.merged_at = merged_at
