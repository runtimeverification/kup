from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Union


@dataclass(frozen=True)
class PackageName:
    base: str
    ext: tuple[str, ...]

    def __init__(self, base: str, ext: Iterable[str] = ()):
        object.__setattr__(self, 'base', base)
        object.__setattr__(self, 'ext', tuple(ext))

    def __str__(self) -> str:
        return '.'.join([self.base] + list(self.ext))

    @staticmethod
    def parse(name: str) -> 'PackageName':
        s = name.split('.')
        return PackageName(s[0], s[1:])


class GithubPackage:
    __slots__ = ['org', 'repo', 'package', 'branch', 'ssh_git', 'access_token', 'substituters', 'public_keys']

    def __init__(
        self,
        org: str,
        repo: str,
        package: PackageName,
        branch: Optional[str] = None,
        ssh_git: bool = False,
        access_token: Optional[str] = None,
        substituters: Optional[list[str]] = None,
        public_keys: Optional[list[str]] = None,
    ):
        self.org = org
        self.repo = repo
        self.package = package
        self.branch = branch
        self.ssh_git = ssh_git
        self.access_token = access_token
        self.substituters = substituters if substituters is not None else []
        self.public_keys = public_keys if public_keys is not None else []


class ConcretePackage(GithubPackage):
    __slots__ = [
        'org',
        'repo',
        'package',
        'status',
        'version',
        'tag',
        'immutable',
        'index',
        'branch',
        'ssh_git',
        'access_token',
        'substituters',
        'public_keys',
    ]

    def __init__(
        self,
        org: str,
        repo: str,
        package: PackageName,
        status: str,
        version: str = '-',
        immutable: bool = True,
        index: int = -1,
        branch: Optional[str] = None,
        ssh_git: bool = False,
        access_token: Optional[str] = None,
        substituters: Optional[list[str]] = None,
        public_keys: Optional[list[str]] = None,
        tag: Optional[str] = None,
    ):
        self.version = version
        self.tag = tag
        self.status = status
        self.immutable = immutable
        self.index = index
        super().__init__(org, repo, package, branch, ssh_git, access_token, substituters, public_keys)


class PackageVersion:
    __slots__ = ['sha', 'message', 'tag', 'merged_at']

    def __init__(self, sha: str, message: str, tag: Optional[str], merged_at: str):
        self.sha = sha
        self.message = message
        self.tag = tag
        self.merged_at = merged_at


class PackageMetadata:
    __slots__ = ['repo', 'rev', 'org', 'inputs']

    def __init__(self, repo: str, rev: str, org: str, inputs: Mapping[str, Union['PackageMetadata', 'Follows']]):
        self.repo = repo
        self.rev = rev
        self.org = org
        self.inputs = inputs


class Follows:
    __slots__ = ['follows']

    def __init__(self, follows: list[str]):
        self.follows = follows
