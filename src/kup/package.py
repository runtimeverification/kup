import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Union

import requests
from xdg import BaseDirectory

from .nix import ARCH, nix

INSTALLED = '🟢 \033[92minstalled\033[0m'
AVAILABLE = '🔵 \033[94mavailable\033[0m'
UPDATE = '🟠 \033[93mnewer version available\033[0m'
LOCAL = '\033[3mlocal checkout\033[0m'

tag_cache: Dict[str, Optional[str]] = {}

# Load any private packages
for config_path in BaseDirectory.load_config_paths('kup'):
    if os.path.exists(os.path.join(config_path, 'tag_cache')):
        with open(os.path.join(config_path, 'tag_cache'), 'r') as f:
            try:
                tag_cache = json.loads(f.read())
            except Exception:
                pass


def save_tags(tags: Dict[str, Optional[str]]) -> None:
    global tag_cache
    for config_path in BaseDirectory.load_config_paths('kup'):
        with open(os.path.join(config_path, 'tag_cache'), 'w') as f:
            tag_cache = tag_cache | tags
            f.write(json.dumps(tag_cache))


@dataclass(frozen=True)
class PackageName:
    base: str
    ext: tuple[str, ...]

    def __init__(self, base: str, ext: Iterable[str] = ()):
        object.__setattr__(self, 'base', base)
        object.__setattr__(self, 'ext', tuple(ext))

    def __str__(self) -> str:
        return '.'.join(['packages', ARCH, self.base] + list(self.ext))

    @property
    def pretty_name(self) -> str:
        return '.'.join([self.base] + list(self.ext))

    @staticmethod
    def parse(name: str) -> 'PackageName':
        s = name.split('.')
        return PackageName(s[0], s[1:])


class GithubPackage:
    __slots__ = ['org', 'repo', 'package_name', 'branch', 'ssh_git', 'access_token', 'substituters', 'public_keys']

    def __init__(
        self,
        org: str,
        repo: str,
        package_name: PackageName,
        branch: Optional[str] = None,
        ssh_git: bool = False,
        access_token: Optional[str] = None,
        substituters: Optional[list[str]] = None,
        public_keys: Optional[list[str]] = None,
    ):
        self.org = org
        self.repo = repo
        self.package_name = package_name
        self.branch = branch
        self.ssh_git = ssh_git
        self.access_token = access_token
        self.substituters = substituters if substituters is not None else []
        self.public_keys = public_keys if public_keys is not None else []

    def repo_path_with_access(self, override_branch_tag_commit_or_path: Optional[str] = None) -> Tuple[str, List[str]]:
        if override_branch_tag_commit_or_path and os.path.isdir(override_branch_tag_commit_or_path):
            return os.path.abspath(override_branch_tag_commit_or_path), []
        else:
            override_branch_commit_or_tag = override_branch_tag_commit_or_path
            if self.ssh_git:
                if override_branch_commit_or_tag:
                    branch_commit_or_tag = (
                        f'?ref={override_branch_commit_or_tag}'
                        if not is_sha1(override_branch_commit_or_tag)
                        else f'?rev={override_branch_commit_or_tag}'
                    )
                else:
                    ref = self.branch if self.branch else 'master'
                    branch_commit_or_tag = f'?ref={ref}'
                return f'git+ssh://git@github.com/{self.org}/{self.repo}{branch_commit_or_tag}', []
            else:
                if override_branch_commit_or_tag:
                    branch_commit_or_tag = '/' + override_branch_commit_or_tag
                elif self.branch:
                    branch_commit_or_tag = '/' + self.branch
                else:
                    branch_commit_or_tag = ''
                access = ['--option', 'access-tokens', f'github.com={self.access_token}'] if self.access_token else []
                return f'github:{self.org}/{self.repo}{branch_commit_or_tag}', access

    def url(self, override_branch_tag_or_commit: Optional[str] = None) -> str:
        path, git_token_options = self.repo_path_with_access(override_branch_tag_or_commit)
        result = nix(['flake', 'metadata', path, '--json'] + git_token_options, is_install=False, refresh=True)
        meta = json.loads(result)
        return meta['url']

    @property
    def uri(self) -> str:
        path, _ = self.repo_path_with_access()
        return f'{path}#{self.package_name}'

    @property
    def base_repo_path(self) -> str:
        return f'github:{self.org}/{self.repo}'

    def concrete(
        self, override_branch_tag_commit_or_path: Optional[str] = None, ext: Optional[Iterable[str]] = None
    ) -> Union['ConcretePackage', 'LocalPackage']:
        package_name = PackageName(self.package_name.base, ext) if ext else self.package_name
        if override_branch_tag_commit_or_path and os.path.isdir(override_branch_tag_commit_or_path):
            return LocalPackage(self, package_name, override_branch_tag_commit_or_path)
        else:
            url = self.url(override_branch_tag_commit_or_path)
            return ConcretePackage.parse(
                url,
                GithubPackage(
                    self.org,
                    self.repo,
                    package_name,
                    self.branch,
                    self.ssh_git,
                    self.access_token,
                    self.substituters,
                    self.public_keys,
                ),
                -1,
                False,
            )


def is_sha1(maybe_sha: str) -> bool:
    if len(maybe_sha) != 40:
        return False
    try:
        int(maybe_sha, 16)
    except ValueError:
        return False
    return True


def check_package_status(p: GithubPackage, current_url: str) -> str:
    if p.url() == current_url:
        return INSTALLED
    else:
        return UPDATE


class LocalPackage(GithubPackage):
    __slots__ = ['github_package', 'path', 'index']

    def __init__(
        self,
        github_package: GithubPackage,
        package_name: PackageName,
        path: str,
        index: Union[int, str] = -1,
    ):
        self.path = path
        self.index = index
        super().__init__(
            github_package.org,
            github_package.repo,
            package_name,
            github_package.branch,
            github_package.ssh_git,
            github_package.access_token,
            github_package.substituters,
            github_package.public_keys,
        )

    @property
    def concrete_repo_path_with_access(self) -> Tuple[str, List[str]]:
        return super().repo_path_with_access(self.path)

    @property
    def uri(self) -> str:
        path, _ = self.concrete_repo_path_with_access
        return f'{path}#{self.package_name}'

    def concrete(
        self, override_branch_tag_commit_or_path: Optional[str] = None, ext: Optional[Iterable[str]] = None
    ) -> Union['ConcretePackage', 'LocalPackage']:
        package_name = PackageName(self.package_name.base, ext) if ext else self.package_name
        if override_branch_tag_commit_or_path and os.path.isdir(override_branch_tag_commit_or_path):
            return LocalPackage(self, package_name, override_branch_tag_commit_or_path, self.index)
        else:
            url = self.url(override_branch_tag_commit_or_path)
            return ConcretePackage.parse(
                url,
                GithubPackage(
                    self.org,
                    self.repo,
                    package_name,
                    self.branch,
                    self.ssh_git,
                    self.access_token,
                    self.substituters,
                    self.public_keys,
                ),
                self.index,
                False,
            )


class ConcretePackage(GithubPackage):
    __slots__ = [
        'org',
        'repo',
        'package',
        'status',
        'commit',
        'tag',
        'index',
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
        commit: str,
        tag: Optional[str] = None,
        index: Union[int, str] = -1,
        ssh_git: bool = False,
        access_token: Optional[str] = None,
        substituters: Optional[list[str]] = None,
        public_keys: Optional[list[str]] = None,
    ):
        self.commit = commit
        self.status = status
        self.index = index
        self.tag = tag
        super().__init__(org, repo, package, None, ssh_git, access_token, substituters, public_keys)

    @property
    def concrete_repo_path_with_access(self) -> Tuple[str, List[str]]:
        return super().repo_path_with_access(self.commit)

    @property
    def uri(self) -> str:
        path, _ = self.concrete_repo_path_with_access
        return f'{path}#{self.package_name}'

    def concrete(
        self, override_branch_tag_commit_or_path: Optional[str] = None, ext: Optional[Iterable[str]] = None
    ) -> Union['ConcretePackage', 'LocalPackage']:
        package_name = PackageName(self.package_name.base, ext) if ext else self.package_name
        if override_branch_tag_commit_or_path and os.path.isdir(override_branch_tag_commit_or_path):
            return LocalPackage(self, package_name, override_branch_tag_commit_or_path, self.index)
        else:
            url = self.url(override_branch_tag_commit_or_path)
            return ConcretePackage.parse(
                url,
                GithubPackage(
                    self.org,
                    self.repo,
                    package_name,
                    self.branch,
                    self.ssh_git,
                    self.access_token,
                    self.substituters,
                    self.public_keys,
                ),
                self.index,
                False,
            )

    @staticmethod
    def parse(url: str, package: GithubPackage, idx: Union[int, str], load_versions: bool) -> 'ConcretePackage':
        global tag_cache
        if package.ssh_git:
            commit = url.split('&rev=')[1]
            tag = None
        else:
            commit = url.removeprefix(f'github:{package.org}/{package.repo}/')
            if commit in tag_cache:
                tag = tag_cache[commit]
            else:
                github_tags = requests.get(
                    f'https://api.github.com/repos/{package.org}/{package.repo}/tags',
                    headers={},
                )
                if github_tags.ok:
                    tagged_releases = {t['commit']['sha']: t['name'] for t in github_tags.json()}
                    if commit in tagged_releases:
                        save_tags(tagged_releases)
                        tag = tagged_releases[commit]
                    else:
                        save_tags({commit: None})
                        tag = None
                else:
                    tag = None
        status = check_package_status(package, url) if load_versions else ''
        return ConcretePackage(
            package.org,
            package.repo,
            package.package_name,
            status,
            commit,
            tag,
            idx,
            package.ssh_git,
        )


class PackageVersion:
    __slots__ = ['sha', 'message', 'tag', 'merged_at', 'cached']

    def __init__(self, sha: str, message: str, tag: Optional[str], merged_at: str, cached: bool):
        self.sha = sha
        self.message = message
        self.tag = tag
        self.merged_at = merged_at
        self.cached = cached


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
