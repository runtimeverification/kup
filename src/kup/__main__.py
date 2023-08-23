import configparser
import json
import os
import sys
import textwrap
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter, _HelpAction
from typing import Any, Dict, Iterable, List, MutableMapping, Optional, Tuple, Union

import requests
import rich
from rich.console import Console
from rich.markdown import Markdown
from rich.theme import Theme
from rich.tree import Tree
from terminaltables import SingleTable  # type: ignore
from tinynetrc import Netrc
from xdg import BaseDirectory

from .nix import (
    CONTAINS_DEFAULT_SUBSTITUTER,
    CURRENT_NETRC_FILE,
    CURRENT_SUBSTITUTERS,
    CURRENT_TRUSTED_PUBLIC_KEYS,
    K_FRAMEWORK_CACHE,
    K_FRAMEWORK_PUBLIC_KEY,
    SYSTEM,
    USER_IS_TRUSTED,
    ask_install_substituters,
    get_extra_substituters_from_flake,
    install_substituters,
    nix,
    nix_detach,
    set_netrc_file,
)
from .package import ConcretePackage, Follows, GithubPackage, PackageMetadata, PackageName, PackageVersion

console = Console(theme=Theme({'markdown.code': 'green'}))

KUP_DIR = os.path.split(os.path.abspath(__file__))[0]  # i.e. /path/to/dir/

INSTALLED = '🟢 \033[92minstalled\033[0m'
AVAILABLE = '🔵 \033[94mavailable\033[0m'
UPDATE = '🟠 \033[93mnewer version available\033[0m'
LOCAL = '\033[3mlocal checkout\033[0m'

available_packages: Dict[str, GithubPackage] = {
    'kup': GithubPackage('runtimeverification', 'kup', PackageName('kup')),
    'k': GithubPackage('runtimeverification', 'k', PackageName('k')),
    'kavm': GithubPackage('runtimeverification', 'avm-semantics', PackageName('kavm')),
    'kevm': GithubPackage('runtimeverification', 'evm-semantics', PackageName('kevm')),
    'kplutus': GithubPackage('runtimeverification', 'plutus-core-semantics', PackageName('kplutus')),
    'kmir': GithubPackage('runtimeverification', 'mir-semantics', PackageName('kmir')),
    'kore-exec': GithubPackage('runtimeverification', 'haskell-backend', PackageName('kore:exe:kore-exec')),
    'kore-rpc': GithubPackage('runtimeverification', 'haskell-backend', PackageName('kore:exe:kore-rpc')),
    'kore-rpc-booster': GithubPackage(
        'runtimeverification', 'hs-backend-booster', PackageName('kore-rpc-booster'), 'main'
    ),
    'pyk': GithubPackage('runtimeverification', 'pyk', PackageName('pyk')),
}

# Load any private packages
for config_path in BaseDirectory.load_config_paths('kup'):
    if os.path.exists(os.path.join(config_path, 'user_packages.ini')):
        config = configparser.ConfigParser()

        config.read(os.path.join(config_path, 'user_packages.ini'))
        for pkg_alias in config.sections():
            substituters = (
                [s.strip() for s in config[pkg_alias]['substituters'].split(' ')]
                if 'substituters' in config[pkg_alias]
                else []
            )
            public_keys = (
                [k.strip() for k in config[pkg_alias]['public_keys'].split(' ')]
                if 'public_keys' in config[pkg_alias]
                else []
            )

            available_packages[pkg_alias] = GithubPackage(
                config[pkg_alias]['org'],
                config[pkg_alias]['repo'],
                PackageName.parse(config[pkg_alias]['package']),
                config[pkg_alias]['branch'] if 'branch' in config[pkg_alias] else None,
                (config[pkg_alias]['ssh+git'].lower() == 'true') if 'ssh+git' in config[pkg_alias] else False,
                config[pkg_alias]['github-access-token'] if 'github-access-token' in config[pkg_alias] else None,
                substituters,
                public_keys,
            )

packages: Dict[str, ConcretePackage] = {}
installed_packages: List[str] = []


def mk_github_repo_path(package: GithubPackage, override_branch: Optional[str] = None) -> Tuple[str, List[str]]:
    if package.ssh_git:
        ref = package.branch if package.branch else 'master'
        branch = f'?ref={ref}'
        if override_branch:
            branch = f'?ref={override_branch}' if not is_sha1(override_branch) else f'?rev={override_branch}'
        return f'git+ssh://git@github.com/{package.org}/{package.repo}{branch}', []
    else:
        if override_branch:
            branch = '/' + override_branch
        elif package.branch:
            branch = '/' + package.branch
        else:
            branch = ''
        access = ['--option', 'access-tokens', f'github.com={package.access_token}'] if package.access_token else []
        return f'github:{package.org}/{package.repo}{branch}', access


def check_package_version(p: GithubPackage, current_url: str) -> str:
    path, git_token_options = mk_github_repo_path(p)
    result = nix(['flake', 'metadata', path, '--json'] + git_token_options, is_install=False)
    meta = json.loads(result)

    if meta['url'] == current_url:
        return INSTALLED
    else:
        return UPDATE


# This walk function walks the metadata returned by nix, where inputs can either point to a final node in
# the root of the tree or an indirection/pointer path through the tree
def walk_path_nix_meta(nodes: dict, current_node_id: str, path: list[str]) -> str:
    if len(path) == 0:
        return current_node_id
    else:
        next_node_path_or_id = nodes[current_node_id]['inputs'][path[0]]
        if type(next_node_path_or_id) == str:
            return walk_path_nix_meta(nodes, next_node_path_or_id, path[1:])
        else:
            next_node_id = walk_path_nix_meta(nodes, next_node_path_or_id[0], next_node_path_or_id[1:])
            return walk_path_nix_meta(nodes, next_node_id, path[1:])


# walk all the inputs recursively and collect only the ones pointing to runtimeverification repos
def parse_package_metadata(nodes: dict, current_node_id: str, root_level: bool = False) -> Union[PackageMetadata, None]:
    if not (
        'original' in nodes[current_node_id]
        and 'owner' in nodes[current_node_id]['original']
        and nodes[current_node_id]['original']['owner'] == 'runtimeverification'
    ):
        if not root_level:
            return None
        else:
            repo = ''
            rev = ''
            org = 'runtimeverification'
    else:
        repo = nodes[current_node_id]['original']['repo']
        rev = nodes[current_node_id]['locked']['rev']
        org = 'runtimeverification'

    raw_inputs = nodes[current_node_id]['inputs'].items() if 'inputs' in nodes[current_node_id] else []
    inputs: MutableMapping[str, Union[PackageMetadata, Follows]] = {}

    for input_key, input_path_or_node_id in raw_inputs:
        if type(input_path_or_node_id) == str:  # direct input
            input_node_id = input_path_or_node_id
            i = parse_package_metadata(nodes, input_node_id)
            if i is not None:
                inputs[input_key] = i
        elif len(input_path_or_node_id) > 0:
            input_node_id = walk_path_nix_meta(nodes, input_path_or_node_id[0], input_path_or_node_id[1:])
            if (
                'original' in nodes[input_node_id]
                and 'owner' in nodes[input_node_id]['original']
                and nodes[input_node_id]['original']['owner'] == 'runtimeverification'
            ):
                inputs[input_key] = Follows(input_path_or_node_id)

    return PackageMetadata(repo, rev, org, inputs)


def get_package_metadata(package: GithubPackage) -> PackageMetadata:
    try:
        path, git_token_options = mk_github_repo_path(package)
        result = nix(['flake', 'metadata', path, '--json'] + git_token_options, is_install=False)
    except Exception:
        rich.print('❗ [red]Could not get package metadata!')
        sys.exit(1)
    meta = json.loads(result)
    root_id = meta['locks']['root']

    res = parse_package_metadata(meta['locks']['nodes'], root_id, True)
    if not res:
        rich.print('❗ [red]Could not parse package metadata!')
        sys.exit(1)
    else:
        return res


# build a rich.Tree of inputs for the given package metadata
def package_metadata_tree(p: Union[PackageMetadata, Follows], lbl: Union[str, None] = None) -> Tree:
    if lbl is None:
        tree = Tree('Inputs:')
    else:
        rev = f' - github:{p.org}/{p.repo}' if type(p) == PackageMetadata else ''
        follows = (' - follows [green]' + '/'.join(p.follows)) if type(p) == Follows else ''
        tree = Tree(f'{lbl}{rev}{follows}')
    if type(p) == PackageMetadata:
        for k in p.inputs.keys():
            tree.add(package_metadata_tree(p.inputs[k], k))
    return tree


def lookup_available_package(raw_name: str) -> Optional[Tuple[str, GithubPackage]]:
    for alias, p in available_packages.items():
        name_prefix = f'packages.{SYSTEM}.{p.package.base}'
        if raw_name == name_prefix:
            return alias, GithubPackage(
                p.org,
                p.repo,
                PackageName(p.package.base),
                p.branch,
                p.ssh_git,
                p.access_token,
                p.substituters,
                p.public_keys,
            )
        name_prefix = name_prefix + '.'
        if raw_name.startswith(name_prefix):
            ext_str = raw_name.removeprefix(name_prefix)
            ext = ext_str.strip().split('.')
            return alias, GithubPackage(
                p.org,
                p.repo,
                PackageName(p.package.base, ext),
                p.branch,
                p.ssh_git,
                p.access_token,
                p.substituters,
                p.public_keys,
            )
    return None


def reload_packages(load_versions: bool = True) -> None:
    global packages, installed_packages

    if os.path.exists(f'{os.getenv("HOME")}/.nix-profile/manifest.json'):
        manifest_file = open(f'{os.getenv("HOME")}/.nix-profile/manifest.json')
        manifest = json.loads(manifest_file.read())['elements']
        manifest_file.close()
    else:
        manifest = []

    packages = {}

    for idx, m in enumerate(manifest):
        if 'attrPath' in m and m['attrPath']:
            res = lookup_available_package(m['attrPath'])
            if res is not None:
                alias, available_package = res
                repo_path, _ = mk_github_repo_path(available_package)
                if 'originalUrl' in m and m['originalUrl'].startswith(repo_path):
                    if available_package.ssh_git:
                        version = m['url'].split('&rev=')[1]
                        immutable = 'rev=' in m['originalUrl'] or 'ref=' in m['originalUrl']
                        tag = None
                    else:
                        version = m['url'].removeprefix(f'github:{available_package.org}/{available_package.repo}/')
                        maybe_tag = m['originalUrl'].removeprefix(
                            f'github:{available_package.org}/{available_package.repo}'
                        )
                        if len(maybe_tag) > 1:
                            immutable = True
                            tag = maybe_tag.removeprefix('/')
                        else:
                            immutable = False
                            tag = None

                    status = check_package_version(available_package, m['url']) if load_versions else ''
                    packages[alias] = ConcretePackage(
                        available_package.org,
                        available_package.repo,
                        available_package.package,
                        status,
                        version,
                        immutable,
                        idx,
                        available_package.branch,
                        available_package.ssh_git,
                        tag=tag,
                    )
                else:
                    packages[alias] = ConcretePackage(
                        available_package.org,
                        available_package.repo,
                        available_package.package,
                        LOCAL,
                        index=idx,
                        branch=available_package.branch,
                        ssh_git=available_package.ssh_git,
                    )

    installed_packages = [p.package.base for p in packages.values()]
    for pkg_alias, available_package in available_packages.items():
        if available_package.package.base not in installed_packages:
            packages[pkg_alias] = ConcretePackage(
                available_package.org,
                available_package.repo,
                available_package.package,
                AVAILABLE,
                '',
                branch=available_package.branch,
                ssh_git=available_package.ssh_git,
            )


def highlight_row(condition: bool, xs: List[str]) -> List[str]:
    if condition:
        return [f'\033[92m{x}\033[0m' for x in xs]
    else:
        return xs


def list_package(package_alias: str, show_inputs: bool) -> None:
    reload_packages()
    if package_alias != 'all':
        if package_alias not in available_packages.keys():
            rich.print(
                f"❗ [red]The package '[green]{package_alias}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        listed_package = available_packages[package_alias]

        if show_inputs:
            inputs = get_package_metadata(listed_package)
            rich.print(package_metadata_tree(inputs))
        else:
            auth = {'Authorization': f'Bearer {listed_package.access_token}'} if listed_package.access_token else {}
            tags = requests.get(
                f'https://api.github.com/repos/{listed_package.org}/{listed_package.repo}/tags', headers=auth
            )
            if not tags.ok:
                rich.print('❗ Listing versions is unsupported for private packages accessed over SSH.')
                return
            commits = requests.get(
                f'https://api.github.com/repos/{listed_package.org}/{listed_package.repo}/commits', headers=auth
            )
            tagged_releases = {t['commit']['sha']: t for t in tags.json()}
            all_releases = [
                PackageVersion(
                    c['sha'],
                    c['commit']['message'],
                    tagged_releases[c['sha']]['name'] if c['sha'] in tagged_releases else None,
                    c['commit']['committer']['date'],
                )
                for c in commits.json()
                if not c['commit']['message'].startswith("Merge remote-tracking branch 'origin/develop'")
            ]

            installed_packages_sha = {p.version for p in packages.values()}

            table_data = [['Version \033[92m(installed)\033[0m', 'Commit', 'Message']] + [
                highlight_row(
                    p.sha in installed_packages_sha,
                    [p.tag if p.tag else '', p.sha[:7], textwrap.shorten(p.message, width=50, placeholder='...')],
                )
                for p in all_releases
            ]
            table = SingleTable(table_data)
            print(table.table)
    else:
        table_data = [['Package name (alias)', 'Installed version', 'Status'],] + [
            [
                str(PackageName(alias, p.package.ext)),
                f'{p.version}{" (" + p.tag + ")" if p.tag else ""}',
                p.status,
            ]
            for alias, p in packages.items()
        ]
        table = SingleTable(table_data)
        print(table.table)


def is_sha1(maybe_sha: str) -> bool:
    if len(maybe_sha) != 40:
        return False
    try:
        int(maybe_sha, 16)
    except ValueError:
        return False
    return True


def mk_path_package(package: GithubPackage, version_or_path: Optional[str]) -> Tuple[str, List[str]]:
    if version_or_path and os.path.isdir(version_or_path):
        return os.path.abspath(version_or_path), []
    else:
        return mk_github_repo_path(package, version_or_path)


def walk_package_metadata(
    node: Union[PackageMetadata, Follows], path: list[str]
) -> Union[PackageMetadata, Follows, None]:
    if len(path) == 0:
        return node
    else:
        if type(node) == PackageMetadata and path[0] in node.inputs:
            return walk_package_metadata(node.inputs[path[0]], path[1:])
        else:
            return None


def mk_override_args(package_alias: str, package: GithubPackage, overrides: List[List[str]]) -> List[str]:
    if not overrides:
        return []
    inputs = get_package_metadata(package)

    nix_overrides = []
    for [input, version_or_path] in overrides:
        input_path = input.split('/')
        possible_input = walk_package_metadata(inputs, input_path)
        if possible_input is not None and type(possible_input) == Follows:
            follows_path = '/'.join(possible_input.follows)
            rich.print(
                f"⚠️ [yellow]The input '[green]{input}[/]' you are trying to override follows '[green]{follows_path}[/]'.\n"
                f"[/]You may want to call this command with '[blue]--override {follows_path}[/]' instead."
            )
            input_path = possible_input.follows
            possible_input = walk_package_metadata(inputs, input_path)
        if possible_input is None:
            rich.print(
                f"❗ [red]'[green]{input}[/]' is not a valid input of the package '[green]{package_alias}[/]'.\n"
                f"[/]To see the valid inputs, run '[blue]kup list {package_alias} --inputs[/]'"
            )
            sys.exit(1)

        if type(possible_input) == PackageMetadata:
            repo = possible_input.repo
            git_path, _ = mk_path_package(GithubPackage('runtimeverification', repo, PackageName('')), version_or_path)
            nix_overrides.append('--override-input')
            nix_overrides.append('/'.join(input_path))
            nix_overrides.append(git_path)
            nix_overrides.append('--update-input')
            nix_overrides.append('/'.join(input_path))
        else:
            rich.print(
                f"❗ [red]Internal error when accessing package metadata. Expected '[green]{input}[/]' to be a direct input.[/]"
            )
            sys.exit(1)
    return nix_overrides


def install_or_update_package(
    package_alias: str,
    package_ext: Iterable[str],
    package_version: Optional[str],
    package_overrides: List[List[str]],
    verbose: bool,
    refresh: bool,
    is_update: bool = False,
) -> None:
    reload_packages()
    if package_alias not in available_packages:
        rich.print(
            f"❗ [red]The package '[green]{package_alias}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if is_update and package_alias not in installed_packages:
        rich.print(
            f"❗ [red]The package '[green]{package_alias}[/]' is not currently installed.\n"
            f"[/]Use '[blue]kup install {package_alias}[/]' to install the latest version."
        )
        return

    if package_alias in installed_packages:
        package: GithubPackage = packages[package_alias]
    else:
        package = available_packages[package_alias]

    path, git_token_options = mk_path_package(package, package_version)
    overrides = mk_override_args(package_alias, package, package_overrides) if package_overrides else []

    # we build the actual package name from the base name of the found package plus any extensions passed to this function
    package_name = PackageName(package.package.base, package_ext)

    if type(package) is ConcretePackage:
        if package.immutable or package_version or package_overrides or package_ext != package.package.ext:
            # we first attempt to build the package before deleting the old one form the profile, to avoid
            # a situation where we delete the old package and then fail to build the new one. This is
            # especially awkward when updating kup
            nix(
                ['build', f'{path}#{package_name}', '--no-link'] + overrides + git_token_options,
                extra_substituters=package.substituters,
                extra_public_keys=package.public_keys,
                verbose=verbose,
                refresh=refresh,
            )
            nix(['profile', 'remove', str(package.index)], is_install=False)
            nix(
                ['profile', 'install', f'{path}#{package_name}'] + overrides + git_token_options,
                extra_substituters=package.substituters,
                extra_public_keys=package.public_keys,
                verbose=verbose,
            )
        else:
            nix(
                ['profile', 'upgrade', str(package.index)] + git_token_options,
                extra_substituters=package.substituters,
                extra_public_keys=package.public_keys,
                verbose=verbose,
                refresh=refresh,
            )
    else:
        nix(
            ['profile', 'install', f'{path}#{package_name}'] + overrides + git_token_options,
            extra_substituters=package.substituters,
            extra_public_keys=package.public_keys,
            verbose=verbose,
            refresh=refresh,
        )

    verb = 'updated' if package_alias in installed_packages else 'installed'
    display_version = f' ({package_version})' if package_version else ' (master)'
    rich.print(
        f" ✅ Successfully {verb} '[green]{package_alias}[/]' to version [blue]{package_name}{display_version}[/]."
    )


def remove_package(package_alias: str) -> None:
    reload_packages(load_versions=False)
    if package_alias not in available_packages.keys():
        rich.print(
            f"❗ [red]The package '[green]{package_alias}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if package_alias not in installed_packages:
        rich.print(f"❗ The package '[green]{package_alias}[/]' is not currently installed.")
        return

    if package_alias == 'kup' and len(installed_packages) > 1:
        rich.print(
            "⚠️ [yellow]You are about to remove '[green]kup[/]' "
            'with other K framework packages still installed.\n'
            '[/]Are you sure you want to continue? \[y/N]'  # noqa: W605
        )

        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}

        choice = input().lower()
        if choice in no:
            return
        elif choice in yes:
            pass
        else:
            sys.stdout.write("Please respond with '[y]es' or '[n]o'\n")
            # in case the user selected a wrong option we want to short-circuit and
            # not try to remove kup twice
            return remove_package(package_alias)
    package = packages[package_alias]
    nix(['profile', 'remove', str(package.index)], is_install=False)


def ping_nix_store(url: str, access_token: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    auth = {'Authorization': f'Bearer {access_token}'} if access_token else {}

    if 'cachix.org' in url:
        cache_name = (
            url.replace('https://', '').replace('http://', '').replace('.cachix.org', '').replace('/', '').strip()
        )
        cache_meta = requests.get(f'https://app.cachix.org/api/v1/cache/{cache_name}', headers=auth)
        if cache_meta.ok:
            res = cache_meta.json()
            reachable = True
            valid_token = None if res['isPublic'] else access_token
        else:
            reachable = False
            valid_token = None
    else:
        cache_meta = requests.get(f'{url}/nix-cache-info', headers=auth)
        reachable = cache_meta.ok
        valid_token = access_token if reachable else None

    return reachable, valid_token


def check_github_api_accessible(org: str, repo: str, access_token: Optional[str]) -> bool:
    auth = {'Authorization': f'Bearer {access_token}'} if access_token else {}
    commits = requests.get(f'https://api.github.com/repos/{org}/{repo}/commits', headers=auth)
    return commits.ok


def add_new_package(
    name: str,
    uri: str,
    package: PackageName,
    github_access_token: Optional[str],
    cache_access_tokens: Dict[str, str],
    strict: bool,
) -> None:
    if '/' in uri:
        org, rest = uri.split('/', 1)
        if '/' in rest:
            repo, branch = rest.split('/', 1)
        else:
            repo = rest
            branch = None

        github_api_accessible = check_github_api_accessible(org, repo, github_access_token)
        try:
            if github_api_accessible:
                new_package = GithubPackage(
                    org,
                    repo,
                    package,
                    branch,
                    ssh_git=False,
                    access_token=github_access_token,
                )
                path, git_token_options = mk_github_repo_path(new_package)
                nix(
                    ['flake', 'metadata', path, '--json'] + git_token_options,
                    is_install=False,
                    exit_on_error=False,
                )
            else:
                rich.print('Detected a private repository without a GitHub access token, using git+ssh...')
                new_package = GithubPackage(org, repo, package, branch, ssh_git=True)
                path, git_token_options = mk_github_repo_path(new_package)
                nix(
                    ['flake', 'metadata', path, '--json'] + git_token_options,
                    is_install=False,
                    exit_on_error=False,
                )
        except Exception:
            rich.print(
                '❗ [red]Could not find the specified package.[/]\n\n'
                '   Make sure that you entered the repository correctly and ensure you have set up the right SSH keys if your repository is private.\n\n'
                '   Alternatively, try using the [blue]--github-access-token[/] option to specify a GitHub personal access token.\n'
                '   For more information on GitHub personal access tokens, see:\n\n'
                '     https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token'
            )
            if not branch:
                rich.print(
                    '   If your repository has a [blue]main[/] branch instead of [blue]master[/], try\n\n'
                    f'     [green] kup add {name} {uri}/main {package}\n'
                )
            sys.exit(1)

        path, git_token_options = mk_github_repo_path(new_package)

        substituters, trusted_public_keys = get_extra_substituters_from_flake(path, git_token_options)
        config_path = BaseDirectory.save_config_path('kup')
        user_packages_config_path = os.path.join(config_path, 'user_packages.ini')
        config = configparser.ConfigParser()
        if config_path and os.path.exists(user_packages_config_path):
            config.read(user_packages_config_path)

        config[name] = {
            'org': new_package.org,
            'repo': new_package.repo,
            'package': str(new_package.package),
            'ssh+git': str(new_package.ssh_git),
            'substituters': ' '.join(substituters),
            'public_keys': ' '.join(trusted_public_keys),
        }

        if new_package.branch:
            config[name]['branch'] = new_package.branch

        if new_package.access_token:
            rich.print(f'✅ The GitHub access token will be saved to {user_packages_config_path}.')
            config[name]['github-access-token'] = new_package.access_token

        substituters_to_add = []
        trusted_public_keys_to_add = []

        for (s, pub_key) in zip(substituters, trusted_public_keys):
            if s in CURRENT_SUBSTITUTERS and pub_key in CURRENT_TRUSTED_PUBLIC_KEYS:
                pass

            reachable, access_token = ping_nix_store(s, cache_access_tokens.get(s, None))

            if not reachable:
                if s in cache_access_tokens:
                    rich.print(f"❗ [red]Could not access '[blue]{s}[/]' cache.[/]\n")
                    return
                # case when the cache is private but an access token has not been provided as an argument
                else:
                    rich.print(
                        f'ℹ️  The {s} binary cache appears to be private.\n'
                        'Please provide an auth token for this cache and press [enter]'
                    )
                    access_token = input()
                    reachable, access_token = ping_nix_store(s, access_token)
                    if not reachable:
                        rich.print(f"❗ [red]Could not access '[blue]{s}[/]' cache.[/]\n")
                        return
            if access_token:
                netrc_file = CURRENT_NETRC_FILE
                if not netrc_file:
                    netrc_file = os.path.join(config_path, 'netrc')
                    set_netrc_file(netrc_file)
                if not os.path.exists(netrc_file):
                    with open(netrc_file, 'a+'):
                        os.utime(netrc_file, None)
                netrc = Netrc(netrc_file)
                s_stripped = s.replace('https://', '').replace('http://', '').replace('/', '').strip()
                netrc[s_stripped]['password'] = access_token
                netrc.save()
                rich.print(f'✅ The access token for {s} was saved to {netrc_file}.')

            substituters_to_add.append(s)
            trusted_public_keys_to_add.append(pub_key)

        install_substituters(name, substituters_to_add, trusted_public_keys_to_add)

        if strict:
            nix(
                ['eval', f'{path}#{package}', '--json'] + git_token_options,
                is_install=False,
                extra_substituters=substituters,
                extra_public_keys=trusted_public_keys,
            )

        with open(user_packages_config_path, 'w') as configfile:
            config.write(configfile)

        rich.print(
            f"✅ Successfully added new package '[green]{name}[/]'. Configuration written to {user_packages_config_path}."
        )

    else:
        rich.print(f"❗ The URI '[red]{uri}[/]' is invalid.\n" "   The correct format is '[green]org/repo[/]'.")


def print_help(subcommand: str, parser: ArgumentParser) -> None:
    parser.print_help()
    print('')
    with open(os.path.join(KUP_DIR, f'{subcommand}-help.md'), 'r') as help_file:
        console.print(Markdown(help_file.read(), code_theme='emacs'))
    parser.exit()


class _HelpListAction(_HelpAction):
    def __call__(
        self, parser: ArgumentParser, namespace: Namespace, values: Any, option_string: Optional[str] = None
    ) -> None:
        print_help('list', parser)


class _HelpInstallAction(_HelpAction):
    def __call__(
        self, parser: ArgumentParser, namespace: Namespace, values: Any, option_string: Optional[str] = None
    ) -> None:
        print_help('install', parser)


class _HelpUpdateAction(_HelpAction):
    def __call__(
        self, parser: ArgumentParser, namespace: Namespace, values: Any, option_string: Optional[str] = None
    ) -> None:
        print_help('update', parser)


class _HelpShellAction(_HelpAction):
    def __call__(
        self, parser: ArgumentParser, namespace: Namespace, values: Any, option_string: Optional[str] = None
    ) -> None:
        print_help('shell', parser)


class _HelpAddAction(_HelpAction):
    def __call__(
        self, parser: ArgumentParser, namespace: Namespace, values: Any, option_string: Optional[str] = None
    ) -> None:
        print_help('add', parser)


def main() -> None:
    parser = ArgumentParser(
        description='The K Framework installer',
        prog='kup',
        formatter_class=RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
         additional information:
             For more detailed help for the different sub-commands, call
               kup {list,install,remove,update,shell} --help
         """
        ),
    )
    shared_args = ArgumentParser(add_help=False)
    shared_args.add_argument('package', type=str)
    shared_args.add_argument('--version', type=str, help='update the package to a custom version')
    shared_args.add_argument(
        '--override', type=str, nargs=2, action='append', help='override an input dependency of a package'
    )
    shared_args.add_argument('--verbose', '-v', default=False, action='store_true', help='verbose output from nix.')
    shared_args.add_argument(
        '--refresh', default=False, action='store_true', help='force a re-fetch when pulling from a GitHub branch'
    )
    subparser = parser.add_subparsers(dest='command')
    list = subparser.add_parser('list', help='show the active and installed K semantics', add_help=False)
    list.add_argument('package', nargs='?', default='all', type=str)
    list.add_argument('--inputs', action='store_true', help='show the input dependencies of the selected package')
    list.add_argument('-h', '--help', action=_HelpListAction)

    install = subparser.add_parser(
        'install', help='download and install the stated package', add_help=False, parents=[shared_args]
    )
    install.add_argument('-h', '--help', action=_HelpInstallAction)

    uninstall = subparser.add_parser('remove', help="remove the given package from the user's PATH")
    uninstall.add_argument('package', type=str)
    uninstall.add_argument('--verbose', action='store_true', help='verbose output from nix')

    update = subparser.add_parser(
        'update', help='update the package to the latest version', add_help=False, parents=[shared_args]
    )
    update.add_argument('-h', '--help', action=_HelpUpdateAction)

    shell = subparser.add_parser(
        'shell', help='add the selected package to the current shell (temporary)', add_help=False, parents=[shared_args]
    )
    shell.add_argument('-h', '--help', action=_HelpShellAction)

    subparser.add_parser('doctor', help='check if kup is installed correctly')

    add = subparser.add_parser('add', help='add a private package to kup', add_help=False)
    add.add_argument('name', type=str)
    add.add_argument('uri', type=str)
    add.add_argument('package', type=str)
    add.add_argument(
        '--github-access-token', type=str, help='provide an OAUTH token to connect to a private repository'
    )
    add.add_argument(
        '--cache-access-token',
        type=str,
        nargs=2,
        action='append',
        help='provide the url and access token to access a private Nix cache',
    )
    add.add_argument('--strict', action='store_true', help='check if the package being added exists')
    add.add_argument('-h', '--help', action=_HelpAddAction)

    args = parser.parse_args()

    if 'help' in args and args.help:
        with open(os.path.join(KUP_DIR, f'{args.command}-help.md'), 'r+') as help_file:
            console.print(Markdown(help_file.read(), code_theme='emacs'))
    elif args.command == 'doctor':
        trusted_check = '🟢' if USER_IS_TRUSTED else '🟠'
        substituter_check = '🟢' if CONTAINS_DEFAULT_SUBSTITUTER else ('🟢' if USER_IS_TRUSTED else '🔴')
        rich.print(
            f'\nUser is trusted                      {trusted_check}\n'
            f'K-framework substituter is set up    {substituter_check}\n'
        )
        if not USER_IS_TRUSTED and not CONTAINS_DEFAULT_SUBSTITUTER:
            print()
            ask_install_substituters('k-framework', [K_FRAMEWORK_CACHE], [K_FRAMEWORK_PUBLIC_KEY])
    else:
        alias_with_ext = PackageName.parse(args.package)
        alias, ext = alias_with_ext.base, alias_with_ext.ext

        if args.command == 'list':
            list_package(alias, args.inputs)

        elif args.command in {'install', 'update'}:
            install_or_update_package(
                alias, ext, args.version, args.override, args.verbose, args.refresh, is_update=args.command == 'update'
            )
        elif args.command == 'remove':
            remove_package(alias)
        elif args.command == 'add':
            add_new_package(
                args.name,
                args.uri,
                PackageName.parse(args.package),
                args.github_access_token,
                {repo: key for [repo, key] in args.cache_access_token} if args.cache_access_token else {},
                args.strict,
            )
        elif args.command == 'shell':
            reload_packages(load_versions=False)
            if alias not in available_packages.keys():
                rich.print(
                    f"❗ [red]The package '[green]{alias}[/]' does not exist.\n"
                    "[/]Use '[blue]kup list[/]' to see all the available packages."
                )
                return
            if alias in installed_packages:
                rich.print(
                    f"❗ [red]The package '[green]{alias}[/]' is currently installed and thus cannot be temporarily added to the PATH.\n"
                    "[/]Use:\n * '[blue]kup update {alias} ...[/]' to replace the installed version or\n * '[blue]kup remove {alias}[/]' to remove the installed version and then re-run this command"
                )
                return
            temporary_package = available_packages[alias]
            path, git_token_options = mk_path_package(temporary_package, args.version)
            overrides = mk_override_args(alias, temporary_package, args.override)
            # combine the actual package name with the possible extensions
            package_name = PackageName(temporary_package.package.base, ext)
            nix_detach(
                ['shell', f'{path}#{package_name}'] + overrides + git_token_options,
                extra_substituters=temporary_package.substituters,
                extra_public_keys=temporary_package.public_keys,
                verbose=args.verbose,
                refresh=args.refresh,
            )


if __name__ == '__main__':
    main()
