import configparser
import json
import os
import subprocess
import sys
import textwrap
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter, _HelpAction
from typing import Any, Dict, List, MutableMapping, Optional, Tuple, Union

import giturlparse
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
    ARCH,
    CONTAINS_DEFAULT_SUBSTITUTER,
    CURRENT_NETRC_FILE,
    CURRENT_SUBSTITUTERS,
    CURRENT_TRUSTED_PUBLIC_KEYS,
    K_FRAMEWORK_BINARY_CACHE,
    K_FRAMEWORK_BINARY_CACHE_NAME,
    K_FRAMEWORK_CACHE,
    K_FRAMEWORK_PUBLIC_KEY,
    USER_IS_TRUSTED,
    ask_install_substituters,
    get_extra_substituters_from_flake,
    install_substituters,
    nix,
    nix_detach,
    set_netrc_file,
)
from .package import (
    AVAILABLE,
    ConcretePackage,
    Follows,
    GithubPackage,
    LocalPackage,
    PackageMetadata,
    PackageName,
    PackageVersion,
)

console = Console(theme=Theme({'markdown.code': 'green'}))

KUP_DIR = os.path.split(os.path.abspath(__file__))[0]  # i.e. /path/to/dir/

available_packages: list[GithubPackage] = [
    GithubPackage('runtimeverification', 'kup', PackageName('kup')),
    GithubPackage('runtimeverification', 'k', PackageName('k')),
    GithubPackage('runtimeverification', 'avm-semantics', PackageName('kavm')),
    GithubPackage('runtimeverification', 'evm-semantics', PackageName('kevm')),
    GithubPackage('runtimeverification', 'plutus-core-semantics', PackageName('kplutus')),
    GithubPackage('runtimeverification', 'mir-semantics', PackageName('kmir')),
    GithubPackage('runtimeverification', 'kontrol', PackageName('kontrol')),
    GithubPackage('runtimeverification', 'haskell-backend', PackageName('kore-exec')),
    GithubPackage('runtimeverification', 'haskell-backend', PackageName('kore-rpc')),
    GithubPackage('runtimeverification', 'hs-backend-booster', PackageName('kore-rpc-booster'), 'main'),
    GithubPackage('runtimeverification', 'pyk', PackageName('pyk')),
]


# Load any private packages
for config_path in BaseDirectory.load_config_paths('kup'):
    if os.path.exists(os.path.join(config_path, 'user_packages.ini')):
        config = configparser.ConfigParser()

        config.read(os.path.join(config_path, 'user_packages.ini'))
        for pkg in config.sections():
            substituters = (
                [s.strip() for s in config[pkg]['substituters'].split(' ')] if 'substituters' in config[pkg] else []
            )
            public_keys = (
                [k.strip() for k in config[pkg]['public_keys'].split(' ')] if 'public_keys' in config[pkg] else []
            )

            available_packages.append(
                GithubPackage(
                    config[pkg]['org'],
                    config[pkg]['repo'],
                    PackageName.parse(config[pkg]['package']),
                    config[pkg]['branch'] if 'branch' in config[pkg] else None,
                    (config[pkg]['ssh+git'].lower() == 'true') if 'ssh+git' in config[pkg] else False,
                    config[pkg]['github-access-token'] if 'github-access-token' in config[pkg] else None,
                    substituters,
                    public_keys,
                )
            )


packages: Dict[str, GithubPackage] = {}
installed_packages: List[str] = []
pinned_package_cache: Dict[str, str] = {}

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
        path, git_token_options = package.repo_path_with_access()
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


def lookup_available_package(raw_name: str) -> Optional[GithubPackage]:
    for p in available_packages:
        name_prefix = f'packages.{ARCH}.{p.package_name.base}'
        if raw_name == name_prefix:
            return GithubPackage(
                p.org,
                p.repo,
                PackageName(p.package_name.base),
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
            return GithubPackage(
                p.org,
                p.repo,
                PackageName(p.package_name.base, ext),
                p.branch,
                p.ssh_git,
                p.access_token,
                p.substituters,
                p.public_keys,
            )
    return None


def reload_packages(load_versions: bool = True) -> None:
    global packages, installed_packages, pinned_package_cache

    pinned = requests.get(f'https://app.cachix.org/api/v1/cache/{K_FRAMEWORK_BINARY_CACHE_NAME}/pin')
    if pinned.ok:
        pinned_package_cache = {r['name']: r['lastRevision']['storePath'] for r in pinned.json()}

    if os.path.exists(f'{os.getenv("HOME")}/.nix-profile/manifest.json'):
        manifest_file = open(f'{os.getenv("HOME")}/.nix-profile/manifest.json')
        manifest = json.loads(manifest_file.read())['elements']
        manifest_file.close()
    else:
        manifest = []

    pinned_package_cache_reverse = {v: k for k, v in pinned_package_cache.items()}
    packages = {}
    for idx, m in enumerate(manifest):
        if 'attrPath' in m and m['attrPath']:
            available_package = lookup_available_package(m['attrPath'])
            if available_package is not None:
                repo_path, _ = available_package.repo_path_with_access()
                if 'url' in m and m['url'].startswith(repo_path):
                    packages[available_package.package_name.base] = ConcretePackage.parse(
                        m['url'], available_package, idx, load_versions
                    )
                elif 'originalUrl' in m and m['originalUrl'].startswith('git+file://'):
                    packages[available_package.package_name.base] = LocalPackage(
                        available_package,
                        available_package.package_name,
                        m['originalUrl'].removeprefix('git+file://'),
                        index=idx,
                    )
        elif m['storePaths'][0] in pinned_package_cache_reverse:
            split = pinned_package_cache_reverse[m['storePaths'][0]].split('#')
            url, attr_path = split[0], split[1]
            available_package = lookup_available_package(attr_path)
            if available_package is not None:
                packages[available_package.package_name.base] = ConcretePackage.parse(
                    url, available_package, idx, load_versions
                )

    installed_packages = [p.package_name.base for p in packages.values()]
    for available_package in available_packages:
        if available_package.package_name.base not in installed_packages:
            packages[available_package.package_name.base] = available_package


def highlight_row(condition: bool, xs: List[str]) -> List[str]:
    if condition:
        return [f'\033[92m{x}\033[0m' for x in xs]
    else:
        return xs


def list_package(package_name: str, show_inputs: bool) -> None:
    reload_packages()
    if package_name != 'all':
        if package_name not in packages.keys():
            rich.print(
                f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        listed_package = packages[package_name]

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
                    f'github:{listed_package.org}/{listed_package.repo}/{c["sha"]}#{listed_package.package_name}'
                    in pinned_package_cache.keys(),
                )
                for c in commits.json()
                if not c['commit']['message'].startswith("Merge remote-tracking branch 'origin/develop'")
            ]

            installed_packages_sha = {p.commit for p in packages.values() if type(p) == ConcretePackage}

            table_data = [['Version \033[92m(installed)\033[0m', 'Commit', 'Message', 'Cached']] + [
                highlight_row(
                    p.sha in installed_packages_sha,
                    [
                        p.tag if p.tag else '',
                        p.sha[:7],
                        textwrap.shorten(p.message, width=50, placeholder='...'),
                        '  ✅' if p.cached else '',
                    ],
                )
                for p in all_releases
            ]
            table = SingleTable(table_data)
            print(table.table)
    else:
        table_data = [['Package name (alias)', 'Installed version', 'Status'],] + [
            [
                str(PackageName(alias, p.package_name.ext).pretty_name),
                f'{p.commit}{" (" + p.tag + ")" if p.tag else ""}' if type(p) == ConcretePackage else '',
                p.status if type(p) == ConcretePackage else AVAILABLE,
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


def mk_override_args(package: GithubPackage, overrides: List[List[str]]) -> List[str]:
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
                f"❗ [red]'[green]{input}[/]' is not a valid input of the package '[green]{package.package_name.base}[/]'.\n"
                f"[/]To see the valid inputs, run '[blue]kup list {package.package_name.base} --inputs[/]'"
            )
            sys.exit(1)

        if type(possible_input) == PackageMetadata:
            repo = possible_input.repo
            git_path, _ = GithubPackage('runtimeverification', repo, PackageName('')).repo_path_with_access(
                version_or_path
            )
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


def install_package(
    package_name: PackageName,
    package_version: Optional[str],
    package_overrides: List[List[str]],
    verbose: bool,
    refresh: bool,
) -> None:
    reload_packages()
    if package_name.base not in packages:
        rich.print(
            f"❗ [red]The package '[green]{package_name.base}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return

    package = packages[package_name.base].concrete(package_version, package_name.ext)
    _, git_token_options = package.concrete_repo_path_with_access
    overrides = mk_override_args(package, package_overrides)

    if not overrides and package.uri in pinned_package_cache:
        rich.print(f" ⌛ Fetching cached version of '[green]{package_name.pretty_name}[/]' ...")
        nix(
            ['copy', '--from', K_FRAMEWORK_BINARY_CACHE, pinned_package_cache[package.uri]],
            verbose=verbose,
        )
        if package_name.base in installed_packages:
            nix(['profile', 'remove', str(package.index)], is_install=False)
        nix(
            ['profile', 'install', pinned_package_cache[package.uri]],
            verbose=verbose,
        )
    else:
        rich.print(f" ⌛ Building '[green]{package_name.pretty_name}[/]' ...")
        # we first attempt to build the package before deleting the old one form the profile, to avoid
        # a situation where we delete the old package and then fail to build the new one. This is
        # especially awkward when updating kup
        nix(
            ['build', package.uri, '--no-link'] + overrides + git_token_options,
            extra_substituters=package.substituters,
            extra_public_keys=package.public_keys,
            verbose=verbose,
            refresh=refresh,
        )
        if package_name.base in installed_packages:
            nix(['profile', 'remove', str(package.index)], is_install=False)
        nix(
            ['profile', 'install', package.uri] + overrides + git_token_options,
            extra_substituters=package.substituters,
            extra_public_keys=package.public_keys,
            verbose=verbose,
        )

    verb = 'updated' if package_name.base in installed_packages else 'installed'
    display_version = f' ({package_version})' if package_version else ' (master)'
    rich.print(
        f" ✅ Successfully {verb} '[green]{package_name.base}[/]' version [blue]{package.uri}{display_version}[/]."
    )


def uninstall_package(package_name: str) -> None:
    reload_packages(load_versions=False)
    if package_name not in packages.keys():
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if package_name not in installed_packages:
        rich.print(f"❗ The package '[green]{package_name}[/]' is not currently installed.")
        return

    if package_name == 'kup' and len(installed_packages) > 1:
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
            return uninstall_package(package_name)
    package = packages[package_name]
    if type(package) == ConcretePackage or type(package) == LocalPackage:
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
    uri: str,
    package_name: PackageName,
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
                    package_name,
                    branch,
                    ssh_git=False,
                    access_token=github_access_token,
                )
                path, git_token_options = new_package.repo_path_with_access()
                nix(
                    ['flake', 'metadata', path, '--json'] + git_token_options,
                    is_install=False,
                    exit_on_error=False,
                )
            else:
                rich.print('Detected a private repository without a GitHub access token, using git+ssh...')
                new_package = GithubPackage(org, repo, package_name, branch, ssh_git=True)
                path, git_token_options = new_package.repo_path_with_access()
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
                    f'     [green] kup add {uri}/main {package_name.pretty_name}\n'
                )
            sys.exit(1)

        substituters, trusted_public_keys = get_extra_substituters_from_flake(path, git_token_options)
        config_path = BaseDirectory.save_config_path('kup')
        user_packages_config_path = os.path.join(config_path, 'user_packages.ini')
        config = configparser.ConfigParser()
        if config_path and os.path.exists(user_packages_config_path):
            config.read(user_packages_config_path)

        config[package_name.base] = {
            'org': new_package.org,
            'repo': new_package.repo,
            'package': new_package.package_name.pretty_name,
            'ssh+git': str(new_package.ssh_git),
            'substituters': ' '.join(substituters),
            'public_keys': ' '.join(trusted_public_keys),
        }

        if new_package.branch:
            config[package_name.base]['branch'] = new_package.branch

        if new_package.access_token:
            rich.print(f'✅ The GitHub access token will be saved to {user_packages_config_path}.')
            config[package_name.base]['github-access-token'] = new_package.access_token

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

        install_substituters(package_name.base, substituters_to_add, trusted_public_keys_to_add)

        if strict:
            nix(
                ['eval', new_package.uri, '--json'] + git_token_options,
                is_install=False,
                extra_substituters=substituters,
                extra_public_keys=trusted_public_keys,
            )

        with open(user_packages_config_path, 'w') as configfile:
            config.write(configfile)

        rich.print(
            f"✅ Successfully added new package '[green]{package_name.pretty_name}[/]'. Configuration written to {user_packages_config_path}."
        )

    else:
        rich.print(f"❗ The URI '[red]{uri}[/]' is invalid.\n" "   The correct format is '[green]org/repo[/]'.")


def publish_package(cache: str, uri_or_path_with_package_name: str, keep_days: Optional[int] = None) -> None:
    split = uri_or_path_with_package_name.split('#')
    if len(split) == 2:
        uri_or_path = split[0]
        package_name = split[1]
    else:
        rich.print('❗ [red]Invalid URI!')
        sys.exit(1)
    if os.path.isdir(uri_or_path):
        uri = uri_or_path
        try:
            output = subprocess.check_output(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=uri_or_path,
            )
            git_url = giturlparse.parse(output.decode('utf8').strip())
            owner = git_url.owner
            repo = git_url.name
            result = nix(['flake', 'metadata', uri_or_path, '--json'], is_install=False)
        except Exception:
            rich.print('❗ [red]Could not get package metadata!')
            sys.exit(1)
        meta = json.loads(result)
        if 'rev' in meta['locked']:
            rev = meta['locked']['rev']
        else:
            rich.print('❗ [red]Repository is dirty, aborting!')
            sys.exit(1)
    elif uri_or_path.startswith('github:'):
        try:
            result = nix(['flake', 'metadata', uri_or_path, '--json'], is_install=False)
        except Exception:
            rich.print('❗ [red]Could not get package metadata!')
            sys.exit(1)
        meta = json.loads(result)
        print(meta['locked'])
        if 'rev' in meta['locked']:
            rev = meta['locked']['rev']
        else:
            rich.print('❗ [red]Repository is dirty, aborting!')
            sys.exit(1)
        owner = meta['locked']['owner']
        repo = meta['locked']['repo']
        uri = f'github:{owner}/{repo}/{rev}'
    else:
        rich.print('❗ [red]Unsupported URI!')
        sys.exit(1)
    cache_key = f'github:{owner}/{repo}/{rev}#{PackageName(package_name)}'
    try:
        result = nix(['build', f'{uri}#{PackageName(package_name)}', '--no-link', '--json'])
        build_meta = json.loads(result)
    except Exception:
        rich.print('❗ [red]Could not build package!')
        sys.exit(1)
    if len(build_meta) == 1 and 'outputs' in build_meta[0] and 'out' in build_meta[0]['outputs']:
        nix_store_path = build_meta[0]['outputs']['out']
    else:
        rich.print('❗ [red]Could not find out path for package!')
        sys.exit(1)

    subprocess.call(['cachix', 'push', cache, nix_store_path])
    pin_args = ['cachix', 'pin', cache, cache_key, nix_store_path] + (
        ['--keep-days', str(keep_days)] if keep_days else []
    )
    subprocess.call(pin_args)


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

    uninstall = subparser.add_parser('uninstall', help="remove the given package from the user's PATH")
    uninstall.add_argument('package', type=str)
    uninstall.add_argument('--verbose', action='store_true', help='verbose output from nix')

    shell = subparser.add_parser(
        'shell', help='add the selected package to the current shell (temporary)', add_help=False, parents=[shared_args]
    )
    shell.add_argument('-h', '--help', action=_HelpShellAction)

    subparser.add_parser('doctor', help='check if kup is installed correctly')

    add = subparser.add_parser('add', help='add a private package to kup', add_help=False)
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

    publish = subparser.add_parser('publish', help='push a package to a cachix cache')
    publish.add_argument('cache', type=str)
    publish.add_argument('uri', type=str)
    publish.add_argument('--keep-days', type=int, help='keep package cached for N days')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
    elif 'help' in args and args.help:
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
    elif args.command == 'publish':
        publish_package(args.cache, args.uri, args.keep_days)
    else:
        package_name = PackageName.parse(args.package)

        if args.command == 'list':
            list_package(package_name.base, args.inputs)

        elif args.command == 'install':
            install_package(package_name, args.version, args.override, args.verbose, args.refresh)
        elif args.command == 'uninstall':
            uninstall_package(package_name.base)
        elif args.command == 'add':
            add_new_package(
                args.uri,
                package_name,
                args.github_access_token,
                {repo: key for [repo, key] in args.cache_access_token} if args.cache_access_token else {},
                args.strict,
            )
        elif args.command == 'shell':
            reload_packages(load_versions=False)
            if package_name.base not in packages.keys():
                rich.print(
                    f"❗ [red]The package '[green]{package_name.pretty_name}[/]' does not exist.\n"
                    "[/]Use '[blue]kup list[/]' to see all the available packages."
                )
                return
            if package_name.base in installed_packages:
                rich.print(
                    f"❗ [red]The package '[green]{package_name.pretty_name}[/]' is currently installed and thus cannot be temporarily added to the PATH.\n"
                    f"[/]Use:\n * '[blue]kup update {package_name.pretty_name} ...[/]' to replace the installed version or\n * '[blue]kup remove {package_name.base}[/]' to remove the installed version and then re-run this command"
                )
                return

            package = packages[package_name.base].concrete(args.version, package_name.ext)
            _, git_token_options = package.concrete_repo_path_with_access

            if not args.override and package.uri in pinned_package_cache:
                rich.print(f" ⌛ Fetching cached version of '[green]{package_name.pretty_name}[/]' ...")
                nix(
                    ['copy', '--from', K_FRAMEWORK_BINARY_CACHE, pinned_package_cache[package.uri]],
                    verbose=args.verbose,
                )
                nix_detach(
                    ['shell', pinned_package_cache[package.uri]],
                    verbose=args.verbose,
                )
            else:
                rich.print(f" ⌛ Building '[green]{package_name.pretty_name}[/]' ...")
                overrides = mk_override_args(package, args.override)
                nix_detach(
                    ['shell', package.uri] + overrides + git_token_options,
                    extra_substituters=package.substituters,
                    extra_public_keys=package.public_keys,
                    verbose=args.verbose,
                    refresh=args.refresh,
                )


if __name__ == '__main__':
    main()
