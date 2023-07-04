import configparser
import json
import os
import sys
import textwrap
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter, _HelpAction
from typing import Any, Dict, List, Optional, Tuple

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
from .package import ConcretePackage, GithubPackage, PackageVersion

console = Console(theme=Theme({'markdown.code': 'green'}))

KUP_DIR = os.path.split(os.path.abspath(__file__))[0]  # i.e. /path/to/dir/

INSTALLED = '🟢 \033[92minstalled\033[0m'
AVAILABLE = '🔵 \033[94mavailable\033[0m'
UPDATE = '🟠 \033[93mnewer version available\033[0m'
LOCAL = '\033[3mlocal checkout\033[0m'

available_packages: Dict[str, GithubPackage] = {
    'kup': GithubPackage('runtimeverification', 'kup', 'kup'),
    'k': GithubPackage('runtimeverification', 'k', 'k'),
    'kavm': GithubPackage('runtimeverification', 'avm-semantics', 'kavm'),
    'kevm': GithubPackage('runtimeverification', 'evm-semantics', 'kevm'),
    'kplutus': GithubPackage('runtimeverification', 'plutus-core-semantics', 'kplutus'),
    'kore-exec': GithubPackage('runtimeverification', 'haskell-backend', 'kore:exe:kore-exec'),
    'kore-rpc': GithubPackage('runtimeverification', 'haskell-backend', 'kore:exe:kore-rpc'),
    'pyk': GithubPackage('runtimeverification', 'pyk', 'pyk'),
    'booster': GithubPackage('runtimeverification', 'hs-backend-booster', 'booster', 'main'),
}

# Load any private packages
for config_path in BaseDirectory.load_config_paths('kup'):
    if os.path.exists(os.path.join(config_path, 'user_packages.ini')):
        config = configparser.ConfigParser()

        config.read(os.path.join(config_path, 'user_packages.ini'))
        for pkg_name in config.sections():
            substituters = (
                [s.strip() for s in config[pkg_name]['substituters'].split(' ')]
                if 'substituters' in config[pkg_name]
                else []
            )
            public_keys = (
                [k.strip() for k in config[pkg_name]['public_keys'].split(' ')]
                if 'public_keys' in config[pkg_name]
                else []
            )

            available_packages[pkg_name] = GithubPackage(
                config[pkg_name]['org'],
                config[pkg_name]['repo'],
                config[pkg_name]['package'],
                config[pkg_name]['branch'] if 'branch' in config[pkg_name] else None,
                (config[pkg_name]['ssh+git'].lower() == 'true') if 'ssh+git' in config[pkg_name] else False,
                config[pkg_name]['github-access-token'] if 'github-access-token' in config[pkg_name] else None,
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


# walk all the inputs and their inputs and collect only the ones pointing to runtimeverification repos
def process_input(nodes: dict, key: str, override: bool = False) -> dict:
    if (
        'original' in nodes[key]
        and 'owner' in nodes[key]['original']
        and nodes[key]['original']['owner'] == 'runtimeverification'
    ):
        repo = nodes[key]['original']['repo']
        rev = nodes[key]['locked']['rev']
        if 'inputs' not in nodes[key]:
            return {key: {'repo': repo, 'org': 'runtimeverification', 'rev': rev}}
        else:
            inputs: dict = {}
            for key_input, path in nodes[key]['inputs'].items():
                if type(path) != list:
                    inputs = inputs | process_input(nodes, path)
                elif len(path) == 0:
                    continue
                else:
                    last = path[-1]
                    if (
                        'original' in nodes[last]
                        and 'owner' in nodes[last]['original']
                        and nodes[last]['original']['owner'] == 'runtimeverification'
                    ):
                        inputs[key_input] = {'follows': path}

            return {key: {'repo': repo, 'org': 'runtimeverification', 'rev': rev, 'inputs': inputs}}

    elif override:
        if 'inputs' not in nodes[key]:
            return {}
        else:
            inputs = {}
            for key_input, path in nodes[key]['inputs'].items():
                if type(path) != list:
                    inputs = inputs | process_input(nodes, path)
                elif len(path) == 0:
                    continue
                else:
                    last = path[-1]
                    if (
                        'original' in nodes[last]
                        and 'owner' in nodes[last]['original']
                        and nodes[last]['original']['owner'] == 'runtimeverification'
                    ):
                        inputs[key_input] = {'follows': path}
            return {key: {'inputs': inputs}}
    else:
        return {}


def get_package_inputs(name: str, package: GithubPackage) -> dict:
    try:
        path, git_token_options = mk_github_repo_path(package)
        result = nix(['flake', 'metadata', path, '--json'] + git_token_options, is_install=False)
    except Exception:
        return {}
    meta = json.loads(result)
    root = meta['locks']['root']

    return {name: process_input(meta['locks']['nodes'], root, True)[root]}


def print_package_tree(inputs: dict, key: str, root: Any = None) -> None:
    rev = (
        f" - github:{inputs[key]['org']}/{inputs[key]['repo']} [green]{inputs[key]['rev'][:7]}[/]"
        if 'rev' in inputs[key]
        else ''
    )
    follows = (' - follows [green]' + '/'.join(inputs[key]['follows'])) if 'follows' in inputs[key] else ''
    if root is None:
        n = Tree('Inputs:')
    else:
        n = Tree(f'{key}{rev}{follows}')
        root.add(n)
    if 'inputs' in inputs[key]:
        for k in inputs[key]['inputs'].keys():
            print_package_tree(inputs[key]['inputs'], k, n)

    if root is None:
        rich.print(n)


# Computes all proper paths and "follows" paths.
# When the user calls `kup shell <package> --override <path> ...`,
# we most likely want the `<path>`` to be a proper path and not a follows path.
# We should emit a warning only however, since the user may know better and
# only wants to override the follow path
def flatten_inputs_paths(inputs: dict) -> Tuple[List[Tuple[List[str], str]], List[Tuple[List[str], List[str]]]]:
    flattened_proper = []
    flattened_follow = []
    for k in inputs.keys():
        if 'follows' in inputs[k]:
            flattened_follow.append(([k], inputs[k]['follows']))
        elif 'inputs' in inputs[k]:
            flattened_proper_k, flattened_follow_k = flatten_inputs_paths(inputs[k]['inputs'])
            flattened_proper.extend(
                [([k] + path, repo) for path, repo in flattened_proper_k]
                if len(flattened_proper_k) > 0
                else [([k], inputs[k]['repo'])]
            )
            flattened_follow.extend([([k] + path, proper_path) for path, proper_path in flattened_follow_k])
    return flattened_proper, flattened_follow


def reload_packages(load_versions: bool = True) -> None:
    global packages, installed_packages

    if os.path.exists(f'{os.getenv("HOME")}/.nix-profile/manifest.json'):
        manifest_file = open(f'{os.getenv("HOME")}/.nix-profile/manifest.json')
        manifest = json.loads(manifest_file.read())['elements']
        manifest_file.close()
    else:
        manifest = []

    packages = {}
    available_packages_lookup = {f'packages.{SYSTEM}.{p.package}': (key, p) for key, p in available_packages.items()}

    for idx, m in enumerate(manifest):
        if 'attrPath' in m and m['attrPath'] in available_packages_lookup:
            (name, available_package) = available_packages_lookup[m['attrPath']]
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
                packages[name] = ConcretePackage(
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
                packages[name] = ConcretePackage(
                    available_package.org,
                    available_package.repo,
                    available_package.package,
                    LOCAL,
                    index=idx,
                    branch=available_package.branch,
                    ssh_git=available_package.ssh_git,
                )

    installed_packages = list(packages.keys())
    for pkg_name in available_packages:
        if pkg_name not in installed_packages:
            available_package = available_packages[pkg_name]
            packages[pkg_name] = ConcretePackage(
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


def list_package(package_name: str, show_inputs: bool) -> None:
    reload_packages()
    if package_name != 'all':
        if package_name not in available_packages.keys():
            rich.print(
                f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        listed_package = available_packages[package_name]

        if show_inputs:
            inputs = get_package_inputs(package_name, listed_package)
            print_package_tree(inputs, package_name)
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
        table_data = [
            ['Package', 'Installed version', 'Status'],
        ] + [[name, f'{p.version}{" (" + p.tag + ")" if p.tag else ""}', p.status] for name, p in packages.items()]
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


def mk_override_args(package_name: str, package: GithubPackage, overrides: List[List[str]]) -> List[str]:
    if not overrides:
        return []
    inputs = get_package_inputs(package_name, package)
    valid_inps, overrides_inps = flatten_inputs_paths(inputs[package_name]['inputs'])
    valid_inputs = {'/'.join(path): repo for path, repo in valid_inps}
    overrides_inputs = [('/'.join(i), '/'.join(j)) for (i, j) in overrides_inps]

    nix_overrides = []
    for [input, version_or_path] in overrides:
        override_input = next((override for (i, override) in overrides_inputs if i == input), None)
        if input not in valid_inputs:
            if override_input:
                rich.print(
                    f"⚠️ [yellow]The input '[green]{input}[/]' you are trying to override follows '[green]{override_input}[/]'.\n"
                    f"[/]You may want to call this command with '[blue]--override {override_input}[/]' instead."
                )
            else:
                rich.print(
                    f"❗ [red]'[green]{input}[/]' is not a valid input of the package '[green]{package_name}[/]'.\n"
                    f"[/]To see the valid inputs, run '[blue]kup list {package_name} --inputs[/]'"
                )
                sys.exit(1)
        repo = valid_inputs[input] if not override_input else valid_inputs[override_input]
        path, _ = mk_path_package(GithubPackage('runtimeverification', repo, ''), version_or_path)
        nix_overrides.append('--override-input')
        nix_overrides.append(input)
        nix_overrides.append(path)
        nix_overrides.append('--update-input')
        nix_overrides.append(input)
    return nix_overrides


def install_or_update_package(
    package_name: str,
    package_version: Optional[str],
    package_overrides: List[List[str]],
    verbose: bool,
    refresh: bool,
    is_update: bool = False,
) -> None:
    reload_packages()
    if package_name not in available_packages:
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if is_update and package_name not in installed_packages:
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' is not currently installed.\n"
            f"[/]Use '[blue]kup install {package_name}[/]' to install the latest version."
        )
        return

    if package_name in installed_packages:
        package: GithubPackage = packages[package_name]
    else:
        package = available_packages[package_name]

    path, git_token_options = mk_path_package(package, package_version)
    overrides = mk_override_args(package_name, package, package_overrides) if package_overrides else []

    if type(package) is ConcretePackage:
        if package.immutable or package_version or package_overrides:
            # we first attempt to build the package before deleting the old one form the profile, to avoid
            # a situation where we delete the old package and then fail to build the new one. This is
            # especially awkward when updating kup
            nix(
                ['build', f'{path}#{package.package}', '--no-link'] + overrides + git_token_options,
                extra_substituters=package.substituters,
                extra_public_keys=package.public_keys,
                verbose=verbose,
                refresh=refresh,
            )
            nix(['profile', 'remove', str(package.index)], is_install=False)
            nix(
                ['profile', 'install', f'{path}#{package.package}'] + overrides + git_token_options,
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
            ['profile', 'install', f'{path}#{package.package}'] + overrides + git_token_options,
            extra_substituters=package.substituters,
            extra_public_keys=package.public_keys,
            verbose=verbose,
            refresh=refresh,
        )

    verb = 'updated' if package_name in installed_packages else 'installed'
    rich.print(f" ✅ Successfully {verb} '[green]{package_name}[/]'.")


def remove_package(package_name: str) -> None:
    reload_packages(load_versions=False)
    if package_name not in available_packages.keys():
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
            return remove_package(package_name)
    package = packages[package_name]
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
    package: str,
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
            'package': new_package.package,
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
            sys.exit(0)
    if args.command == 'list':
        list_package(args.package, args.inputs)
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
    elif args.command in {'install', 'update'}:
        install_or_update_package(
            args.package, args.version, args.override, args.verbose, args.refresh, is_update=args.command == 'update'
        )
    elif args.command == 'remove':
        remove_package(args.package)
    elif args.command == 'add':
        add_new_package(
            args.name,
            args.uri,
            args.package,
            args.github_access_token,
            {repo: key for [repo, key] in args.cache_access_token} if args.cache_access_token else {},
            args.strict,
        )
    elif args.command == 'shell':
        reload_packages(load_versions=False)
        if args.package not in available_packages.keys():
            rich.print(
                f"❗ [red]The package '[green]{args.package}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        temporary_package = available_packages[args.package]
        path, git_token_options = mk_path_package(temporary_package, args.version)
        overrides = mk_override_args(args.package, temporary_package, args.override)
        nix_detach(
            ['shell', f'{path}#{temporary_package.package}'] + overrides + git_token_options,
            extra_substituters=temporary_package.substituters,
            extra_public_keys=temporary_package.public_keys,
            verbose=args.verbose,
            refresh=args.refresh,
        )


if __name__ == '__main__':
    main()
