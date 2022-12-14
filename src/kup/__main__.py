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
from xdg import BaseDirectory

from .nix import (
    CONTAINS_SUBSTITUTERS,
    K_FRAMEWORK_CACHE,
    K_FRAMEWORK_PUBLIC_KEY,
    SYSTEM,
    USER_IS_TRUSTED,
    install_substituter,
    nix,
    nix_detach,
)
from .package import ConcretePackage, GithubPackage, PackageVersion

console = Console(theme=Theme({'markdown.code': 'green'}))

KUP_DIR = os.path.split(os.path.abspath(__file__))[0]  # i.e. /path/to/dir/

INSTALLED = '🟢 \033[92minstalled\033[0m'
AVAILABLE = '🔵 \033[94mavailable\033[0m'
UPDATE = '🟠 \033[93mnewer version available\033[0m'
LOCAL = '\033[3mlocal checkout\033[0m'


available_packages: Dict[str, GithubPackage] = {
    'kup': GithubPackage('runtimeverification', 'kup', f'packages.{SYSTEM}.kup'),
    'k': GithubPackage('runtimeverification', 'k', f'packages.{SYSTEM}.k'),
    'kavm': GithubPackage('runtimeverification', 'avm-semantics', f'packages.{SYSTEM}.kavm'),
    'kevm': GithubPackage('runtimeverification', 'evm-semantics', f'packages.{SYSTEM}.kevm'),
    'kplutus': GithubPackage('runtimeverification', 'plutus-core-semantics', f'packages.{SYSTEM}.kplutus'),
    'kore-exec': GithubPackage('runtimeverification', 'haskell-backend', f'packages.{SYSTEM}.kore:exe:kore-exec'),
    'kore-rpc': GithubPackage('runtimeverification', 'haskell-backend', f'packages.{SYSTEM}.kore:exe:kore-rpc'),
    'pyk': GithubPackage('runtimeverification', 'pyk', f'packages.{SYSTEM}.pyk'),
}

# Load any private packages
for config_path in BaseDirectory.load_config_paths('kup'):
    if os.path.exists(os.path.join(config_path, 'user_packages.ini')):
        config = configparser.ConfigParser()

        config.read(os.path.join(config_path, 'user_packages.ini'))
        for pkg_name in config.sections():
            available_packages[pkg_name] = GithubPackage(
                config[pkg_name]['org'],
                config[pkg_name]['repo'],
                f'packages.{SYSTEM}.{config[pkg_name]["package"]}',
                config[pkg_name]['branch'] if 'branch' in config[pkg_name] else None,
                bool(config[pkg_name]['private']) if 'private' in config[pkg_name] else False,
                config[pkg_name]['github-access-token'] if 'github-access-token' in config[pkg_name] else None,
            )

packages: Dict[str, ConcretePackage] = {}
installed_packages: List[str] = []


def mk_github_repo_path(package: GithubPackage) -> Tuple[str, List[str]]:

    if package.private and not package.access_token:
        branch = f'?ref={package.branch}' if package.branch else ''
        # return f'git+https://github.com/{package.org}/{package.repo}/{branch}'
        return f'git+ssh://git@github.com/{package.org}/{package.repo}.git{branch}', []
    else:
        branch = '/' + package.branch if package.branch else ''
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
    available_packages_lookup = {p.package: (key, p) for key, p in available_packages.items()}

    for idx, m in enumerate(manifest):
        if 'attrPath' in m and m['attrPath'] in available_packages_lookup:
            (name, available_package) = available_packages_lookup[m['attrPath']]
            repo_path, _ = mk_github_repo_path(available_package)
            if 'originalUrl' in m and m['originalUrl'].startswith(repo_path):
                if available_package.private:
                    version = m['url'].split('&rev=')[1]
                    immutable = 'rev=' in m['originalUrl'] or 'ref=' in m['originalUrl']
                else:
                    version = m['url'].removeprefix(f'github:{available_package.org}/{available_package.repo}/')
                    immutable = (
                        len(m['originalUrl'].removeprefix(f'github:{available_package.org}/{available_package.repo}'))
                        > 1
                    )

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
                    available_package.private,
                )
            else:
                packages[name] = ConcretePackage(
                    available_package.org,
                    available_package.repo,
                    available_package.package,
                    LOCAL,
                    index=idx,
                    branch=available_package.branch,
                    private=available_package.private,
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
                private=available_package.private,
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
            if listed_package.private and not listed_package.access_token:
                rich.print('❗ Listing versions is unsupported for private packages accessed over SSH.')
                return
            auth = {'Authorization': f'Bearer {listed_package.access_token}'} if listed_package.access_token else {}
            tags = requests.get(
                f'https://api.github.com/repos/{listed_package.org}/{listed_package.repo}/tags', headers=auth
            )
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
        ] + [[name, p.version, p.status] for name, p in packages.items()]
        table = SingleTable(table_data)
        print(table.table)


def mk_path_package(package: GithubPackage, version_or_path: Optional[str]) -> Tuple[str, List[str]]:
    if version_or_path:
        if os.path.isdir(version_or_path):
            return os.path.abspath(version_or_path), []
        else:
            path, git_token_options = mk_github_repo_path(package)
            if package.private:
                rich.print('⚠️ [yellow]Only commit hashes are currently supported for private packages')
                rev = '&rev=' if package.branch else '?rev='
                return path + rev + version_or_path, git_token_options
            else:
                return path + '/' + version_or_path, git_token_options
    else:
        return mk_github_repo_path(package)


def mk_path(path: str, version_or_path: Optional[str]) -> str:
    if version_or_path:
        if os.path.isdir(version_or_path):
            return os.path.abspath(version_or_path)
        else:
            return path + '/' + version_or_path
    else:
        return path


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
        path = mk_path(f'github:runtimeverification/{repo}', version_or_path)
        nix_overrides.append('--override-input')
        nix_overrides.append(input)
        nix_overrides.append(path)
    return nix_overrides


def update_or_install_package(
    package_name: str,
    package: GithubPackage,
    version: Optional[str],
    package_overrides: List[List[str]],
) -> None:
    path, git_token_options = mk_path_package(package, version)

    if type(package) is ConcretePackage:
        if package.immutable or version or package_overrides:
            nix(['profile', 'remove', str(package.index)], is_install=False)
            overrides = mk_override_args(package_name, package, package_overrides) if package_overrides else []
            nix(['profile', 'install', f'{path}#{package.package}'] + overrides + git_token_options)
        else:
            nix(['profile', 'upgrade', str(package.index)] + git_token_options)
    else:
        overrides = mk_override_args(package_name, package, package_overrides) if package_overrides else []
        nix(['profile', 'install', f'{path}#{package.package}'] + overrides + git_token_options)


def install_package(package_name: str, package_version: Optional[str], package_overrides: List[List[str]]) -> None:
    reload_packages()
    if package_name not in available_packages.keys():
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if package_name in installed_packages and not package_version:
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' is already installed.\n"
            f"[/]Use '[blue]kup update {package_name}[/]' to update to the latest version."
        )
        return
    if package_name in installed_packages:
        package = packages[package_name]
        update_or_install_package(package_name, package, package_version, package_overrides)
    else:
        new_package = available_packages[package_name]
        update_or_install_package(package_name, new_package, package_version, package_overrides)
    rich.print(f" ✅ Successfully installed '[green]{package_name}[/]'.")


def update_package(package_name: str, package_version: Optional[str], package_overrides: List[List[str]]) -> None:
    reload_packages()
    if package_name not in available_packages.keys():
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
            "[/]Use '[blue]kup list[/]' to see all the available packages."
        )
        return
    if package_name not in installed_packages:
        rich.print(
            f"❗ [red]The package '[green]{package_name}[/]' is not currently installed.\n"
            f"[/]Use '[blue]kup install {package_name}[/]' to install the latest version."
        )
        return
    package = packages[package_name]
    if package.status == INSTALLED and not package_version:
        rich.print(f"The package '[green]{package_name}[/]' is up to date.")
        return

    update_or_install_package(package_name, package, package_version, package_overrides)
    rich.print(f" ✅ Successfully updated '[green]{package_name}[/]'.")


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
    subparser = parser.add_subparsers(dest='command')
    list = subparser.add_parser('list', help='show the active and installed K semantics', add_help=False)
    list.add_argument('package', nargs='?', default='all', type=str)
    list.add_argument('--inputs', action='store_true', help='show the input dependencies of the selected package')
    list.add_argument('-h', '--help', action=_HelpListAction)

    install = subparser.add_parser('install', help='download and install the stated package', add_help=False)
    install.add_argument('package', type=str)
    install.add_argument('--version', type=str, help='install a custom version of a package')
    install.add_argument(
        '--override', type=str, nargs=2, action='append', help='override an input dependency of a package'
    )
    install.add_argument('-h', '--help', action=_HelpInstallAction)

    uninstall = subparser.add_parser('remove', help="remove the given package from the user's PATH")
    uninstall.add_argument('package', type=str)

    update = subparser.add_parser('update', help='update the package to the latest version', add_help=False)
    update.add_argument('package', type=str)
    update.add_argument('--version', type=str, help='update the package to a custom version')
    update.add_argument(
        '--override', type=str, nargs=2, action='append', help='override an input dependency of a package'
    )
    update.add_argument('-h', '--help', action=_HelpUpdateAction)

    shell = subparser.add_parser(
        'shell', help='add the selected package to the current shell (temporary)', add_help=False
    )
    shell.add_argument('package', type=str)
    shell.add_argument('--version', type=str, help='temporarily install a custom version of a package')
    shell.add_argument(
        '--override', type=str, nargs=2, action='append', help='override an input dependency of a package'
    )
    shell.add_argument('-h', '--help', action=_HelpShellAction)

    subparser.add_parser('doctor', help='check if kup is installed correctly')

    add = subparser.add_parser('add', help='add a private package to kup', add_help=False)
    add.add_argument('name', type=str)
    add.add_argument('uri', type=str)
    add.add_argument('package', type=str)
    add.add_argument('--github-access-token', type=str, help='provide an OAUTH token to connect to a privat repository')
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
        substituter_check = '🟢' if CONTAINS_SUBSTITUTERS else ('🟠' if USER_IS_TRUSTED else '🔴')
        rich.print(
            f'\nUser is trusted                      {trusted_check}\n'
            f'K-framework substituter is set up    {substituter_check}\n'
        )
        if not USER_IS_TRUSTED and not CONTAINS_SUBSTITUTERS:
            print()
            install_substituter('k-framework', K_FRAMEWORK_CACHE, K_FRAMEWORK_PUBLIC_KEY)
    elif args.command == 'install':
        install_package(args.package, args.version, args.override)
    elif args.command == 'update':
        update_package(args.package, args.version, args.override)
    elif args.command == 'remove':
        remove_package(args.package)
    elif args.command == 'add':
        if '/' in args.uri:
            org, rest = args.uri.split('/', 1)
            if '/' in rest:
                repo, branch = rest.split('/', 1)
            else:
                repo = rest
                branch = None

            try:
                new_package = GithubPackage(
                    org,
                    repo,
                    args.package,
                    branch,
                    private=(args.github_access_token is not None),
                    access_token=args.github_access_token,
                )
                path, git_token_options = mk_github_repo_path(new_package)
                nix(
                    ['flake', 'metadata', path, '--json'] + git_token_options,
                    is_install=False,
                    exit_on_error=False,
                )
            except Exception:
                try:
                    new_package = GithubPackage(org, repo, args.package, branch, private=True)
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
                            f'     [green] kup add {args.name} {args.uri}/main {args.package}\n'
                        )
                    sys.exit(1)

            path, git_token_options = mk_github_repo_path(new_package)

            if args.strict:
                nix(
                    ['eval', f'{path}#packages.{SYSTEM}.{args.package}', '--json'] + git_token_options,
                    is_install=False,
                )
            config_path = BaseDirectory.save_config_path('kup')
            user_packages_config_path = os.path.join(config_path, 'user_packages.ini')
            config = configparser.ConfigParser()
            if config_path and os.path.exists(user_packages_config_path):
                config.read(user_packages_config_path)

            config[args.name] = {
                'org': new_package.org,
                'repo': new_package.repo,
                'package': new_package.package,
                'private': str(new_package.private),
            }

            if new_package.branch:
                config[args.name]['branch'] = new_package.branch

            if new_package.access_token:
                rich.print(f" ✅ The GitHub access token will be saved to '{str(user_packages_config_path)}'.")
                config[args.name]['github-access-token'] = new_package.access_token

            with open(user_packages_config_path, 'w') as configfile:
                config.write(configfile)

            rich.print(f" ✅ Successfully added new package '[green]{args.name}[/]'.")

        else:
            rich.print(f"❗ The URI '[red]{args.uri}[/]' is invalid.\n" "   The correct format is '[green]org/repo[/]'.")
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
        nix_detach(['shell', f'{path}#{temporary_package.package}'] + overrides + git_token_options)


if __name__ == '__main__':
    main()
