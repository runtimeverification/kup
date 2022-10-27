import json
import os
import subprocess
import sys
import textwrap
from argparse import ArgumentParser, RawDescriptionHelpFormatter, _HelpAction
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from terminaltables import SingleTable  # type: ignore
from rich.console import Console
from rich.markdown import Markdown
from rich.tree import Tree
from rich.theme import Theme
import rich

console = Console(theme=Theme({
    'markdown.code': 'green'
    }))

script_path = os.path.abspath(__file__) # i.e. /path/to/dir/foobar.py
script_dir = os.path.split(script_path)[0] #i.e. /path/to/dir/

INSTALLED = '🟢 \033[92minstalled\033[0m'
AVAILABLE = '🔵 \033[94mavailable\033[0m'
UPDATE = '🟠 \033[93mnewer version available\033[0m'
LOCAL = '\033[3mlocal checkout\033[0m'

NIX_SUBSTITUTERS = [
    '--option',
    'extra-substituters',
    'https://k-framework.cachix.org https://cache.iog.io',
    '--option',
    'extra-trusted-public-keys',
    (
        'k-framework.cachix.org-1:jeyMXB2h28gpNRjuVkehg+zLj62ma1RnyyopA/20yFE= '
        'hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ='
    ),
]


def nix_raw(args: List[str], extra_flags: List[str] = NIX_SUBSTITUTERS, gc_dont_gc: bool = True) -> bytes:
    my_env = os.environ.copy()
    if gc_dont_gc:
        my_env['GC_DONT_GC'] = '1'
    try:
        output = subprocess.check_output(
            ['nix'] + args + ['--extra-experimental-features', 'nix-command flakes'] + extra_flags,
            env=my_env,
        )
    except subprocess.CalledProcessError as exc:
        print('❗ \033[91mThe operation could not be completed. See above for the error output ...\033[0m')
        sys.exit(exc.returncode)
    else:
        return output


SYSTEM = (
    nix_raw(['eval', '--impure', '--expr', 'builtins.currentSystem'], extra_flags=[])
    .decode('utf8')
    .strip()
    .replace('"', '')
)

# nix tends to fail on macs with a segfault so we add `GC_DONT_GC=1` if on macOS (i.e. darwin)
# The `GC_DONT_GC` simply disables the garbage collector used during evaluation of a nix
# expression. This may cause the process to run out of memory, but hasn't been observed for our
# derivations in practice, so should be ok to do.
def nix(args: List[str], extra_flags: List[str] = NIX_SUBSTITUTERS) -> bytes:
    return nix_raw(args, extra_flags, True if 'darwin' in SYSTEM else False)


def nix_detach(args: List[str], extra_flags: List[str] = NIX_SUBSTITUTERS) -> None:
    my_env = os.environ.copy()
    if 'darwin' in SYSTEM:
        my_env['GC_DONT_GC'] = '1'
    nix = subprocess.check_output(['which', 'nix']).decode('utf8').strip()
    os.execve(nix, [nix] + args + ['--extra-experimental-features', 'nix-command flakes'] + extra_flags, my_env)


class AvailablePackage:
    __slots__ = ['repo', 'package']

    def __init__(self, repo: str, package: str):
        self.repo = repo
        self.package = package


available_packages: Dict[str, AvailablePackage] = {
    'kup': AvailablePackage('kup', f'packages.{SYSTEM}.kup'),
    'k': AvailablePackage('k', f'packages.{SYSTEM}.k'),
    'kevm': AvailablePackage('evm-semantics', f'packages.{SYSTEM}.kevm'),
    'kore-exec': AvailablePackage('haskell-backend', f'packages.{SYSTEM}.kore:exe:kore-exec'),
    'pyk': AvailablePackage('pyk', f'packages.{SYSTEM}.pyk'),
}


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


packages: Dict[str, ConcretePackage] = {}
installed_packages: List[str] = []


def check_package_version(p: AvailablePackage, current_url: str) -> str:
    result = nix(['flake', 'metadata', f'github:runtimeverification/{p.repo}', '--json'])
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
            return {key: {'repo': repo, 'rev': rev}}
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

            return {key: {'repo': repo, 'rev': rev, 'inputs': inputs}}

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


def get_package_inputs(name: str, package: Union[AvailablePackage, ConcretePackage]) -> dict:
    try:
        result = nix(['flake', 'metadata', f'github:runtimeverification/{package.repo}', '--json'])
    except Exception:
        return {}
    meta = json.loads(result)
    root = meta['locks']['root']

    return {name: process_input(meta['locks']['nodes'], root, True)[root]}


def print_package_tree(inputs: dict, key: str, root: Any = None) -> None:
    rev = f" - github:runtimeverification/{inputs[key]['repo']} [green]{inputs[key]['rev'][:7]}[/]" if 'rev' in inputs[key] else ''
    follows = (' - follows [green]' + '/'.join(inputs[key]['follows'])) if 'follows' in inputs[key] else ''
    if root is None:
        n = Tree(f'Inputs:')
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


def reload_packages() -> None:
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
            if 'originalUrl' in m and m['originalUrl'].startswith(
                f'github:runtimeverification/{available_package.repo}'
            ):
                version = m['url'].removeprefix(f'github:runtimeverification/{available_package.repo}/')
                status = check_package_version(available_package, m['url'])
                immutable = (
                    len(m['originalUrl'].removeprefix(f'github:runtimeverification/{available_package.repo}')) > 1
                )
                packages[name] = ConcretePackage(
                    available_package.repo,
                    available_package.package,
                    status,
                    version,
                    immutable,
                    idx,
                )
            else:
                packages[name] = ConcretePackage(available_package.repo, available_package.package, LOCAL, index=idx)

    installed_packages = list(packages.keys())
    for pkg_name in available_packages:
        if pkg_name not in installed_packages:
            available_package = available_packages[pkg_name]
            packages[pkg_name] = ConcretePackage(available_package.repo, available_package.package, AVAILABLE, '')


class PackageVersion:
    __slots__ = ['sha', 'message', 'tag', 'merged_at']

    def __init__(self, sha: str, message: str, tag: Optional[str], merged_at: str):
        self.sha = sha
        self.message = message
        self.tag = tag
        self.merged_at = merged_at


def highlight_row(condition: bool, xs: List[str]) -> List[str]:
    if condition:
        return [f'\033[92m{x}\033[0m' for x in xs]
    else:
        return xs


def list_package(package_name: str, show_inputs: bool) -> None:
    reload_packages()
    if package_name != 'all':
        if package_name not in available_packages.keys():
            print(
                f"❗ [red]The package '[green]{package_name}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        listed_package = available_packages[package_name]

        if show_inputs:
            inputs = get_package_inputs(package_name, listed_package)
            print_package_tree(inputs, package_name)
        else:
            tags = requests.get(f'https://api.github.com/repos/runtimeverification/{listed_package.repo}/tags')
            commits = requests.get(f'https://api.github.com/repos/runtimeverification/{listed_package.repo}/commits')
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


def mk_path(path: str, version_or_path: Optional[str]) -> str:
    if version_or_path:
        if os.path.isdir(version_or_path):
            return os.path.abspath(version_or_path)
        else:
            return path + '/' + version_or_path
    else:
        return path


def mk_override_args(
    package_name: str, package: Union[AvailablePackage, ConcretePackage], overrides: List[List[str]]
) -> List[str]:
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
                    f"⚠️ [yellow]The input '[green]{input}[/]' you are trying to override follows '[green]{override_input}[/]'.\n",
                    f"[/]You may want to call this command with '[blue]--override {override_input}[/]' instead.",
                )
            else:
                rich.print(
                    f"❗ [red]'[green]{input}[/]' is not a valid input of the package '[green]{package_name}[/]'.\n",
                    f"[/]To see the valid inputs, run '[blue]kup list {package_name} --inputs[/]'",
                )
                sys.exit(1)
        repo = valid_inputs[input] if not override_input else valid_inputs[override_input]
        path = mk_path(f'github:runtimeverification/{repo}', version_or_path)
        nix_overrides.append('--override-input')
        nix_overrides.append(input)
        nix_overrides.append(path)
    # print(nix_overrides)
    return nix_overrides


def update_or_install_package(
    package_name: str,
    package: Union[AvailablePackage, ConcretePackage],
    version: Optional[str],
    package_overrides: List[List[str]],
) -> None:
    path = mk_path(f'github:runtimeverification/{package.repo}', version)

    if type(package) is ConcretePackage:
        if package.immutable or version or package_overrides:
            nix(['profile', 'remove', str(package.index)])
            overrides = mk_override_args(package_name, package, package_overrides) if package_overrides else []
            nix(['profile', 'install', f'{path}#{package.package}'] + overrides)
        else:
            nix(['profile', 'upgrade', str(package.index)])
    else:
        overrides = mk_override_args(package_name, package, package_overrides) if package_overrides else []
        nix(['profile', 'install', f'{path}#{package.package}'] + overrides)


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


def remove_package(package_name: str) -> None:
    reload_packages()
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
            '[/]Are you sure you want to continue? \[y/N]'
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
    nix(['profile', 'remove', str(package.index)])

def print_help(subcommand: str, parser) -> None:
    parser.print_help()
    print('')
    with open(os.path.join(script_dir, f'{subcommand}-help.md'), 'r+') as help_file:
        console.print(Markdown(help_file.read(), code_theme='emacs'))
    parser.exit()

class _HelpListAction(_HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        print_help('list', parser)

class _HelpInstallAction(_HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        print_help('install', parser)

class _HelpUpdateAction(_HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        print_help('update', parser)

class _HelpShellAction(_HelpAction):
    def __call__(self, parser, namespace, values, option_string=None):
        print_help('shell', parser)

def main() -> None:
    parser = ArgumentParser(description='The K Framework installer',
    prog='kup',
    formatter_class=RawDescriptionHelpFormatter,
      epilog=textwrap.dedent('''\
         additional information:
             For more detailed help for the different sub-commands, call
               kup {list,install,remove,update,shell} --help
         '''))
    subparser = parser.add_subparsers(dest='command')
    list = subparser.add_parser('list', help='show the active and installed K semantics', add_help=False)
    list.add_argument('package', nargs='?', default='all', type=str)
    list.add_argument('--inputs', action='store_true', help='show the input dependencies of the selected package')
    list.add_argument('-h', '--help', action=_HelpListAction)

    install = subparser.add_parser('install', help='download and install the stated package', add_help=False)
    install.add_argument('package', type=str)
    install.add_argument('--version', type=str, help='install a custom version of a package')
    install.add_argument('--override', type=str, nargs=2, action='append', help='override an input dependency of a package')
    install.add_argument('-h', '--help', action=_HelpInstallAction)

    uninstall = subparser.add_parser('remove', help="remove the given package from the user's PATH")
    uninstall.add_argument('package', type=str)

    update = subparser.add_parser('update', help='update the package to the latest version', add_help=False)
    update.add_argument('package', type=str)
    update.add_argument('--version', type=str, help='update the package to a custom version')
    update.add_argument('--override', type=str, nargs=2, action='append', help='override an input dependency of a package')
    update.add_argument('-h', '--help', action=_HelpUpdateAction)

    shell = subparser.add_parser('shell', help='add the selected package to the current shell (temporary)', add_help=False)
    shell.add_argument('package', type=str)
    shell.add_argument('--version', type=str, help='temporarily install a custom version of a package')
    shell.add_argument('--override', type=str, nargs=2, action='append', help='override an input dependency of a package')
    shell.add_argument('-h', '--help', action=_HelpShellAction)

    args = parser.parse_args()
    if 'help' in args and args.help:
        with open(os.path.join(script_dir, f'{args.command}-help.md'), 'r+') as help_file:
            console.print(Markdown(help_file.read(), code_theme='emacs'))
            sys.exit(0)
    if args.command == 'list':
        list_package(args.package, args.inputs)
    elif args.command == 'install':
        install_package(args.package, args.version, args.override)
    elif args.command == 'update':
        update_package(args.package, args.version, args.override)
    elif args.command == 'remove':
        remove_package(args.package)
    elif args.command == 'shell':
        reload_packages()
        if args.package not in available_packages.keys():
            rich.print(
                f"❗ [red]The package '[green]{args.package}[/]' does not exist.\n"
                "[/]Use '[blue]kup list[/]' to see all the available packages."
            )
            return
        temporary_package = available_packages[args.package]
        path = mk_path(f'github:runtimeverification/{temporary_package.repo}', args.version)
        overrides = mk_override_args(args.package, temporary_package, args.override)
        nix_detach(['shell', f'{path}#{temporary_package.package}'] + overrides)


if __name__ == '__main__':
    main()
