import json
import os
import pwd
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

import rich

K_FRAMEWORK_CACHE = 'https://k-framework.cachix.org'
K_FRAMEWORK_PUBLIC_KEY = 'k-framework.cachix.org-1:jeyMXB2h28gpNRjuVkehg+zLj62ma1RnyyopA/20yFE='
K_FRAMEWORK_BINARY_PUBLIC_KEY = 'k-framework-binary.cachix.org-1:pJedQ8iG19BW3v/DMMmiRVtwRBGO3fyMv2Ws0OpBADs='


K_FRAMEWORK_BINARY_CACHE = 'https://k-framework-binary.cachix.org'

K_FRAMEWORK_BINARY_CACHE_NAME = 'k-framework-binary'

if os.path.exists('/run/current-system/nixos-version'):
    with open('/run/current-system/nixos-version', 'r') as nixos_version:
        NIXOS_VERSION: Optional[str] = nixos_version.read()
else:
    NIXOS_VERSION = None


def nix_substituters(subsituters: List[str], public_keys: List[str]) -> List[str]:
    return [
        '--option',
        'extra-substituters',
        ' '.join(subsituters),
        '--option',
        'extra-trusted-public-keys',
        ' '.join(public_keys),
    ]


DEFAULT_NIX_SUBSTITUTER = nix_substituters([K_FRAMEWORK_CACHE], [K_FRAMEWORK_PUBLIC_KEY, K_FRAMEWORK_BINARY_PUBLIC_KEY])

SYSTEM_NIX = subprocess.check_output(['which', 'nix']).decode('utf8').strip()
PINNED_NIX = os.getenv('PINNED_NIX', default=SYSTEM_NIX)

def nix_raw(
    args: List[str],
    extra_flags: List[str] = DEFAULT_NIX_SUBSTITUTER,
    gc_dont_gc: bool = True,
    exit_on_error: bool = True,
    verbose: bool = False,
    use_system_nix: bool = False,
) -> bytes:
    my_env = os.environ.copy()
    if gc_dont_gc:
        my_env['GC_DONT_GC'] = '1'
    nix_bin = PINNED_NIX if not use_system_nix else SYSTEM_NIX
    cmd = [nix_bin] + args + ['--extra-experimental-features', 'nix-command flakes'] + extra_flags
    if verbose:
        print('[kup]', ' '.join(cmd))
    if exit_on_error:
        try:
            output = subprocess.check_output(
                cmd,
                env=my_env,
            )
        except subprocess.CalledProcessError as exc:
            if exc.returncode == -9:
                rich.print(
                    '\n❗ [red]The operation could not be completed, as the installer was killed by the operating system. The process likely ran out of memory ...[/]'
                )
            else:
                print(exc)
                rich.print(
                    "\n❗ [red]The operation could not be completed.\n[/]   See the error output above (try re-running this command with '[green]--verbose[/]' for more detailed logs) ..."
                )
            sys.exit(exc.returncode)
    else:
        return subprocess.check_output(
            cmd,
            env=my_env,
            stderr=subprocess.DEVNULL,
        )

    return output


ARCH = (
    nix_raw(['eval', '--impure', '--expr', 'builtins.currentSystem'], extra_flags=[])
    .decode('utf8')
    .strip()
    .replace('"', '')
)

# based on https://github.com/NixOS/nixpkgs/blob/d329d65edb3680f5aa7cc46b364a564bab27f8c7/nixos/modules/config/nix.nix#L114
# to remove warnings about deprecated nix command
SHOW_CONFIG_COMMAND = (
    nix_raw(
        [
            'eval',
            '--impure',
            '--expr',
            'if builtins.compareVersions builtins.nixVersion "2.20pre" == -1 then "show-config" else "config show"',
        ],
        extra_flags=[],
    )
    .decode('utf8')
    .strip()
    .replace('"', '')
)

USER = pwd.getpwuid(os.getuid())[0]
USER_IS_ROOT = os.geteuid() == 0

TRUSTED_USERS = []
CURRENT_SUBSTITUTERS = []
CURRENT_TRUSTED_PUBLIC_KEYS = []
CURRENT_NETRC_FILE = None


def check_substituters() -> Tuple[bool, bool]:
    global TRUSTED_USERS, CURRENT_SUBSTITUTERS, CURRENT_TRUSTED_PUBLIC_KEYS, CURRENT_NETRC_FILE
    try:
        cmd = SHOW_CONFIG_COMMAND.split()
        cmd.append('--json')
        result = nix_raw(cmd, extra_flags=[])
    except Exception:
        rich.print(f"⚠️ [yellow]Could not run 'nix {SHOW_CONFIG_COMMAND}'.")
        return False, False
    config = json.loads(result)
    try:
        TRUSTED_USERS = config['trusted-users']['value']
        current_user_is_trusted = USER in TRUSTED_USERS
        CURRENT_SUBSTITUTERS = config['substituters']['value']
        CURRENT_TRUSTED_PUBLIC_KEYS = config['trusted-public-keys']['value']
        netrc_file = config['netrc-file']['value']
        if os.path.exists(netrc_file):
            try:
                with open(netrc_file, 'a'):
                    CURRENT_NETRC_FILE = netrc_file
            except Exception:
                pass
        elif os.access(os.path.dirname(netrc_file), os.X_OK | os.W_OK):
            CURRENT_NETRC_FILE = netrc_file

        has_all_substituters = (
            K_FRAMEWORK_CACHE in CURRENT_SUBSTITUTERS
            and K_FRAMEWORK_PUBLIC_KEY in CURRENT_TRUSTED_PUBLIC_KEYS
            and K_FRAMEWORK_BINARY_PUBLIC_KEY in CURRENT_TRUSTED_PUBLIC_KEYS
        )
        return current_user_is_trusted, has_all_substituters
    except Exception as e:
        print(str(e))
        rich.print('⚠️ [yellow]Could not fetch nix substituters or figure out if the current user is trusted by nix.')
        return False, False


USER_IS_TRUSTED, CONTAINS_DEFAULT_SUBSTITUTER = check_substituters()

GLUE_MODULE = """# WARN: this file was generated by kup and will get overwritten automatically
{ pkgs, lib, ... }:

let
  folder = ./kup;
  toImport = name: value: folder + ("/" + name);
  filterCaches = key: value: value == "regular" && lib.hasSuffix ".nix" key;
  imports = lib.mapAttrsToList toImport (lib.filterAttrs filterCaches (builtins.readDir folder));
in {
  inherit imports;
  nix.settings.substituters = ["https://cache.nixos.org/"];
}
"""


def install_substituters_nixos(name: str, substituters: List[str], pub_keys: List[str]) -> None:
    nixos_path = '/etc/nixos'
    substituters_str = ' '.join(substituters)
    pub_keys_str = ' '.join(pub_keys)

    cache_module = f"""{{
  nix = {{
    settings = {{
      substituters = [
        "{substituters_str}"
      ];
      trusted-public-keys = [
        "{pub_keys_str}"
      ];
    }};
  }};
}}
"""

    with open('/tmp/kup.nix', 'w') as glue_file:
        glue_file.write(GLUE_MODULE)

    os.makedirs('/tmp/kup', exist_ok=True)

    with open(f'/tmp/{name}.nix', 'w') as cache_file:
        cache_file.write(cache_module)

    if not os.path.exists(f'{nixos_path}/kup'):
        subprocess.call(['sudo', 'mkdir', '-p', f'{nixos_path}/kup'])

    subprocess.call(['sudo', 'mv', '-f', f'/tmp/{name}.nix', f'{nixos_path}/kup'])
    subprocess.call(['sudo', 'mv', '-f', '/tmp/kup.nix', nixos_path])

    rich.print(
        f'The [blue]kup[/] cache configuration was successfully written to [green]{nixos_path}/kup/{name}.nix[/].\n\n'
        'To start using this cache make sure you have the following line in your [green]/etc/nixos/configuration.nix[/]:\n\n'
        '   [green]imports = [ ./kup.nix ];[/]\n\n'
        'Then run:\n\n'
        '   [green]sudo nixos-rebuild switch'
    )


@dataclass(frozen=True)
class Comment:
    comment: str


@dataclass(frozen=True)
class Blank:
    pass


@dataclass(frozen=True)
class KeyVal:
    key: str
    value: str


def read_config(path: str) -> List[Union[Comment, Blank, KeyVal]]:
    conf: List[Union[Comment, Blank, KeyVal]] = []
    if not os.path.exists(path):
        return conf
    with open(path, 'r') as fp:
        for line in fp:
            stripped = line.strip()
            if stripped.startswith('#'):
                conf.append(Comment(line))
            elif '=' in line:
                key, val = stripped.split('=', 1)
                conf.append(KeyVal(key.strip(), val.strip()))
            elif not stripped:
                conf.append(Blank())
    return conf


def write_config(path: str, conf: List[Union[Comment, Blank, KeyVal]]) -> None:
    with open(path, 'w') as fp:
        for c in conf:
            if isinstance(c, Comment):
                fp.write(c.comment)
            elif isinstance(c, Blank):
                fp.write('\n')
            elif isinstance(c, KeyVal):
                fp.write(f'{c.key} = {c.value}\n')


def contains_key(config: List[Union[Comment, Blank, KeyVal]], key: str) -> bool:
    for item in config:
        if isinstance(item, KeyVal) and item.key == key:
            return True
    return False


def append_to_config(
    config: List[Union[Comment, Blank, KeyVal]], my_dict: dict[str, str]
) -> List[Union[Comment, Blank, KeyVal]]:
    for n, item in enumerate(config):
        if isinstance(item, KeyVal):
            if item.key in my_dict.keys():
                config[n] = KeyVal(item.key, f'{item.value} {my_dict[item.key]}')
    return config


def install_substituters_non_nixos(conf_file: str, substituters: List[str], pub_keys: List[str]) -> None:
    conf = read_config(conf_file)
    if not contains_key(conf, 'substituters'):
        conf.append(KeyVal('substituters', 'https://cache.nixos.org/'))
        conf.append(KeyVal('trusted-public-keys', 'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='))
    new_conf = append_to_config(
        conf, {'substituters': ' '.join(substituters), 'trusted-public-keys': ' '.join(pub_keys)}
    )
    write_config('/tmp/nix.conf', new_conf)

    if os.path.exists(conf_file):
        subprocess.call(['sudo', 'cp', '-f', conf_file, f'{conf_file}.bak'])
    else:
        subprocess.call(['sudo', 'mkdir', '-p', os.path.dirname(conf_file)])

    subprocess.call(['sudo', 'mv', '-f', '/tmp/nix.conf', os.path.dirname(conf_file)])
    subprocess.call(['sudo', 'pkill', 'nix-daemon'])

    rich.print(f'The [blue]kup[/] cache configuration was successfully written to [green]{conf_file}[/].')


def print_substituters_warning() -> None:
    new_trusted_users = TRUSTED_USERS if USER_IS_TRUSTED else TRUSTED_USERS + [USER]
    add_user_to_trusted = ' '.join(new_trusted_users)
    add_user_to_trusted_nix = ' '.join([f'"{s}"' for s in new_trusted_users])
    rich.print(
        f'\n⚠️ [yellow] The k-framework binary caches [green]{K_FRAMEWORK_CACHE}[/] and [green]{K_FRAMEWORK_BINARY_CACHE}[/] are\n'
        'not configured in your nix installation and the current user does not have sufficient permissions to add and use them.\n'
        '[blue]kup[/] relies on these caches to provide faster installation using pre-built binaries.[/]\n\n'
        'You can still install kup packages from source, however, to avoid building the packages on your local machine, consider:\n'
    )
    if NIXOS_VERSION is None:
        rich.print(
            f'1) letting [blue]kup[/] modify the nix cache configuration. You will be prompted for root access. ([green]recommended[/])\n\n'
            '2) running the following command, to add the current user as trusted:\n\n'
            f'   [green]echo "trusted-users = {add_user_to_trusted}" | sudo tee -a /etc/nix/nix.conf && sudo pkill nix-daemon[/]\n\n'
            '   and then re-running the current command.\n\n'
            '   Note: [green]/etc/nix/nix.conf[/] may not exist, in which case, you will first need to run:\n\n'
            f'   [green]sudo mkdir -p /etc/nix && sudo touch /etc/nix/nix.conf[/]\n\n'
        )
    else:
        nix_setting = 'nix.settings.trusted-users' if NIXOS_VERSION.startswith('22') else 'nix.trustedUsers'
        rich.print(
            '1) letting [blue]kup[/] modify the nix cache configuration. You will be prompted for root access. ([green]recommended[/])\n\n'
            '2) adding/modifying the following setting in your [green]/etc/nixos/configuration.nix[/] to add the current user as trusted:\n\n'
            f'   [green]{nix_setting} = [ {add_user_to_trusted_nix} ];[/]\n\n'
            '   then rebuilding your configuration via [green]sudo nixos-rebuild switch[/] and re-running this command.'
        )

    rich.print('Please select option [1] or [2], or press any key to continue without any changes: ')


def install_substituters(name: str, substituters: List[str], pub_keys: List[str]) -> None:
    if USER_IS_TRUSTED:
        # no need to write the config, as we can just pass it as an extra flag.
        return

    if NIXOS_VERSION is not None:
        install_substituters_nixos(name, substituters, pub_keys)
    else:
        install_substituters_non_nixos('/etc/nix/nix.conf', substituters, pub_keys)


def ask_install_substituters(name: str, substituters: List[str], pub_keys: List[str]) -> None:
    if USER_IS_TRUSTED:
        # no need to write the config, as we can just pass it as an extra flag.
        return

    print_substituters_warning()
    choice = input().strip().lower()

    if choice in {'1', '1)'}:
        install_substituters(name, substituters, pub_keys)
    elif choice in {'2', '2)'}:
        sys.exit(0)


def set_netrc_file(netrc_file: str) -> None:
    conf_file = '/etc/nix/nix.conf'

    if NIXOS_VERSION is not None:
        rich.print(
            '❗ [red]Cannot set the netrc file path on NixOS. Please make sure the current user can write to the default netrc file.[/]\n'
        )
        sys.exit(0)
    else:
        conf = read_config(conf_file)
        new_conf = conf + [KeyVal('netrc-file', netrc_file)]
        write_config('/tmp/nix.conf', new_conf)

        rich.print(f'Adding a new netrc file ({netrc_file}) to nix config. This operation requires root access.')

        if os.path.exists(conf_file):
            subprocess.call(['sudo', 'cp', '-f', conf_file, f'{conf_file}.bak'])
        else:
            subprocess.call(['sudo', 'mkdir', '-p', os.path.dirname(conf_file)])

        subprocess.call(['sudo', 'mv', '-f', '/tmp/nix.conf', os.path.dirname(conf_file)])
        subprocess.call(['sudo', 'pkill', 'nix-daemon'])


# nix tends to fail on macs with a segfault so we add `GC_DONT_GC=1` if on macOS (i.e. darwin)
# The `GC_DONT_GC` simply disables the garbage collector used during evaluation of a nix
# expression. This may cause the process to run out of memory, but hasn't been observed for our
# derivations in practice, so should be ok to do.
def nix(
    args: List[str],
    is_install: bool = True,
    exit_on_error: bool = True,
    extra_substituters: Optional[List[str]] = None,
    extra_public_keys: Optional[List[str]] = None,
    verbose: bool = False,
    refresh: bool = False,
    use_system_nix: bool = False,
) -> bytes:
    global CONTAINS_DEFAULT_SUBSTITUTER
    if is_install and not CONTAINS_DEFAULT_SUBSTITUTER:
        ask_install_substituters(
            'k-framework', [K_FRAMEWORK_CACHE], [K_FRAMEWORK_PUBLIC_KEY, K_FRAMEWORK_BINARY_PUBLIC_KEY]
        )
        _, CONTAINS_DEFAULT_SUBSTITUTER = check_substituters()

    if is_install and USER_IS_TRUSTED:
        substituters = [K_FRAMEWORK_CACHE] + (extra_substituters if extra_substituters is not None else [])
        public_keys = [K_FRAMEWORK_PUBLIC_KEY, K_FRAMEWORK_BINARY_PUBLIC_KEY] + (
            extra_public_keys if extra_public_keys is not None else []
        )

        extra_subs_and_keys = nix_substituters(
            [s for s in substituters if s not in CURRENT_SUBSTITUTERS],
            [k for k in public_keys if k not in CURRENT_TRUSTED_PUBLIC_KEYS],
        )
    else:
        extra_subs_and_keys = []

    verbosity_flag = ['--print-build-logs', '-vv'] if verbose else []
    refresh_flag = ['--refresh'] if refresh else []

    return nix_raw(
        args,
        extra_flags=extra_subs_and_keys + verbosity_flag + refresh_flag,
        gc_dont_gc=True if 'darwin' in ARCH else False,
        exit_on_error=exit_on_error,
        verbose=verbose,
        use_system_nix=use_system_nix,
    )


def nix_detach(
    args: List[str],
    extra_substituters: Optional[List[str]] = None,
    extra_public_keys: Optional[List[str]] = None,
    verbose: bool = False,
    refresh: bool = False,
    use_system_nix: bool = False,
) -> None:
    my_env = os.environ.copy()
    if 'darwin' in ARCH:
        my_env['GC_DONT_GC'] = '1'
    nix_bin = PINNED_NIX if not use_system_nix else SYSTEM_NIX

    if USER_IS_TRUSTED:
        substituters = [K_FRAMEWORK_CACHE] + (extra_substituters if extra_substituters is not None else [])
        public_keys = [K_FRAMEWORK_PUBLIC_KEY, K_FRAMEWORK_BINARY_PUBLIC_KEY] + (
            extra_public_keys if extra_public_keys is not None else []
        )

        extra_subs_and_keys = nix_substituters(
            [s for s in substituters if s not in CURRENT_SUBSTITUTERS],
            [k for k in public_keys if k not in CURRENT_TRUSTED_PUBLIC_KEYS],
        )
    else:
        extra_subs_and_keys = []

    verbosity_flag = ['--print-build-logs', '-vv'] if verbose else []
    refresh_flag = ['--refresh'] if refresh else []

    cmd = (
        [nix_bin]
        + args
        + ['--accept-flake-config', '--extra-experimental-features', 'nix-command flakes']
        + extra_subs_and_keys
        + verbosity_flag
        + refresh_flag
    )

    if verbose:
        print('[kup]', ' '.join(cmd))

    os.execve(
        nix_bin,
        cmd,
        my_env,
    )


def get_extra_substituters_from_flake(path: str, extra_opts: List[str]) -> Tuple[List[str], List[str]]:
    if os.path.exists('/tmp/tempflake') and os.path.isdir('/tmp/tempflake'):
        shutil.rmtree('/tmp/tempflake')

    nix(['flake', 'clone', path, '--dest', '/tmp/tempflake'] + extra_opts, is_install=False)

    nix_config = json.loads(
        nix_raw(
            ['eval', '--impure', '--expr', '(import /tmp/tempflake/flake.nix).nixConfig or {}', '--json'],
            extra_flags=[],
        ).decode('utf8')
    )

    if 'substituters' in nix_config:
        substituters = nix_config['substituters']
    elif 'extra-substituters' in nix_config:
        substituters = nix_config['extra-substituters']
    else:
        substituters = []

    if 'trusted-public-keys' in nix_config:
        trusted_public_keys = nix_config['trusted-public-keys']
    elif 'extra-trusted-public-keys' in nix_config:
        trusted_public_keys = nix_config['extra-trusted-public-keys']
    else:
        trusted_public_keys = []

    return substituters, trusted_public_keys


def publish_and_pin_package(
    nix_path: str,
    cache: str,
    key: str,
    keep_days: Optional[str] = None,
) -> None:
    subprocess.check_output(['cachix', 'push', cache, nix_path])
    subprocess.check_output(
        ['cachix', 'pin', cache, key, nix_path] + ['--keep-days', str(keep_days)] if keep_days else []
    )
