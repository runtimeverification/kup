# kup - the K Framework installer

`kup` is the new installer tool for downloading and running the latest version of K Framework and any semantics built on top of K. This tool uses the [Nix](https://nixos.org/download.html) package manager as a backbone and is currently supported on all major x86_64 Linux distributions, as well as Intel and ARM macOS. If you're on a compatible system, use this one click install script which installs [Nix](https://nixos.org/download.html) (if not already present) and `kup`:

```
bash <(curl https://kframework.org/install)
```

You can then install K Framework via:

```
kup install k
```

update K with:

```
kup update k
```

And list available versions with:

```
kup list k
```

To list further available packages, run

```
kup list
```

and any further functionality is described in the help commands:

```
kup --help
kup list --help
kup install --help
etc.
```



## For Developers

Use `make` to run common tasks (see the [Makefile](Makefile) for a complete list of available targets).

* `make build`: Build wheel
* `make check`: Check code style
* `make format`: Format code
* `make test-unit`: Run unit tests

For interactive use, spawn a shell with `poetry shell` (after `poetry install`), then run an interpreter.
