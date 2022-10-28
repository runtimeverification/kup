# kup update *<package>* --version

When calling `kup update` *<package>*, `kup` updates the package to the latest available version. To override this with a specific commit hash or version tag, call
```
➜ kup install kevm --version v1.0.1-f5ffb68
```

or

```
➜ kup install kevm --version cede61c
```

Alternatively, you can also specify `--version` to point to a local checkout of the given package:

```
➜ kup install kevm --version ~/git/evm-semantics
```

# kup update *<package>* --override

The packages `kup` manages have dependencies (referred to as inputs). `kup` allows any of these dependencies to be overridden when installing, updating or opening a temporary shell. To see the dependency tree for a given package, for example `kevm`, call:

```
➜ kup list kevm --inputs
Inputs:
├── blockchain-k-plugin - github:runtimeverification/blockchain-k-plugin 8fdc74e
├── haskell-backend - follows k-framework/haskell-backend
├── k-framework - github:runtimeverification/k 43f56ac
│   ├── haskell-backend - github:runtimeverification/haskell-backend 4c3c436
│   ├── llvm-backend - github:runtimeverification/llvm-backend 94e8f4b
│   │   └── immer-src - github:runtimeverification/immer 198c2ae
│   └── rv-utils - github:runtimeverification/rv-nix-tools 7026604
├── pyk - github:runtimeverification/pyk 4240899
└── rv-utils_2 - github:runtimeverification/rv-nix-tools 7026604
```

For example, to override the `llvm-backend` dependency, you can do a local checkout of [github.com/runtimeverification/llvm-backend](github.com/runtimeverification/llvm-backend) and then build `kevm` against the checkout via

```
➜ kup update kevm --override k-framework/llvm-backend ~/git/llvm-backend
```

If you just want to build with a specific commit of `llvm-backend`, you can use the version tag or commit hash instead

```
➜ kup update kevm --override k-framework/llvm-backend 8aef082
```

---

*Note*: Certain inputs in the tree have a `follows `*<path>* instead of the repository and hash. This is because they are linked to the version pointed to by *<path>*. If you want to override one of these inputs, it is almost always the case that you want to override the *<path>* input instead. ``kup` will let you proceed if you know what you are doing but issue a warning.

---
