# kup list

The `list` command without any further arguments lists all the packages provided by `kup` along with the information on the current installed versions:


```
➜ kup list
┌───────────┬──────────────────────────────────────────┬────────────────────────────┐
│ Package   │ Installed version                        │ Status                     │
├───────────┼──────────────────────────────────────────┼────────────────────────────┤
│ kup       │ de9771cb75e9165b3150f64615abc3eeaae2c094 │ 🟠 newer version available │
│ k         │                                          │ 🔵 available               │
│ kevm      │                                          │ 🔵 available               │
│ kore-exec │                                          │ 🔵 available               │
└───────────┴──────────────────────────────────────────┴────────────────────────────┘
```

# kup list *<package>*

Calling `kup list` with one of the package names as an argument provides an overview of the most recent versions available to download, along with the commit notes.

```
➜ kup list kevm
┌─────────────────────┬─────────┬────────────────────────────────────────────────────┐
│ Version (installed) │ Commit  │ Message                                            │
├─────────────────────┼─────────┼────────────────────────────────────────────────────┤
│                     │ 19f4932 │ Update dependency: deps/pyk_release (#1435) *...   │
│                     │ cede61c │ Remove endPC cell (#1422) * evm, driver: remove... │
│                     │ f4de1f4 │ Remove docker hub stage & file (#1418) * update... │
│                     │ 0539c0c │ Handle auto-updates from pyk repo (#1431) *...     │
│                     │ 3d3d79e │ Ignore binRuntime rules in foundry.k.check...      │
│ v1.0.1-f5ffb68      │ f5ffb68 │ Generate individual KCFGs for each method in...    │
│                     │ 602424a │ web/k-web-theme: 8aed71c - feat: Display code...   │
└─────────────────────┴─────────┴────────────────────────────────────────────────────┘
```

Note that both the commit hash and version tags can be used when installing, updating or opening a temporary shell; e.g.

```
➜ kup install kevm --version v1.0.1-f5ffb68
➜ kup shell kevm --version cede61c

```

# kup list *<package>* --inputs

Adding the `--inputs` flag will print out the dependency tree of the given package. For example, we see below that the package `kevm` depends on `k-framework` which in turn depends on several packages including `haskell-backend` and `llvm-backend`: 

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

`kup` allows any of these dependencies to be overridden when installing, updating or opening a temporary shell. For example, to override the `llvm-backend` dependency, you can do a local checkout of [github.com/runtimeverification/llvm-backend](github.com/runtimeverification/llvm-backend) and then build `kevm` against the checkout via

```
➜ kup shell kevm --override k-framework/llvm-backend ~/git/llvm-backend
```

If you just want to build with a specific commit of `llvm-backend`, you can use the version tag or commit hash instead

```
➜ kup shell kevm --override k-framework/llvm-backend 8aef082
```

---

*Note*: Certain inputs in the tree have a `follows `*<path>* instead of the repository and hash. This is because they are linked to the version pointed to by *<path>*. If you want to override one of these inputs, it is almost always the case that you want to override the *<path>* input instead. ``kup` will let you proceed if you know what you are doing but issue a warning.

---
