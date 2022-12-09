# kup add *<package>* *<url>*

Whilst kup contains a set of default curated packaged by default, it is also able to manage user defined packages from any (potentially private) github repositories. To add a new package `foo` to kup, simply call

```
➜ kup add foo myorg/myrepo{/myfeature} bar
```

Where `https://github.com/myorg/myrepo/tree/myfeature` is a valid repository containing a `flake.nix` file with a defined `bar` package output. Adding the last `/myfeature` is optional.

---

*Note*: Nix assumes that the default branch is `master`. If the default branch is e.g. `main` you will have to manually specify this, i.e. `myorg/myrepo/main`

---
