# kup add *<package>* *<url>*

Whilst kup contains a set of default curated packaged by default, it is also able to manage user defined packages from any (potentially private) github repositories. To add a new package `foo` to kup, simply call

```
➜ kup add foo myorg/myrepo{/myfeature} bar
```

Where `https://github.com/myorg/myrepo/tree/myfeature` is a valid repository containing a `flake.nix` file with a defined `bar` package output. Adding the last `/myfeature` is optional.

---

*Note*: Nix assumes that the default branch is `master`. If the default branch is e.g. `main` you will have to manually specify this, i.e. `myorg/myrepo/main`

---


# kup add *<package>* *<url>* --github-access-token *<access_token>*

Kup has two different modes for adding private packages. The default one is to use the `git+ssh` mode, which uses locally stored SSH credentials to access the repository. If you already have your private repository access set up over SSH, adding the package to kup should just work.

However, kup can also use a personal GitHub access token to download the private repository. To generate a personal access token, see:

https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token

Once you have your token with the correct permissions to read from the private repsitory, you can pass it as an argument to `kup add`

```
➜ kup add foo myorg/myrepo{/myfeature} bar --github-access-token ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The added advantage to using an access token is that running `kup list foo` will work just as it does for public packages, whereas this functionality is not available for private packages over SSH.
