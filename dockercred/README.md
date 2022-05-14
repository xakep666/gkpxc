Docker Credential Helper
=====

This helper allows to store your docker credentials in KeepassXC database.

# Installation

* Ensure that your `$GOBIN` directory present in `$PATH`.
* `go get github.com/xakep666/gkpxc/dockercred/cmd/docker-credential-keepassxc`
* Set `"credsStore"` to `"keepassxc"` in your docker client config file (`.docker/config.json`).

# Usage
* Credentials for specific registry looked up by `URL` field of record.
* `docker login` adds new credentials into `Docker Credentials` group.
* `docker login` must be used first time even if record for this url present in KeepassXC database.
* `docker logout` removes record from KeepassXC database.

## Notes
* KeepassXC requires association credentials to fetch logins in database. To store such credentials this utility uses
os-specific credential storages:
  * Windows - WinCred
  * MacOS - Keychain (`login` chain)
  * Linux - KWallet or Gnome Secret Service
* For correct lookup KeepassXC record must contain url starting with `https://`. I.e. for pulling image like `docker.mycompany.com/project/image:v0.1.2` record must have url `https://docker.mycompany.com`.
