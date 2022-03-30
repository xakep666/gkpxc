package dockercred

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/99designs/keyring"
)

func SetupKeyring(service string) (keyring.Keyring, error) {
	backends := []keyring.BackendType{
		// Windows
		keyring.WinCredBackend,
		// MacOS
		keyring.KeychainBackend,
		// Linux
		keyring.KWalletBackend,
		keyring.SecretServiceBackend,
	}

	promptCmd := os.Getenv("DOCKER_CREDENTIAL_KEEPASSXC_ASKPASS")
	if promptCmd != "" {
		backends = append(backends, keyring.FileBackend)
	}

	return keyring.Open(keyring.Config{
		AllowedBackends:          backends,
		WinCredPrefix:            service,
		KeychainName:             "login",
		KeychainTrustApplication: true,
		KWalletAppID:             service,
		KWalletFolder:            service,
		LibSecretCollectionName:  service,
		FileDir:                  fileBackendDir(service),
		FilePasswordFunc: func(prompt string) (string, error) {
			out, err := exec.Command(promptCmd, prompt).Output()
			return string(out), err
		},
	})
}

func fileBackendDir(service string) string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}

	return filepath.Join(cfgDir, service)
}
