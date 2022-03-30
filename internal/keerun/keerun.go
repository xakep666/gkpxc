package keerun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var dir string

func init() {
	var err error
	_, filename, _, _ := runtime.Caller(0)
	dir, err = filepath.Abs(filepath.Dir(filename))
	if err != nil {
		panic(err)
	}
}

type KeeRun struct {
	*exec.Cmd

	password []byte
}

func NewKeeRun(t *testing.T) (*KeeRun, error) {
	passBytes, err := os.ReadFile(filepath.Join(dir, "testdata", "passwd"))
	if err != nil {
		return nil, fmt.Errorf("password read: %w", err)
	}

	keepassxcExecutable := os.Getenv("KEEPASSXC_EXECUTABLE")
	if keepassxcExecutable == "" {
		keepassxcExecutable = "keepassxc"
	}

	cmd := exec.Command(keepassxcExecutable,
		"--pw-stdin",
		"--config", filepath.Join(dir, "testdata", "config.ini"),
		filepath.Join(dir, "testdata", "test.kdbx"),
	)
	cmd.Stdin = bytes.NewReader(passBytes)
	cmd.Stdout = &tLogWriter{T: t, Prefix: "[keepassxc]"}
	cmd.Stderr = &tLogWriter{T: t, Prefix: "[keepassxc err]"}

	return &KeeRun{
		Cmd:      cmd,
		password: passBytes,
	}, nil
}

func (k *KeeRun) Lock() error {
	cmd := exec.Command(k.Path, "--lock")
	cmd.Stdout = k.Stdout
	cmd.Stderr = k.Stderr
	return cmd.Run()
}

func (k *KeeRun) KillWait() {
	k.Process.Kill()
	k.Wait()
}

func DecodeAssociationCreds(to interface{}) error {
	f, err := os.Open(filepath.Join(dir, "testdata", "assoc.json"))
	if err != nil {
		return err
	}

	defer f.Close()

	return json.NewDecoder(f).Decode(to)
}

type tLogWriter struct {
	*testing.T
	Prefix string
}

func (t *tLogWriter) Write(p []byte) (n int, err error) {
	t.Logf("%s: %s", t.Prefix, p)
	return len(p), nil
}
