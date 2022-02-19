package keerun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func NewKeeRun() (*KeeRun, error) {
	passBytes, err := os.ReadFile(filepath.Join(dir, "testdata", "passwd"))
	if err != nil {
		return nil, fmt.Errorf("password read: %w", err)
	}

	keepassxc, err := exec.LookPath("keepassxc")
	if err != nil {
		return nil, fmt.Errorf("keepassxc lookup: %w", err)
	}

	return &KeeRun{
		Cmd: &exec.Cmd{
			Path: keepassxc,
			Args: append([]string{"keepassxc"},
				"--pw-stdin",
				"--config", filepath.Join(dir, "testdata", "config.ini"),
				"--platform", "offscreen",
				filepath.Join(dir, "testdata", "test.kdbx")),
			Stdin: bytes.NewReader(passBytes),
		},
		password: passBytes,
	}, nil
}

func (k *KeeRun) Lock() error {
	return exec.Command(k.Path, "--lock").Run()
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
