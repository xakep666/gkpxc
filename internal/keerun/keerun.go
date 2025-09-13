package keerun

import (
	"bytes"
	"encoding/json"
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
}

type T interface {
	Helper()
	Cleanup(func())
	Fatalf(msg string, args ...any)
	Logf(msg string, args ...any)
}

func NewKeeRun(t T) *KeeRun {
	t.Helper()
	passBytes, err := os.ReadFile(filepath.Join(dir, "testdata", "passwd"))
	if err != nil {
		t.Fatalf("password read: %s", err)
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
	cmd.Stdout = &tLogWriter{T: t, Prefix: "[keepassxc] "}
	cmd.Stderr = &tLogWriter{T: t, Prefix: "[keepassxc err] "}

	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	return &KeeRun{
		Cmd: cmd,
	}
}

func (k *KeeRun) Start(t T) {
	t.Helper()

	if err := k.Cmd.Start(); err != nil {
		t.Fatalf("start: %s", err)
	}
}

func (k *KeeRun) Lock(t T) {
	t.Helper()

	cmd := exec.Command(k.Path, "--lock")
	cmd.Stdout = k.Stdout
	cmd.Stderr = k.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("lock: %s", err)
	}
}

func DecodeAssociationCreds(t T, to any) {
	t.Helper()

	f, err := os.Open(filepath.Join(dir, "testdata", "assoc.json"))
	if err != nil {
		t.Fatalf("open file: %s", err)
	}

	defer f.Close()

	if err := json.NewDecoder(f).Decode(to); err != nil {
		t.Fatalf("decode: %s", err)
	}
}

type tLogWriter struct {
	T
	Prefix string
}

func (t *tLogWriter) Write(p []byte) (n int, err error) {
	t.Helper()
	t.Logf("%s: %s", t.Prefix, p)
	return len(p), nil
}
