// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/koonix/gate/internal/schema"
	"github.com/koonix/x/enc/base64"
	"github.com/koonix/x/omap"
)

func Paths(path string) (srcPath, vaultPath string) {
	before, found := strings.CutSuffix(path, ".gate.json")
	if found {
		srcPath = before
		vaultPath = path
	} else {
		srcPath = path
		vaultPath = path + ".gate.json"
	}
	return srcPath, vaultPath
}

func DecipherPassword(
	ctx context.Context,
	ciphers schema.Map,
) (
	[]byte,
	error,
) {
	errList := make([]error, 0)

	for k, v := range ciphers.All() {
		if k == "gpg" {
			_, pass, err := decryptGpg(ctx, []byte(v))
			if err == nil {
				return pass, nil
			}
			errList = append(errList, err)
		}
	}

	return nil, errors.Join(errList...)
}

func CreateCiphers(
	password []byte,
	owners []schema.Map,
) (
	ciphers schema.Map,
	err error,
) {

	gpgKeys := make([]string, 0)
	ageKeys := make([]string, 0)

	for _, owner := range owners {
		if v, _ := owner.Get("gpg"); v != "" {
			gpgKeys = append(gpgKeys, v)
		}
		if v, _ := owner.Get("age"); v != "" {
			ageKeys = append(ageKeys, v)
		}
	}

	omap.Init(&ciphers)

	if len(gpgKeys) > 0 {
		cmd, cipher, err := encryptGpg(context.Background(), password, gpgKeys...)
		if err != nil {
			return ciphers, fmt.Errorf("could not encrypt with gpg: %w", err)
		}
		if bytes.Contains(cipher, password) {
			return ciphers, fmt.Errorf(
				"gpg-encrypted ciphertext contains the plaintext (%q)",
				cmd,
			)
		}
		ciphers.Set("gpg", string(cipher))
	}

	return ciphers, nil
}

func ChecksumOwners(owners []schema.Map) string {

	buf := new(bytes.Buffer)

	for i, owner := range owners {
		keys := slices.Collect(owner.Keys())
		slices.Sort(keys)
		fmt.Fprintf(buf, "%d\n", i)
		for _, k := range keys {
			v, _ := owner.Get(k)
			fmt.Fprintf(buf,
				"%q:%q\n",
				base64.Encode[string](k),
				base64.Encode[string](v),
			)
		}
	}

	h := sha256.New()
	h.Write(buf.Bytes())
	return string(h.Sum(nil))
}

func MakePassword() []byte {
	x := make([]byte, 32)
	rand.Read(x)
	return base64.EncodeURL[[]byte](x)
}

func makePassword() []byte {
	x := make([]byte, 32)
	rand.Read(x)
	return base64.EncodeURL[[]byte](x)
}

func decryptGpg(
	ctx context.Context,
	data []byte,
) (
	*exec.Cmd,
	[]byte,
	error,
) {
	const GpgBin = "gpg"
	args := append([]string{GpgBin}, "--decrypt")
	return run(ctx, data, args...)
}

func encryptGpg(
	ctx context.Context,
	data []byte,
	recipients ...string,
) (
	*exec.Cmd,
	[]byte,
	error,
) {
	const GpgBin = "gpg"
	args := append([]string{GpgBin}, "--encrypt")
	for _, r := range recipients {
		args = append(args, "--recipient", r)
	}
	return run(ctx, data, args...)
}

func run(
	ctx context.Context,
	stdin []byte,
	args ...string,
) (
	cmd *exec.Cmd,
	stdout []byte,
	err error,
) {
	cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err = cmd.Run()
	if err != nil {
		return cmd, nil, fmt.Errorf(
			"command %q failed: %w\nstdout:\n%s\nstderr:\n%s",
			cmd, err, stdoutBuf.Bytes(), stderrBuf.Bytes(),
		)
	}
	return cmd, stdoutBuf.Bytes(), nil
}
