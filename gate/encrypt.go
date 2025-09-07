// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/koonix/gate/internal/schema"
	"github.com/koonix/gate/internal/util"
	"github.com/koonix/x/aes256"
	"github.com/koonix/x/file"
)

func Encrypt(path string) error {

	srcPath, vaultPath := util.Paths(path)

	vaultBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf(
			"could not read the vault file %q: %w",
			vaultPath, err,
		)
	}

	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf(
			"could not read file %q: %w",
			vaultPath, err,
		)
	}

	vault, err := schema.UnmarshalVault(vaultBytes)
	if err != nil {
		return fmt.Errorf(
			"could not parse the vault file %q: %w",
			vaultPath, err,
		)
	}

	ownersChecksum := util.ChecksumOwners(vault.Owners)

	if ownersChecksum == vault.OwnersChecksum && len(vault.Data) > 0 {
		pass, err := util.DecipherPassword(context.Background(), vault.Ciphers)
		if err != nil {
			return err
		}
		plaintext, err := aes256.Decrypt(vault.Data, pass)
		if err != nil {
			return fmt.Errorf("could not decrypt data: %w", err)
		}
		if bytes.Equal(srcBytes, plaintext) {
			return nil
		}
	}

	pass := util.MakePassword()

	vault.Ciphers, err = util.CreateCiphers(pass, vault.Owners)
	if err != nil {
		return err
	}

	vault.OwnersChecksum = ownersChecksum
	vault.Data = aes256.Encrypt(srcBytes, pass)

	vaultBytes = schema.MarshalVault(vault)

	err = file.WriteAtomic(vaultPath, vaultBytes, 0644)
	if err != nil {
		return fmt.Errorf("could not write file %q: %w", vaultPath, err)
	}

	return nil
}
