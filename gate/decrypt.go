// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"fmt"
	"os"

	"github.com/koonix/gate/internal/schema"
	"github.com/koonix/gate/internal/util"
	"github.com/koonix/x/aes256"
)

func Decrypt(path string) ([]byte, error) {

	_, vaultPath := util.Paths(path)

	vaultBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf(
			"could not read the vault file %q: %w",
			vaultPath, err,
		)
	}

	vault, err := schema.UnmarshalVault(vaultBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"could not parse the vault file %q: %w",
			vaultPath, err,
		)
	}

	pass, err := util.DecipherPassword(context.Background(), vault.Ciphers)
	if err != nil {
		return nil, err
	}

	plaintext, err := aes256.Decrypt(vault.Data, pass)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	return plaintext, nil
}
