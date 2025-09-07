// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/koonix/x/enc/base64"
	"github.com/koonix/x/must"
	"github.com/koonix/x/omap"
)

type Map = omap.Map[string, string]

type Vault struct {
	Data           []byte
	Owners         []Map
	OwnersChecksum string
	Ciphers        Map
}

type schema struct {
	Data   []byte `json:"data"`
	Owners []Map  `json:"owners"`
	Meta   Map    `json:"meta"`
}

func MarshalVault(vault Vault) []byte {
	var s schema
	s.Owners = vault.Owners
	s.Data = vault.Data
	omap.Init(&s.Meta)
	s.Meta.Set("owners_checksum", base64.Encode[string](vault.OwnersChecksum))
	for k, v := range vault.Ciphers.All() {
		s.Meta.Set(k+"_cipher", base64.Encode[string](v))
	}
	return must.Get(json.MarshalIndent(s, "", "\t"))
}

func UnmarshalVault(b []byte) (vault Vault, err error) {

	var s schema

	err = json.Unmarshal(b, &s)
	if err != nil {
		return vault, fmt.Errorf("could not unmarshal json: %w", err)
	}

	vault.Data = s.Data
	vault.Owners = s.Owners

	ownersChecksum, _ := s.Meta.Get("owners_checksum")
	ownersChecksum, err = base64.Decode[string](ownersChecksum)
	if err != nil {
		return vault, fmt.Errorf(
			"could not decode base64 in the %q value: %w",
			"owners_checksum", err,
		)
	}
	vault.OwnersChecksum = ownersChecksum

	omap.Init(&vault.Ciphers)

	for k, v := range s.Meta.All() {
		x, found := strings.CutSuffix(k, "_cipher")
		if !found {
			continue
		}
		v, err = base64.Decode[string](v)
		if err != nil {
			return vault, fmt.Errorf(
				"could not decode base64 in the %q value: %w",
				k, err,
			)
		}
		vault.Ciphers.Set(x, v)
	}

	return vault, nil
}
