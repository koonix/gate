// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/koonix/gate/internal/root_cmd"
	"github.com/koonix/x/must"

	_ "github.com/koonix/gate/internal/decrypt_cmd"
	_ "github.com/koonix/gate/internal/encrypt_cmd"
)

func main() {
	must.Do(root_cmd.Cmd.Execute())
}
