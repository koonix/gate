// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package encrypt_cmd

import (
	"github.com/koonix/gate/gate"
	"github.com/koonix/gate/internal/root_cmd"
	"github.com/koonix/x/must"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:  "encrypt [flags] file...",
	Args: cobra.MinimumNArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		must.Do(encrypt(args))
	},
}

func init() {
	root_cmd.Cmd.AddCommand(Cmd)
}

func encrypt(args []string) error {
	for _, arg := range args {
		err := gate.Encrypt(arg)
		if err != nil {
			return err
		}
	}
	return nil
}
