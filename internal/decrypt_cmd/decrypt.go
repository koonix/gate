// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package decrypt_cmd

import (
	"os"

	"github.com/koonix/gate/gate"
	"github.com/koonix/gate/internal/root_cmd"
	"github.com/koonix/x/must"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:  "decrypt [flags] file",
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		must.Do(decryptArgs(args))
	},
}

func init() {
	root_cmd.Cmd.AddCommand(Cmd)
}

func decryptArgs(args []string) error {
	plaintext, err := gate.Decrypt(args[0])
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext)
	return err
}
