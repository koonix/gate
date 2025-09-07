// Copyright 2025 the gate authors.
// SPDX-License-Identifier: Apache-2.0

package root_cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{}

func init() {
	chdir := ""
	Cmd.PersistentFlags().StringVarP(&chdir, "chdir", "C", ".", "run as if started in this path")
	Cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if chdir == "." {
			return nil
		}
		err := os.Chdir(chdir)
		if err != nil {
			return fmt.Errorf("could not chdir to directory %q: %w", chdir, err)
		}
		return nil
	}
}
