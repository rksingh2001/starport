package networkbuilder

import (
	"context"
	"fmt"
)

type VerificationError struct {
	Err error
}

func (e VerificationError) Error() string {
	return e.Err.Error()
}

// VerifyChain verifies if information of the chain are correct
// Current and only check for now is the eventual custom genesis content
func (b *Builder) VerifyChain(ctx context.Context, chain Chain) error {
	if chain.GenesisURL != "" {
		// Verify custom genesis
		_, hash, err := genesisAndHashFromURL(ctx, chain.GenesisURL)
		if err != nil {
			return err
		}
		if hash != chain.GenesisHash {
			return VerificationError{
				fmt.Errorf(
					"hash of custom genesis for chain %v is incorrect, expected: %v, actual: %v",
					chain.ChainID,
					chain.GenesisHash,
					hash,
				),
			}
		}
	}

	return nil
}
