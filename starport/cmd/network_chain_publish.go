package starportcmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/tendermint/starport/starport/pkg/clispinner"
	"github.com/tendermint/starport/starport/pkg/cosmosaccount"
	"github.com/tendermint/starport/starport/pkg/events"
	"github.com/tendermint/starport/starport/pkg/xurl"
	"github.com/tendermint/starport/starport/services/networkbuilder"
)

const (
	flagTag     = "tag"
	flagBranch  = "branch"
	flagHash    = "hash"
	flagGenesis = "genesis"
)

// NewNetworkChainPublish returns a new command to publish a new chain to start a new network.
func NewNetworkChainPublish() *cobra.Command {
	c := &cobra.Command{
		Use:   "publish [source-url]",
		Short: "Publush a new chain to start a new network",
		Args:  cobra.ExactArgs(1),
		RunE:  networkChainPublishHandler,
	}

	c.Flags().String(flagBranch, "", "Git branch to use for the repo")
	c.Flags().String(flagTag, "", "Git tag to use for the repo")
	c.Flags().String(flagHash, "", "Git hash to use for the repo")
	c.Flags().String(flagGenesis, "", "URL to a custom Genesis")
	c.Flags().String(flagFrom, cosmosaccount.DefaultAccount, "Account name to use for sending transactions to SPN")
	c.Flags().AddFlagSet(flagSetKeyringBackend())
	c.Flags().AddFlagSet(flagSetHome())

	return c
}

func networkChainPublishHandler(cmd *cobra.Command, args []string) error {
	var (
		source        = args[0]
		tag, _        = cmd.Flags().GetString(flagTag)
		branch, _     = cmd.Flags().GetString(flagBranch)
		hash, _       = cmd.Flags().GetString(flagHash)
		genesisURL, _ = cmd.Flags().GetString(flagGenesis)
	)

	s := clispinner.New()
	defer s.Stop()

	ev := events.NewBus()
	go printEvents(ev, s)

	nb, err := newNetworkBuilder(cmd, networkbuilder.CollectEvents(ev))
	if err != nil {
		return err
	}

	// initialize the blockchain
	initOptions := initOptionWithHomeFlag(cmd, []networkbuilder.InitOption{networkbuilder.MustNotInitializedBefore()})

	initChain := func() (*networkbuilder.Blockchain, error) {
		sourceOption := networkbuilder.SourceLocal(source)
		if !xurl.IsLocalPath(source) {
			switch {
			case tag != "":
				sourceOption = networkbuilder.SourceRemoteTag(source, tag)
			case branch != "":
				sourceOption = networkbuilder.SourceRemoteBranch(source, branch)
			case hash != "":
				sourceOption = networkbuilder.SourceRemoteHash(source, hash)
			default:
				sourceOption = networkbuilder.SourceRemote(source)
			}
		}
		return nb.Init(cmd.Context(), sourceOption, initOptions...)
	}

	// init the chain.
	blockchain, err := initChain()

	// ask to delete data dir for the chain if already exists on the fs.
	var e *networkbuilder.DataDirExistsError
	if errors.As(err, &e) {
		s.Stop()

		prompt := promptui.Prompt{
			Label: fmt.Sprintf("Data directory for %q blockchain already exists: %s. Would you like to overwrite it",
				e.ID,
				e.Home,
			),
			IsConfirm: true,
		}
		if _, err := prompt.Run(); err != nil {
			fmt.Println("said no")
			return nil
		}

		if err := os.RemoveAll(e.Home); err != nil {
			return err
		}

		s.Start()

		blockchain, err = initChain()
	}

	s.Stop()

	if err == context.Canceled {
		fmt.Println("aborted")
		return nil
	}
	if err != nil {
		return err
	}
	defer blockchain.Cleanup()

	s.SetText("Submitting...")
	s.Start()

	// create blockchain.
	var createOptions []networkbuilder.CreateOption
	if genesisURL != "" {
		createOptions = append(createOptions, networkbuilder.WithCustomGenesisFromURL(genesisURL))
	}

	if err := blockchain.Create(cmd.Context(), createOptions...); err != nil {
		return err
	}

	s.Stop()

	fmt.Println("\n🌐  Network submitted")
	return nil
}
