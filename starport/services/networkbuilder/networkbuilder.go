package networkbuilder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	sdktypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/tendermint/starport/starport/chainconfig"
	"github.com/tendermint/starport/starport/pkg/chaincmd"
	"github.com/tendermint/starport/starport/pkg/cosmosaccount"
	"github.com/tendermint/starport/starport/pkg/cosmosclient"
	"github.com/tendermint/starport/starport/pkg/events"
	"github.com/tendermint/starport/starport/pkg/jsondoc"
	"github.com/tendermint/starport/starport/pkg/xfilepath"
)

const (
	spnAddressPrefix = "spn"
)

var (
	// spnChainSourcePath returns the path used for the chain source used to build spn chains
	spnChainSourcePath = xfilepath.Join(
		chainconfig.ConfigDirPath,
		xfilepath.Path("spn-chains"),
	)

	spnChainHomesDir = xfilepath.JoinFromHome(
		xfilepath.Path(".spn-chain-homes"),
	)
)

// Builder is network builder.
type Builder struct {
	ev      events.Bus
	cosmos  cosmosclient.Client
	account cosmosaccount.Account
}

type Option func(*Builder)

// CollectEvents collects events from Builder.
func CollectEvents(ev events.Bus) Option {
	return func(b *Builder) {
		b.ev = ev
	}
}

// New creates a Builder.
func New(cosmos cosmosclient.Client, account cosmosaccount.Account, options ...Option) (*Builder, error) {
	b := &Builder{
		cosmos:  cosmos,
		account: account,
	}
	for _, opt := range options {
		opt(b)
	}
	return b, nil
}

// initOptions holds blockchain initialization options.
type initOptions struct {
	chainID                  string
	url                      string
	ref                      plumbing.ReferenceName
	hash                     string
	path                     string
	mustNotInitializedBefore bool
	homePath                 string
	keyringBackend           chaincmd.KeyringBackend
}

// newInitOptions initializes initOptions
func newInitOptions(chainID string, options ...InitOption) (initOpts initOptions, err error) {
	var homePath string
	if chainID != "" {
		homePath, err = xfilepath.Join(
			spnChainHomesDir,
			xfilepath.Path(chainID),
		)()
	} else {
		homePath, err = os.MkdirTemp("", "")
	}
	if err != nil {
		return initOpts, err
	}
	initOpts.homePath = homePath

	// set custom options
	for _, option := range options {
		option(&initOpts)
	}

	return initOpts, nil
}

// SourceOption sets the source for blockchain.
type SourceOption func(*initOptions)

// InitOption sets other initialization options.
type InitOption func(*initOptions)

// SourceChainID makes source determined by the chain's id.
func SourceChainID(chainID string) SourceOption {
	return func(o *initOptions) {
		o.chainID = chainID
	}
}

// SourceRemote sets the default branch on a remote as source for the blockchain.
func SourceRemote(url string) SourceOption {
	return func(o *initOptions) {
		o.url = url
	}
}

// SourceRemoteBranch sets the branch on a remote as source for the blockchain.
func SourceRemoteBranch(url, branch string) SourceOption {
	return func(o *initOptions) {
		o.url = url
		o.ref = plumbing.NewBranchReferenceName(branch)
	}
}

// SourceRemoteTag sets the tag on a remote as source for the blockchain.
func SourceRemoteTag(url, tag string) SourceOption {
	return func(o *initOptions) {
		o.url = url
		o.ref = plumbing.NewTagReferenceName(tag)
	}
}

// SourceRemoteHash uses a remote hash as source for the blockchain.
func SourceRemoteHash(url, hash string) SourceOption {
	return func(o *initOptions) {
		o.url = url
		o.hash = hash
	}
}

// SourceLocal uses a local git repo as source for the blockchain.
func SourceLocal(path string) SourceOption {
	return func(o *initOptions) {
		o.path = path
	}
}

// MustNotInitializedBefore makes the initialization process fail if data dir for
// the blockchain already exists.
func MustNotInitializedBefore() InitOption {
	return func(o *initOptions) {
		o.mustNotInitializedBefore = true
	}
}

// InitializationHomePath provides a specific home path for the blockchain for the initialization
func InitializationHomePath(homePath string) InitOption {
	return func(o *initOptions) {
		o.homePath = homePath
	}
}

// InitializationKeyringBackend provides the keyring backend to use to initialize the blockchain
func InitializationKeyringBackend(keyringBackend chaincmd.KeyringBackend) InitOption {
	return func(o *initOptions) {
		o.keyringBackend = keyringBackend
	}
}

// Init initializes blockchain from by source option and init options.
func (b *Builder) Init(ctx context.Context, source SourceOption, options ...InitOption) (*Blockchain, error) {
	o, err := newInitOptions("", options...)
	if err != nil {
		return nil, err
	}
	source(&o)

	// determine final source configuration.
	var (
		url  = o.url
		hash = o.hash
		path = o.path
		ref  = o.ref
	)

	// pull the chain.
	b.ev.Send(events.New(events.StatusOngoing, "Fetching the source code"))

	var (
		repo    *git.Repository
		githash plumbing.Hash
	)

	switch {
	// clone git repo from local filesystem. this option only used by chain coordinators.
	case path != "":
		if repo, err = git.PlainOpen(path); err != nil {
			return nil, err
		}
		if url, err = b.ensureRemoteSynced(repo); err != nil {
			return nil, err
		}

	// otherwise clone from the remote. this option can be used by chain coordinators
	// as well as validators.
	default:
		sourcePath, err := spnChainSourcePath()
		if err != nil {
			return nil, err
		}

		// ensure the path for chain source exists
		if err := os.MkdirAll(sourcePath, 0755); err != nil {
			return nil, err
		}

		path = filepath.Join(sourcePath, o.chainID)
		if _, err := os.Stat(path); err == nil {
			// if the directory already exists, we overwrite it to ensure we have the last version
			if err := os.RemoveAll(path); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}

		// prepare clone options.
		gitoptions := &git.CloneOptions{
			URL: url,
		}

		// clone the ref when specificied. this is used by chain coordinators on create.
		if ref != "" {
			gitoptions.ReferenceName = ref
			gitoptions.SingleBranch = true
		}
		if repo, err = git.PlainCloneContext(ctx, path, false, gitoptions); err != nil {
			return nil, err
		}

		if hash != "" {
			// checkout to a certain hash when specified. this is used by validators to make sure to use
			// the locked version of the blockchain.
			wt, err := repo.Worktree()
			if err != nil {
				return nil, err
			}
			h, err := repo.ResolveRevision(plumbing.Revision(hash))
			if err != nil {
				return nil, err
			}
			githash = *h
			if err := wt.Checkout(&git.CheckoutOptions{
				Hash: githash,
			}); err != nil {
				return nil, err
			}
		}
	}

	b.ev.Send(events.New(events.StatusDone, "Source code fetched"))

	if hash == "" {
		ref, err := repo.Head()
		if err != nil {
			return nil, err
		}
		githash = ref.Hash()
	}

	return newBlockchain(
		ctx,
		b,
		o.chainID,
		path,
		url,
		githash.String(),
		o.homePath,
		o.keyringBackend,
		o.mustNotInitializedBefore,
	)
}

// ensureRemoteSynced ensures that current worktree in the repository has no unstaged
// changes and synced up with the remote.
// it returns the url of repo or an error related to unstaged changes.
func (b *Builder) ensureRemoteSynced(repo *git.Repository) (url string, err error) {
	// check if there are un-committed changes.
	wt, err := repo.Worktree()
	if err != nil {
		return "", err
	}
	status, err := wt.Status()
	if err != nil {
		return "", err
	}
	if !status.IsClean() {
		return "", errors.New("please either revert or commit your changes")
	}

	// find out remote's url.
	// TODO use the associated upstream branch's remote.
	remotes, err := repo.Remotes()
	if err != nil {
		return "", err
	}
	if len(remotes) == 0 {
		return "", errors.New("please push your blockchain first")
	}
	remote := remotes[0]
	rc := remote.Config()
	if len(rc.URLs) == 0 {
		return "", errors.New("cannot find remote's url")
	}
	return rc.URLs[0], nil
}

type GenesisAccount struct {
	Address string
	Coins   sdktypes.Coins
}

type LaunchInformation struct {
	GenesisAccounts []GenesisAccount
	GenTxs          []jsondoc.Doc
	Peers           []string
}
type Chain struct {
	ChainID     string
	Creator     string
	URL         string
	Hash        string
	GenesisURL  string
	GenesisHash string
	CreatedAt   time.Time
}
