package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
	"golang.org/x/crypto/ssh"
)

var (
	ErrUnsupportedCLI       = errors.New("unsupported 1Password CLI version")
	ErrNoAccounts           = errors.New("no 1Password accounts are available")
	ErrUnsafeProviderOutput = errors.New("1Password output was rejected by the security policy")
	ErrInvalidPublicKey     = errors.New("1Password public-key field is not a valid SSH public key")
)

type CommandRunner interface {
	Run(ctx context.Context, request process.Request) (process.Result, error)
}

type Provider struct {
	Runner     CommandRunner
	AccountIDs []string

	versionMu      sync.Mutex
	versionChecked bool
	versionErr     error
}

type accountSummary struct {
	ID        string `json:"account_uuid"`
	Name      string `json:"name"`
	Shorthand string `json:"shorthand"`
}

type itemSummary struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
}

func (provider *Provider) Check(ctx context.Context) error {
	if err := provider.ensureCompatible(ctx); err != nil {
		return err
	}
	accounts, err := provider.accounts(ctx)
	if err != nil {
		return err
	}
	request, err := buildVaultListCommand(commandInput{AccountID: accounts[0].ID})
	if err != nil {
		return err
	}
	result, err := provider.safeRun(ctx, request)
	security.Wipe(result.Stdout)
	security.Wipe(result.Stderr)
	if err != nil {
		return fmt.Errorf("verify 1Password CLI sign-in: %w", err)
	}
	return nil
}

func (provider *Provider) ListPublicKeys(ctx context.Context) ([]domain.PublicKeyMetadata, error) {
	if err := provider.ensureCompatible(ctx); err != nil {
		return nil, err
	}
	accounts, err := provider.accounts(ctx)
	if err != nil {
		return nil, err
	}

	var keys []domain.PublicKeyMetadata
	for _, account := range accounts {
		request, buildErr := buildSSHKeyListCommand(commandInput{AccountID: account.ID})
		if buildErr != nil {
			return nil, buildErr
		}
		result, runErr := provider.safeRun(ctx, request)
		if runErr != nil {
			security.Wipe(result.Stdout)
			security.Wipe(result.Stderr)
			return nil, fmt.Errorf("list SSH Key metadata for account: %w", runErr)
		}
		var items []itemSummary
		if err := decodeSingleJSON(result.Stdout, &items); err != nil {
			security.Wipe(result.Stdout)
			security.Wipe(result.Stderr)
			return nil, errors.New("could not parse 1Password SSH Key metadata")
		}
		security.Wipe(result.Stdout)
		security.Wipe(result.Stderr)
		for _, item := range items {
			if !isSSHKeyCategory(item.Category) {
				return nil, errors.New("1Password SSH Key metadata used an unsupported category encoding; expected SSH_KEY")
			}
			if security.ValidateIdentifier("item ID", item.ID, false) != nil {
				return nil, errors.New("1Password SSH Key metadata contained an invalid item ID")
			}
			if security.ValidateIdentifier("vault ID", item.Vault.ID, false) != nil {
				return nil, errors.New("1Password SSH Key metadata contained an invalid Vault ID")
			}
			if security.ValidateDisplayText("item title", item.Title, 256, false) != nil {
				return nil, errors.New("1Password SSH Key metadata contained an unsafe item title")
			}
			if security.ValidateDisplayText("vault name", item.Vault.Name, 256, true) != nil {
				return nil, errors.New("1Password SSH Key metadata contained an unsafe Vault name")
			}
			keys = append(keys, domain.PublicKeyMetadata{
				Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: account.ID, VaultID: item.Vault.ID, ItemID: item.ID},
				Title:     item.Title, VaultName: item.Vault.Name, AccountName: account.Name,
			})
		}
	}
	return keys, nil
}

func isSSHKeyCategory(value string) bool {
	return value == "SSH_KEY" || value == "SSH Key"
}

func (provider *Provider) GetPublicKey(ctx context.Context, reference domain.KeyReference) (domain.AuthorizedKey, error) {
	if err := provider.ensureCompatible(ctx); err != nil {
		return domain.AuthorizedKey{}, err
	}
	if reference.Provider != domain.ProviderOnePassword ||
		security.ValidateIdentifier("account ID", reference.AccountID, true) != nil ||
		security.ValidateIdentifier("vault ID", reference.VaultID, false) != nil ||
		security.ValidateIdentifier("item ID", reference.ItemID, false) != nil {
		return domain.AuthorizedKey{}, errors.New("invalid 1Password public-key reference")
	}
	request, err := buildPublicKeyGetCommand(inputForReference(reference))
	if err != nil {
		return domain.AuthorizedKey{}, err
	}
	result, err := provider.safeRun(ctx, request)
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	if err != nil {
		return domain.AuthorizedKey{}, fmt.Errorf("read the selected public-key field: %w", err)
	}

	publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(result.Stdout))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return domain.AuthorizedKey{}, ErrInvalidPublicKey
	}
	canonical := bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey))
	line := make([]byte, 0, len(canonical)+len(comment)+2)
	line = append(line, canonical...)
	if cleanComment := strings.TrimSpace(comment); cleanComment != "" && security.ValidateDisplayText("public key comment", cleanComment, 256, true) == nil {
		line = append(line, ' ')
		line = append(line, cleanComment...)
	}
	line = append(line, '\n')
	return domain.AuthorizedKey{Line: line, Algorithm: publicKey.Type(), Fingerprint: ssh.FingerprintSHA256(publicKey)}, nil
}

func (provider *Provider) ensureCompatible(ctx context.Context) error {
	if provider.Runner == nil {
		return errors.New("1Password provider has no command runner")
	}
	provider.versionMu.Lock()
	defer provider.versionMu.Unlock()
	if provider.versionChecked {
		return provider.versionErr
	}
	if err := ValidateCommandCatalog(); err != nil {
		provider.versionChecked, provider.versionErr = true, err
		return err
	}
	request, _ := buildVersionCommand(commandInput{})
	result, err := provider.safeRun(ctx, request)
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	if err != nil {
		return fmt.Errorf("check 1Password CLI: %w", err)
	}
	versionText := strings.TrimSpace(string(result.Stdout))
	majorText, _, _ := strings.Cut(versionText, ".")
	major, parseErr := strconv.Atoi(majorText)
	if parseErr != nil || major != 2 {
		provider.versionChecked, provider.versionErr = true, ErrUnsupportedCLI
		return provider.versionErr
	}
	provider.versionChecked = true
	return nil
}

func (provider *Provider) accounts(ctx context.Context) ([]accountSummary, error) {
	request, _ := buildAccountListCommand(commandInput{})
	result, err := provider.safeRun(ctx, request)
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	if err != nil {
		return nil, fmt.Errorf("list 1Password account metadata: %w", err)
	}

	var discovered []accountSummary
	if err := decodeSingleJSON(result.Stdout, &discovered); err != nil {
		return nil, errors.New("could not parse 1Password account metadata")
	}
	byID := make(map[string]accountSummary, len(discovered))
	for _, account := range discovered {
		if security.ValidateIdentifier("account ID", account.ID, false) != nil || security.ValidateDisplayText("account name", account.Name, 256, true) != nil {
			return nil, errors.New("1Password returned invalid account metadata")
		}
		byID[account.ID] = account
	}
	if len(provider.AccountIDs) == 0 {
		if len(discovered) == 0 {
			return nil, ErrNoAccounts
		}
		return discovered, nil
	}
	selected := make([]accountSummary, 0, len(provider.AccountIDs))
	for _, accountID := range provider.AccountIDs {
		if security.ValidateIdentifier("account ID", accountID, false) != nil {
			return nil, errors.New("configured 1Password account ID is invalid")
		}
		account, exists := byID[accountID]
		if !exists {
			return nil, errors.New("configured 1Password account is unavailable")
		}
		selected = append(selected, account)
	}
	return selected, nil
}

func (provider *Provider) safeRun(ctx context.Context, request process.Request) (process.Result, error) {
	result, err := provider.Runner.Run(ctx, request)
	if security.ContainsSensitiveMarker(result.Stdout) || security.ContainsSensitiveMarker(result.Stderr) {
		security.Wipe(result.Stdout)
		security.Wipe(result.Stderr)
		return process.Result{}, ErrUnsafeProviderOutput
	}
	return result, err
}

func decodeSingleJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("unexpected trailing JSON")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
