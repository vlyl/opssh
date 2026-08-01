package onepassword

import (
	"errors"
	"fmt"
	"slices"

	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
)

const publicKeyFieldSelector = "label=public key"

type commandKind uint8

const (
	commandVersion commandKind = iota + 1
	commandAccountList
	commandVaultList
	commandSSHKeyList
	commandPublicKeyGet
)

type commandTemplate struct {
	Kind        commandKind
	Description string
	Build       func(commandInput) (process.Request, error)
}

type commandInput struct {
	AccountID string
	VaultID   string
	ItemID    string
}

var commandCatalog = []commandTemplate{
	{Kind: commandVersion, Description: "read CLI version", Build: buildVersionCommand},
	{Kind: commandAccountList, Description: "list non-sensitive account metadata", Build: buildAccountListCommand},
	{Kind: commandVaultList, Description: "list non-sensitive Vault metadata", Build: buildVaultListCommand},
	{Kind: commandSSHKeyList, Description: "list SSH Key item metadata", Build: buildSSHKeyListCommand},
	{Kind: commandPublicKeyGet, Description: "read one explicit public-key field", Build: buildPublicKeyGetCommand},
}

func buildVersionCommand(commandInput) (process.Request, error) {
	return process.Request{Tool: process.ToolOnePassword, Args: []string{"--version"}, OutputLimit: 64 << 10}, nil
}

func buildAccountListCommand(commandInput) (process.Request, error) {
	return process.Request{Tool: process.ToolOnePassword, Args: []string{"account", "list", "--format=json"}}, nil
}

func buildVaultListCommand(input commandInput) (process.Request, error) {
	if input.AccountID == "" {
		return process.Request{}, errors.New("account ID is required")
	}
	return process.Request{Tool: process.ToolOnePassword, Args: []string{"vault", "list", "--account", input.AccountID, "--format=json"}}, nil
}

func buildSSHKeyListCommand(input commandInput) (process.Request, error) {
	if input.AccountID == "" {
		return process.Request{}, errors.New("account ID is required")
	}
	return process.Request{
		Tool:        process.ToolOnePassword,
		Args:        []string{"item", "list", "--categories", "SSH Key", "--account", input.AccountID, "--format=json"},
		OutputLimit: 4 << 20,
	}, nil
}

func buildPublicKeyGetCommand(input commandInput) (process.Request, error) {
	if input.VaultID == "" || input.ItemID == "" {
		return process.Request{}, errors.New("vault ID and item ID are required")
	}
	args := []string{"item", "get", input.ItemID, "--vault", input.VaultID}
	if input.AccountID != "" {
		args = append(args, "--account", input.AccountID)
	}
	args = append(args, "--fields", publicKeyFieldSelector)
	return process.Request{Tool: process.ToolOnePassword, Args: args, OutputLimit: 256 << 10}, nil
}

type AuditFinding struct {
	Command string `json:"command"`
	Safe    bool   `json:"safe"`
	Reason  string `json:"reason"`
}

// AuditCommandCatalog verifies the registered op argv templates without
// executing them.
func AuditCommandCatalog() []AuditFinding {
	findings := make([]AuditFinding, 0, len(commandCatalog))
	for _, template := range commandCatalog {
		input := commandInput{AccountID: "audit-account", VaultID: "audit-vault", ItemID: "audit-item"}
		request, err := template.Build(input)
		finding := AuditFinding{Command: template.Description, Safe: true, Reason: "explicitly allow-listed metadata command"}
		if err != nil {
			finding.Safe = false
			finding.Reason = "template could not be constructed"
		} else if request.Tool != process.ToolOnePassword {
			finding.Safe = false
			finding.Reason = "template targets an unexpected executable"
		} else if containsForbiddenArgument(request.Args) {
			finding.Safe = false
			finding.Reason = "template contains a forbidden argument"
		} else if template.Kind == commandPublicKeyGet && !hasExactPublicKeySelector(request.Args) {
			finding.Safe = false
			finding.Reason = "item get is not restricted to the public-key field"
		} else if isItemGet(request.Args) && template.Kind != commandPublicKeyGet {
			finding.Safe = false
			finding.Reason = "unregistered item get template"
		}
		findings = append(findings, finding)
	}
	return findings
}

func ValidateCommandCatalog() error {
	for _, finding := range AuditCommandCatalog() {
		if !finding.Safe {
			return fmt.Errorf("unsafe 1Password command catalog entry: %s", finding.Command)
		}
	}
	return nil
}

func containsForbiddenArgument(args []string) bool {
	for _, forbidden := range []string{"--reveal", "--otp", "--share-link", "--include-archive"} {
		if slices.Contains(args, forbidden) {
			return true
		}
	}
	if slices.Contains(args, "read") || slices.Contains(args, "document") || slices.Contains(args, "edit") || slices.Contains(args, "delete") {
		return true
	}
	return false
}

func hasExactPublicKeySelector(args []string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--fields" && args[index+1] == publicKeyFieldSelector {
			return true
		}
	}
	return false
}

func isItemGet(args []string) bool {
	return len(args) >= 2 && args[0] == "item" && args[1] == "get"
}

func inputForReference(reference domain.KeyReference) commandInput {
	return commandInput{AccountID: reference.AccountID, VaultID: reference.VaultID, ItemID: reference.ItemID}
}
