package proto

// Why a host reports no signed-in identity. These are fixed codes, never text from the host: a
// code may not carry a path, a user name, an email or a token, and the hub drops any value that is
// not one of them (KnownIdentityReason), so an agent cannot push free text into the admin UI.
const (
	// ReasonNoClaudeJSON: the agent found no ~/.claude.json (Claude Code never signed in here).
	ReasonNoClaudeJSON = "no_claude_json"
	// ReasonNoOAuthAccount: the file is there and parses, but names no oauthAccount.
	ReasonNoOAuthAccount = "no_oauth_account"
	// ReasonUnreadable: the file exists and the agent may not read it (permissions).
	ReasonUnreadable = "unreadable"
	// ReasonConfigDirElsewhere: CLAUDE_CONFIG_DIR points the agent at another config dir, and no
	// account is signed in there.
	ReasonConfigDirElsewhere = "config_dir_elsewhere"
	// ReasonHomeMismatch: the user the agent runs as has no signed-in Claude Code, while another
	// user on the host does.
	ReasonHomeMismatch = "home_mismatch"
	// ReasonParseError: the file is there but is not the JSON the agent expects.
	ReasonParseError = "parse_error"
	// ReasonNoCredentials: an account is named but the host holds no usable login block.
	ReasonNoCredentials = "no_credentials"
)

// KnownIdentityReason reports whether code is one of the identity reasons this version knows.
// An empty code is not a reason: it means the identity is known.
func KnownIdentityReason(code string) bool {
	switch code {
	case ReasonNoClaudeJSON, ReasonNoOAuthAccount, ReasonUnreadable, ReasonConfigDirElsewhere,
		ReasonHomeMismatch, ReasonParseError, ReasonNoCredentials:
		return true
	}
	return false
}
