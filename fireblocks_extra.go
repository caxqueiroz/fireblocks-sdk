package fireblocks

type ExtraParameters struct {
	ContractCallData string `json:"contractCallData"`
}

type ErrorMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type TransactionStatus string

type CreateTransactionResponse struct {
	Id     string            `json:"Id"`
	Status TransactionStatus `json:"status"`
	Error  error
}

type CreateVaultAssetResponse struct {
	Id      string `json:"Id"`      // the Id of the asset
	Address string `json:"address"` // Address of the asset in a Vault Account,
	// for BTC/LTC the address is in segwit (Bech32) format, cash address format BCH
	LegacyAddress  string `json:"legacyAddress"`  // legacy address format for BTC/LTC/BCH
	Tag            string `json:"tag"`            // destination tag for XRP, memo for EOS/XLM
	EosAccountName string `json:"eosAccountName"` // returned for EOS, the acct name.
}

const (
	TransactionSubmitted TransactionStatus = "SUBMITTED"
	QUEUED                                 = "QUEUED"
	PendingAuthorization                   = "PENDING_AUTHORIZATION"
	PendingSignature                       = "PENDING_SIGNATURE"
)

type AssetTypeResponse struct {
	Id              string    `json:"Id"`
	Name            string    `json:"name"`
	TypeAsset       AssetType `json:"typeAsset"`
	ContractAddress string    `json:"contractAddress"`
}

type UnsignedMessage struct {
	content           string //message to be signed - hex format.
	bip44AddressIndex int    //
	bib44Change       int    //bit44 change path level
	derivationPath    []int
}

type RawMessage struct {
	messages  []UnsignedMessage
	algorithm SigningAlgorithm
}

type OneTimeAddress struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type TransferPeerPath struct {
	TPeerType PeerType `json:"type"`
	TPeerId   string   `json:"Id"`
}

type DestinationTransferPeerPath struct {
	TPeerType PeerType       `json:"type"`
	TPeerId   string         `json:"Id"`
	Ota       OneTimeAddress `json:"oneTimeAddress"`
}

type VaultAccount struct {
	Id            string       `json:"id"`
	Name          string       `json:"name"`
	HiddenOnUI    bool         `json:"hiddenOnUI"`
	CustomerRefId string       `json:"customerRefId"`
	AutoFuel      bool         `json:"autoFuel"`
	Assets        []VaultAsset `json:"assets"`
}

type VaultAsset struct {
	Id                   string `json:"Id"`
	Total                string `json:"total"`
	Available            string `json:"available"`
	Pending              string `json:"pending"`
	LockedAmount         string `json:"lockedAmount"`
	TotalStackedCPU      string `json:"totalStackedCPU"`
	TotalStackedNetwork  string `json:"totalStackedNetwork"`
	SelfStackedCPU       string `json:"selfStackedCPU"`
	SelfStakedNetwork    string `json:"selfStakedNetwork"`
	PendingRefundCPU     string `json:"pendingRefundCPU"`
	PendingRefundNetwork string `json:"pendingRefundNetwork"`
}

type PeerType string

const (
	VAULT_ACCOUNT     PeerType = "VAULT_ACCOUNT"
	ExchangeAccount            = "EXCHANGE_ACCOUNT"
	InternalWallet             = "INTERNAL_WALLET"
	ExternalWallet             = "EXTERNAL_WALLET"
	UnknownPeer                = "UNKNOWN"
	FiatAccount                = "FIAT_ACCOUNT"
	NetworkConnection          = "NETWORK_CONNECTION"
	COMPOUND                   = "COMPOUND"
)

type AssetType string

const (
	BaseAsset AssetType = "BASE_ASSET"
	ETH                 = "ETH"
	CONTRACT            = "CONTRACT"
	FIAT                = "FIAT"
)

type SigningAlgorithm string

const (
	MPC_ECDSA_SECP256K1 SigningAlgorithm = "MPC_ECDSA_SECP256K1"
	MPC_EDDSA_ED25519                    = "MPC_EDDSA_ED25519"
)

type FeeLevel string

const (
	HIGH   FeeLevel = "HIGH"
	MEDIUM          = "MEDIUM"
	LOW             = "LOW"
)

type TransactionType string

const (
	TransactionStatusSubmitted                           TransactionType = "SUBMITTED"
	TransactionStatusQueued                                              = "QUEUED"
	TRANSACTION_STATUS_PENDING_SIGNATURE                                 = "PENDING_SIGNATURE"
	TRANSACTION_STATUS_PENDING_AUTHORIZATION                             = "PENDING_AUTHORIZATION"
	TRANSACTION_STATUS_PENDING_3RD_PARTY_MANUAL_APPROVAL                 = "PENDING_3RD_PARTY_MANUAL_APPROVAL"
	TRANSACTION_STATUS_PENDING_3RD_PARTY                                 = "PENDING_3RD_PARTY"
	TRANSACTION_STATUS_PENDING                                           = "PENDING" // Deprecated
	TRANSACTION_STATUS_BROADCASTING                                      = "BROADCASTING"
	TRANSACTION_STATUS_CONFIRMING                                        = "CONFIRMING"
	TRANSACTION_STATUS_CONFIRMED                                         = "CONFIRMED" // Deprecated
	TRANSACTION_STATUS_COMPLETED                                         = "COMPLETED"
	TRANSACTION_STATUS_PENDING_AML_CHECKUP                               = "PENDING_AML_CHECKUP"
	TRANSACTION_STATUS_PARTIALLY_COMPLETED                               = "PARTIALLY_COMPLETED"
	TRANSACTION_STATUS_CANCELLING                                        = "CANCELLING"
	TRANSACTION_STATUS_CANCELLED                                         = "CANCELLED"
	TRANSACTION_STATUS_REJECTED                                          = "REJECTED"
	TRANSACTION_STATUS_FAILED                                            = "FAILED"
	TRANSACTION_STATUS_TIMEOUT                                           = "TIMEOUT"
	TRANSACTION_STATUS_BLOCKED                                           = "BLOCKED"
	TransactionTransfer                                                  = "TRANSFER"
	TransactionMint                                                      = "MINT"
	TransactionBurn                                                      = "BURN"
	TRANSACTION_SUPPLY_TO_COMPOUND                                       = "SUPPLY_TO_COMPOUND"
	TRANSACTION_REDEEM_FROM_COMPOUND                                     = "REDEEM_FROM_COMPOUND"
	RAW                                                                  = "RAW"
	ContractCall                                                         = "CONTRACT_CALL"
	ONE_TIME_ADDRESS                                                     = "ONE_TIME_ADDRESS"
)
