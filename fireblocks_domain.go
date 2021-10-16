package fireblocks

import (
	"github.com/shopspring/decimal"
)

type ExternalWalletAsset struct {
	Id             string                    `json:"id"`             // the id of the asset
	Status         ConfigChangeRequestStatus `json:"status"`         // Status of the External Wallet
	ActivationTime string                    `json:"activationTime"` // The time the wallet will be activated in case wallets activation posponed according to workspace definition
	Address        string                    `json:"address"`        // The address of the wallet
	Tag            string                    `json:"tag"`            // Destination tag (for XRP, used as memo for EOS/XLM) of the wallet, for SEN/Signet used as Bank Transfer Description

}

type ExternalWallet struct {
	Id            string                `json:"id"`                      //The ID of the Unmanaged Wallet
	Name          string                `json:"name"`                    // Name of the Wallet Container
	CustomerRefId string                `json:"customerRefId,omitempty"` //[optional] The ID for AML providers to associate the owner of funds with transactions
	Assets        []ExternalWalletAsset `json:"assets"`                  //Array of the assets available in the exteral wallet
}

type UnmanagedWallet struct {
	Id            string
	Name          string
	CustomerRefId string
	Assets        []WalletAsset
}

type WalletAsset struct {
	Id             string                    `json:"id"`             // the id of the asset
	Balance        string                    `json:"balance"`        // the balance of the wallet
	LockedAmount   string                    `json:"lockedAmount"`   // locked amount in the wallet
	Status         ConfigChangeRequestStatus `json:"status"`         // Status of the External Wallet
	ActivationTime string                    `json:"activationTime"` // The time the wallet will be activated in case wallets activation posponed according to workspace definition
	Address        string                    `json:"address"`        // The address of the wallet
	Tag            string                    `json:"tag"`            // Destination tag (for XRP, used as memo for EOS/XLM) of the wallet, for SEN/Signet used as Bank Transfer Description

}

type User struct {
	Id        string `json:"id"`        // User ID on the Fireblocks platform
	FirstName string `json:"firstName"` // First name
	LastName  string `json:"lastName"`  // Last name
	Role      string `json:"role"`      // The role of the user in the workspace
	Email     string `json:"email"`     // The email of the user
	Enabled   bool   `json:"enabled"`   //The status of the user in the workspace
}

type ConfigChangeRequestStatus string

const (
	WaitingForApproval ConfigChangeRequestStatus = "WAITING_FOR_APPROVAL"
	Approved                                     = "APPROVED"
	Cancelled                                    = "CANCELLED"
	Rejected                                     = "REJECTED"
	Failed                                       = "FAILED"
)

type CreateAddressResponse struct {
	Address       string `json:"address"`       //Address of the asset in a Vault Account, for BTC/LTC the address is in Segwit (Bech32) format, cash address format for BCH
	LegacyAddress string `json:"legacyAddress"` // Legacy address format for BTC/LTC/BCH
	Tag           string `json:"tag"`           // Destination tag for XRP, used as memo for EOS/XLM
}

type ExtraParameters struct {
	ContractCallData string `json:"contractCallData"`
}

type ErrorMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type TransactionStatus string

const (
	TransactionStatusSubmitted               TransactionStatus = "SUBMITTED"
	TransactionStatusQueued                                    = "QUEUED"
	TransactionPendingSignature                                = "PENDING_SIGNATURE"
	TransactionPendingAuthorization                            = "PENDING_AUTHORIZATION"
	TransactionPending3rdPartyManualApproval                   = "PENDING_3RD_PARTY_MANUAL_APPROVAL"
	TransactionPending3rdParty                                 = "PENDING_3RD_PARTY"
	TransactionPending                                         = "PENDING" // Deprecated
	TransactionBroadcasting                                    = "BROADCASTING"
	TransactionConfirming                                      = "CONFIRMING"
	TransactionConfirmed                                       = "CONFIRMED" // Deprecated
	TransactionCompleted                                       = "COMPLETED"
	TransactionPendingAmlCheckup                               = "PENDING_AML_CHECKUP"
	TransactionPartiallyCompleted                              = "PARTIALLY_COMPLETED"
	TransactionCancelling                                      = "CANCELLING"
	TransactionCancelled                                       = "CANCELLED"
	TransactionRejected                                        = "REJECTED"
	TransactionFailed                                          = "FAILED"
	TransactionTimeout                                         = "TIMEOUT"
	TransactionBlocked                                         = "BLOCKED"
)

type TransactionSubStatus string

const (
	InsufficientFunds               TransactionSubStatus = "INSUFFICIENT_FUNDS"
	AmountTooSmall                                       = "AMOUNT_TOO_SMALL"
	UnsupportedAsset                                     = "UNSUPPORTED_ASSET"
	UnauthorisedMissingPermission                        = "UNAUTHORISED__MISSING_PERMISSION"
	InvalidSignature                                     = "INVALID_SIGNATURE"
	ApiInvalidSignature                                  = "API_INVALID_SIGNATURE"
	UnauthorisedMissingCredentials                       = "UNAUTHORISED__MISSING_CREDENTIALS"
	UnauthorisedUser                                     = "UNAUTHORISED__USER"
	UnauthorisedDevice                                   = "UNAUTHORISED__DEVICE"
	InvalidUnmanagedWallet                               = "INVALID_UNMANAGED_WALLET"
	InvalidExchangeAccount                               = "INVALID_EXCHANGE_ACCOUNT"
	InsufficientFundsForFee                              = "INSUFFICIENT_FUNDS_FOR_FEE"
	InvalidAddress                                       = "INVALID_ADDRESS"
	WithdrawLimit                                        = "WITHDRAW_LIMIT"
	ApiCallLimit                                         = "API_CALL_LIMIT"
	AddressNotWhitelisted                                = "ADDRESS_NOT_WHITELISTED"
	TIMEOUT                                              = "TIMEOUT"
	ConnectivityError                                    = "CONNECTIVITY_ERROR"
	ThirdPartyInternalError                              = "THIRD_PARTY_INTERNAL_ERROR"
	CancelledExternally                                  = "CANCELLED_EXTERNALLY"
	InvalidThirdPartyResponse                            = "INVALID_THIRD_PARTY_RESPONSE"
	VaultWalletNotReady                                  = "VAULT_WALLET_NOT_READY"
	MissingDepositAddress                                = "MISSING_DEPOSIT_ADDRESS"
	OneTimeAddressDisabled                               = "ONE_TIME_ADDRESS_DISABLED"
	InternalError                                        = "INTERNAL_ERROR"
	UnknownError                                         = "UNKNOWN_ERROR"
	AuthorizerNotFound                                   = "AUTHORIZER_NOT_FOUND"
	InsufficientReservedFunding                          = "INSUFFICIENT_RESERVED_FUNDING"
	ManualDepositAddressRequired                         = "MANUAL_DEPOSIT_ADDRESS_REQUIRED"
	InvalidFee                                           = "INVALID_FEE"
	ErrorUnsupportedTransactionType                      = "ERROR_UNSUPPORTED_TRANSACTION_TYPE"
	UnsupportedOperation                                 = "UNSUPPORTED_OPERATION"
	T3rdPartyProcessing                                  = "3RD_PARTY_PROCESSING"
	PendingBlockchainConfirmations                       = "PENDING_BLOCKCHAIN_CONFIRMATIONS"
	T3rdPartyConfirming                                  = "3RD_PARTY_CONFIRMING"
	CONFIRMED                                            = "CONFIRMED"
	T3rdPartyCompleted                                   = "3RD_PARTY_COMPLETED"
	RejectedByUser                                       = "REJECTED_BY_USER"
	CancelledByUser                                      = "CANCELLED_BY_USER"
	T3rdPartyCancelled                                   = "3RD_PARTY_CANCELLED"
	T3rdPartyRejected                                    = "3RD_PARTY_REJECTED"
	AmlScreeningRejected                                 = "AML_SCREENING_REJECTED"
	BlockedByPolicy                                      = "BLOCKED_BY_POLICY"
	FailedAmlScreening                                   = "FAILED_AML_SCREENING"
	PartiallyFailed                                      = "PARTIALLY_FAILED"
	T3rdPartyFailed                                      = "3RD_PARTY_FAILED"
	DroppedByBlockchain                                  = "DROPPED_BY_BLOCKCHAIN"
	TooManyInputs                                        = "TOO_MANY_INPUTS"
	SigningError                                         = "SIGNING_ERROR"
	InvalidFeeParams                                     = "INVALID_FEE_PARAMS"
	MissingTagOrMemo                                     = "MISSING_TAG_OR_MEMO"
	GasLimitTooLow                                       = "GAS_LIMIT_TOO_LOW"
	MaxFeeExceeded                                       = "MAX_FEE_EXCEEDED"
	ActualFeeTooHigh                                     = "ACTUAL_FEE_TOO_HIGH"
	InvalidContractCallData                              = "INVALID_CONTRACT_CALL_DATA"
	InvalidNonceTooLow                                   = "INVALID_NONCE_TOO_LOW"
	InvalidNonceTooHigh                                  = "INVALID_NONCE_TOO_HIGH"
	InvalidNonceForRbf                                   = "INVALID_NONCE_FOR_RBF"
	FailOnLowFee                                         = "FAIL_ON_LOW_FEE"
	TooLongMempoolChain                                  = "TOO_LONG_MEMPOOL_CHAIN"
	TxOutdated                                           = "TX_OUTDATED"
	IncompleteUserSetup                                  = "INCOMPLETE_USER_SETUP"
	SignerNotFound                                       = "SIGNER_NOT_FOUND"
	InvalidTagOrMemo                                     = "INVALID_TAG_OR_MEMO"
	ZeroBalanceInPermanentAddress                        = "ZERO_BALANCE_IN_PERMANENT_ADDRESS"
	NeedMoreToCreateDestination                          = "NEED_MORE_TO_CREATE_DESTINATION"
	NonExistingAccountName                               = "NON_EXISTING_ACCOUNT_NAME"
	EnvUnsupportedAsset                                  = "ENV_UNSUPPORTED_ASSET"
)

type TransactionDetails struct {
	Id                            string                   `json:"id"` // ID of the transaction
	AssetId                       string                   `json:"AssetId"`
	Source                        TransferPeerPathResponse `json:"source"`                        // source of the transaction
	Destination                   TransferPeerPathResponse `json:"destination"`                   // Destination of the transaction
	RequestedAmount               decimal.Decimal          `json:"RequestedAmount"`               // the amount requested by the user
	AmountInfo                    AmountInfo               `json:"amountInfo"`                    // Details of the transaction's amount in string format
	FeeInfo                       FeeInfo                  `json:"feeInfo"`                       // Details of the transaction's fee in string format
	Amount                        decimal.Decimal          `json:"amount"`                        // If the transfer is a withdrawal from an exchange, the actual amount that was requested to be transferred. Otherwise, the requested amount
	NetAmount                     decimal.Decimal          `json:"netAmount"`                     // The net amount of the transaction, after fee deduction
	AmountUSD                     decimal.Decimal          `json:"amountUSD"`                     // The USD value of the requested amount
	ServiceFee                    decimal.Decimal          `json:"ServiceFee"`                    // The total fee deducted by the exchange from the actual requested amount (serviceFee = amount - netAmount)
	TreatAsGrossAmount            bool                     `json:"treatAsGrossAmount"`            // For outgoing transactions, if true, the network fee is deducted from the requested amount
	NetworkFee                    decimal.Decimal          `json:"networkFee"`                    //The fee paid to the network
	CreatedAt                     int64                    `json:"createdAt"`                     // Unix timestamp
	LastUpdated                   int64                    `json:"lastUpdated"`                   // Unix timestamp
	Status                        TransactionStatus        `json:"status"`                        // The current status of the transaction
	TxHash                        string                   `json:"txHash"`                        // Blockchain hash of the transaction
	SubStatus                     TransactionSubStatus     `json:"subStatus"`                     // More detailed status of the transaction
	SourceAddress                 string                   `json:"sourceAddress"`                 // For account based assets only, the source address of the transaction
	DestinationAddress            string                   `json:"destinationAddress"`            // Address where the asset were transfered
	DestinationAddressDescription string                   `json:"destinationAddressDescription"` // Description of the address
	DestinationTag                string                   `json:"destinationTag"`                // Destination tag (for XRP, used as memo for EOS/XLM) or Bank Transfer Description for Signet/SEN
	SignedBy                      []string                 `json:"signedBy"`                      //Signers of the transaction
	CreatedBy                     string                   `json:"createdBy"`                     // Initiator of the transaction
	RejectedBy                    string                   `json:"rejectedBy"`                    // User ID of the user that rejected the transaction (in case it was rejected)
	AddressType                   string                   `json:"addressType"`                   // [ ONE_TIME, WHITELISTED ]
	Note                          string                   `json:"note"`                          // Customer note of the transaction
	ExchangeTxId                  string                   `json:"exchangeTxId"`                  // If the transaction originated from an exchange, this is the exchange tx ID
	FeeCurrency                   string                   `json:"feeCurrency"`                   // The asset which was taken to pay the fee (ETH for ERC-20 tokens, BTC for Tether Omni)
	Operation                     string                   `json:"operation"`                     // Default operation is "TRANSFER"
	AmlScreeningResult            AmlScreeningResult       `json:"amlScreeningResult"`            // The result of the AML screening
	CustomerRefId                 string                   `json:"customerRefId"`                 // The ID for AML providers to associate the owner of funds with transactions
	NumberOfConfirmations         int                      `json:"numberOfConfirmations"`         // The number of confirmations of the transaction. The number will increase until the transaction will be considered completed according to the confirmation policy.
	NetworkRecords                []NetworkRecord          `json:"networkRecords"`                // Transaction on the Fireblocks platform can aggregate several blockchain transactions, in such a case these records specify all the transactions that took place on the blockchain.
	ReplacedTxHash                string                   `json:"replacedTxHash"`                // In case of an RBF transaction, the hash of the dropped transaction
	ExternalTxId                  string                   `json:"externalTxId"`                  // Unique transaction ID provided by the user
	Destinations                  []DestinationsResponse   `json:"destinations"`                  // For UTXO based assets, all outputs specified here
	BlockInfo                     BlockInfo                `json:"blockInfo"`                     //The information of the block that this transaction was mined in, the blocks's hash and height
	SignedMessages                []SignedMessage          `json:"signedMessages"`                // A list of signed messages returned for raw signing
	ExtraParameters               map[string]interface{}   `json:"extraParameters"`               // Protocol / operation specific parameters.

}

type BlockInfo struct {
	BlockHeight string `json:"blockHeight"`
	BlockHash   string `json:"blockHash"`
}

type TransactionFee struct {
	FeePerByte string `json:"feePerByte"` // [optional] For UTXOs,
	GasPrice   string `json:"gasPrice"`   // [optional] For Ethereum assets (ETH and Tokens)
	GasLimit   string ` json:"gasLimit"`  // [optional] For Ethereum assets (ETH and Tokens), the limit for how much can be used
	NetworkFee string `json:"networkFee"` // [optional] Transaction fee
}

type EstimatedTransactionFeeResponse struct {
	Low    TransactionFee `json:"low"`    //Transactions with this fee will probably take longer to be mined
	Medium TransactionFee `json:"medium"` // Average transactions fee
	High   TransactionFee `json:"high"`   //Transactions with this fee should be mined the fastest

}

type AddressStatus struct {
	IsValid     bool `json:"isValid"`
	IsActive    bool `json:"isActive"`
	RequiresTag bool `json:"requiresTag"`
}

type SignedMessage struct {
	Content        string                 `json:"content"`        // The message for signing (hex-formatted)
	Algorithm      string                 `json:"algorithm"`      // The algorithm that was used for signing, one of the SigningAlgorithms
	DerivationPath string                 `json:"derivationPath"` // BIP32 derivation path of the signing key. E.g. [44,0,46,0,0]
	Signature      map[string]interface{} `json:"signature"`      // The message signature
	PublicKey      string                 `json:"publicKey"`      // Signature's public key that can be used for verification.
}

type DestinationsResponse struct {
	Amount                        decimal.Decimal          `json:"amount"`                        // The amount to be sent to this destination
	Destination                   TransferPeerPathResponse `json:"destination"`                   // Destination of the transaction
	AmountUSD                     decimal.Decimal          `json:"amountUSD"`                     // The USD value of the requested amount
	DestinationAddress            string                   `json:"destinationAddress"`            // Address where the asset were transfered
	DestinationAddressDescription string                   `json:"destinationAddressDescription"` // Description of the address
	AmlScreeningResult            AmlScreeningResult       `json:"amlScreeningResult"`            // The result of the AML screening
	CustomerRefId                 string                   `json:"customerRefId"`                 // The ID for AML providers to associate the owner of funds with transactions

}

type NetworkRecord struct {
	Source             TransferPeerPathResponse `json:"source"`             // Source of the transaction
	Destination        TransferPeerPathResponse `json:"destination"`        // Destination of the transaction
	TxHash             string                   `json:"txHash"`             // Blockchain hash of the transaction
	NetworkFee         decimal.Decimal          `json:"networkFee"`         // The fee paid to the network
	AssetId            string                   `json:"assetId"`            // transaction asset
	NetAmount          decimal.Decimal          `json:"netAmount"`          // The net amount of the transaction, after fee deduction
	Status             NetworkStatus            `json:"status"`             // Status of the blockchain transaction
	OpType             string                   `json:"type"`               // Type of the operation
	DestinationAddress string                   `json:"destinationAddress"` // Destination address
	SourceAddress      string                   `json:"sourceAddress"`      // For account based assets only, the source address of the transaction

}

type NetworkStatus string

const (
	DROPPED      NetworkStatus = "DROPPED"
	BROADCASTING               = "BROADCASTING"
	CONFIRMING                 = "CONFIRMING"
	FAILED                     = "FAILED"
	NsConfirmed                = "CONFIRMED"
)

type AmlScreeningResult struct {
	Provider string `json:"provider"` // The AML service provider
	Payload  string `json:"payload"`  // The response of the AML service provider
}

type AmountInfo struct {
	Amount          string `json:"amount"`          // If the transfer is a withdrawal from an exchange, the actual amount that was requested to be transferred. Otherwise, the requested amount
	RequestedAmount string `json:"requestedAmount"` //The amount requested by the user
	NetAmount       string `json:"NetAmount"`       // The net amount of the transaction, after fee deduction
	AmountUSD       string `json:"amountUSD"`       // The USD value of the requested amount
}

type FeeInfo struct {
	NetworkFee string `json:"NetworkFee"` // The fee paid to the network
	ServiceFee string `json:"ServiceFee"` // The total fee deducted by the exchange from the actual requested amount (serviceFee = amount - netAmount)
}

type CreateTransactionResponse struct {
	Id     string            `json:"Id"`
	Status TransactionStatus `json:"status"`
	Error  error
}

type CreateVaultAssetResponse struct {
	Id             string `json:"Id"`             // the Id of the asset
	Address        string `json:"address"`        // Address of the asset in a Vault Account, for BTC/LTC the address is in segwit (Bech32) format, cash address format BCH
	LegacyAddress  string `json:"legacyAddress"`  // legacy address format for BTC/LTC/BCH
	Tag            string `json:"tag"`            // destination tag for XRP, memo for EOS/XLM
	EosAccountName string `json:"eosAccountName"` // returned for EOS, the acct name.
}

type AssetTypeResponse struct {
	Id              string `json:"Id"`
	Name            string `json:"name"`
	AssetType       string `json:"type"`
	ContractAddress string `json:"contractAddress"`
	NativeAsset     string `json:"nativeAsset"`
}

type VaultAccountAssetAddress struct {
	AssetId       string `json:"assetId"`        // The ID of the asset
	Address       string `json:"address"`        // Address of the asset in a Vault Account, for BTC/LTC the address is in Segwit (Bech32) format, for BCH cash format
	LegacyAddress string `json:"legacyAddress"`  // For BTC/LTC/BCH the legacy format address
	Description   string `json:"description"`    // Description of the address
	Tag           string `json:"tag"`            // Destination tag for XRP, used as memo for EOS/XLM, for Signet/SEN it is the Bank Transfer Description
	Type          string `json:"type"`           // Address type
	CustomerRefId string `json:" customerRefId"` // [optional] The ID for AML providers to associate the owner of funds with transactions
	AddressFormat string `json:"addressFormat"`
	EnterpriseAddress string `json:"enterpriseAddress"`

}

type UnsignedMessage struct {
	Content           string `json:"content"`           //message to be signed - hex format.
	Bip44AddressIndex int    `json:"bip44AddressIndex"` //
	Bib44Change       int    `json:"bib44Change"`       //bit44 change path level
	DerivationPath    []int  `json:"derivationPath"`
}

type RawMessage struct {
	messages  []UnsignedMessage
	algorithm SigningAlgorithm
}

type OneTimeAddress struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type TransferPeerPathResponse struct {
	TransferType string `json:"type"` //[ PTVaultAccount, EXCHANGE_ACCOUNT, INTERNAL_WALLET, EXTERNAL_WALLET, ONE_TIME_ADDRESS, NETWORK_CONNECTION, FIAT_ACCOUNT, COMPOUND ]
	Id           string `json:"id"`   // The ID of the exchange account to return
	Name         string `json:"name"` // The name of the exchange account
	Subtype      string `json:"subType"`
}

type TransferPeerPath struct {
	TPeerId   string   `json:"id"`
	TPeerType PeerType `json:"type"`
}

type DestinationTransferPeerPath struct {
	TPeerId   string         `json:"id"`
	TPeerType PeerType       `json:"type"`
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
	Id                   string `json:"id"`
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

type ExchangeAccount struct {
	Id            string                    `json:"id"`
	Type          ExchangeType              `json:"type"`
	Name          string                    `json:"name"`
	Status        ConfigChangeRequestStatus `json:"status"`
	Assets        []ExchangeAsset           `json:"assets"`
	IsSubAccount  bool                      `json:"isSubaccount"`
	MainAccountId string                    `json:"mainAccountId"`
}

type TradingAccount struct {
	Type   TradingAccountType `json:"type"`
	Assets []ExchangeAsset    `json:"assets"`
}

type ExchangeAsset struct {
	Id           string `json:"id"`
	Total        string `json:"total"`
	Available    string `json:"available"`
	LockedAmount string `json:"lockedAmount"`
	Balance      string `json:"balance"`
}

type ExchangeType struct {
	Type string `json:"type"`
}

type TradingAccountType ExchangeType

type AssetAddedData struct {
	AccountId   string `json:"accountId"`   // The ID of the vault account under which the wallet was added
	TenantId    string `json:"tenantId"`    // Unique id of your Fireblocks' workspace
	AccountName string `json:"accountName"` // The name of the vault account under which the wallet was added
	AssetId     string `json:"assetId"`     // Wallet's asset
}

type WalletAssetWebhook struct {
	AssetId        string `json:"assetId"`        // Wallet's asset
	Id             string `json:"id"`             // The ID of the wallet
	Name           string `json:"name"`           // The name of wallet
	Address        string `json:"address"`        // The address of the wallet
	Tag            string `json:"tag"`            //Destination tag (for XRP, used as memo for EOS/XLM and as Bank Transfer Description for Signet/SEN) of the wallet
	ActivationTime string `json:"activationTime"` // The time the wallet will be activated in case wallets activation posponed according to workspace definition

}

type ThirdPartyWebhook struct {
	Id      string `json:"id"`      // Id of the thirdparty account on the Fireblocks platform
	SubType string `json:"subType"` // Subtype of the third party, ie. exchange or fiat name
	Name    string `json:"name"`    // Account name
}

type ObjectAdded struct {
	Type      string      `json:"type"`
	TenantId  string      `json:"tenantId"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type ExternalWalletAssetAdded ObjectAdded
type ExchangeAccountAdded ObjectAdded
type FiatAccountAdded ObjectAdded
type NetworkConnectionAdded ObjectAdded

type PeerType string

const (
	PTVaultAccount      PeerType = "VAULT_ACCOUNT"
	PTExchangeAccount            = "EXCHANGE_ACCOUNT"
	PTInternalWallet             = "INTERNAL_WALLET"
	PTExternalWallet             = "EXTERNAL_WALLET"
	PTUnknownPeer                = "UNKNOWN"
	PTFiatAccount                = "FIAT_ACCOUNT"
	PTNetworkConnection          = "NETWORK_CONNECTION"
	PTCompound                   = "COMPOUND"
)

type EventType string

const (
	EventTransactionCreated       EventType = "TRANSACTION_CREATED"
	EventTransactionStatusUpdated           = "TRANSACTION_STATUS_UPDATED"
	EventVaultAccountAdded                  = "VAULT_ACCOUNT_ADDED"
	EventVaultAccountAssetAdded             = "VAULT_ACCOUNT_ASSET_ADDED"
	EventInternalWalletAssetAdded           = "INTERNAL_WALLET_ASSET_ADDED"
	EventExternalWalletAssetAdded           = "EXTERNAL_WALLET_ASSET_ADDED"
	EventExchangeAccountAdded               = "EXCHANGE_ACCOUNT_ADDED"
	EventFiatAccountAdded                   = "FIAT_ACCOUNT_ADDED"
	EventNetworkConnectionAdded             = "NETWORK_CONNECTION_ADDED"
)

type SigningAlgorithm string

const (
	MpcEcdsaSecp256k1 SigningAlgorithm = "MPC_ECDSA_SECP256K1"
	MpcEddsaEd25519                    = "MPC_EDDSA_ED25519"
)

type FeeLevel string

const (
	HIGH   FeeLevel = "HIGH"
	MEDIUM          = "MEDIUM"
	LOW             = "LOW"
)

type TransactionType string

const (
	TxTransfer            TransactionType = "TRANSFER"
	TxMint                                = "MINT"
	TxBurn                                = "BURN"
	TxSupplyToCompound                    = "SUPPLY_TO_COMPOUND"
	TxnRedeemFromCompound                 = "REDEEM_FROM_COMPOUND"
	TxRaw                                 = "RAW"
	TxContractCall                        = "CONTRACT_CALL"
	TxOneTimeAddress                      = "ONE_TIME_ADDRESS"
)
