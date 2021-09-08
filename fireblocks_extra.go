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
	TransactionStatusSubmitted                    TransactionStatus = "SUBMITTED"
	TransactionStatusQueued                                         = "QUEUED"
	TRANSACTION_PENDING_SIGNATURE                                   = "PENDING_SIGNATURE"
	TRANSACTION_PENDING_AUTHORIZATION                               = "PENDING_AUTHORIZATION"
	TRANSACTION_PENDING_3RD_PARTY_MANUAL_APPROVAL                   = "PENDING_3RD_PARTY_MANUAL_APPROVAL"
	TRANSACTION_PENDING_3RD_PARTY                                   = "PENDING_3RD_PARTY"
	TRANSACTION_PENDING                                             = "PENDING" // Deprecated
	TRANSACTION_BROADCASTING                                        = "BROADCASTING"
	TRANSACTION_CONFIRMING                                          = "CONFIRMING"
	TRANSACTION_CONFIRMED                                           = "CONFIRMED" // Deprecated
	TRANSACTION_COMPLETED                                           = "COMPLETED"
	TRANSACTION_PENDING_AML_CHECKUP                                 = "PENDING_AML_CHECKUP"
	TRANSACTION_PARTIALLY_COMPLETED                                 = "PARTIALLY_COMPLETED"
	TRANSACTION_CANCELLING                                          = "CANCELLING"
	TRANSACTION_CANCELLED                                           = "CANCELLED"
	TRANSACTION_REJECTED                                            = "REJECTED"
	TRANSACTION_FAILED                                              = "FAILED"
	TRANSACTION_TIMEOUT                                             = "TIMEOUT"
	TRANSACTION_BLOCKED                                             = "BLOCKED"
)

type TransactionSubStatus string

const (
	INSUFFICIENT_FUNDS                 TransactionSubStatus = "INSUFFICIENT_FUNDS"
	AMOUNT_TOO_SMALL                                        = "AMOUNT_TOO_SMALL"
	UNSUPPORTED_ASSET                                       = "UNSUPPORTED_ASSET"
	UNAUTHORISED__MISSING_PERMISSION                        = "UNAUTHORISED__MISSING_PERMISSION"
	INVALID_SIGNATURE                                       = "INVALID_SIGNATURE"
	API_INVALID_SIGNATURE                                   = "API_INVALID_SIGNATURE"
	UNAUTHORISED__MISSING_CREDENTIALS                       = "UNAUTHORISED__MISSING_CREDENTIALS"
	UNAUTHORISED__USER                                      = "UNAUTHORISED__USER"
	UNAUTHORISED__DEVICE                                    = "UNAUTHORISED__DEVICE"
	INVALID_UNMANAGED_WALLET                                = "INVALID_UNMANAGED_WALLET"
	INVALID_EXCHANGE_ACCOUNT                                = "INVALID_EXCHANGE_ACCOUNT"
	INSUFFICIENT_FUNDS_FOR_FEE                              = "INSUFFICIENT_FUNDS_FOR_FEE"
	INVALID_ADDRESS                                         = "INVALID_ADDRESS"
	WITHDRAW_LIMIT                                          = "WITHDRAW_LIMIT"
	API_CALL_LIMIT                                          = "API_CALL_LIMIT"
	ADDRESS_NOT_WHITELISTED                                 = "ADDRESS_NOT_WHITELISTED"
	TIMEOUT                                                 = "TIMEOUT"
	CONNECTIVITY_ERROR                                      = "CONNECTIVITY_ERROR"
	THIRD_PARTY_INTERNAL_ERROR                              = "THIRD_PARTY_INTERNAL_ERROR"
	CANCELLED_EXTERNALLY                                    = "CANCELLED_EXTERNALLY"
	INVALID_THIRD_PARTY_RESPONSE                            = "INVALID_THIRD_PARTY_RESPONSE"
	VAULT_WALLET_NOT_READY                                  = "VAULT_WALLET_NOT_READY"
	MISSING_DEPOSIT_ADDRESS                                 = "MISSING_DEPOSIT_ADDRESS"
	ONE_TIME_ADDRESS_DISABLED                               = "ONE_TIME_ADDRESS_DISABLED"
	INTERNAL_ERROR                                          = "INTERNAL_ERROR"
	UNKNOWN_ERROR                                           = "UNKNOWN_ERROR"
	AUTHORIZER_NOT_FOUND                                    = "AUTHORIZER_NOT_FOUND"
	INSUFFICIENT_RESERVED_FUNDING                           = "INSUFFICIENT_RESERVED_FUNDING"
	MANUAL_DEPOSIT_ADDRESS_REQUIRED                         = "MANUAL_DEPOSIT_ADDRESS_REQUIRED"
	INVALID_FEE                                             = "INVALID_FEE"
	ERROR_UNSUPPORTED_TRANSACTION_TYPE                      = "ERROR_UNSUPPORTED_TRANSACTION_TYPE"
	UNSUPPORTED_OPERATION                                   = "UNSUPPORTED_OPERATION"
	T3RD_PARTY_PROCESSING                                   = "3RD_PARTY_PROCESSING"
	PENDING_BLOCKCHAIN_CONFIRMATIONS                        = "PENDING_BLOCKCHAIN_CONFIRMATIONS"
	T3RD_PARTY_CONFIRMING                                   = "3RD_PARTY_CONFIRMING"
	CONFIRMED                                               = "CONFIRMED"
	T3RD_PARTY_COMPLETED                                    = "3RD_PARTY_COMPLETED"
	REJECTED_BY_USER                                        = "REJECTED_BY_USER"
	CANCELLED_BY_USER                                       = "CANCELLED_BY_USER"
	T3RD_PARTY_CANCELLED                                    = "3RD_PARTY_CANCELLED"
	T3RD_PARTY_REJECTED                                     = "3RD_PARTY_REJECTED"
	AML_SCREENING_REJECTED                                  = "AML_SCREENING_REJECTED"
	BLOCKED_BY_POLICY                                       = "BLOCKED_BY_POLICY"
	FAILED_AML_SCREENING                                    = "FAILED_AML_SCREENING"
	PARTIALLY_FAILED                                        = "PARTIALLY_FAILED"
	T3RD_PARTY_FAILED                                       = "3RD_PARTY_FAILED"
	DROPPED_BY_BLOCKCHAIN                                   = "DROPPED_BY_BLOCKCHAIN"
	TOO_MANY_INPUTS                                         = "TOO_MANY_INPUTS"
	SIGNING_ERROR                                           = "SIGNING_ERROR"
	INVALID_FEE_PARAMS                                      = "INVALID_FEE_PARAMS"
	MISSING_TAG_OR_MEMO                                     = "MISSING_TAG_OR_MEMO"
	GAS_LIMIT_TOO_LOW                                       = "GAS_LIMIT_TOO_LOW"
	MAX_FEE_EXCEEDED                                        = "MAX_FEE_EXCEEDED"
	ACTUAL_FEE_TOO_HIGH                                     = "ACTUAL_FEE_TOO_HIGH"
	INVALID_CONTRACT_CALL_DATA                              = "INVALID_CONTRACT_CALL_DATA"
	INVALID_NONCE_TOO_LOW                                   = "INVALID_NONCE_TOO_LOW"
	INVALID_NONCE_TOO_HIGH                                  = "INVALID_NONCE_TOO_HIGH"
	INVALID_NONCE_FOR_RBF                                   = "INVALID_NONCE_FOR_RBF"
	FAIL_ON_LOW_FEE                                         = "FAIL_ON_LOW_FEE"
	TOO_LONG_MEMPOOL_CHAIN                                  = "TOO_LONG_MEMPOOL_CHAIN"
	TX_OUTDATED                                             = "TX_OUTDATED"
	INCOMPLETE_USER_SETUP                                   = "INCOMPLETE_USER_SETUP"
	SIGNER_NOT_FOUND                                        = "SIGNER_NOT_FOUND"
	INVALID_TAG_OR_MEMO                                     = "INVALID_TAG_OR_MEMO"
	ZERO_BALANCE_IN_PERMANENT_ADDRESS                       = "ZERO_BALANCE_IN_PERMANENT_ADDRESS"
	NEED_MORE_TO_CREATE_DESTINATION                         = "NEED_MORE_TO_CREATE_DESTINATION"
	NON_EXISTING_ACCOUNT_NAME                               = "NON_EXISTING_ACCOUNT_NAME"
	ENV_UNSUPPORTED_ASSET                                   = "ENV_UNSUPPORTED_ASSET"
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
	Operation                     TransactionOperation     `json:"operation"`                     // Default operation is "TRANSFER"
	AmlScreeningResult            AmlScreeningResult       `json:"amlScreeningResult"`            // The result of the AML screening
	CustomerRefId                 string                   `json:"customerRefId"`                 // The ID for AML providers to associate the owner of funds with transactions
	NumberOfConfirmations         int                      `json:"numberOfConfirmations"`         // The number of confirmations of the transaction. The number will increase until the transaction will be considered completed according to the confirmation policy.
	NetworkRecords                []NetworkRecord          `json:"networkRecords"`                // Transaction on the Fireblocks platform can aggregate several blockchain transactions, in such a case these records specify all the transactions that took place on the blockchain.
	ReplacedTxHash                string                   `json:"replacedTxHash"`                // In case of an RBF transaction, the hash of the dropped transaction
	ExternalTxId                  string                   `json:"externalTxId"`                  // Unique transaction ID provided by the user
	Destinations                  []DestinationsResponse   `json:"destinations"`                  // For UTXO based assets, all outputs specified here
	SignedMessages                []SignedMessage          `json:"signedMessages"`                // A list of signed messages returned for raw signing
	ExtraParameters               map[string]interface{}   `json:"extraParameters"`               // Protocol / operation specific parameters.

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
	NS_CONFIRMED               = "CONFIRMED"
)

type AmlScreeningResult struct {
	Provider string `json:"provider"` // The AML service provider
	Payload  string `json:"payload"`  // The response of the AML service provider
}

type TransactionOperation struct {
	Operation string `json:"operation"` // [ TRANSFER, RAW, CONTRACT_CALL, MINT, BURN, SUPPLY_TO_COMPOUND, REDEEM_FROM_COMPOUND ]
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
	Id      string `json:"Id"`      // the Id of the asset
	Address string `json:"address"` // Address of the asset in a Vault Account,
	// for BTC/LTC the address is in segwit (Bech32) format, cash address format BCH
	LegacyAddress  string `json:"legacyAddress"`  // legacy address format for BTC/LTC/BCH
	Tag            string `json:"tag"`            // destination tag for XRP, memo for EOS/XLM
	EosAccountName string `json:"eosAccountName"` // returned for EOS, the acct name.
}

type AssetTypeResponse struct {
	Id              string    `json:"Id"`
	Name            string    `json:"name"`
	TypeAsset       AssetType `json:"typeAsset"`
	ContractAddress string    `json:"contractAddress"`
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
	PTVaultAccount      PeerType = "VAULT_ACCOUNT"
	PTExchangeAccount            = "EXCHANGE_ACCOUNT"
	PTInternalWallet             = "INTERNAL_WALLET"
	PTExternalWallet             = "EXTERNAL_WALLET"
	PTUnknownPeer                = "UNKNOWN"
	PTFiatAccount                = "FIAT_ACCOUNT"
	PTNetworkConnection          = "NETWORK_CONNECTION"
	PTCompound                   = "COMPOUND"
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
	TransactionTransfer           TransactionType = "TRANSFER"
	TransactionMint                               = "MINT"
	TransactionBurn                               = "BURN"
	TransactionSupplyToCompound                   = "SUPPLY_TO_COMPOUND"
	TransactionRedeemFromCompound                 = "REDEEM_FROM_COMPOUND"
	RAW                                           = "RAW"
	ContractCall                                  = "CONTRACT_CALL"
	ONE_TIME_ADDRESS                              = "ONE_TIME_ADDRESS"
)
