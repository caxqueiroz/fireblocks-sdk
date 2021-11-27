package fireblocks

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gojek/heimdall/v7/hystrix"
	"github.com/golang-jwt/jwt"
	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type FbKeyMgmt struct {
	privateKey *rsa.PrivateKey
	apiKey     string
	rnd        *rand.Rand
}

func NewInstanceKeyMgmt(pk *rsa.PrivateKey, apiKey string) *FbKeyMgmt {
	var s secrets
	k := new(FbKeyMgmt)
	k.privateKey = pk
	k.apiKey = apiKey
	k.rnd = rand.New(s)
	return k
}

type secrets struct{}

func (s secrets) Seed(seed int64) {}

func (s secrets) Uint64() (r uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &r)
	if err != nil {
		log.Error(err)
	}
	return r
}

func (s secrets) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (k *FbKeyMgmt) createAndSignJWTToken(path string, bodyJSON string) (string, error) {

	token := &jwt.MapClaims{
		"uri":      path,
		"nonce":    k.rnd.Int63(),
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Second * 55).Unix(),
		"sub":      k.apiKey,
		"bodyHash": createHash(bodyJSON),
	}

	j := jwt.NewWithClaims(jwt.SigningMethodRS256, token)
	signedToken, err := j.SignedString(k.privateKey)
	if err != nil {
		log.Error(err)
	}

	return signedToken, err
}

func createHash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

type SDK struct {
	httpClient *hystrix.Client
	apiBaseURL string
	kto        *FbKeyMgmt
}

// NewInstance - create new type to handle Fireblocks API requests
func NewInstance(pk []byte, ak string, url string) *SDK {

	s := new(SDK)
	s.apiBaseURL = url

	privateK, err := jwt.ParseRSAPrivateKeyFromPEM(pk)
	if err != nil {
		log.Error(err)
	}

	s.kto = NewInstanceKeyMgmt(privateK, ak)
	s.httpClient = newCircuitBreakerHttpClient()
	return s
}

func newCircuitBreakerHttpClient() *hystrix.Client {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: false,
	}
	c := hystrix.NewClient(hystrix.WithFallbackFunc(func(err error) error {
		log.Errorf("no fallback func implemented: %s", err)
		return err
	}))
	return c
}

// getRequest - internal method to handle API call to Fireblocks
func (s *SDK) getRequest(path string) (string, error) {

	urlEndPoint := s.apiBaseURL + path
	token, err := s.kto.createAndSignJWTToken(path, "")
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error signing JWT token"), err
	}

	request, err := http.NewRequest(http.MethodGet, urlEndPoint, nil)
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error creating NewRequest"), err
	}

	request.Header.Add("X-API-Key", s.kto.apiKey)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	response, err := s.httpClient.Do(request)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("error communicating with fireblocks: %v", err)
		return "", err
	}

	if response.StatusCode >= 300 {
		errMsg := fmt.Sprintf("fireblocks server: %s \n %s", response.Status, string(data))
		log.Warning(errMsg)
	}

	return string(data), err
}

func (s *SDK) changeRequest(path string, payload []byte, idempotencyKey string, requestType string) (string, error) {

	urlEndPoint := s.apiBaseURL + path
	token, err := s.kto.createAndSignJWTToken(path, string(payload))
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error signing JWT token"), err
	}

	request, err := http.NewRequest(requestType, urlEndPoint, bytes.NewBuffer(payload))
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error creating NewRequest"), err
	}
	request.Header.Add("X-API-Key", string(s.kto.apiKey))
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	request.Header.Add("Content-Type", "application/json")

	if len(idempotencyKey) > 0 {
		request.Header.Add("Idempotency-Key", idempotencyKey)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("error on communicating with Fireblocks: %v  \n data: %s", err, data)
		return "", err
	}

	if response.StatusCode >= 300 {
		errMsg := fmt.Sprintf("fireblocks server: %s \n %s", response.Status, string(data))
		log.Warning(errMsg)
	}

	return string(data), err

}

func (s *SDK) GetUsers() ([]User, error) {

	returnedData, err := s.getRequest("/v1/users")
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var users []User
	err = json.Unmarshal([]byte(returnedData), &users)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return users, nil
}

// GetSupportedAssets - Gets all assets that are currently supported by Fireblocks API.
func (s *SDK) GetSupportedAssets() ([]AssetTypeResponse, error) {

	returnedData, err := s.getRequest("/v1/supported_assets")
	if err != nil {
		log.Error(err)
		return nil, err
	}
	var assetsTypeResponse []AssetTypeResponse
	err = json.Unmarshal([]byte(returnedData), &assetsTypeResponse)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return assetsTypeResponse, nil
}

// GetVaultAccounts - gets all vault accounts for the tenant.
func (s *SDK) GetVaultAccounts(namePrefix string, nameSuffix string, minAmountThreshold decimal.Decimal) ([]VaultAccount, error) {

	query := "/v1/vault/accounts"
	params := url.Values{}

	if namePrefix != "" {
		params.Add("namePrefix", namePrefix)
	}
	if nameSuffix != "" {
		params.Add("nameSuffix", nameSuffix)
	}
	if minAmountThreshold.GreaterThan(decimal.NewFromFloat(0.0)) {
		params.Add("minAmountThreshold", fmt.Sprintf("%s", minAmountThreshold))
	}
	if len(params) > 0 {
		query = query + "?" + params.Encode()
	}

	returnedData, err := s.getRequest(query)
	if err != nil {
		return nil, err
	}
	var vaultAccounts []VaultAccount
	err = json.Unmarshal([]byte(returnedData), &vaultAccounts)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return vaultAccounts, nil
}

// GetVaultAccount - retrieve the vault account for the specified id.

func (s *SDK) GetVaultAccount(vaultAccountID string) (VaultAccount, error) {

	query := fmt.Sprintf("/v1/vault/accounts/%s", vaultAccountID)

	returnedData, err := s.getRequest(query)
	if err != nil {
		return VaultAccount{}, err
	}

	var vaultAccount VaultAccount
	err = json.Unmarshal([]byte(returnedData), &vaultAccount)
	if err != nil {
		log.Error(err)
		return VaultAccount{}, err
	}

	if vaultAccount.Id == "" {
		return VaultAccount{}, errors.New(returnedData)
	}

	return vaultAccount, err

}

// GetVaultAccountAsset - Gets a single vault account asset
func (s *SDK) GetVaultAccountAsset(vaultAccountID string, assetID string) (VaultAsset, error) {

	query := fmt.Sprintf("/v1/vault/accounts/%s/%s", vaultAccountID, assetID)

	var vaultAsset VaultAsset
	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
	}
	err = json.Unmarshal([]byte(returnedData), &vaultAsset)
	if err != nil {
		log.Errorf("failed to parse payload: %s. %v", returnedData, err)
		return VaultAsset{}, err
	}
	return vaultAsset, err

}

// GetAddresses - Gets deposit addresses for an asset in a vault account
func (s *SDK) GetAddresses(vaultAccountID string, assetID string) ([]VaultAccountAssetAddress, error) {

	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses", vaultAccountID, assetID)
	returnedData, err := s.getRequest(query)
	if err != nil {
		return nil, err
	}

	var assetAddress []VaultAccountAssetAddress
	err = json.Unmarshal([]byte(returnedData), &assetAddress)
	if err != nil {
		log.Errorf("failed to parse payload: %s. %v", returnedData, err)
		return nil, err
	}

	return assetAddress, nil

}

// GetUnspentInputs - Gets utxo list for an asset in a vault account
func (s *SDK) GetUnspentInputs(vaultAccountID string, assetID string) (string, error) {
	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/unspent_inouts", vaultAccountID, assetID)
	return s.getRequest(query)
}

// GenerateNewAddress - Generates a new address for an asset in a vault account
func (s *SDK) GenerateNewAddress(vaultAccountID string, assetID string, description string, customerRefID string,
	idempotencyKey string,
) (CreateAddressResponse, error) {
	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses", vaultAccountID, assetID)

	payload := make(map[string]interface{})

	if len(description) > 0 {
		payload["description"] = description
	}
	if len(customerRefID) > 0 {
		payload["customerRefId"] = customerRefID
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return CreateAddressResponse{}, err
	}

	returnedData, err := s.changeRequest(query, marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		log.Errorf("returned payload: %s", returnedData)
		return CreateAddressResponse{}, err
	}

	var createdAddress CreateAddressResponse
	err = json.Unmarshal([]byte(returnedData), &createdAddress)
	if err != nil {
		log.Errorf("failed to parse payload: %s. %v", returnedData, err)
		return CreateAddressResponse{}, err
	}

	return createdAddress, nil

}

// SetAddressDescription - Sets the description of an existing address
func (s *SDK) SetAddressDescription(vaultAccountID string, assetID string, description string, address string, tag string) (string, error) {

	payload := make(map[string]interface{})

	if len(description) > 0 {
		payload["description"] = description
	}
	var query string
	if len(tag) > 0 {
		query = fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses/%s:%s", vaultAccountID, assetID, address, tag)
	} else {
		query = fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses/%s", vaultAccountID, assetID, address)
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return s.changeRequest(query, marshalled, "", http.MethodPut)
}

// GetNetworkConnections - Gets all network connections for your tenant
func (s *SDK) GetNetworkConnections() (string, error) {
	return s.getRequest("/v1/network_connections")
}

// GetNetworkConnectionByID - Gets a single network connection by id
func (s *SDK) GetNetworkConnectionByID(connectionID string) (string, error) {
	query := fmt.Sprintf("/v1/network_connections/%s", connectionID)
	return s.getRequest(query)
}

// GetExchangeAccounts - Gets all exchange accounts for your tenant
func (s *SDK) GetExchangeAccounts() ([]ExchangeAccount, error) {

	returnedData, err := s.getRequest("/v1/exchange_accounts")
	if err != nil {
		log.Error(err)
	}
	var exchangeAccounts []ExchangeAccount
	err = json.Unmarshal([]byte(returnedData), &exchangeAccounts)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return exchangeAccounts, nil

}

// GetExchangeAccount - Gets an exchange account for your tenant
func (s *SDK) GetExchangeAccount(exchangeID string) (ExchangeAccount, error) {

	query := fmt.Sprintf("/v1/exchange_accounts/%s", exchangeID)

	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
		return ExchangeAccount{}, err
	}

	var exchangeAccount ExchangeAccount
	err = json.Unmarshal([]byte(returnedData), &exchangeAccount)
	if err != nil {
		log.Error(err)
		return ExchangeAccount{}, err
	}

	return exchangeAccount, nil

}

// GetExchangeAccountAsset - Get a specific asset from an exchange account
func (s *SDK) GetExchangeAccountAsset(exchangeID string, assetID string) (ExchangeAsset, error) {

	query := fmt.Sprintf("/v1/exchange_accounts/%s/%s", exchangeID, assetID)

	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
		return ExchangeAsset{}, err
	}

	var exchangeAsset ExchangeAsset
	err = json.Unmarshal([]byte(returnedData), &exchangeAsset)
	if err != nil {
		log.Error(err)
		return ExchangeAsset{}, err
	}

	return exchangeAsset, nil

}

func (s *SDK) SetCustomerRefId(vaultAccountId string, customerRefId string, idempotencyKey string) error {

	payload := map[string]interface{}{
		"customerRefId": customerRefId,
	}

	marshalled, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	query := fmt.Sprintf("/v1/vault/accounts/%s", vaultAccountId)
	_, err = s.changeRequest(query, marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return err
	}

	return nil

}
 //POST /v1/webhooks/resend

func (s *SDK) ResendFailedWebhookEvents() error {

	_, err := s.changeRequest("/v1/webhooks/resend", nil, "", http.MethodPost)
	if err != nil {
		log.Error(err)
	}
	return err

}

// CreateVaultAccount
// name - vaultaccount name - usually we use as a join of userid + product_id (XXXX_YYYY)
func (s *SDK) CreateVaultAccount(name string, hiddenOnUI bool, customerRefID string, autoFuel bool, idempotencyKey string) (VaultAccount, error) {

	payload := map[string]interface{}{
		"name":       name,
		"hiddenOnUI": hiddenOnUI,
		"autoFuel":   autoFuel,
	}

	if len(customerRefID) > 0 {
		payload["customerRefId"] = customerRefID
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return VaultAccount{}, err
	}

	returnedData, err := s.changeRequest("/v1/vault/accounts", marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
	}
	var vaultAccount VaultAccount
	err = json.Unmarshal([]byte(returnedData), &vaultAccount)
	if err != nil {
		log.Error(err)
	}

	if vaultAccount.Id == "" {
		return vaultAccount, errors.New(returnedData)
	}

	return vaultAccount, err

}

//CreateVaultAsset
// creates a new wallet under the VaultAccount
// args:
//     vaultAccountId
//     assetId
func (s *SDK) CreateVaultAsset(vaultAccountId string, assetId string, idempotencyKey string) (CreateVaultAssetResponse, error) {

	cmd := fmt.Sprintf("/v1/vault/accounts/%s/%s", vaultAccountId, assetId)

	var createVaultAssetResponse CreateVaultAssetResponse
	returnedData, err := s.changeRequest(cmd, nil, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
	}

	err = json.Unmarshal([]byte(returnedData), &createVaultAssetResponse)
	if err != nil {
		log.Error(err)
	}

	if createVaultAssetResponse.Id == "" {
		return createVaultAssetResponse, errors.New(returnedData)
	}

	return createVaultAssetResponse, err

}

// CreateExternalWallet
// customerRefId - used for identifying our clients.
func (s *SDK) CreateExternalWallet(name string, customerRefId string, idempotencyKey string) (ExternalWallet, error) {

	payload := map[string]interface{}{
		"name": name,
	}

	if len(customerRefId) > 0 {
		payload["customerRefId"] = customerRefId
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		log.Error(err)
		return ExternalWallet{}, err
	}

	returnedData, err := s.changeRequest("/v1/external_wallets", marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return ExternalWallet{}, err
	}

	var externalWallet ExternalWallet
	err = json.Unmarshal([]byte(returnedData), &externalWallet)
	if err != nil {
		log.Error(err)
		return ExternalWallet{}, err
	}

	return externalWallet, nil

}

func (s *SDK) CreateExternalWalletAsset(walletId string, assetId string, address string, tag string, idempotencyKey string) (ExternalWalletAsset, error) {

	cmd := fmt.Sprintf("/v1/external_wallets/%s/%s", walletId, assetId)

	payload := map[string]interface{}{
		"address": address,
	}

	if len(tag) > 0 {
		payload["tag"] = tag
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return ExternalWalletAsset{}, err
	}

	returnedData, err := s.changeRequest(cmd, marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return ExternalWalletAsset{}, err
	}
	var extWalletAsset ExternalWalletAsset

	err = json.Unmarshal([]byte(returnedData), &extWalletAsset)
	if err != nil {
		log.Error(err)
		return ExternalWalletAsset{}, err
	}

	return extWalletAsset, nil

}

//CreateInternalWallet

func (s *SDK) CreateInternalWallet(name string, customerRefId string, idempotencyKey string) (UnmanagedWallet, error) {

	payload := map[string]interface{}{
		"name":          name,
		"customerRefId": customerRefId,
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return UnmanagedWallet{}, err
	}

	returnedData, err := s.changeRequest("/v1/internal_wallets", marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return UnmanagedWallet{}, err
	}
	var unmanagedWallet UnmanagedWallet
	err = json.Unmarshal([]byte(returnedData), &unmanagedWallet)
	if err != nil {
		log.Error(err)
		return UnmanagedWallet{}, err
	}

	return unmanagedWallet, nil
}

// CreateInternalWalletAsset

func (s *SDK) CreateInternalWalletAsset(walletId string, assetId string, address string, tag string, idempotencyKey string) (WalletAsset, error) {

	cmd := fmt.Sprintf("/v1/internal_wallets/%s/%s", walletId, assetId)
	payload := map[string]interface{}{
		"address": address,
	}
	if len(tag) > 0 {
		payload["tag"] = tag
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return WalletAsset{}, err
	}

	returnedData, err := s.changeRequest(cmd, marshalled, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return WalletAsset{}, err
	}
	var walletAsset WalletAsset
	err = json.Unmarshal([]byte(returnedData), &walletAsset)
	if err != nil {
		log.Error(err)
		return WalletAsset{}, err
	}

	return walletAsset, nil

}

//GetEstimateTxFee
// Get the estimate fee for a tx.
func (s *SDK) GetEstimateTxFee(assetId string, amount string, source TransferPeerPath, destination DestinationTransferPeerPath, operation string) (EstimatedTransactionFeeResponse, error) {

	payload := map[string]interface{}{
		"assetId":     assetId,
		"amount":      amount,
		"source":      source,
		"destination": destination,
		"operation":   operation,
	}

	marshalled, err := json.Marshal(payload)
	if err != nil {
		return EstimatedTransactionFeeResponse{}, err
	}

	returnedData, err := s.changeRequest("/v1/transactions/estimate_fee", marshalled, "", http.MethodPost)
	if err != nil {
		log.Error(err)
		return EstimatedTransactionFeeResponse{}, err
	}

	if strings.Contains(returnedData, "message") {
		// {"message":"The asset is not supported by Fireblocks, please check the supported assets endpoint.","code":1025}
		errMsg := fmt.Sprintf("Request failed: %s", returnedData)
		return EstimatedTransactionFeeResponse{}, errors.New(errMsg)
	}

	var estimatedTxFee EstimatedTransactionFeeResponse
	err = json.Unmarshal([]byte(returnedData), &estimatedTxFee)
	if err != nil {
		log.Error(err)
		return EstimatedTransactionFeeResponse{}, err
	}

	return estimatedTxFee, nil

}

// CreateTransaction -
func (s *SDK) CreateTransaction(assetId string, amount decimal.Decimal, source TransferPeerPath,
	destination DestinationTransferPeerPath, fee decimal.Decimal, gasPrice decimal.Decimal, waitForStatus bool,
	txType TransactionType, note string, cpuStaking string, networkStaking string,
	autoStaking string, customerRefId string, extraParams ExtraParameters, destinations []DestinationTransferPeerPath,
	feeLevel FeeLevel, failOnFee bool, maxFee string, gasLimit decimal.Decimal, replaceTxByHash string, idempotencyKey string,

) (CreateTransactionResponse, error) {

	payload := CreateTransactionPayload{
		AssetId:            assetId,
		Source:             source,
		Destination:        destination,
		Amount:             amount.String(),
		TreatAsGrossAmount: false,
		FailOnLowFee:       false,
		Operation:          string(txType),
		WaitForStatus:      waitForStatus,
	}

	if fee.IsPositive() {
		payload.Fee = fee.String()
	}

	if len(feeLevel) > 0 {
		payload.FeeLevel = string(feeLevel)
	}

	if len(note) > 0 {
		payload.Note = note
	}

	if len(maxFee) > 0 {
		payload.MaxFee = maxFee
	}

	if gasPrice.IsPositive() {
		payload.GasPrice = gasPrice.String()
	}

	if gasLimit.IsPositive() {
		payload.GasLimit = gasLimit.String()
	}

	if len(cpuStaking) > 0 {
		payload.CpuStaking = cpuStaking
	}

	if len(networkStaking) > 0 {
		payload.NetworkStaking = networkStaking
	}

	if len(autoStaking) > 0 {
		payload.AutoStaking = autoStaking
	}
	if len(customerRefId) > 0 {
		payload.CustomerRefId = customerRefId
	}

	if len(replaceTxByHash) > 0 {
		payload.ReplacedTxHash = replaceTxByHash
	}

	if extraParams != (ExtraParameters{}) {
		payload.ExtraParameters = extraParams
	}

	if len(destinations) > 0 {
		payload.Destinations = destinations
	}

	return s.CreateTransactionWithPayload(payload, idempotencyKey)
}

func (s *SDK) CreateTransactionWithPayload(payload CreateTransactionPayload, idempotencyKey string) (CreateTransactionResponse, error) {

	marshalled, err := json.Marshal(payload)
	if err != nil {
		return CreateTransactionResponse{}, err
	}
	returnedData, err := s.changeRequest("/v1/transactions", marshalled, idempotencyKey, http.MethodPost)

	if err != nil {
		log.Error(err)
	}

	var transactionResponse CreateTransactionResponse
	err = json.Unmarshal([]byte(returnedData), &transactionResponse)
	if err != nil {
		log.Error(err)
		return CreateTransactionResponse{}, errors.New(returnedData)
	}

	return transactionResponse, err
}

func (s *SDK) GetVaultAssetsBalance(accountNamePrefix string, accountNameSuffix string) (string, error) {

	params := url.Values{}
	if len(accountNamePrefix) > 0 {
		params.Add("accountNamePrefix", accountNamePrefix)
	}
	if len(accountNameSuffix) > 0 {
		params.Add("accountNameSuffix", accountNameSuffix)
	}
	uri := "/v1/vault/assets"
	if len(params) > 0 {
		query := fmt.Sprintf(uri+"?%s", params.Encode())
		return s.getRequest(query)
	} else {
		return s.getRequest(uri)
	}
}

func (s *SDK) GetVaultBalanceByAsset(assetId string) (string, error) {

	query := fmt.Sprintf("/v1/vault/assets/%s", assetId)
	return s.getRequest(query)
}

// ValidateAddress - validates the address of a given asset.
// assetId - the id of the asset to validate the address
// address - the address to validate
func (s *SDK) ValidateAddress(assetId string, address string) (AddressStatus, error) {

	query := fmt.Sprintf("/v1/transactions/validate_address/%s/%s", assetId, address)

	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
		return AddressStatus{}, err
	}
	var addressStatus AddressStatus
	err = json.Unmarshal([]byte(returnedData), &addressStatus)
	if err != nil {
		log.Error(err)
		return AddressStatus{}, err
	}

	return addressStatus, nil
}

// GetTransactionById - get the transaction details
// txId - transaction id
func (s *SDK) GetTransactionById(txId string) (TransactionDetails, error) {

	query := fmt.Sprintf("/v1/transactions/%s", txId)
	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
		return TransactionDetails{}, err
	}
	var transactionDetails TransactionDetails
	err = json.Unmarshal([]byte(returnedData), &transactionDetails)
	if err != nil {
		log.Error(err)
		return TransactionDetails{}, err
	}

	return transactionDetails, nil

}

func (s *SDK) GetExternalWallets() ([]ExternalWallet, error) {

	returnedData, err := s.getRequest("/v1/external_wallets")
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var extWallets []ExternalWallet
	err = json.Unmarshal([]byte(returnedData), &extWallets)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return extWallets, nil

}

func (s *SDK) GetExternalWallet(externalWalletId string) (ExternalWallet, error) {

	query := fmt.Sprintf("/v1/external_wallets/%s", externalWalletId)

	returnedData, err := s.getRequest(query)
	if err != nil {
		log.Error(err)
		return ExternalWallet{}, err
	}

	extWallet, err2 := getExtWallet(returnedData)
	if err2 != nil {
		return ExternalWallet{}, err2
	}

	return extWallet, nil

}

func getExtWallet(returnedData string) (ExternalWallet, error) {
	var extWallet ExternalWallet
	err := json.Unmarshal([]byte(returnedData), &extWallet)
	if err != nil {
		log.Error(err)
		return ExternalWallet{}, err
	}
	return extWallet, nil
}
