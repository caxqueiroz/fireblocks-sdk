package fireblocks

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
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
	apiBaseURL string
	kto        *FbKeyMgmt
}

// NewInstance - create new type to handle Fireblocks API requests
func NewInstance(pk []byte, apik string, url string) *SDK {
	s := new(SDK)
	s.apiBaseURL = url
	privateK, err := jwt.ParseRSAPrivateKeyFromPEM(pk)
	if err != nil {
		log.Error(err)
	}

	s.kto = NewInstanceKeyMgmt(privateK, apik)
	return s
}

// getRequest - internal method to handle API call to Fireblocks
func (s *SDK) getRequest(path string) (string, error) {

	client := &http.Client{}
	urlEndPoint := s.apiBaseURL + path
	token, err := s.kto.createAndSignJWTToken(path, "")
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "Error signing JWT token"), err
	}

	request, err := http.NewRequest(http.MethodGet, urlEndPoint, nil)
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "Error creating NewRequest"), err
	}

	request.Header.Add("X-API-Key", s.kto.apiKey)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	response, err := client.Do(request)
	if err != nil {
		log.Error(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Error communicating with Fireblocks: %v", err)
	}

	if response.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("From Fireblocks server: %s \n", errors.New(response.Status)))
		log.Warning(err)
	}

	return string(data), err
}

func (s *SDK) changeRequest(
	path string, payload map[string]interface{}, idempotencyKey string, requestType string,
) (string, error) {

	client := &http.Client{}
	urlEndPoint := s.apiBaseURL + path
	var stringPayload string
	var marshalledPayload []byte

	if payload != nil {
		var err error
		marshalledPayload, err = json.Marshal(payload)
		if err != nil {
			log.Errorf("error processing json payload: %v", err)
		}
		stringPayload = string(marshalledPayload)
	}

	token, err := s.kto.createAndSignJWTToken(path, stringPayload)
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "Error signing JWT token"), err
	}

	request, err := http.NewRequest(requestType, urlEndPoint, bytes.NewBuffer(marshalledPayload))
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "Error creating NewRequest"), err
	}
	request.Header.Add("X-API-Key", string(s.kto.apiKey))
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	request.Header.Add("Content-Type", "application/json")

	if len(idempotencyKey) > 0 {
		request.Header.Add("Idempotency-Key", idempotencyKey)
	}
	response, err := client.Do(request)
	if err != nil {
		log.Error(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Error on communicating with Fireblocks: %v  \n data: %s", err, data)
	}

	if response.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("From Fireblocks server: %s \n", errors.New(response.Status)))
		log.Warningf("Error: %s", err)
	}

	return string(data), err

}

// GetSupportedAssets - Gets all assets that are currently supported by Fireblocks API.
func (s *SDK) GetSupportedAssets() (string, error) {
	return s.getRequest("/v1/supported_assets")
}

// GetVaultAccounts - gets all vault accounts for the tenant.
func (s *SDK) GetVaultAccounts(namePrefix string, nameSuffix string, minAmountThreshold decimal.Decimal) (string, error) {

	query := "/v1/vault/accounts"
	params := url.Values{}

	if namePrefix != "" {
		params.Add("namePrefix", namePrefix)
	}
	if nameSuffix != "" {
		params.Add("nameSuffix", nameSuffix)
	}
	if minAmountThreshold.GreaterThan(decimal.NewFromFloat(0.0)) {
		params.Add("nameSuffix", fmt.Sprintf("%f", minAmountThreshold))
	}
	if len(params) > 0 {
		query = query + "?" + params.Encode()
	}

	return s.getRequest(query)

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
	json.Unmarshal([]byte(returnedData), &vaultAsset)
	return vaultAsset, err

}

// GetDepositAddresses - Gets deposit addresses for an asset in a vault account
func (s *SDK) GetDepositAddresses(vaultAccountID string, assetID string) (string, error) {
	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/addresses", vaultAccountID, assetID)
	return s.getRequest(query)
}

// GetUnspentInputs - Gets utxo list for an asset in a vault account
func (s *SDK) GetUnspentInputs(vaultAccountID string, assetID string) (string, error) {
	query := fmt.Sprintf("/v1/vault/accounts/%s/%s/unspent_inouts", vaultAccountID, assetID)
	return s.getRequest(query)
}

// GenerateNewAddress - Generates a new address for an asset in a vault account
func (s *SDK) GenerateNewAddress(
	vaultAccountID string, assetID string, description string, customerRefID string,
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

	returnedData, err := s.changeRequest(query, payload, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return CreateAddressResponse{}, err
	}

	var createdAddress CreateAddressResponse
	err = json.Unmarshal([]byte(returnedData), &createdAddress)

	if err != nil {
		log.Error(err)
		return CreateAddressResponse{}, err
	}

	return createdAddress, nil

}

// SetAddressDescription - Sets the description of an existing address
func (s *SDK) SetAddressDescription(
	vaultAccountID string, assetID string, description string,
	address string, tag string,
) (string, error) {
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
	return s.changeRequest(query, payload, "", http.MethodPut)
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
func (s *SDK) GetExchangeAccounts() (string, error) {
	return s.getRequest("/v1/exchange_accounts")
}

// GetExchangeAccount - Gets an exchange account for your tenant
func (s *SDK) GetExchangeAccount(exchangeID string) (string, error) {
	query := fmt.Sprintf("/v1/exchange_accounts/%s", exchangeID)
	return s.getRequest(query)
}

// GetExchangeAccountAsset - Get a specific asset from an exchange account
func (s *SDK) GetExchangeAccountAsset(exchangeID string, assetID string) (string, error) {
	query := fmt.Sprintf("/v1/exchange_accounts/%s/%s", exchangeID, assetID)
	return s.getRequest(query)
}

func (s *SDK) SetCustomerRefId(vaultAccountId string, customerRefId string, idempotencyKey string) error {

	payload := map[string]interface{}{
		"customerRefId": customerRefId,
	}
	query := fmt.Sprintf("/v1/vault/accounts/%s", vaultAccountId)
	_, err := s.changeRequest(query, payload, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
		return err
	}

	return nil

}

// CreateVaultAccount
// name - vaultaccount name - usually we use as a join of userid + product_id (XXXX_YYYY)
func (s *SDK) CreateVaultAccount(
	name string, hiddenOnUI bool, customerRefID string, autoFuel bool, idempotencyKey string) (VaultAccount, error) {

	payload := map[string]interface{}{
		"name":       name,
		"hiddenOnUI": hiddenOnUI,
		"autoFuel":   autoFuel,
	}

	if len(customerRefID) > 0 {
		payload["customerRefId"] = customerRefID
	}

	var vaultAccount VaultAccount

	returnedData, err := s.changeRequest("/v1/vault/accounts", payload, idempotencyKey, http.MethodPost)
	if err != nil {
		log.Error(err)
	}

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
func (s *SDK) CreateVaultAsset(
	vaultAccountId string, assetId string, idempotencyKey string) (CreateVaultAssetResponse, error) {

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

	returnedData, err := s.changeRequest("/v1/external_wallets", payload, idempotencyKey, http.MethodPost)
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

	returnedData, err := s.changeRequest(cmd, payload, idempotencyKey, http.MethodPost)
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

func (s *SDK) CreateInternalWallet(name string, customerRefId string, idempotencyKey string) (string, error) {

	payload := map[string]interface{}{
		"name":          name,
		"customerRefId": customerRefId,
	}

	return s.changeRequest("/v1/internal_wallets", payload, idempotencyKey, http.MethodPost)
}

// CreateInternalWalletAsset

func (s *SDK) CreateInternalWalletAsset(walletId string, assetId string, address string, tag string, idempotencyKey string) (string, error) {

	cmd := fmt.Sprintf("/v1/internal_wallets/%s/%s", walletId, assetId)
	payload := map[string]interface{}{
		"address": address,
	}
	if len(tag) > 0 {
		payload["tag"] = tag
	}

	return s.changeRequest(cmd, payload, idempotencyKey, http.MethodPost)

}

// CreateTransaction -
func (s *SDK) CreateTransaction(
	assetId string, amount decimal.Decimal, source TransferPeerPath,
	destination DestinationTransferPeerPath, fee decimal.Decimal, gasPrice decimal.Decimal, waitForStatus bool,
	txType TransactionType, note string, cpuStaking string, networkStaking string,
	autoStaking string,
	customerRefId string, extraParams ExtraParameters, destinations []DestinationTransferPeerPath,
	feeLevel FeeLevel, failOnFee bool, maxFee string, gasLimit decimal.Decimal,
	replaceTxByHash string, idempotencyKey string,
) (CreateTransactionResponse, error) {

	payload := map[string]interface{}{
		"assetId":       assetId,
		"amount":        amount,
		"source":        source,
		"destination":   destination,
		"waitForStatus": waitForStatus,
		"operation":     txType,
	}

	if fee.IsPositive() {
		payload["fee"] = fee
	}

	if len(feeLevel) > 0 {
		payload["feeLevel"] = feeLevel
	}
	if len(note) > 0 {
		payload["note"] = note
	}
	if len(maxFee) > 0 {
		payload["maxFee"] = maxFee
	}

	if gasPrice.IsPositive() {
		payload["gasPrice"] = gasPrice
	}

	if gasLimit.IsPositive() {
		payload["gasLimit"] = gasLimit
	}

	if len(cpuStaking) > 0 {
		payload["cpuStaking"] = cpuStaking
	}

	if len(networkStaking) > 0 {
		payload["networkStaking"] = networkStaking
	}

	if len(autoStaking) > 0 {
		payload["autoStaking"] = autoStaking
	}
	if len(customerRefId) > 0 {
		payload["customerRefId"] = customerRefId
	}

	if len(replaceTxByHash) > 0 {
		payload["replaceTxByHash"] = replaceTxByHash
	}

	if extraParams != (ExtraParameters{}) {
		payload["extraParameters"] = extraParams
	}

	if len(destinations) > 0 {
		var arr []string
		for _, d := range destinations {
			jsonItem, err := json.Marshal(d)
			if err != nil {
				log.Errorf("Error processing destinations :: createTransaction : %v", err)
			} else {
				arr = append(arr, string(jsonItem))
			}
		}
		jsonArray, err := json.Marshal(arr)
		if err != nil {
			log.Errorf("error processing the jsonArray :: createTransaction: %v", err)
		} else {
			payload["destinations"] = string(jsonArray)
		}
	}

	returnedData, err := s.changeRequest("/v1/transactions", payload, idempotencyKey,
		http.MethodPost)

	var transactionResponse CreateTransactionResponse
	if err != nil {
		log.Error(err)
	}
	err = json.Unmarshal([]byte(returnedData), &transactionResponse)
	if err != nil {
		log.Error(err)
	}
	if len(transactionResponse.Id) == 0 {
		return transactionResponse, errors.New(returnedData)
	}
	return transactionResponse, err
}

func (s *SDK) GetVaultAssetsBalance(accountNamePrefix string, accountNameSuffix string) (
	string,
	error,
) {

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
func (s *SDK) GetTransactionById(txId string) (string, error) {
	query := fmt.Sprintf("/v1/transactions/%s", txId)
	return s.getRequest(query)
}

func (s *SDK) GetExternalWallets() (string, error) {
	return s.getRequest("/v1/external_wallets")
}

func (s *SDK) GetExternalWallet(externalWalletId string) (string, error) {
	query := fmt.Sprintf("/v1/external_wallets/%s", externalWalletId)
	return s.getRequest(query)
}
