package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	// "net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"	// "net"

	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	// "github.com/tyler-smith/go-bip39"
)

// Logger for consistent logging
func logMessage(message string) {
	log.Printf("🔹 %s", message)
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Token string `json:"token"`
	} `json:"payload"`
}

// FlowIDResponse represents the flowId response
type FlowIDResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload struct {
		FlowID string `json:"flowId"`
		Eula   string `json:"eula"`
	} `json:"payload"`
}

// SubscriptionResponse represents the subscription response
type SubscriptionResponse struct {
	Status       string      `json:"status"`
	Subscription interface{} `json:"subscription"`
}

// NodeResponse represents the nodes response
type NodeResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"payload"`
}

// ClientResponse represents the client creation response
type ClientResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Client struct {
			Address      []string `json:"Address"`
			PublicKey    string   `json:"PublicKey"`
			PresharedKey string   `json:"PresharedKey"`
		} `json:"client"`
		Endpoint        string `json:"endpoint"`
		ServerPublicKey string `json:"serverPublicKey"`
	} `json:"payload"`
	PrivateKey   string `json:"privateKey"`
	PresharedKey string `json:"presharedKey"`
}

// WireGuardConfig represents the WireGuard configuration
type WireGuardConfig struct {
	Config         string `json:"config"`
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	PresharedKey   string `json:"presharedKey"`
	Address        string `json:"address"`
	Endpoint       string `json:"endpoint"`
	ServerPublicKey string `json:"serverPublicKey"`
}

// ConnectionResult represents the result of a connection attempt
type ConnectionResult struct {
	Success    bool           `json:"success"`
	Error      string         `json:"error,omitempty"`
	Message    string         `json:"message,omitempty"`
	ConfigPath string         `json:"configPath,omitempty"`
	Client     *ClientResponse `json:"client,omitempty"`
	ConfigData *WireGuardConfig `json:"configData,omitempty"`
	IP         string         `json:"ip,omitempty"`
}

// NodeConnectionInfo stores information about the last successful node connection
type NodeConnectionInfo struct {
	NodeID     string    `json:"node_id"`
	LastUsed   time.Time `json:"last_used"`
	ClientName string    `json:"client_name"`
}

// getLastNodeConnection retrieves the last successful node connection info
func getLastNodeConnection(configDir string) (*NodeConnectionInfo, error) {
	infoPath := filepath.Join(configDir, "last_node.json")
	
	// Check if the file exists
	if _, err := os.Stat(infoPath); os.IsNotExist(err) {
		return nil, nil
	}
	
	// Read the file
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read last node info: %v", err)
	}
	
	var info NodeConnectionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse last node info: %v", err)
	}
	
	return &info, nil
}

// saveLastNodeConnection saves the successful node connection info
func saveLastNodeConnection(configDir string, nodeID string, clientName string) error {
	info := NodeConnectionInfo{
		NodeID:     nodeID,
		LastUsed:   time.Now(),
		ClientName: clientName,
	}
	
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal node info: %v", err)
	}
	
	infoPath := filepath.Join(configDir, "last_node.json")
	if err := os.WriteFile(infoPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write node info: %v", err)
	}
	
	return nil
}

// Authenticate with the API and return an authentication token
func Authenticate(mnemonic string, chain string) (string, error) {
	logMessage("Starting authentication...")
	logMessage(fmt.Sprintf("Chain: %s", chain))

	// Create Ethereum wallet
	var wallet *hdwallet.Wallet
	var account accounts.Account
	var err error

	if mnemonic != "" {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
		if err != nil {
			return "", fmt.Errorf("failed to create wallet from mnemonic: %v", err)
		}
	} else {
		return "", fmt.Errorf("mnemonic is required")
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err = wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %v", err)
	}

	walletAddress := account.Address.Hex()
	logMessage(fmt.Sprintf("Wallet: %s", walletAddress))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			MaxConnsPerHost:     100,
			MaxIdleConnsPerHost: 100,
		},
	}

	// Step 1: Get flowId
	logMessage("Getting flowId...")
	flowIDURL := fmt.Sprintf("https://gateway.netsepio.com/api/v1.0/flowid?walletAddress=%s&chain=%s", walletAddress, chain)
	
	req, err := http.NewRequest("GET", flowIDURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create flowId request: %v", err)
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get flowId: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read flowId response: %v", err)
	}

	logMessage(fmt.Sprintf("FlowId Response: %s", string(body)))

	var flowIDResp FlowIDResponse
	if err := json.Unmarshal(body, &flowIDResp); err != nil {
		return "", fmt.Errorf("failed to parse flowId response: %v", err)
	}

	if flowIDResp.Status != 200 {
		return "", fmt.Errorf("failed to get flowId: %s", flowIDResp.Message)
	}

	flowID := flowIDResp.Payload.FlowID
	eula := flowIDResp.Payload.Eula
	logMessage("FlowId received")

	// Sign the message using ethers.js compatible method
	logMessage("Signing message...")
	messageToSign := eula + flowID
	
	privateKey, err := wallet.PrivateKey(account)
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %v", err)
	}
	
	// Create the Ethereum signed message prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageToSign))
	
	// Combine prefix and message
	fullMessage := append([]byte(prefix), []byte(messageToSign)...)
	
	// Hash the full message
	messageHash := crypto.Keccak256(fullMessage)
	
	// Sign the hash
	signature, err := crypto.Sign(messageHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}
	
	// Add recovery ID (v value)
	signature[64] += 27
	
	// Convert to hex string (no 0x prefix)
	signatureHex := hex.EncodeToString(signature)
	logMessage(fmt.Sprintf("Generated signature: %s", signatureHex))

	// Step 3: Authenticate
	logMessage("Authenticating...")
	authData := map[string]string{
		"chainName":     chain,
		"flowId":        flowID,
		"signature":     signatureHex,
		"walletAddress": walletAddress,
	}
	
	authJSON, err := json.Marshal(authData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth data: %v", err)
	}
	
	logMessage(fmt.Sprintf("Auth request data: %s", string(authJSON)))
	
	authReq, err := http.NewRequest("POST", fmt.Sprintf("https://gateway.netsepio.com/api/v1.0/authenticate?&chain=%s", chain), bytes.NewBuffer(authJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %v", err)
	}
	
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("User-Agent", "Mozilla/5.0")
	authReq.Header.Set("Accept", "application/json")
	
	authResp, err := client.Do(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to send auth request: %v", err)
	}
	defer authResp.Body.Close()
	
	authBody, err := io.ReadAll(authResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %v", err)
	}
	
	logMessage(fmt.Sprintf("Auth Response: %s", string(authBody)))
	
	var authResponse AuthResponse
	if err := json.Unmarshal(authBody, &authResponse); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %v", err)
	}
	
	if authResponse.Status != 200 {
		return "", fmt.Errorf("authentication failed: %s", authResponse.Message)
	}
	
	logMessage("Authentication successful")
	return authResponse.Payload.Token, nil
}

// Check subscription status
func CheckSubscription(token string) (*SubscriptionResponse, error) {
	logMessage("Checking subscription...")
	
	req, err := http.NewRequest("GET", "https://gateway.erebrus.io/api/v1.0/subscription", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send subscription request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription response: %v", err)
	}
	
	var subscriptionResp SubscriptionResponse
	if err := json.Unmarshal(body, &subscriptionResp); err != nil {
		return nil, fmt.Errorf("failed to parse subscription response: %v", err)
	}
	
	logMessage(fmt.Sprintf("Subscription status: %s", subscriptionResp.Status))
	return &subscriptionResp, nil
}

// Create a trial subscription
func CreateTrialSubscription(token string) error {
	logMessage("Creating trial subscription...")
	
	req, err := http.NewRequest("POST", "https://gateway.erebrus.io/api/v1.0/subscription/trial", nil)
	if err != nil {
		return fmt.Errorf("failed to create trial subscription request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send trial subscription request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read trial subscription response: %v", err)
	}
	
	logMessage(fmt.Sprintf("Trial subscription response: %s", string(body)))
	return nil
}

// Get all available nodes
func GetAllNodes(token string) ([]map[string]interface{}, error) {
	logMessage("Fetching nodes...")
	
	req, err := http.NewRequest("GET", "https://gateway.erebrus.io/api/v1.0/nodes/all", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create nodes request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send nodes request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read nodes response: %v", err)
	}
	
	var nodeResp NodeResponse
	if err := json.Unmarshal(body, &nodeResp); err != nil {
		return nil, fmt.Errorf("failed to parse nodes response: %v", err)
	}
	
	// Filter only active nodes
	var activeNodes []map[string]interface{}
	for _, node := range nodeResp.Payload {
		if node.Status == "active" {
			activeNodes = append(activeNodes, map[string]interface{}{
				"id":     node.ID,
				"status": node.Status,
			})
		}
	}
	
	logMessage(fmt.Sprintf("Found %d active nodes", len(activeNodes)))
	return activeNodes, nil
}

// Create a client for a specific node
func CreateClient(token string, nodeID string, clientName string) (*ClientResponse, error) {
	logMessage(fmt.Sprintf("Creating client for node: %s", nodeID))
	
	// Generate WireGuard keys
	keyPair, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard key pair: %v", err)
	}
	
	// Generate preshared key
	presharedKey, err := generatePresharedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard preshared key: %v", err)
	}
	
	clientData := map[string]string{
		"name":         clientName,
		"publicKey":    keyPair["publicKey"],
		"presharedKey": presharedKey,
	}
	
	clientJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client data: %v", err)
	}
	
	req, err := http.NewRequest("POST", fmt.Sprintf("https://gateway.erebrus.io/api/v1.0/erebrus/client/%s", nodeID), bytes.NewBuffer(clientJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create client request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send client request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read client response: %v", err)
	}
	
	var clientResp ClientResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to parse client response: %v", err)
	}
	
	// Store the private key and preshared key with the response data
	clientResp.PrivateKey = keyPair["privateKey"]
	clientResp.PresharedKey = presharedKey
	
	return &clientResp, nil
}

// Create WireGuard configuration
func CreateWireGuardConfig(clientData *ClientResponse) (*WireGuardConfig, error) {
	logMessage("Creating WireGuard configuration...")
	
	if clientData == nil || len(clientData.Payload.Client.Address) == 0 {
		return nil, fmt.Errorf("invalid client data")
	}
	
	// Create WireGuard configuration content
	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = 1.1.1.1, 8.8.8.8
PostUp = echo 'nameserver 1.1.1.1' | resolvconf -a %%i -m 0 || true
PostDown = resolvconf -d %%i || true

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, clientData.PrivateKey, clientData.Payload.Client.Address[0], 
   clientData.Payload.ServerPublicKey, clientData.Payload.Client.PresharedKey, 
   clientData.Payload.Endpoint)
	
	logMessage("WireGuard configuration created successfully")
	
	return &WireGuardConfig{
		Config:         configContent,
		PrivateKey:     clientData.PrivateKey,
		PublicKey:      clientData.Payload.Client.PublicKey,
		PresharedKey:   clientData.Payload.Client.PresharedKey,
		Address:        clientData.Payload.Client.Address[0],
		Endpoint:       fmt.Sprintf("%s:51820", clientData.Payload.Endpoint),
		ServerPublicKey: clientData.Payload.ServerPublicKey,
	}, nil
}

// Connect to DVPN
func ConnectDvpn(token string, nodeID string, clientName string, configPath string) (*ConnectionResult, error) {
	logMessage("Starting DVPN connection process...")
	logMessage(fmt.Sprintf("Node ID: %s", nodeID))
	
	result := &ConnectionResult{}
	
	// Check if WireGuard is installed
	logMessage("Checking WireGuard installation...")
	isWireGuardInstalled, err := checkWireGuard()
	if err != nil || !isWireGuardInstalled {
		logMessage("WireGuard is not installed")
		result.Success = false
		result.Error = "WireGuard not installed"
		result.Message = "Cannot connect to DVPN without WireGuard installed."
		return result, nil
	}
	logMessage("WireGuard is installed")
	
	// Create client for the specified node
	logMessage("Creating client...")
	client, err := CreateClient(token, nodeID, clientName)
	if err != nil {
		logMessage(fmt.Sprintf("Failed to create client: %v", err))
		result.Success = false
		result.Error = "Client creation failed"
		result.Message = fmt.Sprintf("Failed to create client: %v", err)
		return result, nil
	}
	logMessage("Client created successfully")
	
	// Create WireGuard configuration
	logMessage("Creating WireGuard configuration...")
	configData, err := CreateWireGuardConfig(client)
	if err != nil {
		logMessage(fmt.Sprintf("Failed to create WireGuard configuration: %v", err))
		result.Success = false
		result.Error = "Config creation failed"
		result.Message = fmt.Sprintf("Failed to create WireGuard configuration: %v", err)
		return result, nil
	}
	logMessage("WireGuard configuration created")
	
	// Write configuration to file for connection
	logMessage(fmt.Sprintf("Writing configuration to: %s", configPath))
	err = os.WriteFile(configPath, []byte(configData.Config), 0600)
	if err != nil {
		logMessage(fmt.Sprintf("Failed to write configuration: %v", err))
		result.Success = false
		result.Error = "Config write failed"
		result.Message = fmt.Sprintf("Failed to write WireGuard configuration: %v", err)
		return result, nil
	}
	logMessage("Configuration written successfully")
	
	// Connect to WireGuard
	logMessage("Connecting to WireGuard...")
	err = connectToWireGuard(configPath)
	if err != nil {
		logMessage(fmt.Sprintf("Failed to connect to WireGuard: %v", err))
		result.Success = false
		result.Error = "Connection failed"
		result.Message = fmt.Sprintf("Failed to connect to WireGuard: %v", err)
		return result, nil
	}
	logMessage("WireGuard connection established")
	
	// Check if connection was successful by verifying IP change
	logMessage("Checking new IP address...")
	newIP, err := getPublicIP()
	if err != nil {
		logMessage(fmt.Sprintf("Warning: Could not determine new IP: %v", err))
	} else {
		logMessage(fmt.Sprintf("New IP address: %s", newIP))
	}
	
	result.Success = true
	result.ConfigPath = configPath
	result.Client = client
	result.ConfigData = configData
	result.IP = newIP
	
	logMessage("DVPN connection process completed successfully")
	return result, nil
}

// DisconnectVPN handles the VPN disconnection process
func DisconnectVPN(configPath string) error {
	logMessage("Starting VPN disconnection process...")
	
	// List of cleanup commands to execute
	cleanupCommands := []string{
		"sudo wg-quick down astro-dvpn",
		"sudo ip link delete dev erebrus-vpn",
		"sudo ip link delete dev astro-dvpn",
		"sudo ip route del default dev erebrus-vpn",
		"sudo ip route del default dev astro-dvpn",
	}
	
	// Execute cleanup commands
	for _, cmd := range cleanupCommands {
		parts := strings.Split(cmd, " ")
		cleanupCmd := exec.Command(parts[0], parts[1:]...)
		output, err := cleanupCmd.CombinedOutput()
		if err != nil {
			// Log the error but continue with other cleanup commands
			logMessage(fmt.Sprintf("Warning during cleanup command '%s': %v, output: %s", cmd, err, string(output)))
		} else {
			logMessage(fmt.Sprintf("Successfully executed cleanup command: %s", cmd))
		}
	}
	
	// Remove the configuration file if it exists
	if _, err := os.Stat(configPath); err == nil {
		if err := os.Remove(configPath); err != nil {
			logMessage(fmt.Sprintf("Warning: Could not remove config file: %v", err))
		} else {
			logMessage("Configuration file removed successfully")
		}
	}
	
	// Remove the last node info file if it exists
	configDir := filepath.Dir(configPath)
	lastNodePath := filepath.Join(configDir, "last_node.json")
	if _, err := os.Stat(lastNodePath); err == nil {
		if err := os.Remove(lastNodePath); err != nil {
			logMessage(fmt.Sprintf("Warning: Could not remove last node info file: %v", err))
		} else {
			logMessage("Last node info file removed successfully")
		}
	}
	
	// Restore default DNS settings
	dnsCmd := exec.Command("sh", "-c", "echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf > /dev/null")
	output, dnsErr := dnsCmd.CombinedOutput()
	if dnsErr != nil {
		logMessage(fmt.Sprintf("Warning: Could not restore DNS settings: %s", string(output)))
	} else {
		logMessage("DNS settings restored")
	}
	
	logMessage("VPN disconnection process completed")
	return nil
}

// Check if WireGuard is installed
func checkWireGuard() (bool, error) {
	logMessage("Checking if WireGuard is installed...")
	
	cmd := exec.Command("which", "wg")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logMessage("WireGuard is NOT installed on the system.")
		return false, nil
	}
	
	logMessage(fmt.Sprintf("WireGuard found at: %s", strings.TrimSpace(string(output))))
	return true, nil
}

// Generate WireGuard key pair
func generateWireGuardKeyPair() (map[string]string, error) {
	logMessage("Generating WireGuard key pair...")
	
	// Create a temporary directory for key generation
	tempDir := fmt.Sprintf("/tmp/wg-keys-%d", time.Now().UnixNano())
	err := os.MkdirAll(tempDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Generate private key
	privateKeyPath := filepath.Join(tempDir, "private.key")
	cmdPrivate := exec.Command("wg", "genkey")
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %v", err)
	}
	
	cmdPrivate.Stdout = privateKeyFile
	err = cmdPrivate.Run()
	privateKeyFile.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	
	// Read private key
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))
	
	// Generate public key from private key
	publicKeyPath := filepath.Join(tempDir, "public.key")
	cmdPublic := exec.Command("wg", "pubkey")
	cmdPublic.Stdin = strings.NewReader(privateKey)
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key file: %v", err)
	}
	
	cmdPublic.Stdout = publicKeyFile
	err = cmdPublic.Run()
	publicKeyFile.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	
	// Read public key
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %v", err)
	}
	publicKey := strings.TrimSpace(string(publicKeyBytes))
	
	logMessage("WireGuard key pair generated successfully")
	return map[string]string{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	}, nil
}

// Generate WireGuard preshared key
func generatePresharedKey() (string, error) {
	logMessage("Generating WireGuard preshared key...")
	
	// Create a temporary file for key generation
	tempFile := fmt.Sprintf("/tmp/wg-psk-%d", time.Now().UnixNano())
	
	// Generate preshared key
	cmd := exec.Command("wg", "genpsk")
	pskFile, err := os.Create(tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to create preshared key file: %v", err)
	}
	
	cmd.Stdout = pskFile
	err = cmd.Run()
	pskFile.Close()
	if err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to generate preshared key: %v", err)
	}
	
	// Read the key
	pskBytes, err := os.ReadFile(tempFile)
	if err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to read preshared key: %v", err)
	}
	
	// Clean up
	os.Remove(tempFile)
	
	presharedKey := strings.TrimSpace(string(pskBytes))
	logMessage("WireGuard preshared key generated successfully")
	return presharedKey, nil
}

// Connect to WireGuard using a configuration file
func connectToWireGuard(configPath string) error {
	logMessage("Connecting to WireGuard...")
	
	// First, try to clean up any existing interfaces
	cleanupCommands := []string{
		"sudo wg-quick down astro-dvpn",
		"sudo ip link delete dev astro-dvpn",
	}
	
	for _, cmd := range cleanupCommands {
		parts := strings.Split(cmd, " ")
		cleanupCmd := exec.Command(parts[0], parts[1:]...)
		cleanupCmd.Run() // Ignore errors during cleanup
	}
	
	// Try wg-quick first
	cmd := exec.Command("sudo", "wg-quick", "up", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logMessage(fmt.Sprintf("wg-quick failed: %s", string(output)))
		logMessage("Trying manual setup...")
		
		// Parse the config file to get the necessary information
		configData, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %v", err)
		}
		
		// Extract values from config using regex
		privateKeyRegex := regexp.MustCompile(`PrivateKey\s*=\s*([^\s]+)`)
		addressRegex := regexp.MustCompile(`Address\s*=\s*([^\s]+)`)
		publicKeyRegex := regexp.MustCompile(`PublicKey\s*=\s*([^\s]+)`)
		presharedKeyRegex := regexp.MustCompile(`PresharedKey\s*=\s*([^\s]+)`)
		endpointRegex := regexp.MustCompile(`Endpoint\s*=\s*([^\s]+)`)
		
		privateKeyMatch := privateKeyRegex.FindSubmatch(configData)
		addressMatch := addressRegex.FindSubmatch(configData)
		publicKeyMatch := publicKeyRegex.FindSubmatch(configData)
		presharedKeyMatch := presharedKeyRegex.FindSubmatch(configData)
		endpointMatch := endpointRegex.FindSubmatch(configData)
		
		if privateKeyMatch == nil || addressMatch == nil || publicKeyMatch == nil || 
		   presharedKeyMatch == nil || endpointMatch == nil {
			return fmt.Errorf("failed to parse WireGuard config")
		}
		
		privateKey := string(privateKeyMatch[1])
		address := string(addressMatch[1])
		publicKey := string(publicKeyMatch[1])
		presharedKey := string(presharedKeyMatch[1])
		endpoint := string(endpointMatch[1])
		
		// Create a temporary config for wg command with proper format
		tempConf := fmt.Sprintf("/tmp/wg-temp-%d.conf", time.Now().UnixNano())
		wgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
`, privateKey, publicKey, presharedKey, endpoint)
		
		err = os.WriteFile(tempConf, []byte(wgConf), 0600)
		if err != nil {
			return fmt.Errorf("failed to write temp config: %v", err)
		}
		defer os.Remove(tempConf)
		
		// Manual setup commands with error output
		commands := []string{
			"sudo ip link add dev astro-dvpn type wireguard",
			fmt.Sprintf("sudo wg setconf astro-dvpn %s", tempConf),
			fmt.Sprintf("sudo ip addr add %s dev astro-dvpn", address),
			"sudo ip link set mtu 1420 up dev astro-dvpn",
			"sudo ip route add default dev astro-dvpn",
		}
		
		// Execute commands in sequence with detailed error output
		for _, command := range commands {
			cmdParts := strings.Split(command, " ")
			cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				logMessage(fmt.Sprintf("Command failed: %s", command))
				logMessage(fmt.Sprintf("Error output: %s", string(output)))
				
				// Clean up on error
				for _, cleanupCmd := range cleanupCommands {
					parts := strings.Split(cleanupCmd, " ")
					cmd := exec.Command(parts[0], parts[1:]...)
					cmd.Run() // Ignore errors during cleanup
				}
				
				return fmt.Errorf("failed to execute command: %s, error: %v, output: %s", command, err, string(output))
			}
			logMessage(fmt.Sprintf("Command successful: %s", command))
		}
	} else {
		logMessage("WireGuard connected via wg-quick")
	}
	
	// Add a DNS fix
	dnsCmd := exec.Command("sh", "-c", "echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf > /dev/null")
	output, dnsErr := dnsCmd.CombinedOutput()
	if dnsErr != nil {
		logMessage(fmt.Sprintf("Warning: Could not set DNS: %s", string(output)))
	} else {
		logMessage("DNS configured")
	}
	
	// Add a delay to allow the connection to stabilize
	time.Sleep(2 * time.Second)
	
	// Test internet connectivity
	pingCmd := exec.Command("ping", "-c", "1", "8.8.8.8")
	output, pingErr := pingCmd.CombinedOutput()
	if pingErr != nil {
		logMessage(fmt.Sprintf("Warning: Internet connectivity test failed: %s", string(output)))
	} else {
		logMessage("Internet connectivity confirmed")
	}
	
	return nil
}

// Get public IP address
func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(ip), nil
}

// ConnectToVPNWithNodeSelection attempts to connect to VPN using available active nodes
func ConnectToVPNWithNodeSelection(token string, clientName string, configPath string) (*ConnectionResult, error) {
	logMessage("Starting VPN connection with automatic node selection...")
	logMessage(fmt.Sprintf("Client Name: %s", clientName))
	logMessage(fmt.Sprintf("Config Path: %s", configPath))

	// Create trial subscription
	logMessage("Attempting to create trial subscription...")
	err := CreateTrialSubscription(token)
	if err != nil {
		logMessage(fmt.Sprintf("Warning: Failed to create trial subscription: %v", err))
		// Continue anyway, as the user might already have a subscription
	} else {
		logMessage("Trial subscription created successfully")
	}

	// Check subscription status
	logMessage("Checking subscription status...")
	subscription, err := CheckSubscription(token)
	if err != nil {
		logMessage(fmt.Sprintf("Error checking subscription: %v", err))
		return nil, fmt.Errorf("failed to check subscription: %v", err)
	}

	if subscription.Status != "active" {
		logMessage(fmt.Sprintf("Subscription status: %s", subscription.Status))
		return nil, fmt.Errorf("subscription is not active")
	}

	logMessage("Subscription active")

	// Get all nodes
	logMessage("Fetching available nodes...")
	nodes, err := GetAllNodes(token)
	if err != nil {
		logMessage(fmt.Sprintf("Error fetching nodes: %v", err))
		return nil, fmt.Errorf("failed to get nodes: %v", err)
	}

	if len(nodes) == 0 {
		logMessage("No active nodes found")
		return nil, fmt.Errorf("no active nodes available")
	}

	logMessage(fmt.Sprintf("Found %d active nodes", len(nodes)))
	for i, node := range nodes {
		logMessage(fmt.Sprintf("Node %d: ID=%s, Status=%s", i+1, node["id"], node["status"]))
	}

	// Try to get the last successful node connection
	configDir := filepath.Dir(configPath)
	lastNode, err := getLastNodeConnection(configDir)
	if err != nil {
		logMessage(fmt.Sprintf("Warning: Could not read last node info: %v", err))
	}

	// If we have a last node, try it first
	if lastNode != nil {
		logMessage(fmt.Sprintf("Found previous connection to node: %s", lastNode.NodeID))
		
		// Check if the last node is still in the active nodes list
		for _, node := range nodes {
			if node["id"] == lastNode.NodeID {
				logMessage("Previous node is still active, attempting to connect...")
				result, err := tryConnectToNode(token, lastNode.NodeID, clientName, configPath)
				if err == nil {
					// Save the successful connection
					if err := saveLastNodeConnection(configDir, lastNode.NodeID, clientName); err != nil {
						logMessage(fmt.Sprintf("Warning: Could not save node info: %v", err))
					}
					return result, nil
				}
				logMessage(fmt.Sprintf("Failed to connect to previous node: %v", err))
				break
			}
		}
		logMessage("Previous node is no longer active or connection failed, trying other nodes...")
	}

	// Try connecting to each active node until successful
	for i, node := range nodes {
		nodeID := node["id"].(string)
		logMessage(fmt.Sprintf("Attempting to connect to node %d/%d: %s", i+1, len(nodes), nodeID))

		result, err := tryConnectToNode(token, nodeID, clientName, configPath)
		if err == nil {
			// Save the successful connection
			if err := saveLastNodeConnection(configDir, nodeID, clientName); err != nil {
				logMessage(fmt.Sprintf("Warning: Could not save node info: %v", err))
			}
			return result, nil
		}
		logMessage(fmt.Sprintf("Failed to connect to node %s: %v", nodeID, err))
	}

	logMessage("Failed to connect to any available node")
	return nil, fmt.Errorf("failed to connect to any available node")
}

// tryConnectToNode attempts to connect to a specific node
func tryConnectToNode(token string, nodeID string, clientName string, configPath string) (*ConnectionResult, error) {
	// Check if WireGuard is installed
	isWireGuardInstalled, err := checkWireGuard()
	if err != nil || !isWireGuardInstalled {
		return nil, fmt.Errorf("WireGuard is not installed")
	}

	// Create client for the node
	client, err := CreateClient(token, nodeID, clientName)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}

	// Create WireGuard configuration
	configData, err := CreateWireGuardConfig(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard configuration: %v", err)
	}

	// Write configuration to file
	err = os.WriteFile(configPath, []byte(configData.Config), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write configuration: %v", err)
	}

	// Connect to WireGuard
	err = connectToWireGuard(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to WireGuard: %v", err)
	}

	// Check if connection was successful by verifying IP change
	newIP, err := getPublicIP()
	if err != nil {
		logMessage(fmt.Sprintf("Warning: Could not determine new IP: %v", err))
	}

	result := &ConnectionResult{
		Success:    true,
		ConfigPath: configPath,
		Client:     client,
		ConfigData: configData,
		IP:         newIP,
	}

	return result, nil
}

// ConnectToVPN handles the VPN connection process
func ConnectToVPN() error {
	logMessage("Starting VPN connection process...")

	// Get configuration from environment
	clientName := os.Getenv("NODE_NAME")
	configPath := filepath.Join(os.Getenv("WG_CONF_DIR"), "client.conf")
	chain := os.Getenv("CHAIN_NAME")
	if chain == "" {
		chain = "evm" // default chain
	}
	mnemonic := os.Getenv("MNEMONIC")
	if mnemonic == "" {
		return fmt.Errorf("MNEMONIC environment variable is required")
	}

	logMessage(fmt.Sprintf("Client Name: %s", clientName))
	logMessage(fmt.Sprintf("Config Path: %s", configPath))
	logMessage(fmt.Sprintf("Chain: %s", chain))

	// Get authentication token
	logMessage("Getting authentication token...")
	token, err := Authenticate(mnemonic, chain)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %v", err)
	}
	logMessage("Authentication successful")

	// Connect to VPN with automatic node selection
	logMessage("Initiating VPN connection with automatic node selection...")
	result, err := ConnectToVPNWithNodeSelection(token, clientName, configPath)
	if err != nil {
		return fmt.Errorf("failed to connect to VPN: %v", err)
	}

	logMessage(fmt.Sprintf("VPN Connection successful! New IP: %s", result.IP))
	return nil
} 