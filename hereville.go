package hereville

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	LogFormat string `long:"log-format" choice:"text" choice:"json" default:"text" description:"Log format"`
	Verbose   []bool `short:"v" long:"verbose" description:"Show verbose debug information, each -v bumps log level"`
	logLevel  slog.Level

	Host     string `short:"H" long:"host" default:"localhost" description:"API host"`
	Port     int    `short:"p" long:"port" default:"3000" description:"API port"`
	Username string `short:"u" long:"username" default:"admin" description:"API username"`
	Password string `short:"P" long:"password" default:"admin" description:"API password"`
	Name     string `short:"n" long:"name" default:"apiorg" description:"Name for the API org"`
}

// Define a struct to represent the JSON response
type APIResponse struct {
	Message string `json:"message"`
	OrgID   int    `json:"orgId"`
}

// Define a struct to represent the token creation JSON response
type TokenCreationResponse struct {
	Token string `json:"key"`
}

// Define a struct to represent the service account JSON response
type ServiceAccountResponse struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Login      string `json:"login"`
	OrgID      int    `json:"orgId"`
	IsDisabled bool   `json:"isDisabled"`
	Role       string `json:"role"`
	Tokens     int    `json:"tokens"`
	AvatarURL  string `json:"avatarUrl"`
}

type AddAdminRequest struct {
	LoginOrEmail string `json:"loginOrEmail"`
	Role         string `json:"role"`
}

func addAdminToOrg(orgID int) error {
	requestPayload := AddAdminRequest{
		LoginOrEmail: "admin",
		Role:         "Admin",
	}

	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("error encoding request payload: %w", err)
	}

	url := fmt.Sprintf("http://%s:%s@%s:%d/api/orgs/%d/users", opts.Username, opts.Password, opts.Host, opts.Port, orgID)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)

	var bodyBytes bytes.Buffer
	_, err = bodyBytes.ReadFrom(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}
	body := bodyBytes.Bytes()

	prettyJSON, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		fmt.Println("Error formatting JSON:", err)
		return fmt.Errorf("error formatting JSON: %w", err)
	}

	file, err := os.Create("resp_add_admin.json")
	if err != nil {
		return fmt.Errorf("error creating resp_add_admin.json: %w", err)
	}
	defer file.Close()

	_, err = file.Write(prettyJSON)
	if err != nil {
		return fmt.Errorf("error writing to resp_add_admin.json: %w", err)
	}

	fmt.Println("Pretty Printed JSON response written to resp_add_admin.json")

	return nil
}

func Execute() int {
	if err := parseFlags(); err != nil {
		slog.Error("error parsing flags", "error", err)
		return 1
	}

	if err := setLogLevel(); err != nil {
		slog.Error("error setting log level", "error", err)
		return 1
	}

	if err := setupLogger(); err != nil {
		slog.Error("error setting up logger", "error", err)
		return 1
	}

	if err := run(); err != nil {
		slog.Error("run failed", "error", err)
		return 1
	}

	return 0
}

func parseFlags() error {
	_, err := flags.Parse(&opts)
	if err != nil {
		return fmt.Errorf("parse flags failed: %w", err)
	}

	return nil
}

func createServiceAccount() (*ServiceAccountResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%s@%s:%d/api/serviceaccounts", opts.Username, opts.Password, opts.Host, opts.Port)

	// Define the request payload
	payload := map[string]interface{}{
		"name": "test",
		"role": "Admin",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error encoding request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Create Service Account Response Status:", resp.Status)

	var bodyBytes bytes.Buffer
	_, err = io.Copy(&bodyBytes, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	body := bodyBytes.Bytes()

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, body, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error pretty printing JSON: %w", err)
	}

	fmt.Println("Pretty JSON Response:")
	fmt.Println(prettyJSON.String())

	var serviceAccount ServiceAccountResponse
	err = json.Unmarshal(body, &serviceAccount)
	if err != nil {
		return nil, fmt.Errorf("error decoding service account JSON response: %w", err)
	}

	fmt.Println("Service Account ID:", serviceAccount.ID)

	return &serviceAccount, nil
}

func createTokenForServiceAccount(serviceAccountID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%s@%s:%d/api/serviceaccounts/%d/tokens", opts.Username, opts.Password, opts.Host, opts.Port, serviceAccountID)

	payload := map[string]interface{}{
		"name": "test-token",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error encoding token creation request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("error creating token creation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making token creation request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Token Creation Response Status:", resp.Status)

	var bodyBytes bytes.Buffer
	_, err = io.Copy(&bodyBytes, resp.Body)
	if err != nil {
		return fmt.Errorf("error reading token creation response body: %w", err)
	}
	body := bodyBytes.Bytes()

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, body, "", "  ")
	if err != nil {
		return fmt.Errorf("error pretty printing token creation JSON: %w", err)
	}

	fmt.Println("Pretty Token Creation JSON Response:")
	fmt.Println(prettyJSON.String())

	file4, err := os.Create("resp_token.json")
	if err != nil {
		return fmt.Errorf("error creating resp_token.json file: %w", err)
	}
	defer file4.Close()

	_, err = file4.Write(prettyJSON.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to resp_token.json file: %w", err)
	}

	var tokenResponse TokenCreationResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return fmt.Errorf("error decoding token creation JSON response: %w", err)
	}

	tokenKey := tokenResponse.Token
	fmt.Println("Captured Token Key:", tokenKey)

	return nil
}

func getToken(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("error getting file info: %w", err)
	}

	fileContents := make([]byte, fileInfo.Size())
	_, err = file.Read(fileContents)
	if err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	type ResponseToken struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
	}

	var respToken ResponseToken
	err = json.Unmarshal(fileContents, &respToken)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON response: %w", err)
	}

	return respToken.Key, nil
}

func waitForGrafana() error {
	url := fmt.Sprintf("http://%s:%s@%s:%d/api/orgs", opts.Username, opts.Password, opts.Host, opts.Port)

	startTime := time.Now()
	maxWaitTime := 1 * time.Minute
	retryInterval := 1*time.Second + 500*time.Millisecond

	for {
		elapsedTime := time.Since(startTime).Round(time.Second)

		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}

		fmt.Printf("Waiting %s to access Grafana endpoint: %v\n", elapsedTime, err)

		if time.Since(startTime) >= maxWaitTime {
			return fmt.Errorf("waitForGrafana: Timeout exceeded, unable to connect to Grafana")
		}

		time.Sleep(retryInterval)
	}

	return nil
}

func createOrg() (APIResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%s@%s:%d/api/orgs", opts.Username, opts.Password, opts.Host, opts.Port)
	payload := []byte(fmt.Sprintf(`{"name":"%s"}`, opts.Name))

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return APIResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Use http.Request's Write method to get standard HTTP request representation
	var debugBuffer bytes.Buffer
	err = req.Write(&debugBuffer)
	if err != nil {
		return APIResponse{}, fmt.Errorf("error writing request: %w", err)
	}
	debugRequest := debugBuffer.String()
	fmt.Println("Request:\n", debugRequest)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return APIResponse{}, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)

	var bodyBytes bytes.Buffer
	_, err = bodyBytes.ReadFrom(resp.Body)
	if err != nil {
		return APIResponse{}, fmt.Errorf("error reading response body: %w", err)
	}
	body := bodyBytes.Bytes()

	var apiResponse APIResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return APIResponse{}, fmt.Errorf("error decoding JSON response: %w", err)
	}

	prettyJSON, err := json.MarshalIndent(apiResponse, "", "  ")
	if err != nil {
		return APIResponse{}, fmt.Errorf("error formatting JSON: %w", err)
	}

	file, err := os.Create("resp_create_org.json")
	if err != nil {
		return APIResponse{}, fmt.Errorf("error creating resp_create_org.json: %w", err)
	}
	defer file.Close()

	_, err = file.Write(prettyJSON)
	if err != nil {
		return APIResponse{}, fmt.Errorf("error writing to resp_create_org.json: %w", err)
	}

	fmt.Println("Pretty Printed JSON written to resp_create_org.json")
	fmt.Println(string(prettyJSON))

	return apiResponse, nil
}

func contextSwitchToOrg(orgID int) error {
	client := &http.Client{}
	contextSwitchURL := fmt.Sprintf("http://%s:%s@%s:%d/api/user/using/%d", opts.Username, opts.Password, opts.Host, opts.Port, orgID)
	contextSwitchResp, err := client.Post(contextSwitchURL, "application/json", nil)
	if err != nil {
		return fmt.Errorf("error making subsequent request: %w", err)
	}
	defer contextSwitchResp.Body.Close()

	fmt.Println("Context Switch Response Status:", contextSwitchResp.Status)

	var contextSwitchBodyBytes bytes.Buffer
	_, err = io.Copy(&contextSwitchBodyBytes, contextSwitchResp.Body)
	if err != nil {
		return fmt.Errorf("error reading contextSwitch response body: %w", err)
	}
	contextSwitchBody := contextSwitchBodyBytes.Bytes()

	var prettycontextSwitchJSON bytes.Buffer
	err = json.Indent(&prettycontextSwitchJSON, contextSwitchBody, "", "  ")
	if err != nil {
		return fmt.Errorf("error pretty printing contextSwitch JSON: %w", err)
	}

	fmt.Println("Pretty contextSwitch JSON Response:")
	fmt.Println(prettycontextSwitchJSON.String())

	file2, err := os.Create("resp_contextswitch.json")
	if err != nil {
		return fmt.Errorf("error creating resp_contextswitch.json file: %w", err)
	}
	defer file2.Close()

	_, err = file2.Write(prettycontextSwitchJSON.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to resp_contextswitch.json file: %w", err)
	}

	return nil
}

func createDashboard(authToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dashboardPayload := map[string]interface{}{
		"dashboard": map[string]interface{}{
			"id":            nil,
			"title":         "Production Overview",
			"tags":          []string{"templated"},
			"timezone":      "browser",
			"rows":          []interface{}{},
			"schemaVersion": 6,
			"version":       0,
		},
		"overwrite": false,
	}

	requestBody, err := json.Marshal(dashboardPayload)
	if err != nil {
		return fmt.Errorf("error encoding request payload: %w", err)
	}

	url := fmt.Sprintf("http://%s:%d/api/dashboards/db", opts.Host, opts.Port)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)

	var bodyBytes bytes.Buffer
	_, err = bodyBytes.ReadFrom(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}
	body := bodyBytes.Bytes()

	prettyJSON, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		fmt.Println("Error formatting JSON:", err)
		return fmt.Errorf("error formatting JSON: %w", err)
	}

	file, err := os.Create("resp_create_dashboard.json")
	if err != nil {
		return fmt.Errorf("error creating resp_create_dashboard.json: %w", err)
	}
	defer file.Close()

	_, err = file.Write(prettyJSON)
	if err != nil {
		return fmt.Errorf("error writing to resp_create_dashboard.json: %w", err)
	}

	fmt.Println("Pretty Printed JSON response written to resp_create_dashboard.json")

	return nil
}

func run() error {
	err := waitForGrafana()
	if err != nil {
		return fmt.Errorf("error waiting for Grafana: %w", err)
	}

	slog.Debug("Successfully connected to Grafana!")

	// 1. Create the org.
	apiResponse, err := createOrg()
	if err != nil {
		return fmt.Errorf("error creating org: %w", err)
	}

	fmt.Println("Captured OrgID:", apiResponse.OrgID)

	// 2. Optional step. If the org was created previously and/or step 3 fails
	// then first add your Admin user to the org:
	orgID := apiResponse.OrgID
	err = addAdminToOrg(orgID)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// 3. Switch the org context for the Admin user to the new org:
	err = contextSwitchToOrg(apiResponse.OrgID)
	if err != nil {
		return fmt.Errorf("error doing more stuff: %w", err)
	}

	// 4. Create a service account and token for the org.
	serviceAccount, err := createServiceAccount()
	if err != nil {
		return fmt.Errorf("error creating service account: %w", err)
	}

	// 5. Create a token for the service account.
	err = createTokenForServiceAccount(serviceAccount.ID)
	if err != nil {
		return fmt.Errorf("error creating token for service account: %w", err)
	}

	// https://grafana.com/docs/grafana/latest/developers/http_api/create-api-tokens-for-org/#how-to-add-a-dashboard
	// re-fetch token from file in order to use it in the next step
	filePath := "resp_token.json"
	authToken, err := getToken(filePath)
	if err != nil {
		return fmt.Errorf("error getting token: %w", err)
	}
	fmt.Println("Token:", authToken)

	// 6. Create a dashboard.
	err = createDashboard(authToken)
	if err != nil {
		return fmt.Errorf("error creating dashboard: %w", err)
	}

	return nil
}
