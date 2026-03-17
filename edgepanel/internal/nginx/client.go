package nginx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// agentApplyRequest is the JSON body sent to POST /apply on the nginx-agent.
type agentApplyRequest struct {
	Files map[string]string `json:"files"`
}

// agentApplyResponse is the JSON body returned by the nginx-agent.
type agentApplyResponse struct {
	Message string `json:"message"`
	Output  string `json:"output"`
	Error   string `json:"error"`
}

// agentHTTPClient is the shared HTTP client used for all agent requests.
var agentHTTPClient = &http.Client{Timeout: 90 * time.Second}

// applyViaAgent sends the rendered config files to the nginx-agent's /apply
// endpoint. The agent writes the files, tests nginx config, and reloads nginx
// atomically. The combined nginx test+reload output is returned.
func (g *Generator) applyViaAgent(files map[string]string) (string, error) {
	reqBody := agentApplyRequest{Files: files}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal agent request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, g.AgentURL+"/apply", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create agent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.AgentToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.AgentToken)
	}

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("call nginx agent at %s: %w", g.AgentURL, err)
	}
	defer resp.Body.Close()

	var result agentApplyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode agent response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return result.Output, fmt.Errorf("nginx agent error: %s", result.Error)
	}
	return result.Output, nil
}
