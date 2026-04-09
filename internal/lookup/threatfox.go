package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ThreatFox queries the abuse.ch ThreatFox API for IOC data.
// Free, no API key required.
type ThreatFox struct {
	result *ThreatFoxResult
}

func NewThreatFox() *ThreatFox {
	return &ThreatFox{}
}

func (t *ThreatFox) Name() string { return "threatfox" }

func (t *ThreatFox) Lookup(ctx context.Context, ip net.IP) error {
	// ThreatFox API: search IOCs by IP
	url := "https://threatfox-api.abuse.ch/api/v1/"

	payload := fmt.Sprintf(`{"query":"search_ioc","search_term":"%s"}`, ip.String())

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url,
		nopCloserFromString(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ThreatFox request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ThreatFox returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tfResp threatFoxResponse
	if err := json.Unmarshal(body, &tfResp); err != nil {
		return fmt.Errorf("ThreatFox parse error: %w", err)
	}

	if tfResp.QueryStatus != "ok" || len(tfResp.Data) == 0 {
		return nil // no results
	}

	t.result = &ThreatFoxResult{
		IOCCount: len(tfResp.Data),
		Link:     fmt.Sprintf("https://threatfox.abuse.ch/browse/?search=ioc%%3A%s", ip.String()),
	}

	// Extract IOC details (up to 10)
	seen := make(map[string]bool)
	for i, ioc := range tfResp.Data {
		if i >= 10 {
			break
		}
		t.result.IOCs = append(t.result.IOCs, ThreatFoxIOC{
			Type:         ioc.IOCType,
			Malware:      ioc.Malware,
			MalwareAlias: ioc.MalwareAlias,
			Confidence:   ioc.ConfidenceLevel,
			FirstSeen:    ioc.FirstSeenUTC,
			LastSeen:     ioc.LastSeenUTC,
			Reporter:     ioc.Reporter,
			Tags:         ioc.Tags,
		})

		if ioc.Malware != "" && !seen[ioc.Malware] {
			t.result.MalwareFamilies = append(t.result.MalwareFamilies, ioc.Malware)
			seen[ioc.Malware] = true
		}
		if ioc.ThreatType != "" && !seen["type:"+ioc.ThreatType] {
			t.result.ThreatTypes = append(t.result.ThreatTypes, ioc.ThreatType)
			seen["type:"+ioc.ThreatType] = true
		}
	}

	return nil
}

func (t *ThreatFox) Apply(result *Result) {
	if t.result != nil {
		result.ThreatFox = t.result
	}
}

// nopCloserFromString creates an io.ReadCloser from a string.
func nopCloserFromString(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

// --- ThreatFox API response types ---

type threatFoxResponse struct {
	QueryStatus string         `json:"query_status"`
	Data        []threatFoxIOC `json:"data"`
}

type threatFoxIOC struct {
	IOCType         string   `json:"ioc_type"`
	IOCValue        string   `json:"ioc"`
	ThreatType      string   `json:"threat_type"`
	Malware         string   `json:"malware"`
	MalwareAlias    string   `json:"malware_alias"`
	ConfidenceLevel int      `json:"confidence_level"`
	FirstSeenUTC    string   `json:"first_seen_utc"`
	LastSeenUTC     string   `json:"last_seen_utc"`
	Reporter        string   `json:"reporter"`
	Tags            []string `json:"tags"`
}
