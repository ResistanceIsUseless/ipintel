package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// GreyNoise queries the GreyNoise Community or Enterprise API.
type GreyNoise struct {
	apiKey string
	result *GreyNoiseResult
}

func NewGreyNoise(apiKey string) *GreyNoise {
	return &GreyNoise{apiKey: apiKey}
}

func (g *GreyNoise) Name() string { return "greynoise" }

func (g *GreyNoise) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip.String())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("key", g.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GreyNoise request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		g.result = &GreyNoiseResult{
			Seen:    false,
			Message: "IP not observed by GreyNoise",
		}
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GreyNoise returned status %d: %s", resp.StatusCode, string(body))
	}

	var gnResp greynoiseResponse
	if err := json.Unmarshal(body, &gnResp); err != nil {
		return fmt.Errorf("GreyNoise parse error: %w", err)
	}

	g.result = &GreyNoiseResult{
		Seen:           true,
		Classification: gnResp.Classification,
		Name:           gnResp.Name,
		Noise:          gnResp.Noise,
		RIOT:           gnResp.RIOT,
		Link:           gnResp.Link,
		LastSeen:       gnResp.LastSeen,
		Message:        gnResp.Message,
	}

	return nil
}

func (g *GreyNoise) Apply(result *Result) {
	result.GreyNoise = g.result
}

type greynoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}
