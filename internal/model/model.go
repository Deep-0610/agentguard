package model

type Server struct {
	Name      string                 `json:"name"`
	Config    string                 `json:"config"`
	Command   string                 `json:"command,omitempty"`
	Args      []string               `json:"args,omitempty"`
	URL       string                 `json:"url,omitempty"`
	Env       map[string]string      `json:"env,omitempty"`
	Tools     []map[string]any       `json:"tools,omitempty"`
	Transport string                 `json:"transport,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Resource    string   `json:"resource"`
	Location    string   `json:"location,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Score       int      `json:"score"`
	Tags        []string `json:"tags,omitempty"`
}

type Result struct {
	Version  string    `json:"version"`
	Servers  []Server  `json:"servers"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

type Summary struct {
	Servers  int `json:"servers"`
	Findings int `json:"findings"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
