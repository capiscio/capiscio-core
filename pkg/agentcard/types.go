package agentcard

// TransportProtocol defines the supported transport protocols for A2A agents.
type TransportProtocol string

const (
	TransportJSONRPC  TransportProtocol = "JSONRPC"
	TransportGRPC     TransportProtocol = "GRPC"
	TransportHTTPJSON TransportProtocol = "HTTP+JSON"
)

// AgentCard represents the A2A Agent Card structure based on v0.3.0 specification.
type AgentCard struct {
	ProtocolVersion                   string                    `json:"protocolVersion"`
	Name                              string                    `json:"name"`
	Description                       string                    `json:"description"`
	URL                               string                    `json:"url"`
	PreferredTransport                TransportProtocol         `json:"preferredTransport,omitempty"`
	AdditionalInterfaces              []AgentInterface          `json:"additionalInterfaces,omitempty"`
	Provider                          *AgentProvider            `json:"provider,omitempty"`
	IconURL                           string                    `json:"iconUrl,omitempty"`
	Version                           string                    `json:"version"`
	DocumentationURL                  string                    `json:"documentationUrl,omitempty"`
	Capabilities                      AgentCapabilities         `json:"capabilities"`
	SecuritySchemes                   map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Security                          []map[string][]string     `json:"security,omitempty"`
	DefaultInputModes                 []string                  `json:"defaultInputModes"`
	DefaultOutputModes                []string                  `json:"defaultOutputModes"`
	Skills                            []AgentSkill              `json:"skills"`
	SupportsAuthenticatedExtendedCard bool                      `json:"supportsAuthenticatedExtendedCard,omitempty"`
	Signatures                        []Signature               `json:"signatures,omitempty"`
	Extensions                        []AgentExtension          `json:"extensions,omitempty"`
}

// AgentProvider contains information about the agent's provider.
type AgentProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url"`
}

// AgentCapabilities defines the capabilities supported by the agent.
type AgentCapabilities struct {
	Streaming              bool `json:"streaming,omitempty"`
	PushNotifications      bool `json:"pushNotifications,omitempty"`
	StateTransitionHistory bool `json:"stateTransitionHistory,omitempty"`
}

// AgentInterface defines additional interfaces for the agent.
type AgentInterface struct {
	URL       string            `json:"url"`
	Transport TransportProtocol `json:"transport"`
}

// SecurityScheme defines the security schemes used by the agent.
type SecurityScheme struct {
	Type             string      `json:"type"`
	Scheme           string      `json:"scheme,omitempty"`
	BearerFormat     string      `json:"bearerFormat,omitempty"`
	OpenIDConnectURL string      `json:"openIdConnectUrl,omitempty"`
	Flows            interface{} `json:"flows,omitempty"` // Using interface{} as 'any'
}

// AgentSkill defines a skill provided by the agent.
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// Signature represents a JWS signature on the Agent Card.
type Signature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// AgentExtension defines an extension supported by the agent.
type AgentExtension struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}
