package domain

type RecordingLoginResult struct {
	Detected bool   `json:"detected"`
	Action   string `json:"action"` // none | created | updated | unchanged | suggestion | error
	SiteID   int64  `json:"site_id,omitempty"`
	Origin   string `json:"origin,omitempty"`
	Message  string `json:"message"`
}
