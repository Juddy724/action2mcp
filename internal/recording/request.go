package recording

type Request struct {
	ID             int64             `json:"id"`
	RecordingID    int64             `json:"recording_id"`
	Seq            int               `json:"seq"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	ResourceType   string            `json:"resource_type"`
	ReqHeaders     map[string]string `json:"req_headers,omitempty"`
	ReqBody        string            `json:"req_body,omitempty"`
	Status         int               `json:"status"`
	RespHeaders    map[string]string `json:"resp_headers,omitempty"`
	RespBody       string            `json:"resp_body,omitempty"`
	RespMime       string            `json:"resp_mime"`
	Noise          bool              `json:"noise"`
	NoiseHeuristic bool              `json:"noise_heuristic"`
	Note           *Note             `json:"note"`
	NoiseReason    string            `json:"noise_reason"`
	TS             string            `json:"ts"`
	ReqSize        int               `json:"req_size"`
	RespSize       int               `json:"resp_size"`
	IsLogin        bool              `json:"is_login,omitempty"`
}

type Note struct {
	RequestID     int64  `json:"request_id"`
	RecordingID   int64  `json:"recording_id"`
	Purpose       string `json:"purpose"`
	Category      string `json:"category"`
	Useful        *bool  `json:"useful"`
	NoiseOverride *bool  `json:"noise_override"`
	Source        string `json:"source"`
	UpdatedAt     string `json:"updated_at"`
}

// Keep the recorded classification available when a note changes which list a
// request belongs to. A nil override always leaves the heuristic in effect.
func ApplyNote(q *Request, notes map[int64]Note) {
	q.NoiseHeuristic = q.Noise
	if n, ok := notes[q.ID]; ok {
		q.Note = &n
		if n.NoiseOverride != nil {
			q.Noise = *n.NoiseOverride
			return
		}
	}
	if q.IsLogin {
		q.Noise, q.NoiseReason = false, "" // always offer 「保存为登录配置」 unless a note overrides it
	}
}
