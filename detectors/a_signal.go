package detectors

import (
	"encoding/json"
	"net"
	"time"
)

const socketPath = "/tmp/ops_signal.sock"

// SignalPayload defines the data sent to the GKE worker
type SignalPayload struct {
	ContainerID string `json:"container_id"`
	EventID     string `json:"event_id"`
	FilePath    string `json:"file_path,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

func sendPauseSignal(containerID, eventID, filePath string) {
	if containerID == "" {
		return
	}

	conn, err := net.DialTimeout("unixgram", socketPath, 50*time.Millisecond)
	if err != nil {
		// Non-blocking: if the worker isn't there, we just log and move on
		return
	}
	defer conn.Close()

	payload := SignalPayload{
		ContainerID: containerID,
		EventID:     eventID,
		FilePath:    filePath,
		Timestamp:   time.Now().UnixNano(),
	}

	data, _ := json.Marshal(payload)
	conn.Write(data)
}
