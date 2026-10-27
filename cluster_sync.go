package main

import (
	"encoding/json"
	"fmt"
	"time"
)

func applyClusterEvent(eventType string, payload json.RawMessage) {
	switch eventType {
	case "beacon_update":
		var b Client
		if json.Unmarshal(payload, &b) == nil && b.ID != "" {
			upsertClientReplica(b)
		}
	case "beacon_offline":
		var m struct {
			BeaconID string `json:"beacon_id"`
		}
		if json.Unmarshal(payload, &m) == nil && m.BeaconID != "" {
			db.Model(&Client{}).Where("id = ? AND status = ?", m.BeaconID, "online").
				Update("status", "offline")
		}
	case "beacon_config":
		var m struct {
			BeaconID string `json:"beacon_id"`
			Sleep    int    `json:"sleep"`
			Jitter   int    `json:"jitter"`
		}
		if json.Unmarshal(payload, &m) == nil && m.BeaconID != "" {
			db.Model(&Client{}).Where("id = ?", m.BeaconID).Updates(map[string]interface{}{
				"sleep": m.Sleep, "jitter": m.Jitter,
			})
			cacheBeaconSleep(m.BeaconID, m.Sleep, m.Jitter)
		}
	case "beacon_note":
		var m struct {
			BeaconID string `json:"beacon_id"`
			Note     string `json:"note"`
		}
		if json.Unmarshal(payload, &m) == nil && m.BeaconID != "" {
			db.Model(&Client{}).Where("id = ?", m.BeaconID).Update("note", m.Note)
		}
	case "task_create":
		var t Task
		if json.Unmarshal(payload, &t) == nil && t.ID != "" && t.ClientID != "" {
			upsertTaskReplica(t)
			// Only the home node actually delivers the command to a beacon.
			var client Client
			if err := db.First(&client, "id = ?", t.ClientID).Error; err == nil &&
				(client.HomeNodeID == "" || client.HomeNodeID == localNodeID()) {
				addLog("TASK", fmt.Sprintf("CLUSTER_TASK_QUEUED: %s for %s (from node %s)", t.Command, t.ClientID, t.OriginNode))
			}
		}
	case "task_result":
		var m struct {
			TaskID string `json:"task_id"`
			Status string `json:"status"`
			Result string `json:"result"`
		}
		if json.Unmarshal(payload, &m) == nil && m.TaskID != "" {
			if m.Status == "" {
				m.Status = "completed"
			}
			result := db.Model(&Task{}).Where("id = ?", m.TaskID).Updates(map[string]interface{}{
				"status": m.Status, "result": m.Result,
			})
			if result.Error == nil && result.RowsAffected > 0 {
				t := Task{ID: m.TaskID, Status: m.Status, Result: m.Result}
				notifyTaskWaiters(&t)
			}
		}
	case "log":
		var m map[string]string
		if json.Unmarshal(payload, &m) == nil {
			appendLog(m["level"], "[peer] "+m["message"], false)
		}
	case "listener_update":
		var l Listener
		if json.Unmarshal(payload, &l) == nil && l.ID != "" {
			upsertListenerReplica(l)
		}
	case "listener_start", "listener_stop":
		var m struct {
			ListenerID string `json:"listener_id"`
		}
		if json.Unmarshal(payload, &m) == nil && m.ListenerID != "" {
			applyRemoteListenerControl(eventType, m.ListenerID)
		}
	case "node_new":
		var p clusterPeer
		if json.Unmarshal(payload, &p) == nil && p.ID != "" && p.ID != localNodeID() {
			upsertPeer(ClusterNode{ID: p.ID, Name: p.Name, URL: p.URL, Token: p.Token, CreatedAt: time.Now()})
			addLog("CLUSTER", fmt.Sprintf("PEER_INTRODUCED: %s (%s)", p.Name, p.URL))
		}
	}
}

// upsertClientReplica merges a beacon record received from a peer.
func upsertClientReplica(b Client) {
	if b.ID == "" {
		return
	}
	if b.HomeNodeID == "" {
		b.HomeNodeID = localNodeID()
	}
	var existing Client
	if err := db.First(&existing, "id = ?", b.ID).Error; err != nil {
		db.Create(&b)
		event := map[string]interface{}{
			"type": "new_beacon", "beacon_id": b.ID,
			"ip": b.IP, "hostname": b.Hostname, "username": b.Username,
			"os": b.OS, "is_admin": b.IsAdmin,
		}
		if eventJSON, err := json.Marshal(event); err == nil {
			broadcastWS(string(eventJSON))
		}
		return
	}
	updates := map[string]interface{}{
		"name": b.Name, "ip": b.IP, "internal_ip": b.InternalIP, "status": b.Status,
		"os": b.OS, "hostname": b.Hostname, "username": b.Username, "domain": b.Domain,
		"arch": b.Arch, "pid": b.PID, "process_name": b.ProcessName, "is_admin": b.IsAdmin,
		"listener_id": b.ListenerID, "home_node_id": b.HomeNodeID, "sleep": b.Sleep,
		"jitter": b.Jitter, "country": b.Country, "country_code": b.CountryCode,
		"last_check": b.LastCheck,
	}
	if b.Note != "" {
		updates["note"] = b.Note
	}
	db.Model(&existing).Updates(updates)
	cacheBeaconSleep(b.ID, b.Sleep, b.Jitter)
}

// upsertTaskReplica stores a task row created on another node (same ID).
func upsertTaskReplica(t Task) {
	var existing Task
	if err := db.First(&existing, "id = ?", t.ID).Error; err != nil {
		if t.Status == "" {
			t.Status = "pending"
		}
		if t.CreatedAt.IsZero() {
			t.CreatedAt = time.Now()
		}
		db.Create(&t)
	}
}

func upsertListenerReplica(l Listener) {
	if l.ID == "" {
		return
	}
	var existing Listener
	if err := db.First(&existing, "id = ?", l.ID).Error; err != nil {
		l.server = nil
		l.tcpListener = nil
		db.Create(&l)
		return
	}
	db.Model(&existing).Updates(map[string]interface{}{
		"name": l.Name, "type": l.Type, "bind_ip": l.BindIP, "port": l.Port,
		"status": l.Status, "node_id": l.NodeID,
	})
}

// applyRemoteListenerControl runs listener start/stop requested by a peer.
// Only the node that owns the listener can actually bind the port.
func applyRemoteListenerControl(action, listenerID string) {
	var l Listener
	if err := db.First(&l, "id = ?", listenerID).Error; err != nil {
		return
	}
	if l.NodeID != "" && l.NodeID != localNodeID() {
		return // not ours; the owning node handles it
	}

	switch action {
	case "listener_start":
		if err := l.Start(); err != nil {
			addLog("CLUSTER", fmt.Sprintf("REMOTE_LISTENER_START_FAILED: %s: %v", l.Name, err))
			return
		}
		addLog("CLUSTER", fmt.Sprintf("REMOTE_LISTENER_STARTED: %s", l.Name))
	case "listener_stop":
		if err := l.Stop(); err != nil {
			addLog("CLUSTER", fmt.Sprintf("REMOTE_LISTENER_STOP_FAILED: %s: %v", l.Name, err))
			return
		}
		addLog("CLUSTER", fmt.Sprintf("REMOTE_LISTENER_STOPPED: %s", l.Name))
	}
	emitClusterEvent("listener_update", l, "")
}
