package mcp

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSessionOwnsSnapshotsAndPackChanges(t *testing.T) {
	var manager Manager
	s := manager.Session("fixture")
	if s != manager.Session("fixture") {
		t.Fatal("identity changed")
	}
	if !s.LoadPack(1) || s.LoadPack(1) {
		t.Fatal("load change indicator")
	}
	snapshot := s.LoadedIDs()
	delete(snapshot, 1)
	if !s.LoadedIDs()[1] {
		t.Fatal("loaded pack map escaped")
	}
	s.HintClientName("hint")
	s.SetClientName("explicit")
	s.HintClientName("later")
	if s.ClientName() != "explicit" {
		t.Fatal("client hint replaced initialized identity")
	}
	if !s.UnloadPack(1) || s.UnloadPack(1) {
		t.Fatal("unload change indicator")
	}
	s.LoadPack(2)
	s.LoadPack(3)
	if s.UnloadAll() != 2 || len(s.LoadedIDs()) != 0 {
		t.Fatal("unload all")
	}
}

func TestStreamReplacementDetachDeleteAndBackpressure(t *testing.T) {
	var manager Manager
	s := manager.Session("fixture")
	old, oldDetach := s.OpenStream()
	current, detach := s.OpenStream()
	defer detach()
	if _, ok := <-old; ok {
		t.Fatal("replaced stream not closed")
	}
	oldDetach()
	manager.BroadcastToolsChanged()
	select {
	case message := <-current:
		if string(message) != string(Notification("notifications/tools/list_changed")) {
			t.Fatalf("notification: %s", message)
		}
	case <-time.After(time.Second):
		t.Fatal("old detach removed current stream")
	}
	for i := 0; i < 32; i++ {
		if !s.Push([]byte("fixture")) {
			t.Fatalf("buffer capacity changed at %d", i)
		}
	}
	if s.Push([]byte("overflow")) {
		t.Fatal("full stream should drop without blocking")
	}
	req := httptest.NewRequest("DELETE", "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "fixture")
	manager.ServeDelete(httptest.NewRecorder(), req)
	if manager.Session("fixture") == s {
		t.Fatal("deleted session reused")
	}
	for range current {
	}
	if s.Push(nil) {
		t.Fatal("deleted stream accepts messages")
	}
}

func TestSessionConcurrentStreamAndPackOperations(t *testing.T) {
	var manager Manager
	s := manager.Session("fixture")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				_, detach := s.OpenStream()
				s.LoadPack(int64(j))
				s.LoadedIDs()
				s.Push([]byte(fmt.Sprint(j)))
				s.UnloadPack(int64(j))
				detach()
			}
		})
	}
	wg.Wait()
}
