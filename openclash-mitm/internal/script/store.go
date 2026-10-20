package script

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Store is a file-backed key/value map used by $persistentStore.
type Store struct {
	path string
	mu   sync.Mutex
	data map[string]string
}

// NewStore loads or creates a persistent store at dir/store.json.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "store.json"), data: map[string]string{}}
	b, err := os.ReadFile(s.path)
	if err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &s.data)
		if s.data == nil {
			s.data = map[string]string{}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Read returns the value for key, or an empty string when missing.
func (s *Store) Read(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

// Write stores value under key. A nil/empty value with explicit delete uses
// Write("", key) and still keeps an empty string; use Delete to remove.
func (s *Store) Write(value, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		return false
	}
	if old, ok := s.data[key]; ok && old == value {
		return true
	}
	s.data[key] = value
	return s.flushLocked() == nil
}

// Delete removes key.
func (s *Store) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; !ok {
		return true
	}
	delete(s.data, key)
	return s.flushLocked() == nil
}

func (s *Store) flushLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
