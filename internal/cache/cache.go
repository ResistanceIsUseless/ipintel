package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultTTL     = 24 * time.Hour
	DefaultBaseDir = ".cache/ipintel"
)

// Cache provides a simple file-based cache for IP lookup results.
// Each result is stored as a JSON file in ~/.cache/ipintel/ with a 24h TTL.
type Cache struct {
	dir string
	ttl time.Duration
}

// New creates a new file-based cache. If dir is empty, uses ~/.cache/ipintel/.
func New(dir string, ttl time.Duration) (*Cache, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, DefaultBaseDir)
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cannot create cache directory: %w", err)
	}

	return &Cache{dir: dir, ttl: ttl}, nil
}

// Get retrieves a cached result for the given IP. Returns nil if not cached or expired.
func (c *Cache) Get(ip string) ([]byte, bool) {
	path := c.path(ip)

	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}

	// Check TTL
	if time.Since(info.ModTime()) > c.ttl {
		os.Remove(path)
		return nil, false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	return data, true
}

// Put stores a result in the cache.
func (c *Cache) Put(ip string, result interface{}) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal for cache: %w", err)
	}

	return os.WriteFile(c.path(ip), data, 0o644)
}

// Evict removes a cached entry.
func (c *Cache) Evict(ip string) {
	os.Remove(c.path(ip))
}

// Clear removes all cached entries.
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			os.Remove(filepath.Join(c.dir, e.Name()))
		}
	}
	return nil
}

// path returns the file path for a cached IP result.
func (c *Cache) path(ip string) string {
	// Use SHA256 to avoid filesystem issues with IPv6 colons
	hash := sha256.Sum256([]byte(ip))
	return filepath.Join(c.dir, fmt.Sprintf("%x.json", hash[:8]))
}
