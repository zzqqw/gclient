package gclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"
)

const fileCacheSuffix = ".bin"

var ErrFileCacheExpired = fmt.Errorf("the key is expired")

type CacheInterface interface {
	Set(key, value string, ttl time.Duration) error
	Get(key string) (string, error)
	Has(key string) bool
	Delete(key string) error
	CleanExpired() error
}

type FileCache struct {
	dir string
	mu  sync.Mutex
}
type CacheItem struct {
	V string    `json:"v"`
	E time.Time `json:"e"`
}

func NewFileCache(paths ...string) CacheInterface {
	dir := os.TempDir() + "gclient/"
	if len(paths) > 0 {
		dir = paths[0]
	}
	fileCache := &FileCache{dir: dir}
	return fileCache
}

func (f *FileCache) Set(key, value string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	item := CacheItem{V: value}
	if ttl != time.Duration(0) {
		item.E = time.Now().Add(ttl)
	}
	cacheFileKey, err := f.getCacheKey(key)
	if err != nil {
		return err
	}
	cacheValue, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFileKey, cacheValue, os.ModePerm)
}

func (f *FileCache) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cacheFileKey, err := f.getCacheKey(key)
	if err != nil {
		return "", err
	}
	item, err := f.getCacheItemByCacheFile(cacheFileKey)
	if err != nil {
		return "", err
	}
	return item.V, nil
}

func (f *FileCache) Has(key string) bool {
	if _, err := f.Get(key); err == nil {
		return true
	}
	return false
}

func (f *FileCache) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	filename, err := f.getCacheKey(key)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil
	}
	if err = os.Remove(filename); err != nil {
		return fmt.Errorf("can not delete this file cache key-value, key is %s and file name is %s", key, filename)
	}
	return nil
}

func (f *FileCache) CleanExpired() error {
	return filepath.Walk(f.dir, func(cachePathOrPath string, info os.FileInfo, err error) error {
		if info != nil {
			if path.Ext(info.Name()) == fileCacheSuffix {
				f.mu.Lock()
				defer f.mu.Unlock()
				_, _ = f.getCacheItemByCacheFile(cachePathOrPath)
			}
		}
		return nil
	})
}

func (f *FileCache) getCacheItemByCacheFile(cacheFile string) (item CacheItem, err error) {
	fileItem, err := os.ReadFile(cacheFile)
	if err != nil {
		return item, err
	}
	if err = json.Unmarshal(fileItem, &item); err != nil {
		return item, err
	}
	var zeroT time.Time
	if zeroT != item.E && item.E.Before(time.Now()) {
		_ = os.Remove(cacheFile)
		return item, ErrFileCacheExpired
	}
	return item, nil
}

func (f *FileCache) getCacheKey(key string) (string, error) {
	keyHash := Md5String(key)
	dir := filepath.Join(f.dir, keyHash[0:2])
	if err := f.ensureDirectory(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%s%s", keyHash, fileCacheSuffix)), nil
}

func (f *FileCache) ensureDirectory(path string) error {
	var err error
	if _, err = os.Stat(path); os.IsNotExist(err) {
		if err = os.MkdirAll(path, os.ModePerm); err != nil {
			return fmt.Errorf("create directory %s err=%v", path, err)
		}
	}
	return err
}
