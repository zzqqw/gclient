package gclient

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	_newCache = NewFileCache("./.cache")
)

// 测试过期的缓存被驱逐
func TestCacheEvict(t *testing.T) {
	err := _newCache.Set("test", "value", 1*time.Second)
	if err != nil {
		t.Error(t, err)
	}
	time.Sleep(2 * time.Second) // 等待过期
	_, err = _newCache.Get("test")
	if !errors.Is(err, ErrFileCacheExpired) {
		t.Error(t, err)
	}
}

// 测试设置和获取字符串缓存
func TestSetGet(t *testing.T) {
	key := "testkey"
	value := "test value"
	err := _newCache.Set(key, value, 0)
	if err != nil {
		t.Error(t, err)
	}
	v, err := _newCache.Get(key)
	if err != nil {
		t.Error(t, err)
	}
	if v != value {
		t.Error(t, fmt.Errorf("file cache get err"))
	}
}

func BenchmarkGet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		_ = _newCache.Set(key, strings.Repeat("a", 100), 0)
	}
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key%d", i)
		_, _ = _newCache.Get(key)
	}
}
