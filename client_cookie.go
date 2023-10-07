package gclient

import (
	"net/http"
	"time"
)

func (c *Client) WithClientJar(jar http.CookieJar) ClientInterface {
	c.Client.Jar = jar
	return c
}
func (c *Client) WithCookieString(cookieString string) ClientInterface {
	c.SetCookie(NewCookieString(cookieString))
	return c
}

func (c *Client) WithCookie(k, v string) ClientInterface {
	c.Cookie.Set(k, v)
	return c
}

func (c *Client) WithCookieMap(cookies map[string]string) ClientInterface {
	for k, v := range cookies {
		c.WithCookie(k, v)
	}
	return c
}

func (c *Client) WithCookieNextRequest(cache CacheInterface, ttl time.Duration) ClientInterface {
	//set cookie
	c.OnResponse(func(c *Client, req *http.Request, resp *Response) error {
		cacheKey := Md5String(req.URL.Host)
		if !cache.Has(cacheKey) {
			cookieRaw := resp.GetCookie()
			if len(cookieRaw) > 0 {
				cookieByte, _ := c.JSONMarshal(cookieRaw)
				_ = cache.Set(cacheKey, string(cookieByte), ttl)
			}
		}
		return nil
	})
	// get cookie
	c.OnAfterRequest(func(c *Client, req *http.Request) error {
		cacheKey := Md5String(req.URL.Host)
		if cache.Has(cacheKey) {
			if cookStr, _ := cache.Get(cacheKey); cookStr != "" {
				var cookie Cookie
				_ = c.JSONUnmarshal([]byte(cookStr), &cookie)
				req.Header.Set(HttpHeaderCookie, cookie.Encode())
			}
		}
		return nil
	})
	return c
}
