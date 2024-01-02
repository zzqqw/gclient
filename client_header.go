package gclient

import "encoding/base64"

func (c *Client) WithHeader(k, v string) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Header.Set(k, v)
	return c
}
func (c *Client) WithHeaderMap(headers map[string]string) *Client {
	for h, v := range headers {
		c.WithHeader(h, v)
	}
	return c
}

func (c *Client) WithContentType(contentType string) *Client {
	c.WithHeader(HttpHeaderContentType, contentType)
	return c
}
func (c *Client) WithUserAgent(userAgent string) *Client {
	c.WithHeader(HttpHeaderUserAgent, userAgent)
	return c
}

func (c *Client) WithRandomUserAgent() *Client {
	c.WithUserAgent(RandomUserAgent())
	return c
}
func (c *Client) WithRandomMobileUserAgent() *Client {
	c.WithUserAgent(RandomMobileUserAgent())
	return c
}
func (c *Client) AsForm() *Client {
	c.WithContentType(HttpHeaderContentTypeForm)
	return c
}
func (c *Client) AsJson() *Client {
	c.WithContentType(HttpHeaderContentTypeJson)
	return c
}
func (c *Client) AsXml() *Client {
	c.WithContentType(HttpHeaderContentTypeXml)
	return c
}

func (c *Client) WithBasicAuth(username, password string) *Client {
	c.WithToken(base64.StdEncoding.EncodeToString([]byte(username+":"+password)), AuthorizationTypeBasic)
	return c
}
func (c *Client) WithToken(token string, authorizationType ...string) *Client {
	if len(authorizationType) > 0 {
		token = authorizationType[0] + token
	} else {
		token = AuthorizationTypeBearer + token
	}
	c.Header.Set(HttpHeaderAuthorization, token)
	return c
}
