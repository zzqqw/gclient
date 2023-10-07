package gclient

import "encoding/base64"

func (c *Client) WithHeader(k, v string) ClientInterface {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Header.Set(k, v)
	return c
}
func (c *Client) WithHeaderMap(headers map[string]string) ClientInterface {
	for h, v := range headers {
		c.WithHeader(h, v)
	}
	return c
}

func (c *Client) WithContentType(contentType string) ClientInterface {
	c.WithHeader(HttpHeaderContentType, contentType)
	return c
}
func (c *Client) WithUserAgent(userAgent string) ClientInterface {
	c.WithHeader(HttpHeaderUserAgent, userAgent)
	return c
}

func (c *Client) WithRandomUserAgent() ClientInterface {
	c.WithUserAgent(RandomUserAgent())
	return c
}
func (c *Client) WithRandomMobileUserAgent() ClientInterface {
	c.WithUserAgent(RandomMobileUserAgent())
	return c
}
func (c *Client) AsForm() ClientInterface {
	c.WithContentType(HttpHeaderContentTypeForm)
	return c
}
func (c *Client) AsJson() ClientInterface {
	c.WithContentType(HttpHeaderContentTypeJson)
	return c
}
func (c *Client) AsXml() ClientInterface {
	c.WithContentType(HttpHeaderContentTypeXml)
	return c
}

func (c *Client) WithBasicAuth(username, password string) ClientInterface {
	c.WithToken(base64.StdEncoding.EncodeToString([]byte(username+":"+password)), AuthorizationTypeBasic)
	return c
}
func (c *Client) WithToken(token string, authorizationType ...string) ClientInterface {
	if len(authorizationType) > 0 {
		token = authorizationType[0] + token
	} else {
		token = AuthorizationTypeBearer + token
	}
	c.Header.Set(HttpHeaderAuthorization, token)
	return c
}
