package gclient

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const Name = "GClient"
const Version = "alpha"

const (
	HttpSchemeName      = `http`
	HttpParamFileHolder = `@file:`
	HttpRegexParamJson  = `^[\w\[\]]+=.+`

	HttpHeaderHost   = `Host`
	HttpHeaderCookie = `Cookie`

	HttpHeaderUserAgent     = `User-Agent`
	HttpHeaderAuthorization = "Authorization"
	HttpHeaderAccept        = "Accept"
	HttpMIMEEventStream     = "text/event-stream"
	HttpHeaderCacheControl  = "Cache-Control"
	HttpHeaderConnection    = "Connection"
	HttpHeaderContentType   = `Content-Type`

	CharsetUTF8                          = "charset=UTF-8"
	HttpHeaderContentTypeJson            = `application/json`
	HttpHeaderContentTypeJsonCharsetUTF8 = HttpHeaderContentTypeJson + "; " + CharsetUTF8
	HttpHeaderContentTypeXml             = `application/xml`
	HttpHeaderContentTypeXmlCharsetUTF8  = HttpHeaderContentTypeXml + "; " + CharsetUTF8
	HttpHeaderContentTypeForm            = `application/x-www-form-urlencoded`

	AuthorizationTypeBearer = "Bearer "
	AuthorizationTypeBasic  = "Basic "
)

var (
	hdrUserAgentKey    = http.CanonicalHeaderKey(HttpHeaderUserAgent)
	hostname, _        = os.Hostname()
	defaultClientAgent = fmt.Sprintf(`%s/%s (github.com/zzqqw/gclient) at %s`, Name, Version, hostname)
	defaultRetryCount  = 3
	defaultWaitTime    = time.Duration(2000) * time.Millisecond
)

type (
	CtxKeyString     string
	MiddlewareFunc   = func(c *Client, r *http.Request) (*Response, error)
	ClientCallback   func(c *Client) error
	RequestCallback  func(c *Client, req *http.Request) error
	ResponseCallback func(c *Client, req *http.Request, resp *Response) error
	ErrorHook        func(c *Client, request *http.Request, err error)
	SuccessHook      func(c *Client, resp *Response)
)

func NewSetHttpClient(client *http.Client) *Client {
	c := &Client{Client: client}
	c.Clone()
	return c
}

func New() *Client {
	c := new(Client)
	c.Clone()
	return c
}

func DefaultHttpClient() *http.Client {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		MaxIdleConnsPerHost: runtime.GOMAXPROCS(0) + 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport}
}

func DefaultHttpClientWithTimeOut(localAddr net.Addr) *http.Client {
	dialer := &net.Dialer{
		Timeout:       30 * time.Second,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 1 * time.Second,
	}
	if localAddr != nil {
		dialer.LocalAddr = localAddr
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport}
}

type Client struct {
	*http.Client

	Debug  bool
	writer io.Writer

	BaseURL       string
	Query         url.Values
	Header        http.Header
	Cookie        Cookie
	Logger        LoggerInterface
	JSONMarshal   func(v any) ([]byte, error)
	JSONUnmarshal func(data []byte, v any) error
	XMLMarshal    func(v any) ([]byte, error)
	XMLUnmarshal  func(data []byte, v any) error

	middlewares            []MiddlewareFunc
	beforeRequestCallbacks []ClientCallback
	afterRequestCallbacks  []RequestCallback
	responseCallbacks      []ResponseCallback
	successHooks           []SuccessHook
	errorHooks             []ErrorHook
	panicHooks             []ErrorHook

	retryCount    int
	retryWaitTime time.Duration
	attempt       int

	clone int
	lock  sync.RWMutex
	ctx   context.Context
}

func (c *Client) Clone() *Client {
	c.Debug = false
	if c.Client == nil {
		c.Client = DefaultHttpClient()
	}
	c.BaseURL = ""
	c.Query = make(url.Values, 0)
	c.Header = make(http.Header, 0)
	c.Cookie = make(Cookie, 0)
	if c.Logger == nil {
		c.SetLogger(NewLogger())
	}
	if c.JSONMarshal == nil {
		c.SetJSONMarshaler(json.Marshal)
	}
	if c.JSONUnmarshal == nil {
		c.SetJSONUnmarshaler(json.Unmarshal)
	}
	if c.XMLMarshal == nil {
		c.SetXMLMarshaler(xml.Marshal)
	}
	if c.XMLUnmarshal == nil {
		c.SetXMLUnmarshaler(xml.Unmarshal)
	}
	c.middlewares = make([]MiddlewareFunc, 0)
	c.beforeRequestCallbacks = make([]ClientCallback, 0)
	c.afterRequestCallbacks = make([]RequestCallback, 0)
	c.responseCallbacks = make([]ResponseCallback, 0)
	c.successHooks = make([]SuccessHook, 0)
	c.errorHooks = make([]ErrorHook, 0)
	c.panicHooks = make([]ErrorHook, 0)

	c.retryCount = defaultRetryCount
	c.retryWaitTime = defaultWaitTime
	c.ctx = context.Background()
	//os.Stderr
	c.writer = nil

	//------------debug-------------------------
	//set debug = true
	c.OnAfterRequest(OnAfterRequestDebug)
	c.OnResponse(OnResponseDebug)
	// set writer = os.Stderr
	c.OnResponse(OnResponseWriterRequestLog)
	//-------------------------------------------

	if c.Header.Get(HttpHeaderUserAgent) == "" {
		c.WithUserAgent(defaultClientAgent)
	}
	c.attempt = 1
	c.clone += 1
	return c
}

func (c *Client) SetHttpClient(client *http.Client) *Client {
	c.Client = client
	return c
}
func (c *Client) SetDebug(debug bool) *Client {
	c.Debug = debug
	return c
}
func (c *Client) EnableDebug() *Client {
	c.SetDebug(true)
	return c
}

func (c *Client) SetLogger(logger LoggerInterface) *Client {
	c.Logger = logger
	return c
}

// SetWriter os.Stderr
func (c *Client) SetWriter(writer io.Writer) *Client {
	c.writer = writer
	return c
}

func (c *Client) SetBaseURL(baseUrl string) *Client {
	c.BaseURL = baseUrl
	return c
}

func (c *Client) SetQuery(query url.Values) *Client {
	c.Query = query
	return c
}

func (c *Client) SetCookie(cookie Cookie) *Client {
	c.Cookie = cookie
	return c
}
func (c *Client) SetHeader(header http.Header) *Client {
	c.Header = header
	return c
}
func (c *Client) SetJSONMarshaler(marshaler func(v interface{}) ([]byte, error)) *Client {
	c.JSONMarshal = marshaler
	return c
}
func (c *Client) SetJSONUnmarshaler(unmarshaler func(data []byte, v interface{}) error) *Client {
	c.JSONUnmarshal = unmarshaler
	return c
}
func (c *Client) SetXMLMarshaler(marshaler func(v any) ([]byte, error)) *Client {
	c.XMLMarshal = marshaler
	return c
}
func (c *Client) SetXMLUnmarshaler(unmarshaler func(data []byte, v any) error) *Client {
	c.XMLUnmarshal = unmarshaler
	return c
}

func (c *Client) SetRetry(retryCount int, retryWaitTime time.Duration) *Client {
	c.retryCount = retryCount
	c.retryWaitTime = retryWaitTime
	return c
}
func (c *Client) SetTimeout(t time.Duration) *Client {
	c.Client.Timeout = t
	return c
}
func (c *Client) SetTLSConfig(tlsConfig *tls.Config) *Client {
	v, ok := c.Transport.(*http.Transport)
	if !ok {
		c.Logger.Errorf(`cannot set TLSClientConfig for custom Transport of the client`)
		return c
	}
	v.TLSClientConfig = tlsConfig
	return c
}
func (c *Client) SetCheckRedirect(fn func(req *http.Request, via []*http.Request) error) {
	c.CheckRedirect = fn
}
func (c *Client) Unmarshal(contentType string, b []byte, d any) (err error) {
	if IsJSONType(contentType) {
		err = c.JSONUnmarshal(b, d)
	} else if IsXMLType(contentType) {
		err = c.XMLUnmarshal(b, d)
	}
	return
}

func (c *Client) WithTLSKeyCrt(crtFile, keyFile string) *Client {
	crt, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		c.Logger.Errorf("LoadKeyCrt failed")
		return c
	}
	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{crt}
	tlsConfig.Time = time.Now
	tlsConfig.Rand = rand.Reader
	tlsConfig.InsecureSkipVerify = true
	c.SetTLSConfig(tlsConfig)
	return c
}

// WithProxyUrl
// The correct pattern is like `http://USER:PASSWORD@IP:PORT` or `socks5://USER:PASSWORD@IP:PORT`.
func (c *Client) WithProxyUrl(proxyURL string) *Client {
	if strings.TrimSpace(proxyURL) == "" {
		return c
	}
	_proxy, err := url.Parse(proxyURL)
	if err != nil {
		c.Logger.Errorf(`%+v`, err)
		return c
	}
	if _proxy.Scheme == HttpSchemeName {
		if v, ok := c.Transport.(*http.Transport); ok {
			v.Proxy = http.ProxyURL(_proxy)
		}
	} else {
		auth := &proxy.Auth{}
		user := _proxy.User.Username()
		if user != "" {
			auth.User = user
			password, hasPassword := _proxy.User.Password()
			if hasPassword && password != "" {
				auth.Password = password
			}
		} else {
			auth = nil
		}
		// refer to the source code, error is always nil
		dialer, err := proxy.SOCKS5("tcp", _proxy.Host, auth, &net.Dialer{
			Timeout:   c.Client.Timeout,
			KeepAlive: c.Client.Timeout,
		})
		if err != nil {
			c.Logger.Errorf(`%+v`, err)
			return c
		}
		if v, ok := c.Transport.(*http.Transport); ok {
			v.DialContext = func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
				return dialer.Dial(network, addr)
			}
		}
	}
	return c
}
