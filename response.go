package gclient

import (
	"bufio"
	"io"
	"net/http"
)

type ResponseInterface interface {
	Close() error
	GetCookie() Cookie
	ReadAll() []byte
	ReadStream(fn func(line []byte, number int64)) int64
	ReadAllString() string
	ContentType() string
	Unmarshal(d any) error
	IsSuccess() bool
	IsError() bool
}

type Response struct {
	*http.Response
	Request *http.Request
	GClient *Client
}

// Close closes the response when it will never be used.
func (r *Response) Close() error {
	if r == nil || r.Response == nil {
		return nil
	}
	r.Request = nil
	r.GClient = nil
	return r.Response.Body.Close()
}

func (r *Response) GetCookie() Cookie {
	raw := make(Cookie)
	for _, c := range r.Cookies() {
		raw.Set(c.Name, c.Value)
	}
	return raw
}

// ReadAll retrieves and returns the response content as []byte.
func (r *Response) ReadAll() []byte {
	// Response might be nil.
	if r == nil || r.Response == nil {
		return []byte{}
	}
	body, err := io.ReadAll(r.Response.Body)
	if err != nil {
		return nil
	}
	return body
}

// ReadStream
//Microsoft ChatGPT Data Structure end
func (r *Response) ReadStream(fn func(line []byte, number int64)) int64 {
	var number int64
	if r.IsError() {
		return number
	}
	if !IsStreamType(r.ContentType()) {
		fn(r.ReadAll(), number)
		return number
	}
	b := bufio.NewReader(r.Response.Body)
	for {
		rawLine, _, err := b.ReadLine()
		if err != nil {
			break
		}
		fn(rawLine, number)
		number += 1
	}
	return number
}

// ReadAllString retrieves and returns the response content as string.
func (r *Response) ReadAllString() string {
	return string(r.ReadAll())
}

// ContentType response header Content-Type
func (r *Response) ContentType() string {
	return r.Response.Header.Get(HttpHeaderContentType)
}

// Unmarshal content into object from JSON or XML
func (r *Response) Unmarshal(d any) error {
	return r.GClient.Unmarshal(r.ContentType(), r.ReadAll(), d)
}

// IsSuccess method returns true if HTTP status `code >= 200 and <= 299` otherwise false.
func (r *Response) IsSuccess() bool {
	return r.StatusCode > 199 && r.StatusCode < 300
}

// IsError method returns true if HTTP status `code >= 400` otherwise false.
func (r *Response) IsError() bool {
	return r.StatusCode > 399
}
