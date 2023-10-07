package gclient

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func (c *Client) Get(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodGet, uri, data)
}
func (c *Client) Put(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodPut, uri, data)
}
func (c *Client) Post(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodPost, uri, data)
}
func (c *Client) Delete(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodDelete, uri, data)
}
func (c *Client) Head(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodHead, uri, data)
}
func (c *Client) Patch(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodPatch, uri, data)
}
func (c *Client) Connect(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodConnect, uri, data)
}
func (c *Client) Options(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodOptions, uri, data)
}
func (c *Client) Trace(ctx context.Context, uri string, data any) (*Response, error) {
	return c.DoRequest(ctx, http.MethodTrace, uri, data)
}
func (c *Client) PostJson(ctx context.Context, uri string, data any) (*Response, error) {
	return c.AsJson().Post(ctx, uri, data)
}
func (c *Client) PostForm(ctx context.Context, uri string, data url.Values) (*Response, error) {
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k := range data {
		v := data.Get(k)
		if err := w.WriteField(k, v); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return c.WithContentType(w.FormDataContentType()).Post(ctx, uri, body)
}

func (c *Client) PostFormWithFiles(ctx context.Context, uri string, data url.Values) (*Response, error) {
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k := range data {
		v := data.Get(k)
		if strings.Contains(v, HttpParamFileHolder) {
			localPathFile := strings.ReplaceAll(strings.ReplaceAll(v, HttpParamFileHolder, ""), " ", "")
			osFile, err := os.Open(localPathFile)
			if err != nil {
				return nil, err
			}
			ioWriter, err := w.CreateFormFile(k, k)
			if err != nil {
				return nil, err
			}
			if _, err = io.Copy(ioWriter, osFile); err != nil {
				return nil, err
			}
		} else {
			if err := w.WriteField(k, v); err != nil {
				return nil, err
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return c.WithContentType(w.FormDataContentType()).Post(ctx, uri, body)
}
