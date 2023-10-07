package gclient

import "net/http"

func (c *Client) OnBeforeRequest(callback ClientCallback) ClientInterface {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.beforeRequestCallbacks = append(c.beforeRequestCallbacks, callback)
	return c
}
func (c *Client) doBeforeRequestCallbacks() error {
	for _, fn := range c.beforeRequestCallbacks {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) OnAfterRequest(callback RequestCallback) ClientInterface {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.afterRequestCallbacks = append(c.afterRequestCallbacks, callback)
	return c
}
func (c *Client) doAfterRequestCallbacks(request *http.Request) error {
	for _, fn := range c.afterRequestCallbacks {
		if err := fn(c, request); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) OnResponse(callback ResponseCallback) ClientInterface {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.responseCallbacks = append(c.responseCallbacks, callback)
	return c
}
func (c *Client) doResponseCallbacks(request *http.Request, response *Response) error {
	for _, fn := range c.responseCallbacks {
		if err := fn(c, request, response); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) OnError(h ErrorHook) ClientInterface {
	c.errorHooks = append(c.errorHooks, h)
	return c
}
func (c *Client) doErrorHooks(request *http.Request, response *Response, err error) {
	if err != nil {
		if response == nil {
			err = &ResponseError{Response: response, Err: err}
		}
		for _, h := range c.errorHooks {
			h(c, request, err)
		}
	} else {
		for _, h := range c.successHooks {
			h(c, response)
		}
	}
}
func (c *Client) OnPanic(h ErrorHook) ClientInterface {
	c.panicHooks = append(c.panicHooks, h)
	return c
}

func (c *Client) doPanicHooks(request *http.Request, err error) {
	for _, h := range c.panicHooks {
		h(c, request, err)
	}
}

func (c *Client) OnSuccess(h SuccessHook) ClientInterface {
	c.successHooks = append(c.successHooks, h)
	return c
}
func (c *Client) doSuccessHooks(resp *Response) {
	for _, h := range c.successHooks {
		h(c, resp)
	}
}
