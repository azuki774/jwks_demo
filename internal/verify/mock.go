package verify

import (
	"bytes"
	"io"
	"net/http"
)

// MockJWSTClient is a mock implementation of the JWSTClient interface.
type MockJWSTClient struct {
	// Response is the *http.Response to return from the Do method.
	Response *http.Response
	// Err is the error to return from the Do method.
	Err error
}

// Do implements the JWSTClient interface for the mock.
// It returns the pre-configured Response and Err values.
func (m *MockJWSTClient) Do(req *http.Request) (*http.Response, error) {
	// You could add logic here to inspect the 'req' if needed for your tests.
	// For example, check the URL, Method, Headers, etc.
	// fmt.Printf("MockJWSTClient received request for: %s %s\n", req.Method, req.URL.String())

	return m.Response, m.Err
}

// Helper function to create a mock HTTP response easily
func NewMockHttpResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header), // Initialize headers if needed
	}
}
