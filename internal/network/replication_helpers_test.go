package network

import (
	"bytes"
	"context"
	"encoding/json"
)

func jsonBody(v any) (*bytes.Reader, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func testContext() context.Context { return context.Background() }
