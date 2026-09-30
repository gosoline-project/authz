// Package authzhttp provides HTTP integration for authz.
package authzhttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gosoline-project/authz"
)

const consistencyTokenHeader = "X-Consistency-Token"

type closeNotifier interface {
	CloseNotify() <-chan bool
}

// ConsistencyOption configures ConsistencyMiddleware.
type ConsistencyOption func(*consistencyTokenCodec)

type consistencyTokenCodec struct {
	decode func(string) string
	encode func(string) string
}

// WithConsistencyTokenCodec configures how the middleware decodes request tokens
// and encodes changed response tokens. A decoder should return an empty string
// for invalid input. Nil functions leave the corresponding identity behavior in place.
func WithConsistencyTokenCodec(decode func(string) string, encode func(string) string) ConsistencyOption {
	return func(codec *consistencyTokenCodec) {
		if decode != nil {
			codec.decode = decode
		}
		if encode != nil {
			codec.encode = encode
		}
	}
}

// ConsistencyMiddleware installs opaque consistency-token state on each request
// and publishes a changed token before the response is committed.
// By default, X-Consistency-Token values pass through without encoding or expiry.
// Unchanged tokens retain their original wire value. A codec handles backend-specific formats.
func ConsistencyMiddleware(next http.Handler, options ...ConsistencyOption) http.Handler {
	codec := consistencyTokenCodec{
		decode: func(token string) string { return token },
		encode: func(token string) string { return token },
	}
	for _, option := range options {
		if option != nil {
			option(&codec)
		}
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		incomingWireToken := request.Header.Get(consistencyTokenHeader)
		initialToken := ""
		if incomingWireToken != "" {
			initialToken = codec.decode(incomingWireToken)
		}
		ctx := authz.WithConsistencyToken(request.Context(), initialToken)
		request = request.WithContext(ctx)

		base := &consistencyTokenResponseWriter{
			ResponseWriter:    writer,
			context:           ctx,
			initialToken:      initialToken,
			incomingWireToken: incomingWireToken,
			codec:             &codec,
		}
		responseWriter := wrapConsistencyTokenResponseWriter(base)

		next.ServeHTTP(responseWriter, request)
		base.finish()
	})
}

func exposeConsistencyTokenHeader(header http.Header) {
	for _, value := range header.Values("Access-Control-Expose-Headers") {
		for {
			exposedHeader, remaining, hasMore := strings.Cut(value, ",")
			if strings.EqualFold(strings.TrimSpace(exposedHeader), consistencyTokenHeader) {
				return
			}
			if !hasMore {
				break
			}
			value = remaining
		}
	}

	header.Add("Access-Control-Expose-Headers", consistencyTokenHeader)
}

type consistencyTokenResponseWriter struct {
	http.ResponseWriter
	context           context.Context
	initialToken      string
	incomingWireToken string
	codec             *consistencyTokenCodec
	committed         bool
	headersInjected   bool
}

func (writer *consistencyTokenResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *consistencyTokenResponseWriter) FlushError() error {
	if !supportsFlush(writer.ResponseWriter) {
		return http.ErrNotSupported
	}

	writer.beforeCommit()
	return http.NewResponseController(writer.ResponseWriter).Flush()
}

func (writer *consistencyTokenResponseWriter) Flush() {
	_ = writer.FlushError()
}

func (writer *consistencyTokenResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(writer.ResponseWriter).Hijack()
}

func (writer *consistencyTokenResponseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := findPusher(writer.ResponseWriter)
	if !ok {
		return http.ErrNotSupported
	}

	return pusher.Push(target, options)
}

func (writer *consistencyTokenResponseWriter) WriteHeader(statusCode int) {
	if statusCode >= http.StatusContinue && statusCode < http.StatusOK && statusCode != http.StatusSwitchingProtocols {
		writer.ResponseWriter.WriteHeader(statusCode)
		return
	}

	writer.beforeCommit()
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *consistencyTokenResponseWriter) Write(body []byte) (int, error) {
	writer.beforeCommit()
	return writer.ResponseWriter.Write(body)
}

func (writer *consistencyTokenResponseWriter) WriteString(body string) (int, error) {
	writer.beforeCommit()
	return io.WriteString(writer.ResponseWriter, body)
}

func (writer *consistencyTokenResponseWriter) finish() {
	if !writer.committed {
		writer.inject()
	}
}

func (writer *consistencyTokenResponseWriter) beforeCommit() {
	if writer.committed {
		return
	}

	writer.committed = true
	writer.inject()
}

func (writer *consistencyTokenResponseWriter) inject() {
	if writer.headersInjected {
		return
	}

	writer.headersInjected = true
	latestToken := authz.ConsistencyToken(writer.context)
	if latestToken == "" {
		return
	}

	wireToken := writer.incomingWireToken
	if latestToken != writer.initialToken {
		wireToken = writer.codec.encode(latestToken)
	}
	if wireToken == "" {
		return
	}

	header := writer.Header()
	header.Set(consistencyTokenHeader, wireToken)
	exposeConsistencyTokenHeader(header)
}

type consistencyTokenCloseNotifyResponseWriter struct {
	*consistencyTokenResponseWriter
	closeNotifier closeNotifier
}

func (writer *consistencyTokenCloseNotifyResponseWriter) CloseNotify() <-chan bool {
	return writer.closeNotifier.CloseNotify()
}

func wrapConsistencyTokenResponseWriter(writer *consistencyTokenResponseWriter) http.ResponseWriter {
	closeNotifier, ok := findCloseNotifier(writer.ResponseWriter)
	if !ok {
		return writer
	}

	return &consistencyTokenCloseNotifyResponseWriter{
		consistencyTokenResponseWriter: writer,
		closeNotifier:                  closeNotifier,
	}
}

func supportsFlush(writer http.ResponseWriter) bool {
	for {
		if _, ok := writer.(interface{ FlushError() error }); ok {
			return true
		}
		if _, ok := writer.(http.Flusher); ok {
			return true
		}
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		writer = unwrapper.Unwrap()
	}
}

func findPusher(writer http.ResponseWriter) (http.Pusher, bool) {
	for {
		if pusher, ok := writer.(http.Pusher); ok {
			return pusher, true
		}
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		writer = unwrapper.Unwrap()
	}
}

func findCloseNotifier(writer http.ResponseWriter) (closeNotifier, bool) {
	for {
		if closeNotifier, ok := writer.(closeNotifier); ok {
			return closeNotifier, true
		}
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		writer = unwrapper.Unwrap()
	}
}
