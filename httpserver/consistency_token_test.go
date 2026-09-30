package authzhttp_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"

	"github.com/gosoline-project/authz"
	authzhttp "github.com/gosoline-project/authz/httpserver"
)

func consistencyTokenCodec() authzhttp.ConsistencyOption {
	return authzhttp.WithConsistencyTokenCodec(
		func(wireToken string) string {
			token, ok := strings.CutPrefix(wireToken, "opaque:")
			if !ok {
				return ""
			}
			return token
		},
		func(token string) string { return "encoded:" + token },
	)
}

// deferredStatusWriter models a framework that stages a status until response finalization.
type deferredStatusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (writer *deferredStatusWriter) WriteHeader(statusCode int) {
	writer.statusCode = statusCode
}

func (writer *deferredStatusWriter) WriteHeaderNow() {
	writer.ResponseWriter.WriteHeader(writer.statusCode)
}

func TestConsistencyMiddlewarePublishesChangedTokenBeforeResponseCommit(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		writeBody  bool
		statusCode int
		wantBody   string
	}{
		{name: "status only", statusCode: http.StatusAccepted},
		{name: "implicit status from body write", writeBody: true, statusCode: http.StatusOK, wantBody: "response body"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if got := authz.ConsistencyToken(request.Context()); got != "incoming" {
					t.Errorf("request token = %q, want incoming", got)
				}
				writer.Header().Add("Access-Control-Expose-Headers", "X-Request-ID")
				writer.Header().Add("Access-Control-Expose-Headers", "Content-Type")
				if !test.writeBody {
					stagedWriter := &deferredStatusWriter{ResponseWriter: writer}
					stagedWriter.WriteHeader(test.statusCode)
					authz.SetConsistencyToken(request.Context(), "published")
					stagedWriter.WriteHeaderNow()
					return
				}
				authz.SetConsistencyToken(request.Context(), "published")
				_, _ = io.WriteString(writer, test.wantBody)
			})
			middleware := authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec())
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("X-Consistency-Token", "opaque:incoming")
			recorder := httptest.NewRecorder()
			middleware.ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()
			if response.StatusCode != test.statusCode {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.statusCode)
			}
			if got := response.Header.Get("X-Consistency-Token"); got != "encoded:published" {
				t.Fatalf("response token = %q, want encoded:published", got)
			}
			if got := response.Header.Values("Access-Control-Expose-Headers"); len(got) != 3 || got[0] != "X-Request-ID" || got[1] != "Content-Type" || got[2] != "X-Consistency-Token" {
				t.Fatalf("exposed headers = %v, want preserved values plus X-Consistency-Token", got)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("reading response body: %v", err)
			}
			if string(body) != test.wantBody {
				t.Fatalf("response body = %q, want %q", body, test.wantBody)
			}
		})
	}
}

func TestConsistencyMiddlewareRetainsIncomingWireTokenWhenRepublishedUnchanged(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authz.SetConsistencyToken(request.Context(), "same")
		writer.WriteHeader(http.StatusNoContent)
	})
	middleware := authzhttp.ConsistencyMiddleware(handler, authzhttp.WithConsistencyTokenCodec(
		func(wireToken string) string { return strings.TrimPrefix(wireToken, "signed:") },
		func(string) string { return "unexpected-reencoding" },
	))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Consistency-Token", "signed:same")
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	if got := response.Header.Get("X-Consistency-Token"); got != "signed:same" {
		t.Fatalf("response token = %q, want original signed:same wire value", got)
	}
}

func TestConsistencyMiddlewareInitializesMissingAndInvalidRequestTokenState(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		requestToken string
	}{
		{name: "missing"},
		{name: "invalid", requestToken: "not-opaque"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if got := authz.ConsistencyToken(request.Context()); got != "" {
					t.Errorf("initial request token = %q, want empty", got)
				}
				authz.SetConsistencyToken(request.Context(), "published")
				writer.WriteHeader(http.StatusAccepted)
			})
			middleware := authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec())
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.requestToken != "" {
				request.Header.Set("X-Consistency-Token", test.requestToken)
			}
			recorder := httptest.NewRecorder()
			middleware.ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusAccepted)
			}
			if got := response.Header.Get("X-Consistency-Token"); got != "encoded:published" {
				t.Fatalf("response token = %q, want encoded:published", got)
			}
		})
	}
}

func TestConsistencyMiddlewareUsesDefaultOpaquePassthrough(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})
	middleware := authzhttp.ConsistencyMiddleware(handler)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Consistency-Token", "opaque-token")
	recorder := httptest.NewRecorder()
	middleware.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()
	if got := response.Header.Get("X-Consistency-Token"); got != "opaque-token" {
		t.Fatalf("response token = %q, want unchanged opaque-token", got)
	}
	if got := response.Header.Get("Access-Control-Expose-Headers"); got != "X-Consistency-Token" {
		t.Fatalf("exposed headers = %q, want X-Consistency-Token", got)
	}
}

func TestConsistencyMiddlewareDoesNotDuplicateCORSExposeHeader(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Expose-Headers", "x-consistency-token, X-Request-ID")
		_, _ = io.WriteString(writer, "ok")
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Consistency-Token", "incoming")
	recorder := httptest.NewRecorder()
	authzhttp.ConsistencyMiddleware(handler).ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()
	if got := response.Header.Values("Access-Control-Expose-Headers"); len(got) != 1 || got[0] != "x-consistency-token, X-Request-ID" {
		t.Fatalf("exposed headers = %v, want existing values without duplication", got)
	}
}

func TestConsistencyMiddlewarePublishesOnHandlerReturnWithoutCommittingEarly(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		authz.SetConsistencyToken(request.Context(), "published")
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET server: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:published" {
		t.Fatalf("response token = %q, want encoded:published", got)
	}
	if len(body) != 0 {
		t.Fatalf("response body = %q, want empty", body)
	}
}

func TestConsistencyMiddlewareDoesNotRewriteTokenAfterCommit(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authz.SetConsistencyToken(request.Context(), "first")
		_, _ = io.WriteString(writer, "first body")
		authz.SetConsistencyToken(request.Context(), "later")
		_, _ = io.WriteString(writer, " second body")
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()).ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:first" {
		t.Fatalf("response token = %q, want token at first commit", got)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != "first body second body" {
		t.Fatalf("response body = %q, want both writes", body)
	}
}

func TestConsistencyMiddlewareFlushCommitsCurrentToken(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authz.SetConsistencyToken(request.Context(), "before-flush")
		if err := http.NewResponseController(writer).Flush(); err != nil {
			t.Errorf("flushing response: %v", err)
			return
		}
		authz.SetConsistencyToken(request.Context(), "after-flush")
		_, _ = io.WriteString(writer, "body")
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET server: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:before-flush" {
		t.Fatalf("response token = %q, want token at flush", got)
	}
	if string(body) != "body" {
		t.Fatalf("response body = %q, want body", body)
	}
}

func TestConsistencyMiddlewareDoesNotInjectOnInformationalResponse(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusEarlyHints)
		authz.SetConsistencyToken(request.Context(), "published-after-hints")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(writer, "body")
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()))
	defer server.Close()

	type interimResponse struct {
		statusCode int
		token      string
	}
	interimResponses := make(chan interimResponse, 1)
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	request.Header.Set("X-Consistency-Token", "opaque:incoming")
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(statusCode int, header textproto.MIMEHeader) error {
			interimResponses <- interimResponse{statusCode: statusCode, token: header.Get("X-Consistency-Token")}
			return nil
		},
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET server: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	var interim interimResponse
	select {
	case interim = <-interimResponses:
	default:
		t.Fatal("client observed no informational response")
	}
	if interim.statusCode != http.StatusEarlyHints {
		t.Fatalf("informational status = %d, want %d", interim.statusCode, http.StatusEarlyHints)
	}
	if interim.token != "" {
		t.Fatalf("informational response token = %q, want no token", interim.token)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusAccepted)
	}
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:published-after-hints" {
		t.Fatalf("final response token = %q, want encoded:published-after-hints", got)
	}
	if string(body) != "body" {
		t.Fatalf("response body = %q, want body", body)
	}
}

func TestConsistencyMiddlewareTreatsSwitchingProtocolsAsFinal(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authz.SetConsistencyToken(request.Context(), "upgrade")
		writer.WriteHeader(http.StatusSwitchingProtocols)
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()))
	defer server.Close()

	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connecting to server: %v", err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", server.Listener.Addr()); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusSwitchingProtocols)
	}
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:upgrade" {
		t.Fatalf("response token = %q, want encoded:upgrade", got)
	}
}

func TestConsistencyMiddlewarePreservesResponseControllerHijacking(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffered, err := http.NewResponseController(writer).Hijack()
		if err != nil {
			t.Errorf("hijacking response: %v", err)
			return
		}
		defer connection.Close()
		if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
			t.Errorf("writing upgrade response: %v", err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Errorf("flushing upgrade response: %v", err)
		}
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler))
	defer server.Close()

	connection, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("connecting to server: %v", err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n", server.Listener.Addr()); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusSwitchingProtocols)
	}
}

type responseWriterWithoutOptionalInterfaces struct {
	http.ResponseWriter
}

func TestConsistencyMiddlewareReturnsUnsupportedOperationErrors(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := http.NewResponseController(writer).Flush(); !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("Flush error = %v, want http.ErrNotSupported", err)
		}
		if _, _, err := http.NewResponseController(writer).Hijack(); !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("Hijack error = %v, want http.ErrNotSupported", err)
		}
		if err := writer.(http.Pusher).Push("/asset", nil); !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("Push error = %v, want http.ErrNotSupported", err)
		}

		authz.SetConsistencyToken(request.Context(), "published")
		_, _ = io.WriteString(writer, "body")
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Consistency-Token", "opaque:incoming")
	recorder := httptest.NewRecorder()
	underlying := responseWriterWithoutOptionalInterfaces{ResponseWriter: recorder}
	authzhttp.ConsistencyMiddleware(handler, consistencyTokenCodec()).ServeHTTP(underlying, request)

	response := recorder.Result()
	defer response.Body.Close()
	if got := response.Header.Get("X-Consistency-Token"); got != "encoded:published" {
		t.Fatalf("response token = %q after unsupported operations, want encoded:published", got)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != "body" {
		t.Fatalf("response body = %q, want body", body)
	}
}

func TestConsistencyMiddlewarePreservesImplicitWriteContentType(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "plain response")
	})
	server := httptest.NewServer(authzhttp.ConsistencyMiddleware(handler))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET server: %v", err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("implicit response Content-Type = %q, want text/plain; charset=utf-8", got)
	}
}
