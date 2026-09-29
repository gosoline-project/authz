package authzhttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gosoline-project/authz"
)

const (
	consistencyTokenHeader     = "X-Consistency-Token"
	accessControlExposeHeaders = "Access-Control-Expose-Headers"
	consistencyTokenVersion    = "v1"
	consistencyTokenMaxAge     = 30 * time.Second
)

// ConsistencyMiddleware parses and installs an incoming consistency token and
// writes the incoming or newly published token to the response before its
// headers are committed.
func ConsistencyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader(consistencyTokenHeader)
		incomingToken, valid := parseConsistencyToken(header, time.Now())
		if !valid {
			header = ""
		}

		ctx := authz.WithConsistencyToken(c.Request.Context(), incomingToken)
		c.Request = c.Request.WithContext(ctx)
		writer := &consistencyResponseWriter{
			ResponseWriter: c.Writer,
			ctx:            ctx,
			incomingHeader: header,
		}
		c.Writer = writer

		c.Next()
		// Gin can commit its internal writer without calling this wrapper for
		// status-only responses. Set the header before Gin makes that commit.
		if !writer.Written() {
			writer.writeConsistencyHeaders()
		}
	}
}

type consistencyResponseWriter struct {
	gin.ResponseWriter
	ctx            context.Context
	incomingHeader string
	headersWritten bool
}

func (w *consistencyResponseWriter) Write(data []byte) (int, error) {
	w.writeConsistencyHeaders()

	return w.ResponseWriter.Write(data)
}

func (w *consistencyResponseWriter) WriteString(value string) (int, error) {
	w.writeConsistencyHeaders()

	return w.ResponseWriter.WriteString(value)
}

func (w *consistencyResponseWriter) WriteHeaderNow() {
	w.writeConsistencyHeaders()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *consistencyResponseWriter) Flush() {
	w.writeConsistencyHeaders()
	w.ResponseWriter.Flush()
}

func (w *consistencyResponseWriter) writeConsistencyHeaders() {
	if w.headersWritten {
		return
	}
	w.headersWritten = true

	if token := authz.NewConsistencyToken(w.ctx); token != "" {
		w.Header().Set(consistencyTokenHeader, formatConsistencyToken(token))
		appendExposedHeader(w.Header(), consistencyTokenHeader)

		return
	}
	if w.incomingHeader == "" {
		return
	}

	w.Header().Set(consistencyTokenHeader, w.incomingHeader)
	appendExposedHeader(w.Header(), consistencyTokenHeader)
}

func appendExposedHeader(header http.Header, name string) {
	for _, value := range header.Values(accessControlExposeHeaders) {
		for _, existing := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(existing), name) {
				return
			}
		}
	}

	header.Add(accessControlExposeHeaders, name)
}

func parseConsistencyToken(header string, now time.Time) (string, bool) {
	prefix := consistencyTokenVersion + "."
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", false
	}

	payload := string(decoded)
	separator := strings.IndexByte(payload, '|')
	if separator < 0 {
		return "", false
	}

	unixMilliseconds, err := strconv.ParseInt(payload[:separator], 10, 64)
	if err != nil {
		return "", false
	}

	issuedAt := time.UnixMilli(unixMilliseconds)
	age := now.Sub(issuedAt)
	if age < 0 || age > consistencyTokenMaxAge {
		return "", false
	}

	zedToken := payload[separator+1:]
	if zedToken == "" {
		return "", false
	}

	return zedToken, true
}

func formatConsistencyToken(zedToken string) string {
	payload := strconv.FormatInt(time.Now().UnixMilli(), 10) + "|" + zedToken

	return consistencyTokenVersion + "." + base64.StdEncoding.EncodeToString([]byte(payload))
}
