package routers

import (
	"net/http"
	"path"
	"strings"

	"github.com/beego/beego/context"
)

func PathFilter(ctx *context.Context) {
	urlPath := ctx.Request.URL.Path

	prefixWhitelist := []string{"/api/", "/.well-known/", "/cas"}
	suffixWhitelist := []string{"/serviceValidate", "/proxy", "/proxyValidate", "/validate", "/p3/serviceValidate", "/p3/proxyValidate", "/samlValidate"}

	needCheck := false

	for _, prefix := range prefixWhitelist {
		if strings.HasPrefix(urlPath, prefix) {
			needCheck = true
		}
	}

	for _, prefix := range suffixWhitelist {
		if strings.HasSuffix(urlPath, prefix) {
			needCheck = true
		}
	}

	if !needCheck {
		return
	}

	if ctx.Request.URL.Path != path.Clean(ctx.Request.URL.Path) {
		responseError(ctx, T(ctx, "auth:Wrong URL"), http.StatusBadRequest) // c.T("auth:Wrong URL")
	}

	return
}
