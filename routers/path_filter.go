package routers

import (
	"net/http"
	"path"
	"strings"

	"github.com/beego/beego/context"
)

func PathFilter(ctx *context.Context) {
	urlPath := ctx.Request.URL.Path
	if !strings.HasPrefix(urlPath, "/api/") && !strings.HasPrefix(urlPath, "/.well-known/") &&
		!strings.HasPrefix(urlPath, "/cas") && !strings.HasSuffix(urlPath, "/serviceValidate") &&
		!strings.HasSuffix(urlPath, "/proxy") && !strings.HasSuffix(urlPath, "/proxyValidate") &&
		!strings.HasSuffix(urlPath, "/validate") && !strings.HasSuffix(urlPath, "/p3/serviceValidate") &&
		!strings.HasSuffix(urlPath, "/p3/proxyValidate") && !strings.HasSuffix(urlPath, "/samlValidate") {
		return
	}

	if ctx.Request.URL.Path != path.Clean(ctx.Request.URL.Path) {
		responseError(ctx, T(ctx, "auth:Wrong URL"), http.StatusBadRequest) // c.T("auth:Wrong URL")
	}

	return
}
