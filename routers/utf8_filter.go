package routers

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/beego/beego/context"
)

func UTF8Filter(ctx *context.Context) {
	for key := range ctx.Request.Form {
		value := ctx.Request.Form.Get(key)
		if !utf8.ValidString(value) || strings.Contains(value, "\x00") {
			responseError(ctx, fmt.Sprintf(T(ctx, "general:%s field is not valid utf-8 string"), key), http.StatusBadRequest)
			return
		}
	}

	return
}
