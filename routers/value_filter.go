package routers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/beego/beego/context"
)

type NamedEntity struct {
	Name string `json:"name,omitempty"`
}

func ValueFilter(ctx *context.Context) {
	if ctx.Request.Method != http.MethodPost {
		return
	}

	var entity NamedEntity
	_ = json.Unmarshal(ctx.Input.RequestBody, &entity)

	if strings.Contains(entity.Name, "/") {
		responseError(
			ctx,
			"name shouldn't contains /",
			http.StatusBadRequest,
		)
		return
	}

	return
}
