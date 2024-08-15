// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"github.com/casdoor/casdoor/orm"
	"github.com/casdoor/casdoor/util/logger"
	"net/http"

	"github.com/beego/beego"
	"github.com/beego/beego/logs"
	_ "github.com/beego/beego/session/redis"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/ldap"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/radius"
	"github.com/casdoor/casdoor/repository"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/txmanager"
)

func main() {
	orm.InitFlag()
	ormer := orm.InitAdapter()
	trm := txmanager.NewTransactionManager(ormer.Engine)
	repo := repository.NewRepo(trm)
	object.InitRepo(trm, repo)
	object.CreateTables()
	object.DoMigration()

	ctx := context.Background()

	object.InitDb(ctx)
	object.InitFromFile(ctx)
	object.InitLdapAutoSynchronizer(ctx)
	proxy.InitHttpClient()
	object.InitUserManager()

	// beego.DelStaticPath("/static")
	// beego.SetStaticPath("/static", "web/build/static")

	beego.BConfig.WebConfig.DirectoryIndex = true
	beego.SetStaticPath("/swagger", "swagger")
	beego.SetStaticPath("/files", "files")
	// https://studygolang.com/articles/2303
	beego.InsertFilter("*", beego.BeforeRouter, routers.StaticFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.InitRecordMessage, false)
	beego.InsertFilter("*", beego.BeforeRouter, routers.AutoSigninFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.CorsFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.PrometheusFilter)
	beego.InsertFilter("*", beego.AfterExec, routers.LogRecordMessage, false)

	beego.BConfig.WebConfig.Session.SessionOn = true
	beego.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
	if conf.GetConfigString("redisEndpoint") == "" {
		beego.BConfig.WebConfig.Session.SessionProvider = "file"
		beego.BConfig.WebConfig.Session.SessionProviderConfig = "./tmp"
	} else {
		beego.BConfig.WebConfig.Session.SessionProvider = "redis"
		beego.BConfig.WebConfig.Session.SessionProviderConfig = conf.GetConfigString("redisEndpoint")
	}
	beego.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30
	beego.BConfig.WebConfig.Session.SessionCookieSameSite = http.SameSiteLaxMode

	err := logs.SetLogger(logs.AdapterFile, conf.GetConfigString("logConfig"))
	if err != nil {
		panic(err)
	}
	logger.InitGlobal(&logger.Config{Level: conf.GetConfigString("logLevel")})
	port := beego.AppConfig.DefaultInt("httpport", 8000)
	// logs.SetLevel(logs.LevelInformational)
	logs.SetLogFuncCall(false)

	go ldap.StartLdapServer()
	go radius.StartRadiusServer()
	go object.ClearThroughputPerSecond()

	beego.Run(fmt.Sprintf(":%v", port))
}
