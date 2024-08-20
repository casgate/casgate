module github.com/casdoor/casdoor

go 1.21

require (
	github.com/Masterminds/squirrel v1.5.3
	github.com/alexedwards/argon2id v0.0.0-20211130144151-3585854a6387
	github.com/aws/aws-sdk-go v1.45.5 // indirect
	github.com/beego/beego v1.12.12
	github.com/beevik/etree v1.1.0
	github.com/casbin/casbin/v2 v2.77.2
	github.com/casdoor/go-sms-sender v0.14.0
	github.com/casdoor/gomail/v2 v2.0.1
	github.com/casdoor/notify v0.44.0
	github.com/casdoor/xorm-adapter/v3 v3.0.4
	github.com/dchest/captcha v0.0.0-20200903113550-03f5f0333e1f
	github.com/denisenkom/go-mssqldb v0.9.0
	github.com/forestmgy/ldapserver v1.1.0
	github.com/go-ldap/ldap/v3 v3.4.8
	github.com/go-mysql-org/go-mysql v1.7.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/go-telegram-bot-api/telegram-bot-api v4.6.4+incompatible
	github.com/go-webauthn/webauthn v0.6.0
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/google/uuid v1.6.0
	github.com/lestrrat-go/jwx v1.2.29
	github.com/lib/pq v1.10.9
	github.com/lor00x/goldap v0.0.0-20180618054307-a546dffdd1a3
	github.com/markbates/goth v1.75.2
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nyaruka/phonenumbers v1.1.5
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.11.1
	github.com/prometheus/client_model v0.3.0
	github.com/russellhaering/gosaml2 v0.9.0
	github.com/russellhaering/goxmldsig v1.3.0
	github.com/shiena/ansicolor v0.0.0-20200904210342-c7312218db18 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/siddontang/go-log v0.0.0-20190221022429-1e957dd83bed
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/stretchr/testify v1.9.0
	github.com/thanhpk/randstr v1.0.4
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/xorm-io/builder v0.3.13
	github.com/xorm-io/core v0.7.4
	github.com/xorm-io/xorm v1.1.6
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/crypto v0.21.0
	golang.org/x/net v0.23.0
	golang.org/x/oauth2 v0.11.0
	golang.org/x/sync v0.3.0
	google.golang.org/api v0.138.0
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0
	layeh.com/radius v0.0.0-20221205141417-e7fbddd11d68
	maunium.net/go/mautrix v0.16.0
	modernc.org/sqlite v1.18.2
)

require github.com/r3labs/diff/v3 v3.0.1

require (
	cloud.google.com/go/compute v1.23.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/RocketChat/Rocket.Chat.Go.SDK v0.0.0-20221121042443-a3fd332d56d9 // indirect
	github.com/SherClockHolmes/webpush-go v1.2.0 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.62.545 // indirect
	github.com/atc0005/go-teams-notify/v2 v2.6.1 // indirect
	github.com/baidubce/bce-sdk-go v0.9.156 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blinkbean/dingtalk v0.0.0-20210905093040-7d935c0f7e19 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/bwmarrin/discordgo v0.27.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/crewjam/saml v0.4.14
	github.com/cschomburg/go-pushbullet v0.0.0-20171206132031-67759df45fbb // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/dghubble/oauth1 v0.7.2 // indirect
	github.com/dghubble/sling v1.4.0 // indirect
	github.com/drswork/go-twitter v0.0.0-20221107160839-dea1b6ed53d7 // indirect
	github.com/elazarl/go-bindata-assetfs v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-lark/lark v1.9.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-webauthn/revoke v0.1.6 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomodule/redigo v2.0.0+incompatible // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/s2a-go v0.1.5 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.5 // indirect
	github.com/googleapis/gax-go/v2 v2.12.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/gregdel/pushover v1.2.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/line/line-bot-sdk-go v7.8.0+incompatible // indirect
	github.com/markbates/going v1.0.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mileusna/viber v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mrjones/oauth v0.0.0-20180629183705-f4e24b6d100c // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/pingcap/errors v0.11.5-0.20210425183316-da1aaba5fb63 // indirect
	github.com/pingcap/log v0.0.0-20210625125904-98ed8e2eb1c7 // indirect
	github.com/pingcap/tidb/parser v0.0.0-20221126021158-6b02a5d8ba7d // indirect
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.30.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/rs/zerolog v1.30.0 // indirect
	github.com/shopspring/decimal v0.0.0-20180709203117-cd690d0c9e24 // indirect
	github.com/siddontang/go v0.0.0-20180604090527-bdc77568d726 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/slack-go/slack v0.12.3 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/syndtr/goleveldb v1.0.0 // indirect
	github.com/technoweenie/multipartstreamer v1.0.1 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.744 // indirect
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sms v1.0.744 // indirect
	github.com/tidwall/gjson v1.16.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/twilio/twilio-go v1.13.0 // indirect
	github.com/ucloud/ucloud-sdk-go v0.22.5 // indirect
	github.com/utahta/go-linenotify v0.5.0 // indirect
	github.com/vartanbeno/go-reddit/v2 v2.0.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.5 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/volcengine/volc-sdk-golang v1.0.117 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.mau.fi/util v0.0.0-20230805171708-199bf3eec776 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/exp v0.0.0-20230810033253-352e893a4cad // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230807174057-1744710a1577 // indirect
	google.golang.org/grpc v1.57.1 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	maunium.net/go/maulogger/v2 v2.4.1 // indirect
	modernc.org/cc/v3 v3.37.0 // indirect
	modernc.org/ccgo/v3 v3.16.9 // indirect
	modernc.org/libc v1.18.0 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.3.0 // indirect
	modernc.org/opt v0.1.1 // indirect
	modernc.org/strutil v1.1.3 // indirect
	modernc.org/token v1.0.1 // indirect
)
