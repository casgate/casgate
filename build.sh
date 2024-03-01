#!/bin/bash
#try to connect to google to determine whether user need to use proxy
curl www.google.com -o /dev/null --connect-timeout 5 2> /dev/null
if [ $? == 0 ]
then
    echo "Successfully connected to Google, no need to use Go proxy"
else
    echo "Google is blocked, Go proxy is enabled: GOPROXY=https://goproxy.cn,direct"
    export GOPROXY="https://goproxy.cn,direct"
fi

UTILS_PACKAGE=github.com/casdoor/casdoor/internal/utils
BUILD_TIME=$(date +"%Y-%m-%dT%H:%M:%S%z")
GIT_HASH=$(git log -1 --pretty=format:%h || echo '')
GIT_TAG=$(git describe --abbrev=0 || echo '')
GIT_COMMIT_OFFSET=0

if git describe --abbrev=0
then
GIT_COMMIT_OFFSET=$(git rev-list $(git describe --abbrev=0 || "")..HEAD --count)
else
GIT_COMMIT_OFFSET=$(git rev-list HEAD --count)
fi

LDFLAGS=
LDFLAGS="$LDFLAGS -X '$UTILS_PACKAGE.BuildTime=$BUILD_TIME'"
LDFLAGS="$LDFLAGS -X '$UTILS_PACKAGE.GitCommitHash=$GIT_HASH'"
LDFLAGS="$LDFLAGS -X '$UTILS_PACKAGE.GitLastTag=$GIT_TAG'"
LDFLAGS="$LDFLAGS -X '$UTILS_PACKAGE.GitCommitOffset=$GIT_COMMIT_OFFSET'"
LDFLAGS="$LDFLAGS -w -s"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o server_linux_amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o server_linux_arm64 .

