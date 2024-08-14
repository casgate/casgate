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

// modified from https://github.com/casbin/casnode/blob/master/service/mail.go

package object

import (
	"crypto/tls"
	"errors"

	"github.com/casdoor/casdoor/email"
	"github.com/casdoor/gomail/v2"
)

// We do not use the error from the net/smtp package because
// the error from net/smtp is not exported (it is declared within the function)
//https://github.com/golang/go/blob/master/src/net/smtp/auth.go#L68
var ErrUnencryptedConnection = errors.New("unencrypted connection")

func getDialer(provider *Provider) (*gomail.Dialer, error) {
	dialer := &gomail.Dialer{}
	dialer = gomail.NewDialer(provider.Host, provider.Port, provider.ClientId, provider.ClientSecret)

	if provider.Cert != "" {
		conf, err := GetTlsConfigForCert(provider.Cert)
		if err != nil {
			return nil, err
		}
		conf.ServerName = provider.Host
		dialer.TLSConfig = conf	
	}

	if provider.Type == "SUBMAIL" {
		dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	dialer.SSL = !provider.DisableSsl

	return dialer, nil
}

func SendEmail(provider *Provider, title string, content string, dest string, sender string) error {
	var conf *tls.Config
	var err error
	if provider.Cert != "" {
		conf, err = GetTlsConfigForCert(provider.Cert)
		if err != nil {
			return err
		}	
		conf.ServerName = provider.Host
	}
	emailProvider := email.GetEmailProvider(provider.Type, provider.ClientId, provider.ClientSecret, provider.Host, provider.Port, provider.DisableSsl, conf)

	fromAddress := provider.ClientId2
	if fromAddress == "" {
		fromAddress = provider.ClientId
	}

	fromName := provider.ClientSecret2
	if fromName == "" {
		fromName = sender
	}
	err = emailProvider.Send(fromAddress, fromName, dest, title, content)
	if err != nil {
		if err.Error() == ErrUnencryptedConnection.Error() {
			return ErrUnencryptedConnection
		}
		return err
	}
	return nil
}

// DailSmtpServer Dail Smtp server
func DailSmtpServer(provider *Provider) error {
	dialer, err := getDialer(provider)
	if err != nil {
		return err
	}

	sender, err := dialer.Dial()
	if err != nil {
		if err.Error() == ErrUnencryptedConnection.Error() {
			return ErrUnencryptedConnection
		}
		return err
	}
	defer sender.Close()

	return nil
}
