// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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

package pp

import (
	"net/http"
)

type PaymentState string

const (
	PaymentStatePaid     PaymentState = "Paid"
	PaymentStateCreated  PaymentState = "Created"
	PaymentStateCanceled PaymentState = "Canceled"
	PaymentStateError    PaymentState = "Error"
)

type NotifyResult struct {
	PaymentName   string
	PaymentStatus PaymentState
	NotifyMessage string

	ProviderName       string
	ProductName        string
	ProductDisplayName string
	Price              float64
	Currency           string

	OutOrderId string
}

type PaymentProvider interface {
	Pay(providerName string, productName string, payerName string, paymentName string, productDisplayName string, price float64, currency string, returnUrl string, notifyUrl string) (string, string, error)
	Notify(request *http.Request, body []byte, authorityPublicKey string, orderId string) (*NotifyResult, error)
	GetInvoice(paymentName string, personName string, personIdCard string, personEmail string, personPhone string, invoiceType string, invoiceTitle string, invoiceTaxId string) (string, error)
	GetResponseError(err error) string
}

func GetPaymentProvider(typ string, clientId string, clientSecret string, host string, appCertificate string, appPrivateKey string, authorityPublicKey string, authorityRootPublicKey string, clientId2 string) (PaymentProvider, error) {
	if typ == "Dummy" {
		pp, err := NewDummyPaymentProvider()
		if err != nil {
			return nil, err
		}
		return pp, nil
	} else if typ == "Alipay" {
		pp, err := NewAlipayPaymentProvider(clientId, appCertificate, appPrivateKey, authorityPublicKey, authorityRootPublicKey)
		if err != nil {
			return nil, err
		}
		return pp, nil
	} else if typ == "GC" {
		return NewGcPaymentProvider(clientId, clientSecret, host), nil
	} else if typ == "WeChat Pay" {
		pp, err := NewWechatPaymentProvider(clientId, clientSecret, clientId2, appCertificate, appPrivateKey)
		if err != nil {
			return nil, err
		}
		return pp, nil
	} else if typ == "PayPal" {
		pp, err := NewPaypalPaymentProvider(clientId, clientSecret)
		if err != nil {
			return nil, err
		}
		return pp, nil
	}

	return nil, nil
}
