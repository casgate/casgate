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

import React from "react";
import {Button, Result, Spin} from "antd";
import * as PaymentBackend from "./backend/PaymentBackend";
import * as Setting from "./Setting";
import i18next from "i18next";

class PaymentResultPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      paymentName: props.match.params.paymentName,
      organizationName: props.match.params.organizationName,
      payment: null,
      timeout: null,
    };
  }

  UNSAFE_componentWillMount() {
    this.getPayment();
  }

  componentWillUnmount() {
    if (this.state.timeout !== null) {
      clearTimeout(this.state.timeout);
    }
  }

  getPayment() {
    PaymentBackend.getPayment(this.state.organizationName, this.state.paymentName)
      .then((res) => {
        this.setState({
          payment: res.data,
        });
        // window.console.log("payment=", res.data);
        if (res.data.state === "Created") {
          if (res.data.type === "PayPal") {
            this.setState({
              timeout: setTimeout(() => {
                PaymentBackend.notifyPayment(this.state.organizationName, this.state.paymentName)
                  .then((res) => {
                    this.getPayment();
                  });
              }, 1000),
            });
          } else {
            this.setState({timeout: setTimeout(() => this.getPayment(), 1000)});
          }
        }
      });
  }

  goToPaymentUrl(payment) {
    if (payment.returnUrl === undefined || payment.returnUrl === null || payment.returnUrl === "") {
      Setting.goToLink(`${window.location.origin}/products/${payment.owner}/${payment.productName}/buy`);
    } else {
      Setting.goToLink(payment.returnUrl);
    }
  }

  render() {
    const payment = this.state.payment;

    if (payment === null) {
      return null;
    }

    if (payment.state === "Paid") {
      return (
        <div>
          {
            Setting.renderHelmet(payment)
          }
          <Result
            status="success"
            title={`${i18next.t("payment:You have successfully completed the payment")}: ${payment.productDisplayName}`}
            subTitle={i18next.t("payment:Please click the below button to return to the original website")}
            extra={[
              <Button type="primary" key="returnUrl" onClick={() => {
                this.goToPaymentUrl(payment);
              }}>
                {i18next.t("payment:Return to Website")}
              </Button>,
            ]}
          />
        </div>
      );
    } else if (payment.state === "Created") {
      return (
        <div>
          {
            Setting.renderHelmet(payment)
          }
          <Result
            status="info"
            title={`${i18next.t("payment:The payment is still under processing")}: ${payment.productDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}, ${i18next.t("payment:please wait for a few seconds...")}`}
            subTitle={i18next.t("payment:Please click the below button to return to the original website")}
            extra={[
              <Spin key="returnUrl" size="large" tip={i18next.t("payment:Processing...")} />,
            ]}
          />
        </div>
      );
    } else if (payment.state === "Canceled") {
      return (
        <div>
          {
            Setting.renderHelmet(payment)
          }
          <Result
            status="warning"
            title={`${i18next.t("payment:The payment has been canceled")}: ${payment.productDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}`}
            subTitle={i18next.t("payment:Please click the below button to return to the original website")}
            extra={[
              <Button type="primary" key="returnUrl" onClick={() => {
                this.goToPaymentUrl(payment);
              }}>
                {i18next.t("payment:Return to Website")}
              </Button>,
            ]}
          />
        </div>
      );
    } else {
      return (
        <div>
          {
            Setting.renderHelmet(payment)
          }
          <Result
            status="error"
            title={`${i18next.t("payment:The payment has failed")}: ${payment.productDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}`}
            subTitle={`${i18next.t("payment:Failed reason")}: ${payment.message}`}
            extra={[
              <Button type="primary" key="returnUrl" onClick={() => {
                this.goToPaymentUrl(payment);
              }}>
                {i18next.t("payment:Return to Website")}
              </Button>,
            ]}
          />
        </div>
      );
    }
  }
}

export default PaymentResultPage;
