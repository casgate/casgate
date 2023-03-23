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
import {Button, Card, Col, Input, InputNumber, Row, Select} from "antd";
import * as SubscriptionBackend from "./backend/SubscriptionBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import * as ProviderBackend from "./backend/ProviderBackend";

const {Option} = Select;

class SubscriptionEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      subscriptionName: props.match.params.subscriptionName,
      subscription: null,
      providers: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getSubscription();
    this.getPaymentProviders();
  }

  getSubscription() {
    SubscriptionBackend.getSubscription("admin", this.state.subscriptionName)
      .then((subscription) => {
        this.setState({
          subscription: subscription,
        });
      });
  }

  getPaymentProviders() {
    ProviderBackend.getProviders("admin")
      .then((res) => {
        this.setState({
          providers: res.filter(provider => provider.category === "Payment"),
        });
      });
  }

  parseSubscriptionField(key, value) {
    if ([""].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  updateSubscriptionField(key, value) {
    value = this.parseSubscriptionField(key, value);

    const subscription = this.state.subscription;
    subscription[key] = value;
    this.setState({
      subscription: subscription,
    });
  }

  renderSubscription() {
    return (
      <Card size="small" title={
        <div>
          {this.state.mode === "add" ? i18next.t("subscription:New Subscription") : i18next.t("subscription:Edit Subscription")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitSubscriptionEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitSubscriptionEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} onClick={() => this.deleteSubscription()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      } style={(Setting.isMobile()) ? {margin: "5px"} : {}} type="inner">
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.name} onChange={e => {
              this.updateSubscriptionField("name", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.displayName} onChange={e => {
              this.updateSubscriptionField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:expire In Days"), i18next.t("subscription:Expire In Days - Tooltip"))} :
          </Col>
          <Col span={22} >
            <InputNumber value={this.state.subscription.expireInDays} onChange={value => {
              this.updateSubscriptionField("expireInDays", value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("user:Tag"), i18next.t("subscription:Tag - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.tag} onChange={e => {
              this.updateSubscriptionField("tag", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Detail"), i18next.t("subscription:Detail - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.detail} onChange={e => {
              this.updateSubscriptionField("detail", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Description"), i18next.t("general:Description - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.description} onChange={e => {
              this.updateSubscriptionField("description", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:State"), i18next.t("general:State - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} value={this.state.subscription.state} onChange={(value => {
              this.updateSubscriptionField("state", value);
            })}>
              {
                [
                  {id: "Published", name: "Published"},
                  {id: "Draft", name: "Draft"},
                ].map((item, index) => <Option key={index} value={item.id}>{item.name}</Option>)
              }
            </Select>
          </Col>
        </Row>
      </Card>
    );
  }

  submitSubscriptionEdit(willExist) {
    const subscription = Setting.deepCopy(this.state.subscription);
    SubscriptionBackend.updateSubscription(this.state.subscription.owner, this.state.subscriptionName, subscription)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            subscriptionName: this.state.subscription.name,
          });

          if (willExist) {
            this.props.history.push("/subscriptions");
          } else {
            this.props.history.push(`/subscriptions/${this.state.subscription.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateSubscriptionField("name", this.state.subscriptionName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteSubscription() {
    SubscriptionBackend.deleteSubscription(this.state.subscription)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/subscriptions");
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  render() {
    return (
      <div>
        {
          this.state.subscription !== null ? this.renderSubscription() : null
        }
        <div style={{marginTop: "20px", marginLeft: "40px"}}>
          <Button size="large" onClick={() => this.submitSubscriptionEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitSubscriptionEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} size="large" onClick={() => this.deleteSubscription()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      </div>
    );
  }
}

export default SubscriptionEditPage;
