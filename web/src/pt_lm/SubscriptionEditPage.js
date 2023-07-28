// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
import {Button, Card, Col, DatePicker, Input, InputNumber, Row, Select, Switch} from "antd";
import * as OrganizationBackend from "./../backend/OrganizationBackend";
import * as PlanBackend from "./../backend/PlanBackend";
import * as SubscriptionBackend from "./../backend/SubscriptionBackend";
import * as UserBackend from "./../backend/UserBackend";
import * as Setting from "./../Setting";
import i18next from "i18next";
import dayjs from "dayjs";

class SubscriptionEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      subscriptionName: props.match.params.subscriptionName,
      subscription: null,
      subscriptionStateOptions: [],
      organizations: [],
      users: [],
      planes: [],
      providers: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
      isGlobalAdmin: Setting.isAdminUser(props.account),
    };
  }

  UNSAFE_componentWillMount() {
    this.getSubscription();
    this.getOrganizations();
  }

  getStateOption(state, disabled) {
    const option = Setting.getOption(i18next.t(`subscription:${state}`), state);
    if (disabled) {
      option.style = {color: "#000000", opacity: 0.25};
    }
    return option;
  }

  getSubscriptionAvailableStates() {
    const allStates = ["New", "Pilot", "PilotExpired", "Pending", "PreAuthorized", "IntoCommerce", "Authorized", "Unauthorized", "Started", "PreFinished", "Finished", "Cancelled"];
    SubscriptionBackend.getSubscriptionAvailableStates(this.state.organizationName, this.state.subscriptionName)
      .then((subscriptionStates) => {
        const subscriptionStatesOptions = subscriptionStates.map((state) => this.getStateOption(state, false));
        if (this.state.isGlobalAdmin) {
          subscriptionStatesOptions.push(...allStates.filter(n => !subscriptionStates.includes(n)).map((state) => this.getStateOption(state, true)));
        }
        this.setState({
          subscriptionStateOptions: subscriptionStatesOptions,
        });
      });
  }

  getSubscription() {
    SubscriptionBackend.getSubscription(this.state.organizationName, this.state.subscriptionName)
      .then((subscription) => {
        if (subscription === null) {
          this.props.history.push("/404");
          return;
        }

        this.setState({
          subscription: subscription,
        });

        this.getUsers(subscription.owner);
        this.getPlanes(subscription.owner);
        this.getSubscriptionAvailableStates();
      });
  }

  getPlanes(organizationName) {
    PlanBackend.getPlans(organizationName)
      .then((res) => {
        this.setState({
          planes: res,
        });
      });
  }

  getUsers(organizationName) {
    UserBackend.getUsers(organizationName)
      .then((res) => {
        this.setState({
          users: res.filter(user => user.tag === "client"),
        });
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        this.setState({
          organizations: (res.msg === undefined) ? res : [],
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
        <Row style={{marginTop: "10px", display: (Setting.isAdminUser(this.props.account) || Setting.isDistributor(this.props.account)) ? "" : "none"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select disabled={!this.state.isGlobalAdmin} virtual={false} style={{width: "100%"}} value={this.state.subscription.owner} onChange={(owner => {
              this.updateSubscriptionField("owner", owner);
              this.getUsers(owner);
              this.getPlanes(owner);
            })}
            options={this.state.organizations.map((organization) => Setting.getOption(organization.name, organization.name))
            } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Name"), i18next.t("subscription:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input disabled value={this.state.subscription.name} onChange={e => {
              this.updateSubscriptionField("name", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:User"), i18next.t("subscription:User - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select style={{width: "100%"}} value={this.state.subscription.user}
              onChange={(value => {this.updateSubscriptionField("user", value);})}
              options={this.state.users.map((user) => Setting.getOption(`${user.owner}/${user.name}`, `${user.owner}/${user.name}`))}
            />
          </Col>
        </Row>
        <Row style={{marginTop: "20px", display: "none"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.displayName} onChange={e => {
              this.updateSubscriptionField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px", display: "none"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Duration"), i18next.t("subscription:Duration - Tooltip"))}
          </Col>
          <Col span={22} >
            <InputNumber value={this.state.subscription.duration} onChange={value => {
              this.updateSubscriptionField("duration", value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Plan"), i18next.t("general:Plan - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} value={this.state.subscription.plan} onChange={(value => {this.updateSubscriptionField("plan", value);})}
              options={this.state.planes.map((plan) => Setting.getOption(`${plan.owner}/${plan.name}`, `${plan.owner}/${plan.name}`))
              } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Discount"), i18next.t("general:Discount - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100px"}} value={this.state.subscription.discount} onChange={(value => {
              this.updateSubscriptionField("discount", value);
            })}
            options={[
              {value: 15, name: "15"},
              {value: 20, name: "20"},
              {value: 25, name: "25"},
              {value: 30, name: "30"},
              {value: 35, name: "35"},
              {value: 40, name: "40"},
            ].map((item) => Setting.getOption(item.name, item.value))}
            />
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
            {Setting.getLabel(i18next.t("general:Comment"), i18next.t("general:Comment - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.subscription.comment} onChange={e => {
              this.updateSubscriptionField("comment", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Start date"), i18next.t("subscription:Start date - Tooltip"))}
          </Col>
          <Col span={22} >
            <DatePicker value={this.state.subscription.startDate !== "0001-01-01T00:00:00Z" && this.state.subscription.startDate !== null ? dayjs(this.state.subscription.startDate) : null} onChange={value => {
              this.updateSubscriptionField("startDate", value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:End date"), i18next.t("subscription:End date - Tooltip"))}
          </Col>
          <Col span={22} >
            <DatePicker value={this.state.subscription.endDate !== "0001-01-01T00:00:00Z" && this.state.subscription.endDate !== null ? dayjs(this.state.subscription.endDate) : null} onChange={value => {
              this.updateSubscriptionField("endDate", value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:State"), i18next.t("general:State - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} disabled={!Setting.isLocalAdminUser(this.props.account) && !Setting.isDistributor(this.props.account)} style={{width: "100%"}} value={this.state.subscription.state} onChange={(value => {
              this.updateSubscriptionField("state", value);
            })}
            options={this.state.subscriptionStateOptions}
            />
          </Col>
        </Row>
        <Row style={{marginTop: "20px", display: Setting.isDistributor(this.props.account) ? "none" : ""}}>
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Was Pilot"), i18next.t("subscription:Was Pilot - Tooltip"))} :
          </Col>
          <Col span={(Setting.isMobile()) ? 22 : 2} >
            <Select
              disabled={!Setting.isAdminUser(this.props.account)}
              value={this.state.subscription.wasPilot}
              style={{width: 120}}
              onChange={value => {
                this.updateSubscriptionField("wasPilot", value);
              }}
              options={[
                {value: true, label: "Да"},
                {value: false, label: "Нет"},
              ]}
            />
          </Col>
        </Row>
        <Row style={{marginTop: "20px", display: this.state.subscription.state === "Pilot" ? "" : "none"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Pilot Expiry Date"), i18next.t("subscription:Pilot Expiry Date - Tooltip"))}
          </Col>
          <Col span={22} >
            <DatePicker
              disabled={!Setting.isAdminUser(this.props.account)}
              value={this.state.subscription.pilotExpiryDate !== null ? dayjs(this.state.subscription.pilotExpiryDate) : null}
              onChange={value => {
                this.updateSubscriptionField("pilotExpiryDate", value);
              }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px", display: "none"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 19 : 2}>
            {Setting.getLabel(i18next.t("general:Is enabled"), i18next.t("general:Is enabled - Tooltip"))} :
          </Col>
          <Col span={1} >
            <Switch checked={this.state.subscription.isEnabled} onChange={checked => {
              this.updateSubscriptionField("isEnabled", checked);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Submitter"), i18next.t("subscription:Submitter - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input disabled={true} value={this.state.subscription.submitter} onChange={e => {
              this.updateSubscriptionField("submitter", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Approver"), i18next.t("subscription:Approver - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input disabled={true} value={this.state.subscription.approver} onChange={e => {
              this.updateSubscriptionField("approver", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("subscription:Approve time"), i18next.t("subscription:Approve time - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input disabled={true} value={Setting.getFormattedDate(this.state.subscription.approveTime)} onChange={e => {
              this.updatePermissionField("approveTime", e.target.value);
            }} />
          </Col>
        </Row>
      </Card>
    );
  }

  submitSubscriptionEdit(willExist) {
    const subscription = Setting.deepCopy(this.state.subscription);
    SubscriptionBackend.updateSubscription(this.state.organizationName, this.state.subscriptionName, subscription)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            subscriptionName: subscription.name,
            organizationName: subscription.owner,
          }, this.getSubscription);

          if (willExist) {
            this.props.history.push("/subscriptions");
          } else {
            this.props.history.push(`/subscriptions/${this.state.subscription.owner}/${this.state.subscription.name}`);
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
