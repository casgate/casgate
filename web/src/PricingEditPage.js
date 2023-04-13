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
import {Button, Card, Col, Input, Row, Select, Switch} from "antd";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as PricingBackend from "./backend/PricingBackend";
import * as PlanBackend from "./backend/PlanBackend";
import * as Setting from "./Setting";
import i18next from "i18next";

class PricingEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      // organizationName: props.account.organization.name,
      pricingName: props.match.params.pricingName,
      organizations: [],
      pricing: null,
      plans: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getPricing();
    // this.getUsers();
    this.getOrganizations();
  }

  getPricing() {
    PricingBackend.getPricing(this.state.organizationName, this.state.pricingName)
      .then((pricing) => {
        this.setState({
          pricing: pricing,
        });
        this.getPlans(pricing.owner);
      });
  }

  getPlans(organizationName) {
    PlanBackend.getPlans(organizationName)
      .then((res) => {
        this.setState({
          plans: res,
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

  parsePricingField(key, value) {
    if ([""].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  updatePricingField(key, value) {
    value = this.parsePricingField(key, value);

    const pricing = this.state.pricing;
    pricing[key] = value;
    this.setState({
      pricing: pricing,
    });
  }

  renderPricing() {
    return (
      <Card size="small" title={
        <div>
          {this.state.mode === "add" ? i18next.t("pricing:New Pricing") : i18next.t("pricing:Edit Pricing")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitPricingEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitPricingEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} onClick={() => this.deletePricing()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      } style={(Setting.isMobile()) ? {margin: "5px"} : {}} type="inner">
        <Row style={{marginTop: "10px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} value={this.state.pricing.owner} onChange={(owner => {
              this.updatePricingField("owner", owner);
              this.getPlans(owner);
            })}
            options={this.state.organizations.map((organization) => Setting.getOption(organization.name, organization.name))
            } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.pricing.name} onChange={e => {
              this.updatePricingField("name", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.pricing.displayName} onChange={e => {
              this.updatePricingField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Description"), i18next.t("general:Description - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.pricing.description} onChange={e => {
              this.updatePricingField("description", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("pricing:Sub plans"), i18next.t("pricing:Sub plans - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select mode="tags" style={{width: "100%"}} value={this.state.pricing.plans}
              onChange={(value => {this.updatePricingField("plans", value);})}
              options={this.state.plans.map((plan) => Setting.getOption(`${plan.owner}/${plan.name}`, `${plan.owner}/${plan.name}`))}
            />
          </Col>
        </Row>

        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 19 : 2}>
            {Setting.getLabel(i18next.t("general:Is enabled"), i18next.t("general:Is enabled - Tooltip"))} :
          </Col>
          <Col span={1} >
            <Switch checked={this.state.pricing.isEnabled} onChange={checked => {
              this.updatePricingField("isEnabled", checked);
            }} />
          </Col>
        </Row>
      </Card>
    );
  }

  submitPricingEdit(willExist) {
    const pricing = Setting.deepCopy(this.state.pricing);
    PricingBackend.updatePricing(this.state.organizationName, this.state.pricingName, pricing)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            pricingName: this.state.pricing.name,
          });

          if (willExist) {
            this.props.history.push("/pricings");
          } else {
            this.props.history.push(`/pricings/${this.state.pricing.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updatePricingField("name", this.state.pricingName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deletePricing() {
    PricingBackend.deletePricing(this.state.pricing)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/pricings");
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
          this.state.pricing !== null ? this.renderPricing() : null
        }
        <div style={{marginTop: "20px", marginLeft: "40px"}}>
          <Button size="large" onClick={() => this.submitPricingEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitPricingEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} size="large" onClick={() => this.deletePricing()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      </div>
    );
  }
}

export default PricingEditPage;
