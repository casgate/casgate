// Copyright 2023 The Casgate Authors. All Rights Reserved.
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
import * as Setting from "./Setting";
import i18next from "i18next";
import * as DomainBackend from "./backend/DomainBackend";

class DomainEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      domainName: decodeURIComponent(props.match.params.domainName),
      domain: null,
      organizations: [],
      domains: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getDomain();
    this.getOrganizations();
  }

  getDomain() {
    DomainBackend.getDomain(this.state.organizationName, this.state.domainName)
      .then((res) => {
        if (res.data === null) {
          this.props.history.push("/404");
          return;
        }
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          domain: res.data,
        });

        this.getDomains(this.state.organizationName);
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizations("admin")
      .then((res) => {
        this.setState({
          organizations: res.data || [],
        });
      });
  }

  getDomains(organizationName) {
    DomainBackend.getDomains(organizationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.setState({
          domains: res.data,
        });
      });
  }

  parseDomainField(key, value) {
    if ([""].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  updateDomainField(key, value) {
    value = this.parseDomainField(key, value);

    const domain = this.state.domain;
    domain[key] = value;
    this.setState({
      domain: domain,
    });
  }

  renderDomain() {
    return (
      <Card size="small" title={
        <div>
          {this.state.mode === "add" ? i18next.t("domain:New Domain") : i18next.t("domain:Edit Domain")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitDomainEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitDomainEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} onClick={() => this.deleteDomain()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      } style={(Setting.isMobile()) ? {margin: "5px"} : {}} type="inner">
        <Row style={{marginTop: "10px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} disabled={!Setting.isAdminUser(this.props.account)} value={this.state.domain.owner} onChange={(value => {this.updateDomainField("owner", value);})}
              options={this.state.organizations.map((organization) => Setting.getOption(organization.name, organization.name))
              } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.domain.name} onChange={e => {
              this.updateDomainField("name", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.domain.displayName} onChange={e => {
              this.updateDomainField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Description"), i18next.t("general:Description - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.domain.description} onChange={e => {
              this.updateDomainField("description", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("domain:Sub domains"), i18next.t("domain:Sub domains - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} mode="multiple" style={{width: "100%"}} value={this.state.domain.domains} onChange={(value => {this.updateDomainField("domains", value);})}
              options={this.state.domains.filter(domain => (domain.owner !== this.state.domain.owner || domain.name !== this.state.domain.name)).map((domain) => Setting.getOption(`${domain.owner}/${domain.name}`, `${domain.owner}/${domain.name}`))
              } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 19 : 2}>
            {Setting.getLabel(i18next.t("general:Is enabled"), i18next.t("general:Is enabled - Tooltip"))} :
          </Col>
          <Col span={1} >
            <Switch checked={this.state.domain.isEnabled} onChange={checked => {
              this.updateDomainField("isEnabled", checked);
            }} />
          </Col>
        </Row>
      </Card>
    );
  }

  submitDomainEdit(willExist) {
    const domain = Setting.deepCopy(this.state.domain);
    DomainBackend.updateDomain(this.state.organizationName, this.state.domainName, domain)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            domainName: this.state.domain.name,
          });

          if (willExist) {
            this.props.history.push("/domains");
          } else {
            this.props.history.push(`/domains/${this.state.domain.owner}/${encodeURIComponent(this.state.domain.name)}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateDomainField("name", this.state.domainName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteDomain() {
    DomainBackend.deleteDomain(this.state.domain)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push("/domains");
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
          this.state.domain !== null ? this.renderDomain() : null
        }
        <div style={{marginTop: "20px", marginLeft: "40px"}}>
          <Button size="large" onClick={() => this.submitDomainEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitDomainEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} size="large" onClick={() => this.deleteDomain()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      </div>
    );
  }
}

export default DomainEditPage;
