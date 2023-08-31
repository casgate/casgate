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
import {Button, Card, Col, Input, Row, Select, Switch} from "antd";
import * as GroupBackend from "./backend/GroupBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as Setting from "./Setting";
import i18next from "i18next";

const {Option} = Select;

class GroupEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      groupName: props.match.params.groupName,
      organizationName: props.organizationName !== undefined ? props.organizationName : props.match.params.organizationName,
      group: null,
      users: [],
      groups: [],
      organizations: [],
      mode: props.location.mode !== undefined ? props.location.mode : "edit",
    };
  }

  UNSAFE_componentWillMount() {
    this.getGroup();
    this.getGroups(this.state.organizationName);
    this.getOrganizations();
  }

  getGroup() {
    GroupBackend.getGroup(this.state.organizationName, this.state.groupName)
      .then((res) => {
        if (res.status === "ok") {

          if (!res.data.tags) {
            res.data.tags = [];
          }

          this.setState({
            group: res.data,
          });
        }
      });
  }

  getGroups(organizationName) {
    GroupBackend.getGroups(organizationName)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            groups: res.data,
          });
        }
      });
  }

  getOrganizations() {
    OrganizationBackend.getOrganizationNames("admin")
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            organizations: res.data || [],
          });
        }
      });
  }

  parseGroupField(key, value) {
    if ([""].includes(key)) {
      value = Setting.myParseInt(value);
    }
    return value;
  }

  updateGroupField(key, value) {
    value = this.parseGroupField(key, value);

    const group = this.state.group;
    group[key] = value;
    this.setState({
      group: group,
    });
  }

  getParentIdOptions() {
    const groups = this.state.groups.filter((group) => group.name !== this.state.group.name);
    const organization = this.state.organizations.find((organization) => organization.name === this.state.group.owner);
    if (organization !== undefined) {
      groups.push({name: organization.name, displayName: organization.displayName});
    }
    return groups.map((group) => ({label: group.displayName, value: group.name}));
  }

  renderGroup() {
    return (
      <Card size="small" title={
        <div>
          {this.state.mode === "add" ? i18next.t("group:New Group") : i18next.t("group:Edit Group")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitGroupEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitGroupEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} onClick={() => this.deleteGroup()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      }
      style={(Setting.isMobile()) ? {margin: "5px"} : {}}
      type="inner"
      >
        <Row style={{marginTop: "10px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} style={{width: "100%"}} disabled={!Setting.isAdminUser(this.props.account)} value={this.state.group.owner}
              onChange={(value => {
                this.updateGroupField("owner", value);
                this.getGroups(value);
              })}
              options={this.state.organizations.map((organization) => Setting.getOption(organization.displayName, organization.name))
              } />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Name"), i18next.t("general:Name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.group.name} onChange={e => {
              this.updateGroupField("name", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Display name"), i18next.t("general:Display name - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Input value={this.state.group.displayName} onChange={e => {
              this.updateGroupField("displayName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("general:Type"), i18next.t("general:Type - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select style={{width: "100%"}}
              options={
                [
                  {label: i18next.t("group:Virtual"), value: "Virtual"},
                  {label: i18next.t("group:Physical"), value: "Physical"},
                ].map((item) => ({label: item.label, value: item.value}))
              }
              value={this.state.group.type} onChange={(value => {
                this.updateGroupField("type", value);
              }
              )} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("group:Parent group"), i18next.t("group:Parent group - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select style={{width: "100%"}}
              options={this.getParentIdOptions()}
              value={this.state.group.parentId} onChange={(value => {
                this.updateGroupField("parentId", value);
              }
              )} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 22 : 2}>
            {Setting.getLabel(i18next.t("organization:Tags"), i18next.t("organization:Tags - Tooltip"))} :
          </Col>
          <Col span={22} >
            <Select virtual={false} mode="tags" style={{width: "100%"}} value={this.state.group.tags} onChange={(value => {this.updateGroupField("tags", value);})}>
              {
                this.state.group.tags?.map((item, index) => <Option key={index} value={item}>{item}</Option>)
              }
            </Select>
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{marginTop: "5px"}} span={(Setting.isMobile()) ? 19 : 2}>
            {Setting.getLabel(i18next.t("general:Is enabled"), i18next.t("general:Is enabled - Tooltip"))} :
          </Col>
          <Col span={1} >
            <Switch checked={this.state.group.isEnabled} onChange={checked => {
              this.updateGroupField("isEnabled", checked);
            }} />
          </Col>
        </Row>
      </Card>
    );
  }

  submitGroupEdit(willExist) {
    const group = Setting.deepCopy(this.state.group);
    group["isTopGroup"] = this.state.organizations.some((organization) => organization.name === group.parentId);

    GroupBackend.updateGroup(this.state.organizationName, this.state.groupName, group)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully saved"));
          this.setState({
            groupName: this.state.group.name,
          });

          if (willExist) {
            const groupTreeUrl = sessionStorage.getItem("groupTreeUrl");
            if (groupTreeUrl !== null) {
              sessionStorage.removeItem("groupTreeUrl");
              this.props.history.push(groupTreeUrl);
            } else {
              this.props.history.push("/groups");
            }
          } else {
            this.props.history.push(`/groups/${this.state.group.owner}/${this.state.group.name}`);
          }
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to save")}: ${res.msg}`);
          this.updateGroupField("name", this.state.groupName);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteGroup() {
    GroupBackend.deleteGroup(this.state.group)
      .then((res) => {
        if (res.status === "ok") {
          const groupTreeUrl = sessionStorage.getItem("groupTreeUrl");
          if (groupTreeUrl !== null) {
            sessionStorage.removeItem("groupTreeUrl");
            this.props.history.push(groupTreeUrl);
          } else {
            this.props.history.push("/groups");
          }
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
          this.state.group !== null ? this.renderGroup() : null
        }
        <div style={{marginTop: "20px", marginLeft: "40px"}}>
          <Button size="large" onClick={() => this.submitGroupEdit(false)}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitGroupEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          {this.state.mode === "add" ? <Button style={{marginLeft: "20px"}} size="large" onClick={() => this.deleteGroup()}>{i18next.t("general:Cancel")}</Button> : null}
        </div>
      </div>
    );
  }
}

export default GroupEditPage;
