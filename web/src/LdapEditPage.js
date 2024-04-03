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

import React from "react";
import {Button, Card, Col, Input, InputNumber, Row, Select, Switch} from "antd";
import {ClearOutlined, EyeInvisibleOutlined, EyeTwoTone} from "@ant-design/icons";
import * as LdapBackend from "./backend/LdapBackend";
import * as OrganizationBackend from "./backend/OrganizationBackend";
import * as CertBackend from "./backend/CertBackend";
import * as Setting from "./Setting";
import i18next from "i18next";
import LdapAttributeMappingTable from "./table/LdapAttributeMappingTable";
import RoleMappingTable from "./table/RoleMappingTable";

const {Option} = Select;

class LdapEditPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      ldapId: props.match.params.ldapId,
      organizationName: props.match.params.organizationName,
      ldap: null,
      organizations: [],
      caCerts: [],
      clientCerts: [],
    };
  }

  UNSAFE_componentWillMount() {
    this.getLdap();
    this.getOrganizations();
  }

  getCACerts(owner) {
    CertBackend.getCerts(owner, -1, -1, "scope", Setting.CertScopeCACert, "", "")
      .then((res) => {
        this.setState({
          caCerts: (res.status === "ok") ? res.data : [],
        });
      });
  }

  getClientCerts(owner) {
    CertBackend.getCerts(owner, -1, -1, "scope", Setting.CertScopeClientCert, "", "")
      .then((res) => {
        this.setState({
          clientCerts: (res.status === "ok") ? res.data : [],
        });
      });
  }

  getLdap() {
    LdapBackend.getLdap(this.state.organizationName, this.state.ldapId)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            ldap: res.data,
          });
          this.getCACerts(res.data.owner);
          this.getClientCerts(res.data.owner);
        } else {
          Setting.showMessage("error", res.msg);
        }
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

  updateLdapField(key, value) {
    this.setState((prevState) => {
      prevState.ldap[key] = value;
      return prevState;
    });
  }

  renderAutoSyncWarn() {
    if (this.state.ldap.autoSync > 0) {
      return (
        <span style={{
          color: "#faad14",
          marginLeft: "20px",
        }}>{i18next.t("ldap:The Auto Sync option will sync all users to specify organization")}</span>
      );
    }
  }

  renderLdap() {
    return (
      <Card size="small" title={
        <div>
          {i18next.t("ldap:Edit LDAP")}&nbsp;&nbsp;&nbsp;&nbsp;
          <Button onClick={() => this.submitLdapEdit()}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" onClick={() => this.submitLdapEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
          <Button style={{marginLeft: "20px"}}
            onClick={() => Setting.goToLink(`/ldap/sync/${this.state.organizationName}/${this.state.ldapId}`)}>
            {i18next.t("general:Sync")} LDAP
          </Button>
        </div>
      } style={{marginLeft: "5px"}} type="inner">
        <Row style={{marginTop: "10px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("general:Organization"), i18next.t("general:Organization - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Select virtual={false} style={{width: "100%"}} disabled={!Setting.isAdminUser(this.props.account)}
              value={this.state.ldap.owner} onChange={(value => {
                this.updateLdapField("owner", value);
              })}>
              {
                this.state.organizations.map((organization, index) => <Option key={index}
                  value={organization.name}>{organization.name}</Option>)
              }
            </Select>
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("general:ID"), i18next.t("general:ID - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Input value={this.state.ldap.id} disabled={true} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Server name"), i18next.t("ldap:Server name - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Input value={this.state.ldap.serverName} onChange={e => {
              this.updateLdapField("serverName", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Server host"), i18next.t("ldap:Server host - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Input value={this.state.ldap.host} onChange={e => {
              this.updateLdapField("host", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Server port"), i18next.t("ldap:Server port - Tooltip"))} :
          </Col>
          <Col span={20}>
            <InputNumber min={0} max={65535} formatter={value => value.replace(/\$\s?|(,*)/g, "")}
              value={this.state.ldap.port} onChange={value => {
                this.updateLdapField("port", value);
              }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Enable SSL"), i18next.t("ldap:Enable SSL - Tooltip"))} :
          </Col>
          <Col span={20} >
            <Switch checked={this.state.ldap.enableSsl} onChange={checked => {
              this.updateLdapField("enableSsl", checked);
            }} />
          </Col>
        </Row>
        {
          this.state.ldap.enableSsl ? (
            <Row style={{marginTop: "20px"}} >
              <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
                {Setting.getLabel(i18next.t("cert:CA Certificate"), i18next.t("cert:CA Certificate - Tooltip"))} :
              </Col>
              <Col span={19} >
                <Select virtual={false} style={{width: "100%"}} value={this.state.ldap.cert} onChange={(value => {this.updateLdapField("cert", value);})}>
                  {
                    this.state.caCerts.map((cert, index) => <Option key={index} value={cert.name}>{cert.name}</Option>)
                  }
                </Select>
              </Col>
              <Col style={{paddingLeft: "5px"}} span={1} >
                <Button icon={<ClearOutlined />} type="text" onClick={() => {this.updateLdapField("cert", "");}} >
                </Button>
              </Col>
            </Row>
          ) : null
        }
        {
          this.state.ldap.enableSsl ? (
            <Row style={{marginTop: "20px"}} >
              <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
                {Setting.getLabel(i18next.t("ldap:Enable Cryptographic Authentication"), i18next.t("ldap:Enable Cryptographic Authentication - Tooltip"))} :
              </Col>
              <Col span={20} >
                <Switch checked={this.state.ldap.enableCryptographicAuth} onChange={checked => {
                  this.updateLdapField("enableCryptographicAuth", checked);
                }} />
              </Col>
            </Row>
          ) : null
        }
        {
          this.state.ldap.enableSsl && this.state.ldap.enableCryptographicAuth ? (
            <Row style={{marginTop: "20px"}} >
              <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
                {Setting.getLabel(i18next.t("cert:Client Certificate"), i18next.t("cert:Client Certificate - Tooltip"))} :
              </Col>
              <Col span={19} >
                <Select virtual={false} style={{width: "100%"}} value={this.state.ldap.clientCert} onChange={(value => {this.updateLdapField("clientCert", value);})}>
                  {
                    this.state.clientCerts.map((cert, index) => <Option key={index} value={cert.name}>{cert.name}</Option>)
                  }
                </Select>
              </Col>
              <Col style={{paddingLeft: "5px"}} span={1} >
                <Button icon={<ClearOutlined />} type="text" onClick={() => {this.updateLdapField("clientCert", "");}} >
                </Button>
              </Col>
            </Row>
          ) : null
        }
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Base DN"), i18next.t("ldap:Base DN - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Input value={this.state.ldap.baseDn} onChange={e => {
              this.updateLdapField("baseDn", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Search Filter"), i18next.t("ldap:Search Filter - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Input value={this.state.ldap.filter} onChange={e => {
              this.updateLdapField("filter", e.target.value);
            }} />
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Filter fields"), i18next.t("ldap:Filter fields - Tooltip"))} :
          </Col>
          <Col span={20}>
            <Select value={this.state.ldap.filterFields ?? []} style={{width: "100%"}} mode={"multiple"} options={[
              {value: "uid", label: "uid"},
              {value: "mail", label: "Email"},
              {value: "mobile", label: "mobile"},
              {value: "sAMAccountName", label: "sAMAccountName"},
              {value: "userPrincipalName", label: "userPrincipalName"},
            ].map((item) => Setting.getOption(item.label, item.value))} onChange={value => {
              this.updateLdapField("filterFields", value);
            }} />
          </Col>
        </Row>
        {
          this.state.ldap.enableSsl && this.state.ldap.enableCryptographicAuth ? null :
            <Row style={{marginTop: "20px"}}>
              <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
                {Setting.getLabel(i18next.t("ldap:Admin"), i18next.t("ldap:Admin - Tooltip"))} :
              </Col>
              <Col span={20}>
                <Input value={this.state.ldap.username} onChange={e => {
                  this.updateLdapField("username", e.target.value);
                }} />
              </Col>
            </Row>
        }
        {
          this.state.ldap.enableSsl && this.state.ldap.enableCryptographicAuth ? null :
            <Row style={{marginTop: "20px"}}>
              <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
                {Setting.getLabel(i18next.t("ldap:Admin Password"), i18next.t("ldap:Admin Password - Tooltip"))} :
              </Col>
              <Col span={20}>
                <Input.Password
                  iconRender={visible => (visible ? <EyeTwoTone /> : <EyeInvisibleOutlined />)}
                  value={this.state.ldap.password}
                  onChange={e => {
                    this.updateLdapField("password", e.target.value);
                  }}
                />
              </Col>
            </Row>
        }
        <Row style={{marginTop: "20px"}}>
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Auto Sync"), i18next.t("ldap:Auto Sync - Tooltip"))} :
          </Col>
          <Col span={20}>
            <InputNumber min={0} formatter={value => value.replace(/\$\s?|(,*)/g, "")} disabled={false}
              value={this.state.ldap.autoSync} onChange={value => {
                this.updateLdapField("autoSync", value);
              }} /><span>&nbsp;mins</span>
            {this.renderAutoSyncWarn()}
          </Col>
        </Row>
        <Row style={{marginTop: "20px"}} >
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Enable Attribute Mapping"), i18next.t("ldap:Enable Attribute Mapping - Tooltip"))} :
          </Col>
          <Col span={20} >
            <Switch checked={this.state.ldap.enableAttributeMapping} onChange={checked => {
              this.updateLdapField("enableAttributeMapping", checked);
            }} />
          </Col>
        </Row>
        {this.state.ldap?.enableAttributeMapping &&
          <Row style={{marginTop: "20px"}}>
            <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
              {Setting.getLabel(i18next.t("ldap:Attribute mapping"), i18next.t("ldap:Attribute mapping - Tooltip"))} :
            </Col>
            <Col span={20}>
              <LdapAttributeMappingTable
                title={i18next.t("ldap:Attribute mapping rules")}
                table={this.state.ldap.attributeMappingItems}
                onUpdateTable={(value) => {this.updateLdapField("attributeMappingItems", value);}}
              />
            </Col>
          </Row>
        }
        <Row style={{marginTop: "20px"}} >
          <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
            {Setting.getLabel(i18next.t("ldap:Enable Role Mapping"), i18next.t("ldap:Enable Role Mapping - Tooltip"))} :
          </Col>
          <Col span={20} >
            <Switch checked={this.state.ldap.enableRoleMapping} onChange={checked => {
              this.updateLdapField("enableRoleMapping", checked);
            }} />
          </Col>
        </Row>
        {this.state.ldap?.enableRoleMapping &&
          <Row style={{marginTop: "20px"}}>
            <Col style={{lineHeight: "32px", textAlign: "right", paddingRight: "25px"}} span={4}>
              {Setting.getLabel(i18next.t("ldap:Role mapping"), i18next.t("ldap:Role mapping - Tooltip"))} :
            </Col>
            <Col span={20}>
              <RoleMappingTable
                title={i18next.t("ldap:Role mapping rules")}
                table={this.state.ldap.roleMappingItems}
                owner={this.state.ldap.owner}
                attributes={["uidNumber", "cn", "sn", "gidNumber", "entryUUID", "displayName", "mail", "email",
                  "emailAddress", "telephoneNumber", "mobile", "mobileTelephoneNumber", "registeredAddress", "postalAddress",
                  "userPrincipalName", "memberOf"]}
                onUpdateTable={(value) => {this.updateLdapField("roleMappingItems", value);}}
              />
            </Col>
          </Row>
        }
      </Card>
    );
  }

  submitLdapEdit(willExist) {
    LdapBackend.updateLdap(this.state.ldap)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", "Update LDAP server success");
          this.setState({
            organizationName: this.state.ldap.owner,
          });

          if (willExist) {
            this.props.history.push(`/organizations/${this.state.organizationName}`);
          }
        } else {
          Setting.showMessage("error", res.msg);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `Update LDAP server failed: ${error}`);
      });
  }

  render() {
    return (
      <div>
        {
          this.state.ldap !== null ? this.renderLdap() : null
        }
        <div style={{marginTop: "20px", marginLeft: "40px"}}>
          <Button size="large" onClick={() => this.submitLdapEdit()}>{i18next.t("general:Save")}</Button>
          <Button style={{marginLeft: "20px"}} type="primary" size="large" onClick={() => this.submitLdapEdit(true)}>{i18next.t("general:Save & Exit")}</Button>
        </div>
      </div>
    );
  }
}

export default LdapEditPage;
