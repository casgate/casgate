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
import {Button, Col, Divider, Input, Row, Select, Space, Table, Tooltip} from "antd";
import * as Setting from "../Setting";
import i18next from "i18next";
import {DeleteOutlined, PlusOutlined} from "@ant-design/icons";
import * as RoleBackend from "../backend/RoleBackend";

class LdapRoleMappingTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      attributes: this.getDefaultAttributes(),
      newAttributeName: "",
      roles: [],
      roleMappingTable: this.props.table ? this.props.table.map((item, index) => {
        item.key = index;
        return item;
      }) : [],
    };
  }

  count = this.props.table?.length ?? 0;

  componentDidMount() {
    this.getRoles(this.props.owner);
  }

  componentDidUpdate(prevProps) {
    if (this.props.owner !== prevProps.owner) {
      this.getRoles(this.props.owner);
      this.props.table.forEach((item) => {
        item.role = "";
      });
      this.updateTable(this.props.table);
    }
  }

  updateTable(table) {
    this.setState({
      roleMappingTable: table,
    });

    this.props.onUpdateTable([...table].map((item) => {
      const newItem = Setting.deepCopy(item);
      delete newItem.key;
      return newItem;
    }));
  }

  updateField(table, index, key, value) {
    table[index][key] = value;
    this.updateTable(table);
  }

  addRow(table) {
    const row = {key: this.count, attribute: "", values: [], role: ""};
    if (!table) {
      table = [];
    }

    this.count += 1;
    table = Setting.addRow(table, row);
    this.updateTable(table);
  }

  addAttributeListItem() {
    const newItem = this.state.newAttributeName;
    if (newItem === "" || this.state.attributes.includes(newItem)) {
      return;
    }
    this.setState({
      attributes: [...this.state.attributes, newItem],
      newAttributeName: "",
    });
  }

  deleteRow(table, i) {
    table = Setting.deleteRow(table, i);
    this.updateTable(table);
  }

  getDefaultAttributes() {
    return ["uidNumber", "cn", "sn", "gidNumber", "entryUUID", "displayName", "mail", "email",
      "emailAddress", "telephoneNumber", "mobile", "mobileTelephoneNumber", "registeredAddress", "postalAddress",
      "userPrincipalName", "memberOf"];
  }

  getRoles(organizationName) {
    RoleBackend.getRoles(organizationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        this.setState({
          roles: res,
        });
      });
  }

  renderTable(table) {
    const columns = [
      {
        title: i18next.t("ldap:Attribute"),
        dataIndex: "attribute",
        key: "attribute",
        width: "600px",
        sorter: (a, b) => a.attribute.localeCompare(b.attribute),
        render: (text, record, index) => {
          return (
            <Select
              style={{width: 600}}
              placeholder="Please select an attribute"
              dropdownRender={(menu) => (
                <>
                  {menu}
                  <Divider style={{margin: "8px 0"}} />
                  <Space style={{padding: "0 8px 4px"}}>
                    <Input
                      style={{width: 300}}
                      placeholder="Please enter attribute name"
                      value={this.state.newAttributeName}
                      onChange={(event) => this.setState({newAttributeName: event.target.value})}
                    />
                    <Button type="text" icon={<PlusOutlined />} onClick={() => this.addAttributeListItem()}>
                      Add attribute
                    </Button>
                  </Space>
                </>
              )}
              options={this.state.attributes.map((item) => ({label: item, value: item}))}
              onChange={value => {
                this.updateField(table, index, "attribute", value);
              }}
              value={text}
            />
          );
        },
      },
      {
        title: i18next.t("ldap:Values"),
        dataIndex: "values",
        key: "values",
        ellipsis: true,
        sorter: (a, b) => a.values.length - b.values.length,
        render: (text, record, index) => {
          return (
            <Select virtual={false} style={{width: "100%"}}
              value={text}
              mode="tags"
              onChange={value => {
                this.updateField(table, index, "values", value);
              }} >
            </Select>
          );
        },
      },
      {
        title: i18next.t("ldap:Role"),
        dataIndex: "role",
        key: "role",
        ellipsis: true,
        sorter: (a, b) => a.role.localeCompare(b.role),
        render: (text, record, index) => {
          return (
            <Select
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "role", value);
              }}
              options={this.state.roles.map((item) => ({label: item.displayName, value: `${this.props.owner}/${item.name}`}))}
              value={text}
            />
          );
        },
      },
      {
        title: i18next.t("general:Action"),
        dataIndex: "",
        key: "op",
        width: "80px",
        render: (text, record, index) => {
          return (
            <div>
              <Tooltip placement="topLeft" title={i18next.t("general:Delete")}>
                <Button icon={<DeleteOutlined />} size="small" onClick={() => this.deleteRow(table, index)} />
              </Tooltip>
            </div>
          );
        },
      },
    ];

    return (
      <Table scroll={{x: "max-content"}} rowKey="key" columns={columns} dataSource={table} size="middle" bordered pagination={false}
        title={() => (
          <div>
            {this.props.title}&nbsp;&nbsp;&nbsp;&nbsp;
            <Button style={{marginRight: "5px"}} type="primary" size="small"
              onClick={() => this.addRow(table)}>{i18next.t("general:Add")}</Button>
          </div>
        )}
      />
    );
  }

  render() {
    return (
      <div>
        <Row style={{marginTop: "20px"}}>
          <Col span={24}>
            {
              this.renderTable(this.state.roleMappingTable)
            }
          </Col>
        </Row>
      </div>
    );
  }
}

export default LdapRoleMappingTable;
