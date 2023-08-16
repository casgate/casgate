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
import {Button, Col, Input, Row, Select, Table, Tooltip} from "antd";
import * as Setting from "../Setting";
import i18next from "i18next";
import {DeleteOutlined} from "@ant-design/icons";

class LdapAttributeMappingTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
    };
  }

  updateTable(table) {
    this.props.onUpdateTable(table);
  }

  updateField(table, index, key, value) {
    table[index][key] = value;
    this.updateTable(table);
  }

  addRow(table) {
    const row = {userField: "", attribute: ""};
    if (!table) {
      table = [];
    }

    table = Setting.addRow(table, row);
    this.updateTable(table);
  }

  deleteRow(table, i) {
    table = Setting.deleteRow(table, i);
    this.updateTable(table);
  }

  getUserFields() {
    return ["uid", "displayName", "email", "Phone", "Address"].filter((item) => !this.props.table.map(item => item.userField).includes(item));
  }

  renderTable(table) {
    const columns = [
      {
        title: i18next.t("ldap:User Field"),
        dataIndex: "userField",
        key: "userField",
        width: "600px",
        sorter: (a, b) => a.userField.localeCompare(b.userField),
        render: (text, record, index) => {
          return (
            <Select
              style={{width: 600}}
              placeholder="Please select an user field"
              options={this.getUserFields().map((item) => ({label: item, value: item}))}
              onChange={value => {
                this.updateField(table, index, "userField", value);
              }}
              value={text}
            />
          );
        },
      },
      {
        title: i18next.t("ldap:Attribute"),
        dataIndex: "attribute",
        key: "attribute",
        ellipsis: true,
        sorter: (a, b) => a.attribute.localeCompare(b.attribute),
        render: (text, record, index) => {
          return (
            <Input value={text} onChange={e => {
              this.updateField(table, index, "attribute", e.target.value);
            }} />
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
              this.renderTable(this.props.table)
            }
          </Col>
        </Row>
      </div>
    );
  }
}

export default LdapAttributeMappingTable;
