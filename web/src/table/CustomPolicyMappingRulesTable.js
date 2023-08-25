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
import {Button, Input, Select, Table, Tooltip} from "antd";
import * as Setting from "../Setting";
import i18next from "i18next";
import {DeleteOutlined} from "@ant-design/icons";

class CustomPolicyMappingRulesTable extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      table: this.props.table ? this.props.table.map((item, index) => {
        return {
          key: index,
          Ptype: item[0],
          V0: item[1],
          V1: item[2],
          V2: item[3],
          V3: item[4],
          V4: item[5],
        };
      }) : [],
      loading: false,
    };
  }

  count = this.props.table?.length ?? 0;

  getIndex(index) {
    // Need to be used in all place when modify table. Parameter is the row index in table, need to calculate the index in dataSource.
    return index;
  }

  updateTable(table) {
    this.setState({table: table});

    this.props.onUpdateTable([...table].map((item) => {
      const newItem = Setting.deepCopy(item);
      delete newItem.key;
      return [newItem.Ptype, newItem.V0, newItem.V1, newItem.V2, newItem.V3, newItem.V4];
    }));
  }

  updateField(table, index, key, value) {
    table[this.getIndex(index)][key] = value;
    this.updateTable(table);
  }

  addRow(table) {
    const row = {key: this.count, Ptype: "p"};
    if (table === undefined) {
      table = [];
    }
    table = Setting.addRow(table, row, "top");

    this.count = this.count + 1;
    this.updateTable(table);
  }

  deleteRow(table, index) {
    table = Setting.deleteRow(table, this.getIndex(index));
    this.updateTable(table);
  }

  deleteRule(table, index) {
    this.deleteRow(table, index);
  }

  getOptions() {
    return [
      {value: "", label: ""},
      {value: "role.name", label: i18next.t("ldap:role.name")},
      {value: "role.subrole", label: i18next.t("ldap:role.subrole")},
      {value: "role.domain", label: i18next.t("ldap:role.domain")},
      {value: "role.user", label: i18next.t("ldap:role.user")},
      {value: "permission.action", label: i18next.t("ldap:permission.action")},
      {value: "permission.resource", label: i18next.t("ldap:permission.resource")},
      {value: "permission.user", label: i18next.t("ldap:permission.user")},
      {value: "permission.effect", label: i18next.t("ldap:permission.effect")},
      {value: "permission.domain", label: i18next.t("ldap:permission.domain")},
    ];
  }

  renderTable(table) {
    const columns = [
      {
        title: "Rule Type",
        dataIndex: "Ptype",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Input value={text} onChange={e => {
              this.updateField(table, index, "Ptype", e.target.value);
            }} />
          );
        },
      },
      {
        title: "V0",
        dataIndex: "V0",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Select
              defaultValue=""
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "V0", value);
              }}
              options={this.getOptions()}
              value={text}
            />
          );
        },
      },
      {
        title: "V1",
        dataIndex: "V1",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Select
              defaultValue=""
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "V1", value);
              }}
              options={this.getOptions()}
              value={text}
            />
          );
        },
      },
      {
        title: "V2",
        dataIndex: "V2",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Select
              defaultValue=""
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "V2", value);
              }}
              options={this.getOptions()}
              value={text}
            />
          );
        },
      },
      {
        title: "V3",
        dataIndex: "V3",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Select
              defaultValue=""
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "V3", value);
              }}
              options={this.getOptions()}
              value={text}
            />
          );
        },
      },
      {
        title: "V4",
        dataIndex: "V4",
        width: "100px",
        render: (text, record, index) => {
          return (
            <Select
              defaultValue=""
              style={{width: "100%"}}
              onChange={value => {
                this.updateField(table, index, "V4", value);
              }}
              options={this.getOptions()}
              value={text}
            />
          );
        },
      },
      {
        title: "Option",
        key: "option",
        width: "100px",
        render: (text, record, index) => {
          return (
            <div>
              <Tooltip placement="topLeft" title="Delete">
                <Button disabled={Setting.builtInObject({owner: this.props.owner, name: this.props.name})} style={{marginRight: "5px"}} icon={<DeleteOutlined />} size="small" onClick={() => this.deleteRule(table, index)} />
              </Tooltip>
            </div>
          );
        },
      }];

    return (
      <Table
        columns={columns} dataSource={table} rowKey="key" size="middle" bordered
        loading={this.state.loading}
        title={() => (
          <div>
            <Button disabled={Setting.builtInObject({owner: this.props.owner, name: this.props.name})} style={{marginRight: "5px"}} type="primary" size="small" onClick={() => this.addRow(table)}>{i18next.t("general:Add")}</Button>
          </div>
        )}
      />
    );
  }

  render() {
    return (
      <React.Fragment>
        {
          this.renderTable(this.state.table)
        }
      </React.Fragment>
    );
  }
}

export default CustomPolicyMappingRulesTable;
