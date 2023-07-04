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
import {Link} from "react-router-dom";
import {Button, Table} from "antd";
import moment from "moment";
import * as Setting from "../Setting";
import * as OrganizationBackend from "../backend/OrganizationBackend";
import i18next from "i18next";
import BaseListPage from "../BaseListPage";
import PopconfirmModal from "../common/modal/PopconfirmModal";

class OrganizationListPage extends BaseListPage {
  newOrganization() {
    const randomName = Setting.getRandomName();
    return {
      owner: "admin", // this.props.account.organizationname,
      name: `organization_${randomName}`,
      createdTime: moment().format(),
      displayName: `New Organization - ${randomName}`,
      websiteUrl: "https://door.casdoor.com",
      favicon: `${Setting.StaticBaseUrl}/img/favicon.png`,
      passwordType: "bcrypt",
      PasswordSalt: Setting.getRandomName(),
      countryCodes: ["RU"],
      defaultAvatar: "https://static.vecteezy.com/system/resources/thumbnails/000/439/863/small/Basic_Ui__28186_29.jpg",
      defaultApplication: "",
      tags: [],
      languages: Setting.Countries.map(item => item.key),
      masterPassword: "",
      enableSoftDeletion: false,
      isProfilePublic: true,
      properties: {
        "ИНН": "",
        "КПП": "",
      },
      email: "",
      phone: "",
      manager: "",
      accountItems: [
        {name: "Organization", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "ID", visible: false, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Name", visible: true, viewRule: "Public", modifyRule: "Admin"},
        {name: "Display name", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Avatar", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "User type", visible: false, viewRule: "Public", modifyRule: "Admin"},
        {name: "Password", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Email", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Phone", visible: true, viewRule: "Public", modifyRule: "Self"},
        {name: "Country/Region", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Location", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Affiliation", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Title", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Homepage", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Bio", visible: false, viewRule: "Public", modifyRule: "Self"},
        {name: "Tag", visible: true, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Signup application", visible: false, viewRule: "Public", modifyRule: "Admin"},
        {name: "Roles", visible: false, viewRule: "Public", modifyRule: "Immutable"},
        {name: "Permissions", visible: false, viewRule: "Public", modifyRule: "Immutable"},
        {name: "3rd-party logins", visible: false, viewRule: "Self", modifyRule: "Self"},
        {name: "Properties", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is admin", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is global admin", visible: false, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is forbidden", visible: true, viewRule: "Admin", modifyRule: "Admin"},
        {name: "Is deleted", visible: true, viewRule: "Admin", modifyRule: "Admin"},
      ],
    };
  }

  addOrganization() {
    const newOrganization = this.newOrganization();
    OrganizationBackend.addOrganization(newOrganization)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/organizations/${newOrganization.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteOrganization(i) {
    OrganizationBackend.deleteOrganization(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.setState({
            data: Setting.deleteRow(this.state.data, i),
            pagination: {
              ...this.state.pagination,
              total: this.state.pagination.total - 1},
          });
          window.dispatchEvent(new Event("storageOrganizationsChanged"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  renderTable(organizations) {

    const columns = [
      {
        title: i18next.t("organization:Name"),
        dataIndex: "name",
        key: "name",
        width: "120px",
        fixed: "left",
        sorter: true,
        ...this.getColumnSearchProps("name"),
        render: (text, record, index) => {
          return (
            <Link to={`/organizations/${text}`}>
              {text}
            </Link>
          );
        },
      },
      {
        title: i18next.t("general:Display name"),
        dataIndex: "displayName",
        key: "displayName",
        width: "250px",
        sorter: true,
        ...this.getColumnSearchProps("displayName"),
      },
      {
        title: i18next.t("general:Created time"),
        dataIndex: "createdTime",
        key: "createdTime",
        width: "160px",
        sorter: true,
        render: (text, record, index) => {
          return Setting.getFormattedDate(text);
        },
      },
      {
        title: i18next.t("organization:INN"),
        dataIndex: "organization:INN",
        key: "organization:INN",
        width: "120px",
        sorter: true,
        ...this.getColumnSearchProps("properties"),
        render: (text, record, index) => {
          return (
            <span>
              {record?.properties?.["ИНН"] || ""}
            </span>
          );
        },
      },
      {
        title: i18next.t("organization:KPP"),
        dataIndex: "organization:KPP",
        key: "organization:KPP",
        width: "120px",
        sorter: true,
        ...this.getColumnSearchProps("properties"),
        render: (text, record, index) => {
          return (
            <span>
              {record?.properties?.["КПП"] || ""}
            </span>
          );
        },
      },
      {
        title: i18next.t("organization:Tags"),
        dataIndex: "tags",
        key: "tags",
        width: "100px",
        sorter: true,
        ...this.getColumnSearchProps("tags"),
        render: (text, record, index) => {
          return (
            <span>
              {Setting.getTags(record.tags)}
            </span>
          );
        },
      },
      {
        title: i18next.t("general:Action"),
        dataIndex: "",
        key: "op",
        width: "240px",
        fixed: (Setting.isMobile()) ? "false" : "right",
        render: (text, record, index) => {
          return (
            <div>
              <Button style={{marginTop: "10px", marginBottom: "10px", marginRight: "10px", display: "none"}} type="primary" onClick={() => this.props.history.push(`/organizations/${record.name}/users`)}>{i18next.t("general:Users")}</Button>
              <Button style={{marginTop: "10px", marginBottom: "10px", marginRight: "10px"}} onClick={() => this.props.history.push(`/organizations/${record.name}`)}>{i18next.t("general:Edit")}</Button>
              <PopconfirmModal
                title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                onConfirm={() => this.deleteOrganization(index)}
                disabled={record.name === "built-in"}
              >
              </PopconfirmModal>
            </div>
          );
        },
      },
    ];

    const paginationProps = {
      total: this.state.pagination.total,
      showQuickJumper: true,
      showSizeChanger: true,
      showTotal: () => i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total),
    };

    return (
      <div>
        <Table scroll={{x: "max-content"}} columns={columns} dataSource={organizations} rowKey="name" size="middle" bordered pagination={paginationProps}
          title={() => (
            <div>
              {i18next.t("general:Organizations")}&nbsp;&nbsp;&nbsp;&nbsp;
              <Button type="primary" size="small" onClick={this.addOrganization.bind(this)}>{i18next.t("general:Add")}</Button>
            </div>
          )}
          loading={this.state.loading}
          onChange={this.handleTableChange}
        />
      </div>
    );
  }

  fetch = (params = {}) => {
    let field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (params.passwordType !== undefined && params.passwordType !== null) {
      field = "passwordType";
      value = params.passwordType;
    }
    this.setState({loading: true});
    OrganizationBackend.getOrganizations("admin", Setting.isDefaultOrganizationSelected(this.props.account) ? "" : Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            loading: false,
            data: res.data,
            pagination: {
              ...params.pagination,
              total: res.data2,
            },
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          if (Setting.isResponseDenied(res)) {
            this.setState({
              loading: false,
              isAuthorized: false,
            });
          }
        }
      });
  };
}

export default OrganizationListPage;
