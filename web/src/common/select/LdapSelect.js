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
import {Select} from "antd";
import i18next from "i18next";
import * as LdapBackend from "../../backend/LdapBackend";
import * as Setting from "../../Setting";

function LdapSelect(props) {
  const {onChange, initValue, style, onSelect, className} = props;
  const [ldaps, setLdaps] = React.useState(undefined);
  const [value, setValue] = React.useState(initValue);

  React.useEffect(() => {
    if (ldaps === undefined) {
      getLdapServerNames(props.organization);
    }
  }, [value]);

  const getLdapServerNames = (org) => {
    LdapBackend.getLdapServerNames(org)
      .then((res) => {
        if (res.status === "ok") {
          setLdaps(res.data);
          if (!res.data) {
            res.data = [];
          }
          const selectedValueExist = res.data.filter(ldap => ldap.id === value).length > 0;
          if (initValue === undefined || !selectedValueExist) {
            handleOnChange(res.data.length > 0 ? Setting.getOption(res.data[0].name, res.data[0].id) : "");
          }
        }
      });
  };

  const handleOnChange = (obj) => {
    setValue(obj);
    props.ldapIdSetter(obj.value);
    onChange?.(obj);
  };

  const getLdapItems = () => {
    const items = [];
    if (!ldaps) {
      return items;
    }
    ldaps.forEach((ldap) => items.push(Setting.getOption(ldap.name, ldap.id)));
    return items;
  };

  const items = getLdapItems();
  if (items.length === 0) {
    return null;
  }
  return (
    <div style={{marginBottom: "20px"}}>
      <p style={{fontSize: ""}}>
        {i18next.t("login:Choose server")}
      </p>
      <Select
        options={getLdapItems()}
        virtual={false}
        placeholder={i18next.t("login:Please select an ldap server")}
        value={value}
        onChange={handleOnChange}
        filterOption={(input, option) => (option?.label ?? "").toLowerCase().includes(input.toLowerCase())}
        style={style}
        onSelect={onSelect}
        className={className}
      >
      </Select>
    </div>
  );
}

export default LdapSelect;
