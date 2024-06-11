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
import * as Setting from "../../Setting";
import {Dropdown} from "antd";
import "../../App.less";
import {GlobalOutlined} from "@ant-design/icons";

function flagIcon(country, alt) {
  return (
    <img width={24} alt={alt} src={Setting.getCountryImageUrl(country)} />
  );
}

class LanguageSelect extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      languages: props.languages ?? Setting.Countries.map(item => item.key),
    };

    Setting.Countries.forEach((country) => {
      new Image().src = Setting.getCountryImageUrl(country.country);
    });
  }

  items = Setting.Countries.map((country) => Setting.getItem(country.label, country.key, flagIcon(country.country, country.alt)));

  getOrganizationLanguages(languages) {
    const select = [];
    for (const language of languages) {
      this.items.map((item, index) => item.key === language ? select.push(item) : null);
    }
    return select;
  }

  render() {
    const languageItems = this.getOrganizationLanguages(this.state.languages);
    const onClick = (e) => {
      Setting.setLanguage(e.key);
    };

    return (
      <Dropdown menu={{items: languageItems, onClick}} >
        <div className="select-box" style={{display: languageItems.length === 0 ? "none" : null, ...this.props.style}} >
          <GlobalOutlined style={{fontSize: "24px", color: "#4d4d4d"}} />
        </div>
      </Dropdown>
    );
  }
}

export default LanguageSelect;
