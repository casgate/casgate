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
import {Card, Col, Row} from "antd";
import * as PlanBackend from "../backend/PlanBackend";
import * as Setting from "../Setting";
import SingleCard from "./SingleCard";
import i18next from "i18next";

class PricingPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      applications: null,
      pricing: props.pricingProp,
      plans: [],
    };
  }

  UNSAFE_componentWillMount() {
    this.setState({
      applications: [],
    });

    console.log(this.state.pricing);

    if (this.state.pricing.plans) {
      const plans = this.state.pricing.plans.map((plan) =>
        PlanBackend.getPlanById(plan, true));

      Promise.all(plans)
        .then(results => {
          this.setState({
            plans: results,
          });
        })
        .catch(error => {
          console.error("An error occurred:", error);
        });

    }

  }

  getItems() {
    let items = [];

    items = [
      {link: "/organizations", name: i18next.t("general:Pro"), organizer: i18next.t("general:For small teams, with limited technical support (via Tickets)"), options: ["DDoS Protection", "MAX RPS 1000"]},
      {link: "/users", name: i18next.t("general:Business"), organizer: i18next.t("general:For fast growing start-ups, with full technical support (8x5)"), options: ["DDoS Protection", "MAX RPS 10000", "Uptime SLA 100%"]},
      {link: "/providers", name: i18next.t("general:Enterprise"), organizer: i18next.t("general:For large & medium-sized enterprise, with full technical support (8x5)"), options: ["DDoS Protection", "MAX RPS 10000", "Uptime SLA 100%", "Network Prioritization"]},
    ];

    for (let i = 0; i < items.length; i++) {
      let filename = items[i].link;
      if (filename === "/account") {
        filename = "/users";
      }
      items[i].logo = `${Setting.StaticBaseUrl}/img${filename}.png`;
      items[i].createdTime = "";
    }

    return items;
  }

  renderCards() {
    if (this.state.plans === null) {
      return null;
    }

    const items = this.getItems();

    if (Setting.isMobile()) {
      return (
        <Card bodyStyle={{padding: 0}}>
          {
            this.state.plans.map(item => {
              return (
                <SingleCard key={item.link} logo={item.logo} link={item.link} title={item.displayName} desc={item.organizer} isSingle={items.length === 1} />
              );
            })
          }
        </Card>
      );
    } else {
      return (
        <div style={{marginRight: "15px", marginLeft: "15px"}}>
          <Row style={{marginLeft: "-20px", marginRight: "-20px", marginTop: "20px"}} gutter={24}>
            {
              this.state.plans.map(item => {
                return (
                  <SingleCard key={item.name} plan={item} isSingle={items.length === 1} />
                );
              })
            }
          </Row>
        </div>
      );
    }
  }

  render() {
    return (
      <div>
        <Row style={{width: "100%"}}>
          <Col span={24} style={{display: "flex", justifyContent: "center"}} >
            {
              this.renderCards()
            }
          </Col>
        </Row>
      </div>
    );
  }
}

export default PricingPage;
