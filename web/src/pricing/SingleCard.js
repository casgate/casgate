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
import {Card, Col} from "antd";
import * as Setting from "../Setting";
import {withRouter} from "react-router-dom";

const {Meta} = Card;

class SingleCard extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
    };
  }

  wrappedAsSilentSigninLink(link) {
    if (link.startsWith("http")) {
      link += link.includes("?") ? "&silentSignin=1" : "?silentSignin=1";
    }
    return link;
  }

  renderCardMobile(logo, link, title, desc, time, isSingle) {
    const gridStyle = {
      width: "100vw",
      textAlign: "center",
      cursor: "pointer",
    };
    const silentSigninLink = this.wrappedAsSilentSigninLink(link);

    return (
      <Card.Grid style={gridStyle} onClick={() => Setting.goToLinkSoft(this, silentSigninLink)}>
        <img src={logo} alt="logo" width={"100%"} style={{marginBottom: "20px"}} />
        <Meta
          title={title}
          description={desc}
          style={{justifyContent: "center"}}
        />
      </Card.Grid>
    );
  }

  renderCard(logo, link, title, desc, time, isSingle, options) {
    const silentSigninLink = this.wrappedAsSilentSigninLink(link);

    return (
      <Col style={{paddingLeft: "20px", paddingRight: "20px", paddingBottom: "20px", marginBottom: "20px"}} span={6}>
        <Card
          hoverable
          cover={
            <img alt="logo" src={logo} style={{width: "100%", height: "200px", padding: "20px", objectFit: "scale-down"}} />
          }
          onClick={() => Setting.goToLinkSoft(this, silentSigninLink)}
          style={isSingle ? {width: "320px", height: "100%"} : {width: "100%", height: "100%"}}
        >
          <Meta title={title} description={desc} />
          <br />
          <br />
          <Meta title={""} description={Setting.getFormattedDateShort(time)} />
          <ul style={{listStyleType: "none", paddingLeft: "0px"}}>

            {/* iterate  options and render div*/}
            {options.map((option) => {
            // eslint-disable-next-line react/jsx-key
              return <li>
                <svg style={{height: "1rem", width: "1rem", fill: "green", marginRight: "10px"}} xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 20 20">
                  <path d="M0 11l2-2 5 5L18 3l2 2L7 18z"></path>
                </svg>
                <span style={{fontSize: "16px"}}>{option}</span>
              </li>;
            })}
          </ul>

        </Card>
      </Col>
    );
  }

  render() {
    if (Setting.isMobile()) {
      return this.renderCardMobile(this.props.logo, this.props.link, this.props.title, this.props.desc, this.props.time, this.props.isSingle);
    } else {
      return this.renderCard(this.props.logo, this.props.link, this.props.title, this.props.desc, this.props.time, this.props.isSingle, this.props.options);
    }
  }
}

export default withRouter(SingleCard);
