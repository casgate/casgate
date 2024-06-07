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
import {Button, Col, Form, Input, Row, Select, Steps} from "antd";
import * as AuthBackend from "./AuthBackend";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Util from "./Util";
import * as Setting from "../Setting";
import i18next from "i18next";
import {SendCodeInput} from "../common/SendCodeInput";
import * as UserBackend from "../backend/UserBackend";
import CustomGithubCorner from "../common/CustomGithubCorner";
import {withRouter} from "react-router-dom";
import * as PasswordChecker from "../common/PasswordChecker";
import {CaptchaModal} from "../common/modal/CaptchaModal";

const {Option} = Select;

class ForgetPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      applicationName: props.applicationName ?? props.match.params?.applicationName,
      msg: null,
      name: "",
      username: "",
      phone: "",
      email: "",
      dest: "",
      isVerifyTypeFixed: false,
      verifyType: "", // "email", "phone"
      current: 0,
      captchaCode: "",
      captchaToken: "",
      captchaVisible: false,
      oneTimeCode: "",
    };

    this.form = React.createRef();
  }
  componentDidMount() {
    if (this.getApplicationObj() === undefined) {
      if (this.state.applicationName !== undefined) {
        this.getApplication();
      } else {
        Setting.showMessage("error", i18next.t("forget:Unknown forget type") + ": " + this.state.type);
      }
    }
  }

  getApplication() {
    if (this.state.applicationName === undefined) {
      return;
    }

    ApplicationBackend.getApplication("admin", this.state.applicationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }
        this.onUpdateApplication(res.data);
      });
  }
  getApplicationObj() {
    return this.props.application;
  }

  onUpdateApplication(application) {
    this.props.onUpdateApplication(application);
  }

  onFormFinish(name, info, forms) {
    switch (name) {
    case "step1":
      if (this.state.captchaCode !== "") {
        const username = forms.step1.getFieldValue("username");
        AuthBackend.getEmailAndPhone(forms.step1.getFieldValue("organization"), Setting.getApplicationName(this.getApplicationObj()), username, this.state.captchaToken, this.state.captchaCode)
          .then((res) => {
            if (res.status === "ok") {
              const phone = res.data.phone;
              const email = res.data.email;

              if (!phone && !email) {
                Setting.showMessage("error", "no verification method!");
              } else {
                this.setState({
                  name: res.data.name,
                  phone: phone,
                  email: email,
                  oneTimeCode: res.data.oneTimeCode,
                });

                const saveFields = (type, dest, fixed) => {
                  this.setState({
                    verifyType: type,
                    isVerifyTypeFixed: fixed,
                    dest: dest,
                  });
                };

                switch (res.data2) {
                case "email":
                  saveFields("email", email, true);
                  break;
                case "phone":
                  saveFields("phone", phone, true);
                  break;
                case "username":
                  phone !== "" ? saveFields("phone", phone, false) : saveFields("email", email, false);
                }

                this.setState({
                  current: 1,
                });
              }
            } else {
              this.setState({captchaVisible: false, captchaCode: "", captchaToken: ""});
              Setting.showMessage("error", res.msg);
            }
          });
        break;
      }
      this.setState({captchaVisible: true});
      break;
    case "step2":
      UserBackend.verifyCode({
        application: forms.step2.getFieldValue("application"),
        organization: forms.step2.getFieldValue("organization"),
        username: forms.step2.getFieldValue("dest"),
        name: this.state.name,
        code: forms.step2.getFieldValue("code"),
        type: "login",
      }).then(res => {
        if (res.status === "ok") {
          this.setState({current: 2, code: forms.step2.getFieldValue("code")});
        } else {
          Setting.showMessage("error", res.msg);
        }
      });

      break;
    default:
      break;
    }
  }

  onCaptchaFinish(captchaType, captchaToken, clientSecret) {
    this.setState({captchaVisible: false, captchaCode: clientSecret, captchaToken: captchaToken});
    this.form.current.submit();
  }

  onFinish(values) {
    values.username = this.state.name;
    values.userOwner = this.getApplicationObj()?.organizationObj.name;
    UserBackend.setPassword(values.userOwner, values.username, "", values?.newPassword, this.state.code).then(res => {
      if (res.status === "ok") {
        Setting.redirectToLoginPage(this.getApplicationObj(), this.props.history);
      } else {
        Setting.showMessage("error", res.msg);
      }
    });
  }

  onFinishFailed(values, errorFields) {}

  renderOptions() {
    const options = [];

    if (this.state.phone !== "") {
      options.push(
        <Option key={"phone"} value={this.state.phone} >
          &nbsp;&nbsp;{this.state.phone}
        </Option>
      );
    }

    if (this.state.email !== "") {
      options.push(
        <Option key={"email"} value={this.state.email} >
          &nbsp;&nbsp;{this.state.email}
        </Option>
      );
    }

    return options;
  }

  renderForm(application) {
    return (
      <Form.Provider onFormFinish={(name, {info, forms}) => {
        this.onFormFinish(name, info, forms);
      }}>
        {/* STEP 1: input username -> get email & phone */}
        {this.state.current === 0 ?
          <Form
            ref={this.form}
            name="step1"
            // eslint-disable-next-line no-console
            onFinishFailed={(errorInfo) => console.log(errorInfo)}
            initialValues={{
              application: application.name,
              organization: application.organization,
            }}
            size="large"
          >
            <Form.Item
              hidden
              name="application"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your application!"),
                },
              ]}
            />
            <Form.Item
              hidden
              name="organization"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your organization!"),
                },
              ]}
            />
            <Form.Item
              name="username"
              rules={[
                {
                  required: true,
                  message: i18next.t("forget:Please input your username!"),
                  whitespace: true,
                },
              ]}
            >
              <Input
                style={{marginTop: 24}}
                placeholder={i18next.t("login:username, Email or phone")}
              />
            </Form.Item>
            <Form.Item>
              <Button block type="primary" htmlType="submit">
                {i18next.t("forget:Next Step")}
              </Button>
            </Form.Item>
          </Form> : null}

        {/* STEP 2: verify email or phone */}
        {this.state.current === 1 ? <Form
          ref={this.form}
          name="step2"
          onFinishFailed={(errorInfo) =>
            this.onFinishFailed(
              errorInfo.values,
              errorInfo.errorFields,
              errorInfo.outOfDate
            )
          }
          onValuesChange={(changedValues, allValues) => {
            const verifyType = changedValues.dest?.indexOf("@") === -1 ? "phone" : "email";
            this.setState({
              dest: changedValues.dest,
              verifyType: verifyType,
            });
          }}
          initialValues={{
            application: application.name,
            organization: application.organization,
            dest: this.state.dest,
          }}
          size="large"
        >
          <Form.Item
            style={{height: 0, visibility: "hidden", margin: 0}}
            name="application"
            rules={[
              {
                required: true,
                message: i18next.t("application:Please input your application!"),
              },
            ]}
          />
          <Form.Item
            hidden
            name="organization"
            rules={[
              {
                required: true,
                message: i18next.t("application:Please input your organization!"),
              },
            ]}
          />
          <Form.Item
            name="dest"
            validateFirst
            hasFeedback
          >
            {
              <Select virtual={false}
                disabled={this.state.isVerifyTypeFixed}
                style={{textAlign: "left"}}
                placeholder={i18next.t("forget:Choose email or phone")}
              >
                {
                  this.renderOptions()
                }
              </Select>
            }
          </Form.Item>
          <Form.Item
            name="code"
            rules={[
              {
                required: true,
                message: i18next.t("code:Please input your verification code!"),
              },
            ]}
          >
            <SendCodeInput disabled={this.state.dest === ""}
              method={"forget"}
              onButtonClickArgs={[this.state.dest, this.state.verifyType, Setting.getApplicationName(this.getApplicationObj()), this.state.name]}
              application={application}
              oneTimeCode={this.state.oneTimeCode}
            />
          </Form.Item>
          <Form.Item>
            <Button
              block
              type="primary"
              htmlType="submit"
            >
              {i18next.t("forget:Next Step")}
            </Button>
          </Form.Item>
        </Form> : null}

        {/* STEP 3 */}
        {this.state.current === 2 ?
          <Form
            ref={this.form}
            name="step3"
            onFinish={(values) => this.onFinish(values)}
            onFinishFailed={(errorInfo) =>
              this.onFinishFailed(
                errorInfo.values,
                errorInfo.errorFields,
                errorInfo.outOfDate
              )
            }
            initialValues={{
              application: application.name,
              organization: application.organization,
            }}
            size="large"
          >
            <Form.Item
              hidden
              name="application"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your application!"),
                },
              ]}
            />
            <Form.Item
              hidden
              name="organization"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your organization!"),
                },
              ]}
            />
            <Form.Item
              name="newPassword"
              hidden={this.state.current !== 2}
              rules={[
                {
                  required: true,
                  validateTrigger: "onChange",
                  validator: (rule, value) => {
                    const errorMsg = PasswordChecker.checkPasswordComplexity(value, application.organizationObj.passwordOptions, application.organizationObj.passwordSpecialChars);
                    if (errorMsg === "") {
                      return Promise.resolve();
                    } else {
                      return Promise.reject(errorMsg);
                    }
                  },
                },
              ]}
              hasFeedback
            >
              <Input.Password
                placeholder={i18next.t("general:Password")}
              />
            </Form.Item>
            <Form.Item
              name="confirm"
              dependencies={["newPassword"]}
              hasFeedback
              rules={[
                {
                  required: true,
                  message: i18next.t("signup:Please confirm your password!"),
                },
                ({getFieldValue}) => ({
                  validator(rule, value) {
                    if (!value || getFieldValue("newPassword") === value) {
                      return Promise.resolve();
                    }
                    return Promise.reject(
                      i18next.t("signup:Your confirmed password is inconsistent with the password!")
                    );
                  },
                }),
              ]}
            >
              <Input.Password
                placeholder={i18next.t("signup:Confirm")}
              />
            </Form.Item>
            <Form.Item hidden={this.state.current !== 2}>
              <Button block type="primary" htmlType="submit">
                {i18next.t("forget:Change Password")}
              </Button>
            </Form.Item>
          </Form> : null}
      </Form.Provider>
    );
  }

  render() {
    const application = this.getApplicationObj();
    if (application === undefined) {
      return null;
    }
    if (application === null) {
      return Util.renderMessageLarge(this, this.state.msg);
    }

    return (
      <React.Fragment>
        <CustomGithubCorner />
        <div className="forget-wrapper">
          <div className="forget-content" style={{padding: Setting.isMobile() ? "0" : null, boxShadow: Setting.isMobile() ? "none" : null}}>
            <Row>
              <Col span={24}>
                <Row>
                  <Col span={24}>
                    <div>
                      {
                        Setting.renderHelmet(application)
                      }
                      {
                        Setting.renderLogo(application)
                      }
                    </div>
                  </Col>
                </Row>
                <Row>
                  <Col span={24}>
                    <h1>{i18next.t("forget:Retrieve password")}</h1>
                  </Col>
                </Row>
                <Row>
                  <Col span={24}>
                    <Steps
                      current={this.state.current}
                      items={[
                        {
                          title: i18next.t("forget:Account"),
                        },
                        {
                          title: i18next.t("forget:Verify"),
                        },
                        {
                          title: i18next.t("forget:Reset"),
                        },
                      ]}
                    >
                    </Steps>
                  </Col>
                </Row>
              </Col>
              <Col span={24}>
                <div>
                  {this.renderForm(application)}
                </div>
              </Col>
            </Row>
            <Row>
              <CaptchaModal
                owner={application.owner}
                name={application.name}
                visible={this.state.captchaVisible}
                onOk={this.onCaptchaFinish.bind(this)}
                onCancel={() => this.setState({captchaVisible: false})}
                isCurrentProvider={false} />
            </Row>
          </div>
        </div>
      </React.Fragment>
    );
  }
}

export default withRouter(ForgetPage);
