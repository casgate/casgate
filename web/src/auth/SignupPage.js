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
import {Button, Form, Input, Result} from "antd";
import * as Setting from "../Setting";
import * as AuthBackend from "./AuthBackend";
import * as ProviderButton from "./ProviderButton";
import i18next from "i18next";
import * as Util from "./Util";
import {authConfig} from "./Auth";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as AgreementModal from "../common/modal/AgreementModal";
import {SendCodeInput} from "../common/SendCodeInput";
import RegionSelect from "../common/select/RegionSelect";
import CustomGithubCorner from "../common/CustomGithubCorner";
import LanguageSelect from "../common/select/LanguageSelect";
import {withRouter} from "react-router-dom";
import {CountryCodeSelect} from "../common/select/CountryCodeSelect";
import * as PasswordChecker from "../common/PasswordChecker";

const formItemLayout = {
  labelCol: {
    xs: {
      span: 24,
    },
    sm: {
      span: 8,
    },
  },
  wrapperCol: {
    xs: {
      span: 24,
    },
    sm: {
      span: 16,
    },
  },
};

export const tailFormItemLayout = {
  wrapperCol: {
    xs: {
      span: 24,
      offset: 0,
    },
    sm: {
      span: 16,
      offset: 8,
    },
  },
};

class SignupPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      applicationName: (props.applicationName ?? props.match?.params?.applicationName) ?? null,
      email: new URLSearchParams(this.props.location?.search).get("e") ?? "",
      phone: "",
      countryCode: "",
      emailCode: "",
      phoneCode: "",
      validEmail: false,
      validPhone: false,
      region: "",
      isTermsOfUseVisible: false,
      termsOfUseContent: "",
    };

    this.form = React.createRef();
  }

  componentDidMount() {
    const oAuthParams = Util.getOAuthGetParameters();
    if (oAuthParams !== null) {
      const signinUrl = window.location.href.replace("/signup/oauth/authorize", "/login/oauth/authorize");
      sessionStorage.setItem("signinUrl", signinUrl);
    }

    if (this.getApplicationObj() === undefined) {
      if (this.state.applicationName !== null) {
        this.getApplication(this.state.applicationName);
      } else if (oAuthParams !== null) {
        this.getApplicationLogin(oAuthParams);
      } else {
        Setting.showMessage("error", `Unknown application name: ${this.state.applicationName}`);
        this.onUpdateApplication(null);
      }
    }

    this.setState(
      {validEmail: Setting.isValidEmail(this.state.email)}
    );
  }

  getApplication(applicationName) {
    if (applicationName === undefined) {
      return;
    }

    ApplicationBackend.getApplication("admin", applicationName)
      .then((res) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          return;
        }

        this.onUpdateApplication(res.data);
      });
  }

  getApplicationLogin(oAuthParams) {
    AuthBackend.getApplicationLogin(oAuthParams)
      .then((res) => {
        if (res.status === "ok") {
          const application = res.data;
          this.onUpdateApplication(application);
        } else {
          this.onUpdateApplication(null);
          this.setState({
            msg: res.msg,
          });
        }
      });
  }

  getResultPath(application, signupParams) {
    if (signupParams?.plan && signupParams?.pricing) {
      // the prompt page needs the user to be signed in, so for paid-user sign up, just go to buy-plan page
      return `/buy-plan/${application.organization}/${signupParams?.pricing}?user=${signupParams.username}&plan=${signupParams.plan}`;
    }
    if (authConfig.appName === application.name) {
      return "/result";
    } else {
      if (Setting.hasPromptPage(application)) {
        return `/prompt/${application.name}`;
      } else {
        return `/result/${application.name}`;
      }
    }
  }

  getApplicationObj() {
    return this.props.application;
  }

  onUpdateAccount(account) {
    this.props.onUpdateAccount(account);
  }

  onUpdateApplication(application) {
    this.props.onUpdateApplication(application);
  }

  parseOffset(offset) {
    if (offset === 2 || offset === 4 || Setting.inIframe() || Setting.isMobile()) {
      return "0 auto";
    }
    if (offset === 1) {
      return "0 10%";
    }
    if (offset === 3) {
      return "0 60%";
    }
  }

  onFinish(values) {
    const application = this.getApplicationObj();

    const params = new URLSearchParams(window.location.search);
    values.plan = params.get("plan");
    values.pricing = params.get("pricing");
    values.id = params.get("id");
    AuthBackend.signup(values)
      .then((res) => {
        if (res.status === "ok") {
          // the user's id will be returned by `signup()`, if user signup by phone, the `username` in `values` is undefined.
          values.username = res.data.split("/")[1];
          if (Setting.hasPromptPage(application) && (!values.plan || !values.pricing)) {
            AuthBackend.getAccount("")
              .then((res) => {
                let account = null;
                if (res.status === "ok") {
                  account = res.data;
                  account.organization = res.data2;

                  this.onUpdateAccount(account);
                  Setting.goToLinkSoft(this, this.getResultPath(application, values));
                } else {
                  Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
                }
              });
          } else {
            Setting.goToLinkSoft(this, this.getResultPath(application, values));
          }
        } else {
          Setting.showMessage("error", i18next.t(`signup:${res.msg}`));
        }
      });
  }

  onFinishFailed(values, errorFields, outOfDate) {
    this.form.current.scrollToField(errorFields[0].name);
  }

  isProviderVisible(providerItem) {
    return Setting.isProviderVisibleForSignUp(providerItem);
  }

  renderFormItem(application, signupItem) {
    if (!signupItem.visible) {
      return null;
    }

    const required = signupItem.required;

    if (signupItem.name === "Username") {
      return (
        <Form.Item
          name="username"
          label={i18next.t("signup:Username")}
          rules={[
            {
              required: required,
              message: i18next.t("forget:Please input your username!"),
              whitespace: true,
            },
          ]}
        >
          <Input disabled={new URLSearchParams(this.props.location?.search).get("u") !== null} />
        </Form.Item>
      );
    } else if (signupItem.name === "Display name") {
      if (signupItem.rule === "First, last" && Setting.getLanguage() !== "zh") {
        return (
          <React.Fragment>
            <Form.Item
              name="firstName"
              label={i18next.t("general:First name")}
              rules={[
                {
                  required: required,
                  message: i18next.t("signup:Please input your first name!"),
                  whitespace: true,
                },
              ]}
            >
              <Input />
            </Form.Item>
            <Form.Item
              name="lastName"
              label={i18next.t("general:Last name")}
              rules={[
                {
                  required: required,
                  message: i18next.t("signup:Please input your last name!"),
                  whitespace: true,
                },
              ]}
            >
              <Input />
            </Form.Item>
          </React.Fragment>
        );
      }

      return (
        <Form.Item
          name="name"
          label={(signupItem.rule === "Real name" || signupItem.rule === "First, last") ? i18next.t("general:Real name") : i18next.t("general:Display name")}
          rules={[
            {
              required: required,
              message: (signupItem.rule === "Real name" || signupItem.rule === "First, last") ? i18next.t("signup:Please input your real name!") : i18next.t("signup:Please input your display name!"),
              whitespace: true,
            },
          ]}
        >
          <Input />
        </Form.Item>
      );
    } else if (signupItem.name === "Affiliation") {
      return (
        <Form.Item
          name="affiliation"
          label={i18next.t("user:Affiliation")}
          rules={[
            {
              required: required,
              message: i18next.t("signup:Please input your affiliation!"),
              whitespace: true,
            },
          ]}
        >
          <Input />
        </Form.Item>
      );
    } else if (signupItem.name === "ID card") {
      return (
        <Form.Item
          name="idCard"
          label={i18next.t("user:ID card")}
          rules={[
            {
              required: required,
              message: i18next.t("signup:Please input your ID card number!"),
              whitespace: true,
            },
            {
              required: required,
              pattern: new RegExp(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9X]$/, "g"),
              message: i18next.t("signup:Please input the correct ID card number!"),
            },
          ]}
        >
          <Input />
        </Form.Item>
      );
    } else if (signupItem.name === "Country/Region") {
      return (
        <Form.Item
          name="country_region"
          label={i18next.t("user:Country/Region")}
          rules={[
            {
              required: required,
              message: i18next.t("signup:Please select your country/region!"),
            },
          ]}
        >
          <RegionSelect onChange={(value) => {this.setState({region: value});}} />
        </Form.Item>
      );
    } else if (signupItem.name === "Email") {
      return (
        <React.Fragment>
          <Form.Item
            name="email"
            label={i18next.t("general:Email")}
            rules={[
              {
                required: required,
                message: i18next.t("signup:Please input your Email!"),
              },
              {
                validator: (_, value) => {
                  if (this.state.email !== "" && !Setting.isValidEmail(this.state.email)) {
                    this.setState({validEmail: false});
                    return Promise.reject(i18next.t("signup:The input is not valid Email!"));
                  }

                  this.setState({validEmail: true});
                  return Promise.resolve();
                },
              },
            ]}
          >
            <Input disabled={new URLSearchParams(this.props.location?.search).get("e") !== null} onChange={e => this.setState({email: e.target.value})} />
          </Form.Item>
          {
            signupItem.rule !== "No verification" &&
            <Form.Item
              name="emailCode"
              label={i18next.t("code:Email code")}
              rules={[{
                required: required,
                message: i18next.t("code:Please input your verification code!"),
              }]}
            >
              <SendCodeInput
                disabled={!this.state.validEmail}
                method={"signup"}
                onButtonClickArgs={[this.state.email, "email", Setting.getApplicationName(application)]}
                application={application}
              />
            </Form.Item>
          }
        </React.Fragment>
      );
    } else if (signupItem.name === "Phone") {
      return (
        <React.Fragment>
          <Form.Item label={i18next.t("general:Phone")} required={required}>
            <Input.Group compact>
              <Form.Item
                name="countryCode"
                noStyle
                rules={[
                  {
                    required: required,
                    message: i18next.t("signup:Please select your country code!"),
                  },
                ]}
              >
                <CountryCodeSelect
                  style={{width: "35%"}}
                  countryCodes={this.getApplicationObj().organizationObj.countryCodes}
                />
              </Form.Item>
              <Form.Item
                name="phone"
                dependencies={["countryCode"]}
                noStyle
                rules={[
                  {
                    required: required,
                    message: i18next.t("signup:Please input your phone number!"),
                  },
                  ({getFieldValue}) => ({
                    validator: (_, value) => {
                      if (!required && !value) {
                        return Promise.resolve();
                      }

                      if (value && !Setting.isValidPhone(value, getFieldValue("countryCode"))) {
                        this.setState({validPhone: false});
                        return Promise.reject(i18next.t("signup:The input is not valid Phone!"));
                      }

                      this.setState({validPhone: true});
                      return Promise.resolve();
                    },
                  }),
                ]}
              >
                <Input
                  style={{width: "65%"}}
                  onChange={e => this.setState({phone: e.target.value})}
                />
              </Form.Item>
            </Input.Group>
          </Form.Item>
          {
            signupItem.rule !== "No verification" &&
            <Form.Item
              name="phoneCode"
              label={i18next.t("code:Phone code")}
              rules={[
                {
                  required: required,
                  message: i18next.t("code:Please input your phone verification code!"),
                },
              ]}
            >
              <SendCodeInput
                disabled={!this.state.validPhone}
                method={"signup"}
                onButtonClickArgs={[this.state.phone, "phone", Setting.getApplicationName(application)]}
                application={application}
                countryCode={this.form.current?.getFieldValue("countryCode")}
              />
            </Form.Item>
          }
        </React.Fragment>
      );
    } else if (signupItem.name === "Password") {
      return (
        <Form.Item
          name="password"
          label={i18next.t("general:Password")}
          rules={[
            {
              required: required,
              validateTrigger: "onChange",
              validator: (rule, value) => {
                const errorMsg = PasswordChecker.checkPasswordComplexity(value, application.organizationObj.passwordOptions);
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
          <Input.Password />
        </Form.Item>
      );
    } else if (signupItem.name === "Confirm password") {
      return (
        <Form.Item
          name="confirm"
          label={i18next.t("signup:Confirm")}
          dependencies={["password"]}
          hasFeedback
          rules={[
            {
              required: required,
              message: i18next.t("signup:Please confirm your password!"),
            },
            ({getFieldValue}) => ({
              validator(rule, value) {
                if (!value || getFieldValue("password") === value) {
                  return Promise.resolve();
                }

                return Promise.reject(i18next.t("signup:Your confirmed password is inconsistent with the password!"));
              },
            }),
          ]}
        >
          <Input.Password />
        </Form.Item>
      );
    } else if (signupItem.name === "Invitation code") {
      return (
        <Form.Item
          name="invitationCode"
          label={i18next.t("application:Invitation code")}
          rules={[
            {
              required: required,
              message: i18next.t("signup:Please input your invitation code!"),
            },
          ]}
        >
          <Input />
        </Form.Item>
      );
    } else if (signupItem.name === "Agreement") {
      return AgreementModal.renderAgreementFormItem(application, required, tailFormItemLayout, this);
    }
  }

  renderForm(application) {
    if (!application.enableSignUp) {
      return (
        <Result
          status="error"
          title={i18next.t("application:Sign Up Error")}
          subTitle={i18next.t("application:The application does not allow to sign up new account")}
          extra={[
            <Button type="primary" key="signin" onClick={() => Setting.redirectToLoginPage(application, this.props.history)}>
              {
                i18next.t("login:Sign In")
              }
            </Button>,
          ]}
        >
        </Result>
      );
    }
    return (
      <Form
        {...formItemLayout}
        ref={this.form}
        name="signup"
        onFinish={(values) => this.onFinish(values)}
        onFinishFailed={(errorInfo) => this.onFinishFailed(errorInfo.values, errorInfo.errorFields, errorInfo.outOfDate)}
        initialValues={{
          application: application.name,
          organization: application.organization,
          countryCode: application.organizationObj.countryCodes?.[0],
          username: new URLSearchParams(this.props.location?.search).get("u") ?? "",
          email: new URLSearchParams(this.props.location?.search).get("e") ?? "",
        }}
        size="large"
        layout={Setting.isMobile() ? "vertical" : "horizontal"}
        style={{width: Setting.isMobile() ? "300px" : "400px"}}
      >
        <Form.Item
          name="application"
          hidden={true}
          rules={[
            {
              required: true,
              message: "Please input your application!",
            },
          ]}
        >
        </Form.Item>
        <Form.Item
          name="organization"
          hidden={true}
          rules={[
            {
              required: true,
              message: "Please input your organization!",
            },
          ]}
        >
        </Form.Item>
        {
          application.signupItems?.map(signupItem => this.renderFormItem(application, signupItem))
        }
        <Form.Item {...tailFormItemLayout}>
          <Button type="primary" htmlType="submit">
            {i18next.t("account:Sign Up")}
          </Button>
            &nbsp;&nbsp;{i18next.t("signup:Have account?")}&nbsp;
          <a onClick={() => {
            const linkInStorage = sessionStorage.getItem("signinUrl");
            if (linkInStorage !== null && linkInStorage !== "") {
              Setting.goToLink(linkInStorage);
            } else {
              Setting.redirectToLoginPage(application, this.props.history);
            }
          }}>
            {i18next.t("signup:sign in now")}
          </a>
        </Form.Item>
        {
          application.providers.filter(providerItem => this.isProviderVisible(providerItem)).map(providerItem => {
            return ProviderButton.renderProviderLogo(providerItem.provider, application, 30, 5, "small", this.props.location);
          })
        }
      </Form>
    );
  }

  render() {
    const application = this.getApplicationObj();
    if (application === undefined || application === null) {
      return null;
    }

    if (application.signupHtml !== "") {
      return (
        <div dangerouslySetInnerHTML={{__html: application.signupHtml}} />
      );
    }

    return (
      <React.Fragment>
        <CustomGithubCorner />
        <div className="login-content" style={{margin: this.props.preview ?? this.parseOffset(application.formOffset)}}>
          {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
          {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
          <div className="login-panel" >
            <div className="side-image" style={{display: application.formOffset !== 4 ? "none" : null}}>
              <div dangerouslySetInnerHTML={{__html: application.formSideHtml}} />
            </div>
            <div className="login-form">
              {
                Setting.renderHelmet(application)
              }
              {
                Setting.renderLogo(application)
              }
              <LanguageSelect languages={application.organizationObj.languages} style={{top: "55px", right: "5px", position: "absolute"}} />
              {
                this.renderForm(application)
              }
            </div>
          </div>
        </div>
      </React.Fragment>
    );
  }
}

export default withRouter(SignupPage);
