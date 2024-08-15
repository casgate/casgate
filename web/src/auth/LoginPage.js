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
import {Button, Checkbox, Col, Form, Input, Result, Row, Spin, Tabs} from "antd";
import {ArrowLeftOutlined} from "@ant-design/icons";
import {withRouter} from "react-router-dom";
import * as UserWebauthnBackend from "../backend/UserWebauthnBackend";
import OrganizationSelect from "../common/select/OrganizationSelect";
import * as Conf from "../Conf";
import * as AuthBackend from "./AuthBackend";
import * as OrganizationBackend from "../backend/OrganizationBackend";
import * as ApplicationBackend from "../backend/ApplicationBackend";
import * as Provider from "./Provider";
import * as ProviderButton from "./ProviderButton";
import * as Util from "./Util";
import * as Setting from "../Setting";
import * as AgreementModal from "../common/modal/AgreementModal";
import SelfLoginButton from "./SelfLoginButton";
import i18next from "i18next";
import CustomGithubCorner from "../common/CustomGithubCorner";
import {SendCodeInput} from "../common/SendCodeInput";
import {CaptchaModal, CaptchaRule} from "../common/modal/CaptchaModal";
import RedirectForm from "../common/RedirectForm";
import {MfaAuthVerifyForm, NextMfa, RequiredMfa} from "./mfa/MfaAuthVerifyForm";
import {ChangePasswordForm, NextChangePasswordForm} from "./ChangePasswordForm";

import {GoogleOneTapLoginVirtualButton} from "./GoogleLoginButton";
import LdapSelect from "../common/select/LdapSelect";
class LoginPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      type: props.type,
      applicationName: props.applicationName ?? (props.match?.params?.applicationName ?? null),
      owner: props.owner ?? (props.match?.params?.owner ?? null),
      mode: props.mode ?? (props.match?.params?.mode ?? null), // "signup" or "signin"
      msg: null,
      username: null,
      validEmailOrPhone: false,
      validEmail: false,
      enableCaptchaModal: CaptchaRule.Never,
      openCaptchaModal: false,
      verifyCaptcha: undefined,
      samlResponse: "",
      relayState: "",
      redirectUrl: "",
      isTermsOfUseVisible: false,
      termsOfUseContent: "",
      orgChoiceMode: new URLSearchParams(props.location?.search).get("orgChoiceMode") ?? null,
      ldapId: "",
    };
    this.ldapSelectIdSetter = this.ldapSelectIdSetter.bind(this);

    if (this.state.type === "cas" && props.match?.params.casApplicationName !== undefined) {
      this.state.owner = props.match?.params?.owner;
      this.state.applicationName = props.match?.params?.casApplicationName;
    }

    this.form = React.createRef();
  }

  componentDidMount() {
    if (this.getApplicationObj() === undefined) {
      if (this.state.type === "login" || this.state.type === "saml") {
        this.getApplication();
      } else if (this.state.type === "code" || this.state.type === "cas") {
        this.getApplicationLogin();
      } else {
        Setting.showMessage("error", `Unknown authentication type: ${this.state.type}`);
      }
    }
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (prevState.loginMethod === undefined && this.state.loginMethod === undefined) {
      const application = this.getApplicationObj();
      this.setState({loginMethod: this.getDefaultLoginMethod(application)});
    }
    if (prevProps.application !== this.props.application) {
      this.setState({loginMethod: this.getDefaultLoginMethod(this.props.application)});

      const captchaProviderItems = this.getCaptchaProviderItems(this.props.application);
      if (captchaProviderItems) {
        if (captchaProviderItems.some(providerItem => providerItem.rule === "Always")) {
          this.setState({enableCaptchaModal: CaptchaRule.Always});
        } else if (captchaProviderItems.some(providerItem => providerItem.rule === "Dynamic")) {
          this.setState({enableCaptchaModal: CaptchaRule.Dynamic});
        } else {
          this.setState({enableCaptchaModal: CaptchaRule.Never});
        }
      }

      if (this.props.account && this.props.account.owner === this.props.application?.organization) {
        const params = new URLSearchParams(this.props.location.search);
        const silentSignin = params.get("silentSignin");
        if (silentSignin !== null) {
          this.sendSilentSigninData("signing-in");

          const values = {};
          values["application"] = this.props.application.name;
          this.login(values);
        }

        if (params.get("popup") === "1") {
          window.addEventListener("beforeunload", () => {
            this.sendPopupData({type: "windowClosed"}, params.get("redirect_uri"));
          });
        }

        if (this.props.application.enableAutoSignin) {
          const values = {};
          values["application"] = this.props.application.name;
          this.login(values);
        }
      }
    }
  }

  checkCaptchaStatus(values) {
    AuthBackend.getCaptchaStatus(values)
      .then((res) => {
        if (res.status === "ok") {
          if (res.data) {
            this.setState({
              openCaptchaModal: true,
              values: values,
            });
            return null;
          }
        }
        this.login(values);
      });
  }

  getApplicationLogin() {
    const loginParams = (this.state.type === "cas") ? Util.getCasLoginParameters("admin", this.state.applicationName) : Util.getOAuthGetParameters();
    AuthBackend.getApplicationLogin(loginParams)
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

  getApplication() {
    if (this.state.applicationName === null) {
      return null;
    }

    if (this.state.owner === null || this.state.type === "saml") {
      ApplicationBackend.getApplication("admin", this.state.applicationName)
        .then((res) => {
          if (res.status === "error") {
            this.onUpdateApplication(null);
            this.setState({
              msg: res.msg,
            });
            return ;
          }
          this.onUpdateApplication(res.data);
        });
    } else {
      OrganizationBackend.getDefaultApplication("admin", this.state.owner)
        .then((res) => {
          if (res.status === "ok") {
            const application = res.data;
            this.onUpdateApplication(application);
            this.setState({
              applicationName: res.data.name,
            });
          } else {
            this.onUpdateApplication(null);
            Setting.showMessage("error", res.msg);

            this.props.history.push("/404");
          }
        });
    }
  }

  getApplicationObj() {
    return this.props.application;
  }

  getPlaceholder() {
    switch (this.state.loginMethod) {
    case "verificationCode": return i18next.t("login:Email or phone");
    case "verificationCodeEmail": return i18next.t("login:Email");
    case "verificationCodePhone": return i18next.t("login:Phone");
    case "ldap": return i18next.t("login:LDAP username, Email or phone");
    default: return i18next.t("login:username, Email or phone");
    }
  }

  getDefaultLoginMethod(application) {
    if (application?.signinMethods.length > 0) {
      switch (application?.signinMethods[0].name) {
      case "Password": return "password";
      case "Verification code": {
        switch (application?.signinMethods[0].rule) {
        case "All": return "verificationCode"; // All
        case "Email only": return "verificationCodeEmail";
        case "Phone only": return "verificationCodePhone";
        }
        break;
      }
      case "WebAuthn": return "webAuthn";
      case "LDAP": return "ldap";
      }
    }

    return "password";
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

  populateOauthValues(values) {
    if (this.getApplicationObj()?.organization) {
      values["organization"] = this.getApplicationObj().organization;
    }

    if (this.state.loginMethod === "password") {
      values["signinMethod"] = "Password";
    } else if (this.state.loginMethod?.includes("verificationCode")) {
      values["signinMethod"] = "Verification code";
    } else if (this.state.loginMethod === "webAuthn") {
      values["signinMethod"] = "WebAuthn";
    } else if (this.state.loginMethod === "ldap") {
      values["signinMethod"] = "LDAP";
    }

    const oAuthParams = Util.getOAuthGetParameters();

    values["type"] = oAuthParams?.responseType ?? this.state.type;

    if (oAuthParams?.samlRequest) {
      values["samlRequest"] = oAuthParams.samlRequest;
      values["type"] = "saml";
      values["relayState"] = oAuthParams.relayState;
    }
  }

  sendPopupData(message, redirectUri) {
    const params = new URLSearchParams(this.props.location.search);
    if (params.get("popup") === "1") {
      window.opener.postMessage(message, redirectUri);
    }
  }

  postCodeLoginAction(resp) {
    const application = this.getApplicationObj();
    const ths = this;
    const oAuthParams = Util.getOAuthGetParameters();
    const code = resp.data;
    const concatChar = oAuthParams?.redirectUri?.includes("?") ? "&" : "?";
    const noRedirect = oAuthParams.noRedirect;
    const redirectUrl = `${oAuthParams.redirectUri}${concatChar}code=${code}&state=${oAuthParams.state}`;
    if (resp.data === RequiredMfa) {
      this.props.onLoginSuccess(window.location.href);
      return;
    }

    if (Setting.hasPromptPage(application)) {
      AuthBackend.getAccount()
        .then((res) => {
          if (res.status === "ok") {
            const account = res.data;
            account.organization = res.data2;
            this.onUpdateAccount(account);

            if (Setting.isPromptAnswered(account, application)) {
              Setting.goToLink(redirectUrl);
            } else {
              Setting.goToLinkSoft(ths, `/prompt/${application.name}?redirectUri=${oAuthParams.redirectUri}&code=${code}&state=${oAuthParams.state}`);
            }
          } else {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          }
        });
    } else {
      if (noRedirect === "true") {
        window.close();
        const newWindow = window.open(redirectUrl);
        if (newWindow) {
          setInterval(() => {
            if (!newWindow.closed) {
              newWindow.close();
            }
          }, 1000);
        }
      } else {
        Setting.goToLink(redirectUrl);
        this.sendPopupData({type: "loginSuccess", data: {code: code, state: oAuthParams.state}}, oAuthParams.redirectUri);
      }
    }
  }

  onFinish(values) {
    if (this.state.loginMethod === "webAuthn") {
      let username = this.state.username;
      if (username === null || username === "") {
        username = values["username"];
      }

      this.signInWithWebAuthn(username, values);
      return;
    }
    if (this.state.loginMethod === "password") {
      if (this.state.enableCaptchaModal === CaptchaRule.Always) {
        this.setState({
          openCaptchaModal: true,
          values: values,
        });
        return;
      } else if (this.state.enableCaptchaModal === CaptchaRule.Dynamic) {
        this.checkCaptchaStatus(values);
        return;
      }
    }
    this.login(values);
  }

  login(values) {
    // here we are supposed to determine whether Casdoor is working as an OAuth server or CAS server
    if (this.state.type === "cas") {
      // CAS
      const casParams = Util.getCasParameters();
      values["type"] = this.state.type;
      AuthBackend.loginCas(values, casParams).then((res) => {
        if (res.status === "ok") {
          let msg = "Logged in successfully. ";
          if (casParams.service === "") {
            // If service was not specified, Casdoor must display a message notifying the client that it has successfully initiated a single sign-on session.
            msg += "Now you can visit apps protected by Casdoor.";
          }
          Setting.showMessage("success", msg);

          if (casParams.service !== "") {
            const st = res.data;
            const newUrl = new URL(casParams.service);
            newUrl.searchParams.append("ticket", st);
            window.location.href = newUrl.toString();
          }
        } else {
          Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
        }
      });
    } else {
      // OAuth
      const oAuthParams = Util.getOAuthGetParameters();
      this.populateOauthValues(values);
      values["ldapId"] = this.state.ldapId;
      AuthBackend.login(values, oAuthParams)
        .then((res) => {
          const callback = (res) => {
            const responseType = values["type"];

            if (responseType === "login") {
              Setting.showMessage("success", i18next.t("application:Logged in successfully"));
              this.props.onLoginSuccess();
            } else if (responseType === "code") {
              this.postCodeLoginAction(res);
            } else if (responseType === "token" || responseType === "id_token") {
              const amendatoryResponseType = responseType === "token" ? "access_token" : responseType;
              const accessToken = res.data;
              Setting.goToLink(`${oAuthParams.redirectUri}#${amendatoryResponseType}=${accessToken}&state=${oAuthParams.state}&token_type=bearer`);
            } else if (responseType === "saml") {
              if (res.data2.method === "POST") {
                this.setState({
                  samlResponse: res.data,
                  redirectUrl: res.data2.redirectUrl,
                  relayState: oAuthParams.relayState,
                });
              } else {
                const SAMLResponse = res.data;
                const redirectUri = res.data2.redirectUrl;
                Setting.goToLink(`${redirectUri}?SAMLResponse=${encodeURIComponent(SAMLResponse)}&RelayState=${oAuthParams.relayState}`);
              }
            }
          };

          const changePasswordForm = () => {
            return (
              <ChangePasswordForm
                application={this.getApplicationObj()}
                userOwner={values.organization}
                userName={this.state.username}
                onSuccess={(newValues) => {
                  values.password = newValues.newPassword;
                  AuthBackend.login(values, oAuthParams).then((res) => {
                    if (res.status === "ok") {
                      return callback(res);
                    } else {
                      Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
                    }
                  });
                }}
                onFail={(res) => {
                  Setting.showMessage("error", i18next.t(`signup:${res.msg}`));
                }}
              />
            );
          };

          if (res.status === "ok") {
            if (res.data === NextMfa) {
              this.setState({
                getVerifyTotp: () => {
                  return (
                    <MfaAuthVerifyForm
                      mfaProps={res.data2}
                      formValues={values}
                      oAuthParams={oAuthParams}
                      application={this.getApplicationObj()}
                      onFail={() => {
                        Setting.showMessage("error", i18next.t("mfa:Verification failed"));
                      }}
                      onSuccess={(res) => {
                        if (res.data === NextChangePasswordForm) {
                          this.setState({
                            getVerifyTotp: undefined,
                            getChangePasswordForm: changePasswordForm,
                          });
                        } else {
                          return callback(res);
                        }
                      }}
                    />);
                },
              });
            } else if (res.data === NextChangePasswordForm) {
              this.setState({
                values: values,
                getChangePasswordForm: changePasswordForm,
              });
            } else {
              callback(res);
            }
          } else {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          }
        });
    }
  }

  isProviderVisible(providerItem) {
    if (this.state.mode === "signup") {
      return Setting.isProviderVisibleForSignUp(providerItem);
    } else {
      return Setting.isProviderVisibleForSignIn(providerItem);
    }
  }

  renderOtherFormProvider(application) {
    for (const providerConf of application.providers) {
      if (providerConf.provider?.type === "Google" && providerConf.rule === "OneTap" && this.props.preview !== "auto") {
        return (
          <GoogleOneTapLoginVirtualButton application={application} providerConf={providerConf} />
        );
      }
    }
  }

  renderAuthProviders(application) {
    const authProviders = application.providers.filter(providerItem => this.isProviderVisible(providerItem));
    if (authProviders.length) {
      return <React.Fragment>
        {
          authProviders.map(providerItem => {
            return ProviderButton.renderProviderLogo(providerItem.provider, application, 30, 5, "small", this.props.location);
          })
        }
        {
          this.renderOtherFormProvider(application)
        }
      </React.Fragment>;
    }
  }

  renderForm(application) {
    if (this.state.msg !== null) {
      return Util.renderMessage(this.state.msg);
    }

    if (this.state.mode === "signup" && !application.enableInternalSignUp && !application.enableIdpSignUp) {
      return (
        <Result
          status="error"
          title={i18next.t("application:Sign Up Error")}
          subTitle={i18next.t("application:The application does not allow to sign up new account")}
          extra={[
            <Button type="primary" key="signin"
              onClick={() => Setting.redirectToLoginPage(application, this.props.history)}>
              {
                i18next.t("login:Sign In")
              }
            </Button>,
          ]}
        >
        </Result>
      );
    }

    const showForm = Setting.isPasswordEnabled(application) || Setting.isCodeSigninEnabled(application) || Setting.isWebAuthnEnabled(application) || Setting.isLdapEnabled(application);
    if (showForm) {
      return (
        <React.Fragment>
          <h1>{i18next.t("application:Login")}</h1>
          <Form
            name="normal_login"
            initialValues={{
              organization: application.organization,
              application: application.name,
              autoSignin: true,
              username: Conf.ShowGithubCorner ? "admin" : new URLSearchParams(this.props.location?.search).get("u") ?? "",
              password: Conf.ShowGithubCorner ? "123" : "",
            }}
            onFinish={(values) => {
              this.onFinish(values);
            }}
            size="large"
            ref={this.form}
          >
            <Form.Item
              hidden={true}
              name="application"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your application!"),
                },
              ]}
            >
            </Form.Item>
            <Form.Item
              hidden={true}
              name="organization"
              rules={[
                {
                  required: true,
                  message: i18next.t("application:Please input your organization!"),
                },
              ]}
            >
            </Form.Item>
            {this.renderMethodChoiceBox()}
            {this.renderLdapServerChoiceBox(this.getApplicationObj()?.organization)}
            <Row style={{minHeight: 130, alignItems: "center"}}>
              <Col span={24}>
                <Form.Item
                  name="username"
                  rules={[
                    {
                      required: true,
                      message: () => {
                        switch (this.state.loginMethod) {
                        case "verificationCodeEmail": return i18next.t("login:Please input your Email!");
                        case "verificationCodePhone": return i18next.t("login:Please input your Phone!");
                        case "ldap": return i18next.t("login:Please input your LDAP username!");
                        default: return i18next.t("login:Please input your Email or Phone!");
                        }
                      },
                    },
                    {
                      validator: (_, value) => {
                        if (this.state.loginMethod === "verificationCode") {
                          if (!Setting.isValidEmail(value) && !Setting.isValidPhone(value)) {
                            this.setState({validEmailOrPhone: false});
                            return Promise.reject(i18next.t("login:The input is not valid Email or phone number!"));
                          }

                          if (Setting.isValidEmail(value)) {
                            this.setState({validEmail: true});
                          } else {
                            this.setState({validEmail: false});
                          }
                        }

                        this.setState({validEmailOrPhone: true});
                        return Promise.resolve();
                      },
                    },
                  ]}
                >
                  <Input
                    id="input"
                    disabled={new URLSearchParams(this.props.location?.search).get("u") !== null}
                    placeholder={this.getPlaceholder()}
                    onChange={e => {
                      this.setState({
                        username: e.target.value,
                      });
                    }}
                  />
                </Form.Item>
              </Col>
              {
                this.renderPasswordOrCodeInput()
              }
            </Row>
            <Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                style={{width: "100%"}}
              >
                {
                  this.state.loginMethod === "webAuthn" ? i18next.t("login:Sign in with WebAuthn") :
                    i18next.t("login:Sign In")
                }
              </Button>
              {
                this.renderCaptchaModal(application)
              }
              {
                this.renderFooter(application)
              }
            </Form.Item>
            <div style={{
              display: "inline-flex",
              justifyContent: "space-between",
              width: "320px",
              marginBottom: AgreementModal.isAgreementRequired(application) && "5px",
            }}>
              <Form.Item name="autoSignin" valuePropName="checked" noStyle>
                <Checkbox>
                  {i18next.t("login:Auto sign in")}
                </Checkbox>
              </Form.Item>
            </div>
            {AgreementModal.isAgreementRequired(application) ? AgreementModal.renderAgreementFormItem(application, true, {}, this) : null}
            {this.props.application?.enablePasswordRecovery && <div style={{paddingTop: "24px"}}>
              {
                Setting.renderForgetLink(application, i18next.t("login:Forgot password?"))
              }
            </div>}
            <div style={{display: "flex", justifyContent: "center", marginBottom: "unset", marginTop: 24}}>
              {
                this.renderAuthProviders(application)
              }
            </div>
          </Form>
        </React.Fragment>
      );
    } else {
      return (
        <div style={{marginTop: "20px"}}>
          <div style={{fontSize: 16, textAlign: "left"}}>
            {i18next.t("login:To access")}&nbsp;
            <a target="_blank" rel="noreferrer" href={application.homepageUrl}>
              <span style={{fontWeight: "bold"}}>
                {application.displayName}
              </span>
            </a>
            :
          </div>
          <br />
          {
            application.providers?.filter(providerItem => this.isProviderVisible(providerItem)).map(providerItem => {
              return ProviderButton.renderProviderLogo(providerItem.provider, application, 40, 10, "big", this.props.location);
            })
          }
          {
            this.renderOtherFormProvider(application)
          }
          <div>
            <br />
            {
              this.renderFooter(application)
            }
          </div>
        </div>
      );
    }
  }

  getCaptchaProviderItems(application) {
    const providers = application?.providers;

    if (providers === undefined || providers === null) {
      return null;
    }

    return providers.filter(providerItem => {
      if (providerItem.provider === undefined || providerItem.provider === null) {
        return false;
      }

      return providerItem.provider.category === "Captcha";
    });
  }

  renderCaptchaModal(application) {
    if (this.state.enableCaptchaModal === CaptchaRule.Never) {
      return null;
    }
    const captchaProviderItems = this.getCaptchaProviderItems(application);
    const alwaysProviderItems = captchaProviderItems.filter(providerItem => providerItem.rule === "Always");
    const dynamicProviderItems = captchaProviderItems.filter(providerItem => providerItem.rule === "Dynamic");
    const provider = alwaysProviderItems.length > 0
      ? alwaysProviderItems[0].provider
      : dynamicProviderItems[0].provider;

    return <CaptchaModal
      owner={provider.owner}
      name={provider.name}
      visible={this.state.openCaptchaModal}
      onOk={(captchaType, captchaToken, clientSecret) => {
        const values = this.state.values;
        values["captchaType"] = captchaType;
        values["captchaToken"] = captchaToken;
        values["clientSecret"] = clientSecret;

        this.login(values);
        this.setState({openCaptchaModal: false});
      }}
      onCancel={() => this.setState({openCaptchaModal: false})}
      isCurrentProvider={true}
    />;
  }

  renderFooter(application) {
    if (!application.enableInternalSignUp) {
      return;
    }

    return (
      <span style={{float: "right", marginTop: 16}}>
        {
          <React.Fragment>
            {i18next.t("login:No account?")}&nbsp;
            {
              Setting.renderSignupLink(application, i18next.t("login:sign up now"))
            }
          </React.Fragment>
        }
      </span>
    );
  }

  sendSilentSigninData(data) {
    if (Setting.inIframe()) {
      const message = {tag: "Casdoor", type: "SilentSignin", data: data};
      window.parent.postMessage(message, "*");
    }
  }

  renderSignedInBox() {
    if (this.props.account === undefined || this.props.account === null) {
      this.sendSilentSigninData("user-not-logged-in");
      return null;
    }

    const application = this.getApplicationObj();
    if (this.props.account.owner !== application?.organization) {
      return null;
    }

    return (
      <div>
        <div style={{fontSize: 16, textAlign: "left"}}>
          {i18next.t("login:Continue with")}&nbsp;:
        </div>
        <br />
        <SelfLoginButton account={this.props.account} onClick={() => {
          const values = {};
          values["application"] = application.name;
          this.login(values);
        }} />
        <br />
        <br />
        <div style={{fontSize: 16, textAlign: "left"}}>
          {i18next.t("login:Or sign in with another account")}&nbsp;:
        </div>
      </div>
    );
  }

  signInWithWebAuthn(username, values) {
    const oAuthParams = Util.getOAuthGetParameters();
    this.populateOauthValues(values);
    const application = this.getApplicationObj();
    return fetch(`${Setting.ServerUrl}/api/webauthn/signin/begin?owner=${application.organization}&name=${username}`, {
      method: "GET",
      credentials: "include",
    })
      .then(res => res.json())
      .then((credentialRequestOptions) => {
        if ("status" in credentialRequestOptions) {
          Setting.showMessage("error", credentialRequestOptions.msg);
          throw credentialRequestOptions.status.msg;
        }

        credentialRequestOptions.publicKey.challenge = UserWebauthnBackend.webAuthnBufferDecode(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials.forEach(function(listItem) {
          listItem.id = UserWebauthnBackend.webAuthnBufferDecode(listItem.id);
        });

        return navigator.credentials.get({
          publicKey: credentialRequestOptions.publicKey,
        });
      })
      .then((assertion) => {
        const authData = assertion.response.authenticatorData;
        const clientDataJSON = assertion.response.clientDataJSON;
        const rawId = assertion.rawId;
        const sig = assertion.response.signature;
        const userHandle = assertion.response.userHandle;
        return fetch(`${Setting.ServerUrl}/api/webauthn/signin/finish?responseType=${values["type"]}`, {
          method: "POST",
          credentials: "include",
          body: JSON.stringify({
            id: assertion.id,
            rawId: UserWebauthnBackend.webAuthnBufferEncode(rawId),
            type: assertion.type,
            response: {
              authenticatorData: UserWebauthnBackend.webAuthnBufferEncode(authData),
              clientDataJSON: UserWebauthnBackend.webAuthnBufferEncode(clientDataJSON),
              signature: UserWebauthnBackend.webAuthnBufferEncode(sig),
              userHandle: UserWebauthnBackend.webAuthnBufferEncode(userHandle),
            },
          }),
        })
          .then(res => res.json()).then((res) => {
            if (res.status === "ok") {
              const responseType = values["type"];
              if (responseType === "code") {
                this.postCodeLoginAction(res);
              } else if (responseType === "token" || responseType === "id_token") {
                const accessToken = res.data;
                Setting.goToLink(`${oAuthParams.redirectUri}#${responseType}=${accessToken}?state=${oAuthParams.state}&token_type=bearer`);
              } else {
                Setting.showMessage("success", i18next.t("login:Successfully logged in with WebAuthn credentials"));
                Setting.goToLink("/");
              }
            } else {
              Setting.showMessage("error", res.msg);
            }
          })
          .catch(error => {
            Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}${error}`);
          });
      });
  }

  renderPasswordOrCodeInput() {
    const application = this.getApplicationObj();
    if (this.state.loginMethod === "password" || this.state.loginMethod === "ldap") {
      const passwordVisibleIcon = <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M2.32118 13.9685C2.56899 14.0603 2.84472 13.9444 2.97219 13.7129C3.07372 13.5286 3.18284 13.3482 3.29396 13.17C3.66067 12.5817 4.2176 11.7983 4.97763 11.0167C6.49947 9.45174 8.79933 7.92748 12.0004 7.92748C15.2014 7.92748 17.5013 9.45174 19.0231 11.0167C19.7832 11.7983 20.3401 12.5817 20.7068 13.17C20.8177 13.3479 20.927 13.5286 21.0287 13.7133C21.156 13.9446 21.4316 14.0602 21.6791 13.9684C21.9532 13.8667 22.0836 13.5535 21.9425 13.2974C21.8332 13.099 21.716 12.9047 21.5968 12.7134C21.2047 12.0844 20.6082 11.2447 19.7899 10.4031C18.155 8.72194 15.5984 7 12.0004 7C8.40238 7 5.84578 8.72194 4.2109 10.4031C3.39258 11.2447 2.7961 12.0844 2.40398 12.7134C2.28438 12.9053 2.16694 13.0996 2.05745 13.2981C1.91627 13.5541 2.04706 13.867 2.32118 13.9685Z" fill="black" /><path fillRule="evenodd" clipRule="evenodd" d="M15 14C15 15.6569 13.6569 17 12 17C10.3431 17 9 15.6569 9 14C9 12.3431 10.3431 11 12 11C13.6569 11 15 12.3431 15 14ZM14 14C14 15.1046 13.1046 16 12 16C10.8954 16 10 15.1046 10 14C10 12.8954 10.8954 12 12 12C13.1046 12 14 12.8954 14 14Z" fill="black" /></svg>;
      const passwordHiddenIcon = <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 10C20 10 18 15 12 15C6 15 4 10 4 10" stroke="black" /><path d="M12 15V17" stroke="black" /><path d="M7 13.9995L6 15.9995" stroke="black" /><path d="M17 13.9995L18 15.9995" stroke="black" /></svg>;

      return (
        <Col span={24}>
          <Form.Item
            name="password"
            rules={[{required: true, message: i18next.t("login:Please input your password!")}]}
          >
            <Input.Password
              type="password"
              placeholder={i18next.t("general:Password")}
              disabled={this.state.loginMethod === "password" ?
                !Setting.isPasswordEnabled(application) :
                !Setting.isLdapEnabled(application)}
              iconRender={visible => visible ? passwordVisibleIcon : passwordHiddenIcon}
            />
          </Form.Item>
        </Col>
      );
    } else if (this.state.loginMethod === "verificationCode") {
      return (
        <Col span={24}>
          <Form.Item
            name="code"
            rules={[{required: true, message: i18next.t("login:Please input your code!")}]}
          >
            <SendCodeInput
              disabled={this.state.username?.length === 0 || !this.state.validEmailOrPhone}
              method={"login"}
              onButtonClickArgs={[this.state.username, this.state.validEmail ? "email" : "phone", Setting.getApplicationName(application)]}
              application={application}
            />
          </Form.Item>
        </Col>
      );
    } else {
      return null;
    }
  }

  renderMethodChoiceBox() {
    const application = this.getApplicationObj();
    const items = [];

    const generateItemKey = (name, rule) => {
      return `${name}-${rule}`;
    };

    const itemsMap = new Map([
      [generateItemKey("Password", "All"), {label: i18next.t("general:Password"), key: "password"}],
      [generateItemKey("Password", "Non-LDAP"), {label: i18next.t("general:Password"), key: "password"}],
      [generateItemKey("Verification code", "All"), {label: i18next.t("login:Verification code"), key: "verificationCode"}],
      [generateItemKey("Verification code", "Email only"), {label: i18next.t("login:Verification code"), key: "verificationCodeEmail"}],
      [generateItemKey("Verification code", "Phone only"), {label: i18next.t("login:Verification code"), key: "verificationCodePhone"}],
      [generateItemKey("WebAuthn", "None"), {label: i18next.t("login:WebAuthn"), key: "webAuthn"}],
      [generateItemKey("LDAP", "None"), {label: i18next.t("login:LDAP"), key: "ldap"}],
    ]);

    application?.signinMethods.forEach((signinMethod) => {
      const item = itemsMap.get(generateItemKey(signinMethod.name, signinMethod.rule));
      if (item) {
        const label = signinMethod.name === signinMethod.displayName ? item.label : signinMethod.displayName;
        items.push({label: label, key: item.key});
      }
    });

    if (items.length > 1) {
      return (
        <div>
          <Tabs items={items} size={"small"} defaultActiveKey={this.getDefaultLoginMethod(application)} onChange={(key) => {
            this.setState({loginMethod: key});
          }} centered>
          </Tabs>
        </div>
      );
    }
  }

  renderLoginPanel(application) {
    const orgChoiceMode = application.orgChoiceMode;

    if (this.isOrganizationChoiceBoxVisible(orgChoiceMode)) {
      return this.renderOrganizationChoiceBox(orgChoiceMode);
    }

    if (this.state.getVerifyTotp !== undefined) {
      return this.state.getVerifyTotp();
    } else if (this.state.getChangePasswordForm !== undefined) {
      return this.state.getChangePasswordForm();
    } else {
      return (
        <React.Fragment>
          {this.renderSignedInBox()}
          {this.renderForm(application)}
        </React.Fragment>
      );
    }
  }

  renderOrganizationChoiceBox(orgChoiceMode) {
    const renderChoiceBox = () => {
      switch (orgChoiceMode) {
      case "None":
        return null;
      case "Select":
        return (
          <div>
            <p style={{fontSize: "large"}}>
              {i18next.t("login:Please select an organization to sign in")}
            </p>
            <OrganizationSelect style={{width: "70%"}}
              onSelect={(value) => {
                Setting.goToLink(`/login/${value}?orgChoiceMode=None`);
              }} />
          </div>
        );
      case "Input":
        return (
          <div>
            <p style={{fontSize: "large"}}>
              {i18next.t("login:Please type an organization to sign in")}
            </p>
            <Form
              name="basic"
              onFinish={(values) => {Setting.goToLink(`/login/${values.organizationName}?orgChoiceMode=None`);}}
            >
              <Form.Item
                name="organizationName"
                rules={[{required: true, message: i18next.t("login:Please input your organization name!")}]}
              >
                <Input style={{width: "70%"}} onPressEnter={(e) => {
                  Setting.goToLink(`/login/${e.target.value}?orgChoiceMode=None`);
                }} />
              </Form.Item>
              <Button type="primary" htmlType="submit">
                {i18next.t("general:Confirm")}
              </Button>
            </Form>
          </div>
        );
      default:
        return null;
      }
    };

    return (
      <div style={{height: 300, width: 300}}>
        {renderChoiceBox()}
      </div>
    );
  }

  ldapSelectIdSetter(ldapId) {
    this.setState({
      ldapId: ldapId,
    });
  }

  renderLdapServerChoiceBox(organization) {
    const renderChoiceBox = () => {
      if (!this.state || !this.state.loginMethod) {
        return null;
      }
      switch (this.state.loginMethod) {
      case "ldap":
        return (
          <LdapSelect organization={organization} style={{width: "100%"}}
            ldapIdSetter={(value) => {
              this.ldapSelectIdSetter(value);
            }}
            onSelect={(value) => {
              this.setState({ldapId: value});
            }} />
        );
      default:
        return null;
      }
    };

    return (
      <div style={{}}>
        {renderChoiceBox()}
      </div>
    );
  }

  isOrganizationChoiceBoxVisible(orgChoiceMode) {
    if (this.state.orgChoiceMode === "None") {
      return false;
    }

    const path = this.props.match?.path;
    if (path === "/login" || path === "/login/:owner") {
      return orgChoiceMode === "Select" || orgChoiceMode === "Input";
    }

    return false;
  }

  renderBackButton() {
    if (this.state.orgChoiceMode === "None") {
      return (
        <Button type="text" size="large" icon={<ArrowLeftOutlined />}
          style={{top: "65px", left: "15px", position: "absolute"}}
          onClick={() => history.back()}>
        </Button>
      );
    }
  }

  render() {
    const application = this.getApplicationObj();
    if (application === undefined) {
      return null;
    }
    if (application === null) {
      return Util.renderMessageLarge(this, this.state.msg);
    }

    if (this.state.samlResponse !== "") {
      return <RedirectForm samlResponse={this.state.samlResponse} redirectUrl={this.state.redirectUrl} relayState={this.state.relayState} />;
    }

    if (application.signinHtml !== "") {
      return (
        <div dangerouslySetInnerHTML={{__html: application.signinHtml}} />
      );
    }

    const visibleOAuthProviderItems = (application.providers === null) ? [] : application.providers.filter(providerItem => this.isProviderVisible(providerItem));
    if (this.props.preview !== "auto" && !Setting.isPasswordEnabled(application) && !Setting.isCodeSigninEnabled(application) && !Setting.isWebAuthnEnabled(application) && !Setting.isLdapEnabled(application) && visibleOAuthProviderItems.length === 1) {
      Setting.goToLink(Provider.getAuthUrl(application, visibleOAuthProviderItems[0].provider, "signup"));
      return (
        <div style={{display: "flex", justifyContent: "center", alignItems: "center", width: "100%"}}>
          <Spin size="large" tip={i18next.t("login:Signing in...")} />
        </div>
      );
    }

    return (
      <React.Fragment>
        <CustomGithubCorner />
        <div className="login-content" style={{margin: this.props.preview ?? this.parseOffset(application.formOffset)}}>
          {Setting.inIframe() || Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCss}} />}
          {Setting.inIframe() || !Setting.isMobile() ? null : <div dangerouslySetInnerHTML={{__html: application.formCssMobile}} />}
          <div className="login-panel">
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
              {
                this.renderBackButton()
              }
              {/* Choose lang button removed, default browser lang will use */}
              {/* <LanguageSelect languages={application.organizationObj.languages} style={{top: "55px", right: "5px", position: "absolute"}} /> */}
              {
                this.renderLoginPanel(application)
              }
            </div>
          </div>
        </div>
      </React.Fragment>
    );
  }
}

export default withRouter(LoginPage);
