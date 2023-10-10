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
import {ArrowLeftOutlined, LockOutlined, UserOutlined} from "@ant-design/icons";
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
import LanguageSelect from "../common/select/LanguageSelect";
import {CaptchaModal, CaptchaRule} from "../common/modal/CaptchaModal";
import RedirectForm from "../common/RedirectForm";
import {MfaAuthVerifyForm, NextMfa, RequiredMfa} from "./mfa/MfaAuthVerifyForm";
import {ChangePasswordForm, NextChangePasswordForm} from "./ChangePasswordForm";

import {GoogleOneTapLoginVirtualButton} from "./GoogleLoginButton";
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
    };

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

  getDefaultLoginMethod(application) {
    if (application?.enablePassword) {
      return "password";
    }
    if (application?.enableCodeSignin) {
      return "verificationCode";
    }
    if (application?.enableWebAuthn) {
      return "webAuthn";
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
            } else if (res.data === "SelectPlan") {
              // paid-user does not have active or pending subscription, go to application default pricing page to select-plan
              const pricing = res.data2;
              Setting.goToLink(`/select-plan/${pricing.owner}/${pricing.name}?user=${values.username}`);
            } else if (res.data === "BuyPlanResult") {
              // paid-user has pending subscription, go to buy-plan/result apge to notify payment result
              const sub = res.data2;
              Setting.goToLink(`/buy-plan/${sub.owner}/${sub.pricing}/result?subscription=${sub.name}`);
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

  renderForm(application) {
    if (this.state.msg !== null) {
      return Util.renderMessage(this.state.msg);
    }

    if (this.state.mode === "signup" && !application.enableSignUp) {
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

    const showForm = application.enablePassword || application.enableCodeSignin || application.enableWebAuthn;
    if (showForm) {
      let loginWidth = 320;
      if (Setting.getLanguage() === "fr") {
        loginWidth += 20;
      } else if (Setting.getLanguage() === "es") {
        loginWidth += 40;
      } else if (Setting.getLanguage() === "ru") {
        loginWidth += 10;
      }

      return (
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
          style={{width: `${loginWidth}px`}}
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
          <Row style={{minHeight: 130, alignItems: "center"}}>
            <Col span={24}>
              <Form.Item
                name="username"
                rules={[
                  {
                    required: true,
                    message: i18next.t("login:Please input your Email or Phone!"),
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
                  prefix={<UserOutlined className="site-form-item-icon" />}
                  disabled={new URLSearchParams(this.props.location?.search).get("u") !== null}
                  placeholder={(this.state.loginMethod === "verificationCode") ? i18next.t("login:Email or phone") : i18next.t("login:username, Email or phone")}
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
          <div style={{display: "inline-flex", justifyContent: "space-between", width: "320px", marginBottom: AgreementModal.isAgreementRequired(application) ? "5px" : "25px"}}>
            <Form.Item name="autoSignin" valuePropName="checked" noStyle>
              <Checkbox style={{float: "left"}}>
                {i18next.t("login:Auto sign in")}
              </Checkbox>
            </Form.Item>
            {
              Setting.renderForgetLink(application, i18next.t("login:Forgot password?"))
            }
          </div>
          {AgreementModal.isAgreementRequired(application) ? AgreementModal.renderAgreementFormItem(application, true, {}, this) : null}
          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              style={{width: "100%", marginBottom: "5px"}}
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
          <Form.Item>
            {
              application.providers.filter(providerItem => this.isProviderVisible(providerItem)).map(providerItem => {
                return ProviderButton.renderProviderLogo(providerItem.provider, application, 30, 5, "small", this.props.location);
              })
            }
            {
              this.renderOtherFormProvider(application)
            }
          </Form.Item>
        </Form>
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
    return (
      <span style={{float: "right"}}>
        {
          !application.enableSignUp ? null : (
            <React.Fragment>
              {i18next.t("login:No account?")}&nbsp;
              {
                Setting.renderSignupLink(application, i18next.t("login:sign up now"))
              }
            </React.Fragment>
          )
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
    if (this.state.loginMethod === "password") {
      return (
        <Col span={24}>
          <Form.Item
            name="password"
            rules={[{required: true, message: i18next.t("login:Please input your password!")}]}
          >
            <Input.Password
              prefix={<LockOutlined className="site-form-item-icon" />}
              type="password"
              placeholder={i18next.t("general:Password")}
              disabled={!application.enablePassword}
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
    application.enablePassword ? items.push({label: i18next.t("general:Password"), key: "password"}) : null;
    application.enableCodeSignin ? items.push({label: i18next.t("login:Verification code"), key: "verificationCode"}) : null;
    application.enableWebAuthn ? items.push({label: i18next.t("login:WebAuthn"), key: "webAuthn"}) : null;

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
    if (this.props.preview !== "auto" && !application.enablePassword && !application.enableCodeSignin && !application.enableWebAuthn && visibleOAuthProviderItems.length === 1) {
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
              <div>
                <div>
                  {
                    Setting.renderHelmet(application)
                  }
                  {
                    Setting.renderLogo(application)
                  }
                  {
                    this.renderBackButton()
                  }
                  <LanguageSelect languages={application.organizationObj.languages} style={{top: "55px", right: "5px", position: "absolute"}} />
                  {
                    this.renderLoginPanel(application)
                  }
                </div>
              </div>
            </div>
          </div>
        </div>
      </React.Fragment>
    );
  }
}

export default withRouter(LoginPage);
