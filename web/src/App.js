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

import React, {Component} from "react";
import "./App.less";
import {Helmet} from "react-helmet";
import {MfaRuleRequired} from "./Setting";
import * as Setting from "./Setting";
import {StyleProvider, legacyLogicalPropertiesTransformer} from "@ant-design/cssinjs";
import {AppstoreTwoTone, BarsOutlined, DollarTwoTone, DownOutlined, HomeTwoTone, InfoCircleFilled, LockTwoTone, LogoutOutlined, SafetyCertificateTwoTone, SettingOutlined, SettingTwoTone, WalletTwoTone} from "@ant-design/icons";
import {Alert, Avatar, Button, Card, ConfigProvider, Drawer, Dropdown, FloatButton, Layout, Menu, Result} from "antd";
import {Link, Redirect, Route, Switch, withRouter} from "react-router-dom";
import OrganizationListPage from "./OrganizationListPage";
import OrganizationEditPage from "./OrganizationEditPage";
import UserListPage from "./UserListPage";
import UserEditPage from "./UserEditPage";
import RoleListPage from "./RoleListPage";
import RoleEditPage from "./RoleEditPage";
import PermissionListPage from "./PermissionListPage";
import PermissionEditPage from "./PermissionEditPage";
import EnforcerEditPage from "./EnforcerEditPage";
import EnforcerListPage from "./EnforcerListPage";
import GroupTreePage from "./GroupTreePage";
import GroupEditPage from "./GroupEdit";
import GroupListPage from "./GroupList";
import ProviderListPage from "./ProviderListPage";
import ProviderEditPage from "./ProviderEditPage";
import ApplicationListPage from "./ApplicationListPage";
import ApplicationEditPage from "./ApplicationEditPage";
import ResourceListPage from "./ResourceListPage";
import LdapEditPage from "./LdapEditPage";
import LdapSyncPage from "./LdapSyncPage";
import TokenListPage from "./TokenListPage";
import TokenEditPage from "./TokenEditPage";
import RecordListPage from "./RecordListPage";
import WebhookListPage from "./WebhookListPage";
import WebhookEditPage from "./WebhookEditPage";
import SyncerListPage from "./SyncerListPage";
import SyncerEditPage from "./SyncerEditPage";
import CertListPage from "./CertListPage";
import CertEditPage from "./CertEditPage";
import SubscriptionListPage from "./SubscriptionListPage";
import SubscriptionEditPage from "./SubscriptionEditPage";
import PricingListPage from "./PricingListPage";
import PricingEditPage from "./PricingEditPage";
import PlanListPage from "./PlanListPage";
import PlanEditPage from "./PlanEditPage";
import ProductListPage from "./ProductListPage";
import ProductEditPage from "./ProductEditPage";
import ProductBuyPage from "./ProductBuyPage";
import PaymentListPage from "./PaymentListPage";
import PaymentEditPage from "./PaymentEditPage";
import PaymentResultPage from "./PaymentResultPage";
import ModelListPage from "./ModelListPage";
import ModelEditPage from "./ModelEditPage";
import AdapterListPage from "./AdapterListPage";
import AdapterEditPage from "./AdapterEditPage";
import SessionListPage from "./SessionListPage";
import MfaSetupPage from "./auth/MfaSetupPage";
import SystemInfo from "./SystemInfo";
import AccountPage from "./account/AccountPage";
import HomePage from "./basic/HomePage";
import CustomGithubCorner from "./common/CustomGithubCorner";
import * as Conf from "./Conf";

import * as Auth from "./auth/Auth";
import EntryPage from "./EntryPage";
import * as AuthBackend from "./auth/AuthBackend";
import AuthCallback from "./auth/AuthCallback";
import OdicDiscoveryPage from "./auth/OidcDiscoveryPage";
import SamlCallback from "./auth/SamlCallback";
import i18next from "i18next";
import {withTranslation} from "react-i18next";
import EnableMfaNotification from "./common/notifaction/EnableMfaNotification";
import LanguageSelect from "./common/select/LanguageSelect";
import ThemeSelect from "./common/select/ThemeSelect";
import OrganizationSelect from "./common/select/OrganizationSelect";
import {clearWeb3AuthToken} from "./auth/Web3Auth";
import AccountAvatar from "./account/AccountAvatar";

const {Header, Footer, Content} = Layout;

import {setTwoToneColor} from "@ant-design/icons";
import DomainListPage from "./DomainListPage";
import DomainEditPage from "./DomainEditPage";

setTwoToneColor("rgb(87,52,211)");

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      classes: props,
      selectedMenuKey: 0,
      account: undefined,
      uri: null,
      menuVisible: false,
      themeAlgorithm: ["default"],
      themeData: Conf.ThemeDefault,
      logo: this.getLogo(Setting.getAlgorithmNames(Conf.ThemeDefault)),
      requiredEnableMfa: false,
    };

    Setting.initServerUrl();
    Auth.initAuthWithConfig({
      serverUrl: Setting.ServerUrl,
      appName: Conf.DefaultApplication, // the application used in Casdoor root path: "/"
    });
  }

  UNSAFE_componentWillMount() {
    this.updateMenuKey();
    this.getAccount();
  }

  componentDidUpdate(prevProps, prevState, snapshot) {
    const uri = location.pathname;
    if (this.state.uri !== uri) {
      this.updateMenuKey();
    }

    if (this.state.account !== prevState.account) {
      const requiredEnableMfa = Setting.isRequiredEnableMfa(this.state.account, this.state.account?.organization);
      this.setState({
        requiredEnableMfa: requiredEnableMfa,
      });

      if (requiredEnableMfa === true) {
        const mfaType = Setting.getMfaItemsByRules(this.state.account, this.state.account?.organization, [MfaRuleRequired])
          .find((item) => item.rule === MfaRuleRequired)?.name;
        if (mfaType !== undefined) {
          this.props.history.push(`/mfa/setup?mfaType=${mfaType}`, {from: "/login"});
        }
      }
    }
  }

  updateMenuKey() {
    const uri = location.pathname;
    this.setState({
      uri: uri,
    });
    if (uri === "/") {
      this.setState({selectedMenuKey: "/"});
    } else if (uri.includes("/organizations") || uri.includes("/trees") || uri.includes("/users") || uri.includes("/groups")) {
      this.setState({selectedMenuKey: "/orgs"});
    } else if (uri.includes("/roles") || uri.includes("/domains") || uri.includes("/permissions") || uri.includes("/models") || uri.includes("/adapters") || uri.includes("/enforcers")) {
      this.setState({selectedMenuKey: "/auth"});
    } else if (uri.includes("/applications") || uri.includes("/providers") || uri.includes("/resources") || uri.includes("/certs")) {
      this.setState({selectedMenuKey: "/identity"});
    } else if (uri.includes("/records") || uri.includes("/tokens") || uri.includes("/sessions")) {
      this.setState({selectedMenuKey: "/logs"});
    } else if (uri.includes("/products") || uri.includes("/payments") || uri.includes("/plans") || uri.includes("/pricings") || uri.includes("/subscriptions")) {
      this.setState({selectedMenuKey: "/business"});
    } else if (uri.includes("/sysinfo") || uri.includes("/syncers") || uri.includes("/webhooks")) {
      this.setState({selectedMenuKey: "/admin"});
    } else if (uri.includes("/signup")) {
      this.setState({selectedMenuKey: "/signup"});
    } else if (uri.includes("/login")) {
      this.setState({selectedMenuKey: "/login"});
    } else if (uri.includes("/result")) {
      this.setState({selectedMenuKey: "/result"});
    } else {
      this.setState({selectedMenuKey: -1});
    }
  }

  getAccessTokenParam(params) {
    // "/page?access_token=123"
    const accessToken = params.get("access_token");
    return accessToken === null ? "" : `?accessToken=${accessToken}`;
  }

  getCredentialParams(params) {
    // "/page?username=abc&password=123"
    if (params.get("username") === null || params.get("password") === null) {
      return "";
    }
    return `?username=${params.get("username")}&password=${params.get("password")}`;
  }

  getUrlWithoutQuery() {
    return window.location.toString().replace(window.location.search, "");
  }

  getLanguageParam(params) {
    // "/page?language=en"
    const language = params.get("language");
    if (language !== null) {
      Setting.setLanguage(language);
      return `language=${language}`;
    }
    return "";
  }

  getLogo(themes) {
    if (themes.includes("dark")) {
      return `${Setting.StaticBaseUrl}/img/casdoor-logo_1185x256_dark.png`;
    } else {
      return `${Setting.StaticBaseUrl}/img/casdoor-logo_1185x256.png`;
    }
  }

  setLanguage(account) {
    const language = account?.language;
    if (language !== null && language !== "" && language !== i18next.language) {
      Setting.setLanguage(language);
    }
  }

  setTheme = (theme, initThemeAlgorithm) => {
    this.setState({
      themeData: theme,
    });

    if (initThemeAlgorithm) {
      this.setState({
        logo: this.getLogo(Setting.getAlgorithmNames(theme)),
        themeAlgorithm: Setting.getAlgorithmNames(theme),
      });
    }
  };

  getAccount() {
    const params = new URLSearchParams(this.props.location.search);

    let query = this.getAccessTokenParam(params);
    if (query === "") {
      query = this.getCredentialParams(params);
    }

    const query2 = this.getLanguageParam(params);
    if (query2 !== "") {
      const url = window.location.toString().replace(new RegExp(`[?&]${query2}`), "");
      window.history.replaceState({}, document.title, url);
    }

    if (query !== "") {
      window.history.replaceState({}, document.title, this.getUrlWithoutQuery());
    }

    AuthBackend.getAccount(query)
      .then((res) => {
        let account = null;
        if (res.status === "ok") {
          account = res.data;
          account.organization = res.data2;

          this.setLanguage(account);
          this.setTheme(Setting.getThemeData(account.organization), Conf.InitThemeAlgorithm);
        } else {
          if (res.data !== "Please login first") {
            Setting.showMessage("error", `${i18next.t("application:Failed to sign in")}: ${res.msg}`);
          }
        }

        this.setState({
          account: account,
        });
      });
  }

  logout() {
    this.setState({
      expired: false,
      submitted: false,
    });

    AuthBackend.logout()
      .then((res) => {
        if (res.status === "ok") {
          const owner = this.state.account.owner;
          this.setState({
            account: null,
            themeAlgorithm: ["default"],
          });
          clearWeb3AuthToken();
          Setting.showMessage("success", i18next.t("application:Logged out successfully"));
          const redirectUri = res.data2;
          if (redirectUri !== null && redirectUri !== undefined && redirectUri !== "") {
            Setting.goToLink(redirectUri);
          } else if (owner !== "built-in") {
            Setting.goToLink(`${window.location.origin}/login/${owner}`);
          } else {
            Setting.goToLinkSoft(this, "/");
          }
        } else {
          Setting.showMessage("error", `Failed to log out: ${res.msg}`);
        }
      });
  }

  onUpdateAccount(account) {
    this.setState({
      account: account,
    });
  }

  renderAvatar() {
    if (this.state.account.avatar === "") {
      return (
        <Avatar style={{backgroundColor: Setting.getAvatarColor(this.state.account.name), verticalAlign: "middle"}} size="large">
          {Setting.getShortName(this.state.account.name)}
        </Avatar>
      );
    } else {
      return (
        <Avatar src={this.state.account.avatar} style={{verticalAlign: "middle"}} size="large"
          icon={<AccountAvatar src={this.state.account.avatar} style={{verticalAlign: "middle"}} size={40} />}
        >
          {Setting.getShortName(this.state.account.name)}
        </Avatar>
      );
    }
  }

  renderRightDropdown() {
    const items = [];
    if (this.state.requiredEnableMfa === false) {
      items.push(Setting.getItem(<><SettingOutlined />&nbsp;&nbsp;{i18next.t("account:My Account")}</>,
        "/account"
      ));
    }
    items.push(Setting.getItem(<><LogoutOutlined />&nbsp;&nbsp;{i18next.t("account:Logout")}</>,
      "/logout"));

    const onClick = (e) => {
      if (e.key === "/account") {
        this.props.history.push("/account");
      } else if (e.key === "/subscription") {
        this.props.history.push("/subscription");
      } else if (e.key === "/logout") {
        this.logout();
      }
    };

    return (
      <Dropdown key="/rightDropDown" menu={{items, onClick}} >
        <div className="rightDropDown">
          {
            this.renderAvatar()
          }
          &nbsp;
          &nbsp;
          {Setting.isMobile() ? null : Setting.getNameAtLeast(this.state.account.displayName)} &nbsp; <DownOutlined />
          &nbsp;
          &nbsp;
          &nbsp;
        </div>
      </Dropdown>
    );
  }

  renderAccountMenu() {
    if (this.state.account === undefined) {
      return null;
    } else if (this.state.account === null) {
      return null;
    } else {
      return (
        <React.Fragment>
          {this.renderRightDropdown()}
          <ThemeSelect
            themeAlgorithm={this.state.themeAlgorithm}
            onChange={(nextThemeAlgorithm) => {
              this.setState({
                themeAlgorithm: nextThemeAlgorithm,
                logo: this.getLogo(nextThemeAlgorithm),
              });
            }} />
          <LanguageSelect languages={this.state.account.organization.languages} />
          {Setting.isAdminUser(this.state.account) && !Setting.isMobile() &&
            <OrganizationSelect
              initValue={Setting.getOrganization()}
              withAll={true}
              style={{marginRight: "20px", width: "180px", display: "flex"}}
              onChange={(value) => {
                Setting.setOrganization(value);
              }}
              className="select-box"
            />
          }
        </React.Fragment>
      );
    }
  }

  getMenuItems() {
    const res = [];

    if (this.state.account === null || this.state.account === undefined) {
      return [];
    }

    res.push(Setting.getItem(<Link to="/">{i18next.t("general:Home")}</Link>, "/", <HomeTwoTone />));

    if (Setting.isLocalAdminUser(this.state.account)) {
      if (Conf.ShowGithubCorner) {
        res.push(Setting.getItem(<a href={"https://casdoor.com"}>
          <span style={{fontWeight: "bold", backgroundColor: "rgba(87,52,211,0.4)", marginTop: "12px", paddingLeft: "5px", paddingRight: "5px", display: "flex", alignItems: "center", height: "40px", borderRadius: "5px"}}>
            🚀 SaaS Hosting 🔥
          </span>
        </a>, "#"));
      }

      res.push(Setting.getItem(<Link style={{color: "black"}} to="/organizations">{i18next.t("general:User Management")}</Link>, "/orgs", <AppstoreTwoTone />, [
        Setting.getItem(<Link to="/organizations">{i18next.t("general:Organizations")}</Link>, "/organizations"),
        Setting.getItem(<Link to="/groups">{i18next.t("general:Groups")}</Link>, "/groups"),
        Setting.getItem(<Link to="/users">{i18next.t("general:Users")}</Link>, "/users"),
      ]));

      res.push(Setting.getItem(<Link style={{color: "black"}} to="/roles">{i18next.t("general:Authorization")}</Link>, "/auth", <SafetyCertificateTwoTone />, [
        Setting.getItem(<Link to="/roles">{i18next.t("general:Roles")}</Link>, "/roles"),
        Setting.getItem(<Link to="/domains">{i18next.t("general:Domains")}</Link>, "/domains"),
        Setting.getItem(<Link to="/permissions">{i18next.t("general:Permissions")}</Link>, "/permissions"),
        Setting.getItem(<Link to="/models">{i18next.t("general:Models")}</Link>, "/models"),
        Setting.getItem(<Link to="/adapters">{i18next.t("general:Adapters")}</Link>, "/adapters"),
        Setting.getItem(<Link to="/enforcers">{i18next.t("general:Enforcers")}</Link>, "/enforcers"),
      ].filter(item => {
        if (!Setting.isLocalAdminUser(this.state.account) && ["/models", "/adapters", "/enforcers"].includes(item.key)) {
          return false;
        } else {
          return true;
        }
      })));
    }

    if (Setting.isLocalAdminUser(this.state.account)) {
      res.push(Setting.getItem(<Link style={{color: "black"}} to="/applications">{i18next.t("general:Identity")}</Link>, "/identity", <LockTwoTone />, [
        Setting.getItem(<Link to="/applications">{i18next.t("general:Applications")}</Link>, "/applications"),
        Setting.getItem(<Link to="/providers">{i18next.t("general:Providers")}</Link>, "/providers"),
        Setting.getItem(<Link to="/resources">{i18next.t("general:Resources")}</Link>, "/resources"),
        Setting.getItem(<Link to="/certs">{i18next.t("general:Certs")}</Link>, "/certs"),
      ]));

      res.push(Setting.getItem(<Link style={{color: "black"}} to="/records">{i18next.t("general:Logging & Auditing")}</Link>, "/logs", <WalletTwoTone />, [
        Setting.getItem(<Link to="/records">{i18next.t("general:Records")}</Link>, "/records"),
        Setting.getItem(<Link to="/tokens">{i18next.t("general:Tokens")}</Link>, "/tokens"),
        Setting.getItem(<Link to="/sessions">{i18next.t("general:Sessions")}</Link>, "/sessions"),
      ]));

      res.push(Setting.getItem(<Link style={{color: "black"}} to="/products">{i18next.t("general:Business & Payments")}</Link>, "/business", <DollarTwoTone />, [
        Setting.getItem(<Link to="/products">{i18next.t("general:Products")}</Link>, "/products"),
        Setting.getItem(<Link to="/payments">{i18next.t("general:Payments")}</Link>, "/payments"),
        Setting.getItem(<Link to="/plans">{i18next.t("general:Plans")}</Link>, "/plans"),
        Setting.getItem(<Link to="/pricings">{i18next.t("general:Pricings")}</Link>, "/pricings"),
        Setting.getItem(<Link to="/subscriptions">{i18next.t("general:Subscriptions")}</Link>, "/subscriptions"),
      ]));

      res.push(Setting.getItem(<Link style={{color: "black"}} to="/sysinfo">{i18next.t("general:Admin")}</Link>, "/admin", <SettingTwoTone />, [
        Setting.getItem(<Link to="/sysinfo">{i18next.t("general:System Info")}</Link>, "/sysinfo"),
        Setting.getItem(<Link to="/syncers">{i18next.t("general:Syncers")}</Link>, "/syncers"),
        Setting.getItem(<Link to="/webhooks">{i18next.t("general:Webhooks")}</Link>, "/webhooks"),
        Setting.getItem(<a target="_blank" rel="noreferrer" href={Setting.isLocalhost() ? `${Setting.ServerUrl}/swagger` : "/swagger"}>{i18next.t("general:Swagger")}</a>, "/swagger")]));
    }

    return res;
  }

  renderLoginIfNotLoggedIn(component) {
    if (this.state.account === null) {
      sessionStorage.setItem("from", window.location.pathname);
      return <Redirect to="/login" />;
    } else if (this.state.account === undefined) {
      return null;
    } else {
      return component;
    }
  }

  renderRouter() {
    return (
      <Switch>
        <Route exact path="/" render={(props) => this.renderLoginIfNotLoggedIn(<HomePage account={this.state.account} {...props} />)} />
        <Route exact path="/account" render={(props) => this.renderLoginIfNotLoggedIn(<AccountPage account={this.state.account} {...props} />)} />
        <Route exact path="/organizations" render={(props) => this.renderLoginIfNotLoggedIn(<OrganizationListPage account={this.state.account} {...props} />)} />
        <Route exact path="/organizations/:organizationName" render={(props) => this.renderLoginIfNotLoggedIn(<OrganizationEditPage account={this.state.account} onChangeTheme={this.setTheme} {...props} />)} />
        <Route exact path="/organizations/:organizationName/users" render={(props) => this.renderLoginIfNotLoggedIn(<UserListPage account={this.state.account} {...props} />)} />
        <Route exact path="/trees/:organizationName" render={(props) => this.renderLoginIfNotLoggedIn(<GroupTreePage account={this.state.account} {...props} />)} />
        <Route exact path="/trees/:organizationName/:groupName" render={(props) => this.renderLoginIfNotLoggedIn(<GroupTreePage account={this.state.account} {...props} />)} />
        <Route exact path="/groups" render={(props) => this.renderLoginIfNotLoggedIn(<GroupListPage account={this.state.account} {...props} />)} />
        <Route exact path="/groups/:organizationName/:groupName" render={(props) => this.renderLoginIfNotLoggedIn(<GroupEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/users" render={(props) => this.renderLoginIfNotLoggedIn(<UserListPage account={this.state.account} {...props} />)} />
        <Route exact path="/users/:organizationName/:userName" render={(props) => <UserEditPage account={this.state.account} {...props} />} />
        <Route exact path="/roles" render={(props) => this.renderLoginIfNotLoggedIn(<RoleListPage account={this.state.account} {...props} />)} />
        <Route exact path="/roles/:organizationName/:roleName" render={(props) => this.renderLoginIfNotLoggedIn(<RoleEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/domains" render={(props) => this.renderLoginIfNotLoggedIn(<DomainListPage account={this.state.account} {...props} />)} />
        <Route exact path="/domains/:organizationName/:domainName" render={(props) => this.renderLoginIfNotLoggedIn(<DomainEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/permissions" render={(props) => this.renderLoginIfNotLoggedIn(<PermissionListPage account={this.state.account} {...props} />)} />
        <Route exact path="/permissions/:organizationName/:permissionName" render={(props) => this.renderLoginIfNotLoggedIn(<PermissionEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/models" render={(props) => this.renderLoginIfNotLoggedIn(<ModelListPage account={this.state.account} {...props} />)} />
        <Route exact path="/models/:organizationName/:modelName" render={(props) => this.renderLoginIfNotLoggedIn(<ModelEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/enforcers" render={(props) => this.renderLoginIfNotLoggedIn(<EnforcerListPage account={this.state.account} {...props} />)} />
        <Route exact path="/enforcers/:organizationName/:enforcerName" render={(props) => this.renderLoginIfNotLoggedIn(<EnforcerEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/adapters" render={(props) => this.renderLoginIfNotLoggedIn(<AdapterListPage account={this.state.account} {...props} />)} />
        <Route exact path="/adapters/:organizationName/:adapterName" render={(props) => this.renderLoginIfNotLoggedIn(<AdapterEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/providers" render={(props) => this.renderLoginIfNotLoggedIn(<ProviderListPage account={this.state.account} {...props} />)} />
        <Route exact path="/providers/:organizationName/:providerName" render={(props) => this.renderLoginIfNotLoggedIn(<ProviderEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/applications" render={(props) => this.renderLoginIfNotLoggedIn(<ApplicationListPage account={this.state.account} {...props} />)} />
        <Route exact path="/applications/:organizationName/:applicationName" render={(props) => this.renderLoginIfNotLoggedIn(<ApplicationEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/resources" render={(props) => this.renderLoginIfNotLoggedIn(<ResourceListPage account={this.state.account} {...props} />)} />
        {/* <Route exact path="/resources/:resourceName" render={(props) => this.renderLoginIfNotLoggedIn(<ResourceEditPage account={this.state.account} {...props} />)}/>*/}
        <Route exact path="/ldap/:organizationName/:ldapId" render={(props) => this.renderLoginIfNotLoggedIn(<LdapEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/ldap/sync/:organizationName/:ldapId" render={(props) => this.renderLoginIfNotLoggedIn(<LdapSyncPage account={this.state.account} {...props} />)} />
        <Route exact path="/tokens" render={(props) => this.renderLoginIfNotLoggedIn(<TokenListPage account={this.state.account} {...props} />)} />
        <Route exact path="/sessions" render={(props) => this.renderLoginIfNotLoggedIn(<SessionListPage account={this.state.account} {...props} />)} />
        <Route exact path="/tokens/:tokenName" render={(props) => this.renderLoginIfNotLoggedIn(<TokenEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/webhooks" render={(props) => this.renderLoginIfNotLoggedIn(<WebhookListPage account={this.state.account} {...props} />)} />
        <Route exact path="/webhooks/:webhookName" render={(props) => this.renderLoginIfNotLoggedIn(<WebhookEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/syncers" render={(props) => this.renderLoginIfNotLoggedIn(<SyncerListPage account={this.state.account} {...props} />)} />
        <Route exact path="/syncers/:syncerName" render={(props) => this.renderLoginIfNotLoggedIn(<SyncerEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/certs" render={(props) => this.renderLoginIfNotLoggedIn(<CertListPage account={this.state.account} {...props} />)} />
        <Route exact path="/certs/:organizationName/:certName" render={(props) => this.renderLoginIfNotLoggedIn(<CertEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/plans" render={(props) => this.renderLoginIfNotLoggedIn(<PlanListPage account={this.state.account} {...props} />)} />
        <Route exact path="/plans/:organizationName/:planName" render={(props) => this.renderLoginIfNotLoggedIn(<PlanEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/pricings" render={(props) => this.renderLoginIfNotLoggedIn(<PricingListPage account={this.state.account} {...props} />)} />
        <Route exact path="/pricings/:organizationName/:pricingName" render={(props) => this.renderLoginIfNotLoggedIn(<PricingEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/subscriptions" render={(props) => this.renderLoginIfNotLoggedIn(<SubscriptionListPage account={this.state.account} {...props} />)} />
        <Route exact path="/subscriptions/:organizationName/:subscriptionName" render={(props) => this.renderLoginIfNotLoggedIn(<SubscriptionEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/products" render={(props) => this.renderLoginIfNotLoggedIn(<ProductListPage account={this.state.account} {...props} />)} />
        <Route exact path="/products/:organizationName/:productName" render={(props) => this.renderLoginIfNotLoggedIn(<ProductEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/products/:organizationName/:productName/buy" render={(props) => this.renderLoginIfNotLoggedIn(<ProductBuyPage account={this.state.account} {...props} />)} />
        <Route exact path="/payments" render={(props) => this.renderLoginIfNotLoggedIn(<PaymentListPage account={this.state.account} {...props} />)} />
        <Route exact path="/payments/:organizationName/:paymentName" render={(props) => this.renderLoginIfNotLoggedIn(<PaymentEditPage account={this.state.account} {...props} />)} />
        <Route exact path="/payments/:organizationName/:paymentName/result" render={(props) => this.renderLoginIfNotLoggedIn(<PaymentResultPage account={this.state.account} {...props} />)} />
        <Route exact path="/records" render={(props) => this.renderLoginIfNotLoggedIn(<RecordListPage account={this.state.account} {...props} />)} />
        <Route exact path="/mfa/setup" render={(props) => this.renderLoginIfNotLoggedIn(<MfaSetupPage account={this.state.account} onfinish={() => this.setState({requiredEnableMfa: false})} {...props} />)} />
        <Route exact path="/.well-known/openid-configuration" render={(props) => <OdicDiscoveryPage />} />
        <Route exact path="/sysinfo" render={(props) => this.renderLoginIfNotLoggedIn(<SystemInfo account={this.state.account} {...props} />)} />
        <Route path="" render={() => <Result status="404" title="404 NOT FOUND" subTitle={i18next.t("general:Sorry, the page you visited does not exist.")}
          extra={<a href="/"><Button type="primary">{i18next.t("general:Back Home")}</Button></a>} />} />
      </Switch>
    );
  }

  onClose = () => {
    this.setState({
      menuVisible: false,
    });
  };

  showMenu = () => {
    this.setState({
      menuVisible: true,
    });
  };

  isWithoutCard() {
    return Setting.isMobile() || window.location.pathname.startsWith("/trees");
  }

  renderContent() {
    const onClick = ({key}) => {
      if (key === "/swagger") {
        window.open(Setting.isLocalhost() ? `${Setting.ServerUrl}/swagger` : "/swagger", "_blank");
      } else {
        if (this.state.requiredEnableMfa) {
          Setting.showMessage("info", "Please enable MFA first!");
        } else {
          this.props.history.push(key);
        }
      }
    };
    const menuStyleRight = Setting.isAdminUser(this.state.account) && !Setting.isMobile() ? "calc(180px + 260px)" : "260px";
    return (
      <Layout id="parent-area">
        <EnableMfaNotification account={this.state.account} />
        <Header style={{padding: "0", marginBottom: "3px", backgroundColor: this.state.themeAlgorithm.includes("dark") ? "black" : "white"}} >
          {Setting.isMobile() ? null : (
            <Link to={"/"}>
              <div className="logo" style={{background: `url(${this.state.logo})`}} />
            </Link>
          )}
          {this.state.requiredEnableMfa || (Setting.isMobile() ?
            <React.Fragment>
              <Drawer title={i18next.t("general:Close")} placement="left" visible={this.state.menuVisible} onClose={this.onClose}>
                <Menu
                  items={this.getMenuItems()}
                  mode={"inline"}
                  selectedKeys={[this.state.selectedMenuKey]}
                  style={{lineHeight: "64px"}}
                  onClick={this.onClose}
                >
                </Menu>
              </Drawer>
              <Button icon={<BarsOutlined />} onClick={this.showMenu} type="text">
                {i18next.t("general:Menu")}
              </Button>
            </React.Fragment> :
            <Menu
              onClick={onClick}
              items={this.getMenuItems()}
              mode={"horizontal"}
              selectedKeys={[this.state.selectedMenuKey]}
              style={{position: "absolute", left: "145px", right: menuStyleRight}}
            />
          )}
          {
            this.renderAccountMenu()
          }
        </Header>
        <Content style={{display: "flex", flexDirection: "column"}} >
          {this.isWithoutCard() ?
            this.renderRouter() :
            <Card className="content-warp-card">
              {this.renderRouter()}
            </Card>
          }
        </Content>
        {this.renderFooter()}
      </Layout>
    );
  }

  renderFooter() {
    return (
      <React.Fragment>
        {!this.state.account ? null : <div style={{display: "none"}} id="CasdoorApplicationName" value={this.state.account.signupApplication} />}
        <Footer id="footer" style={
          {
            textAlign: "center",
          }
        }>
          {
            Conf.CustomFooter !== null ? Conf.CustomFooter : (
              <React.Fragment>
                Powered by <a target="_blank" href="https://casdoor.org" rel="noreferrer"><img style={{paddingBottom: "3px"}} height={"20px"} alt={"Casdoor"} src={this.state.logo} /></a>
              </React.Fragment>
            )
          }
        </Footer>
      </React.Fragment>
    );
  }

  isDoorPages() {
    return this.isEntryPages() || window.location.pathname.startsWith("/callback");
  }

  isEntryPages() {
    return window.location.pathname.startsWith("/signup") ||
        window.location.pathname.startsWith("/login") ||
        window.location.pathname.startsWith("/forget") ||
        window.location.pathname.startsWith("/prompt") ||
        window.location.pathname.startsWith("/result") ||
        window.location.pathname.startsWith("/cas") ||
        window.location.pathname.startsWith("/auto-signup") ||
        window.location.pathname.startsWith("/select-plan");
  }

  renderPage() {
    if (this.isDoorPages()) {
      return (
        <Layout id="parent-area">
          <Content style={{display: "flex", justifyContent: "center"}}>
            {
              this.isEntryPages() ?
                <EntryPage
                  account={this.state.account}
                  theme={this.state.themeData}
                  onLoginSuccess={(redirectUrl) => {
                    localStorage.setItem("mfaRedirectUrl", redirectUrl);
                    this.getAccount();
                  }}
                  onUpdateAccount={(account) => this.onUpdateAccount(account)}
                  updataThemeData={this.setTheme}
                /> :
                <Switch>
                  <Route exact path="/callback" component={AuthCallback} />
                  <Route exact path="/callback/saml" component={SamlCallback} />
                  <Route path="" render={() => <Result status="404" title="404 NOT FOUND" subTitle={i18next.t("general:Sorry, the page you visited does not exist.")}
                    extra={<a href="/"><Button type="primary">{i18next.t("general:Back Home")}</Button></a>} />} />
                </Switch>
            }
          </Content>
          {
            this.renderFooter()
          }
        </Layout>
      );
    }

    return (
      <React.Fragment>
        {/* { */}
        {/*   this.renderBanner() */}
        {/* } */}
        <FloatButton.BackTop />
        <CustomGithubCorner />
        {
          this.renderContent()
        }
      </React.Fragment>
    );
  }

  renderBanner() {
    if (!Conf.IsDemoMode) {
      return null;
    }

    const language = Setting.getLanguage();
    if (language === "en" || language === "zh") {
      return null;
    }

    return (
      <Alert type="info" banner showIcon={false} closable message={
        <div style={{textAlign: "center"}}>
          <InfoCircleFilled style={{color: "rgb(87,52,211)"}} />
          &nbsp;&nbsp;
          {i18next.t("general:Found some texts still not translated? Please help us translate at")}
          &nbsp;
          <a target="_blank" rel="noreferrer" href={"https://crowdin.com/project/casdoor-site"}>
            Crowdin
          </a>
          &nbsp;!&nbsp;🙏
        </div>
      } />
    );
  }

  render() {
    return (
      <React.Fragment>
        {(this.state.account === undefined || this.state.account === null) ?
          <Helmet>
            <link rel="icon" href={"https://cdn.casdoor.com/static/favicon.png"} />
          </Helmet> :
          <Helmet>
            <title>{this.state.account.organization?.displayName}</title>
            <link rel="icon" href={this.state.account.organization?.favicon} />
          </Helmet>
        }
        <ConfigProvider theme={{
          token: {
            colorPrimary: this.state.themeData.colorPrimary,
            colorInfo: this.state.themeData.colorPrimary,
            borderRadius: this.state.themeData.borderRadius,
          },
          algorithm: Setting.getAlgorithm(this.state.themeAlgorithm),
        }}>
          <StyleProvider hashPriority="high" transformers={[legacyLogicalPropertiesTransformer]}>
            {
              this.renderPage()
            }
          </StyleProvider>
        </ConfigProvider>
      </React.Fragment>
    );
  }
}

export default withRouter(withTranslation()(App));
