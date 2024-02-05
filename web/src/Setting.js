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
import {Select, Tag, Tooltip, message, theme} from "antd";
import {QuestionCircleTwoTone} from "@ant-design/icons";
import {isMobile as isMobileDevice} from "react-device-detect";
import "./i18n";
import i18next from "i18next";
import copy from "copy-to-clipboard";
import {authConfig} from "./auth/Auth";
import {Helmet} from "react-helmet";
import * as Conf from "./Conf";
import * as phoneNumber from "libphonenumber-js";
import moment from "moment";

const {Option} = Select;

export let ServerUrl = "";

export const StaticBaseUrl = "https://cdn.casbin.org";

export const Countries = [
  {label: "English", key: "en", country: "US", alt: "English"},
  {label: "Español", key: "es", country: "ES", alt: "Español"},
  {label: "Français", key: "fr", country: "FR", alt: "Français"},
  {label: "Deutsch", key: "de", country: "DE", alt: "Deutsch"},
  {label: "中文", key: "zh", country: "CN", alt: "中文"},
  {label: "Indonesia", key: "id", country: "ID", alt: "Indonesia"},
  {label: "日本語", key: "ja", country: "JP", alt: "日本語"},
  {label: "한국어", key: "ko", country: "KR", alt: "한국어"},
  {label: "Русский", key: "ru", country: "RU", alt: "Русский"},
  {label: "TiếngViệt", key: "vi", country: "VN", alt: "TiếngViệt"},
  {label: "Português", key: "pt", country: "PT", alt: "Português"},
  {label: "Italiano", key: "it", country: "IT", alt: "Italiano"},
  {label: "Malay", key: "ms", country: "MY", alt: "Malay"},
  {label: "Türkçe", key: "tr", country: "TR", alt: "Türkçe"},
  {label: "لغة عربية", key: "ar", country: "SA", alt: "لغة عربية"},
  {label: "עִבְרִית", key: "he", country: "IL", alt: "עִבְרִית"},
  {label: "Nederlands", key: "nl", country: "NL", alt: "Nederlands"},
  {label: "Polski", key: "pl", country: "PL", alt: "Polski"},
  {label: "Suomi", key: "fi", country: "FI", alt: "Suomi"},
  {label: "Svenska", key: "sv", country: "SE", alt: "Svenska"},
  {label: "Українська", key: "uk", country: "UA", alt: "Українська"},
  {label: "Қазақ", key: "kk", country: "KZ", alt: "Қазақ"},
  {label: "فارسی", key: "fa", country: "IR", alt: "فارسی"},
];

export function getThemeData(organization, application) {
  if (application?.themeData?.isEnabled) {
    return application.themeData;
  } else if (organization?.themeData?.isEnabled) {
    return organization.themeData;
  } else {
    return Conf.ThemeDefault;
  }
}

export function getAlgorithm(themeAlgorithmNames) {
  return themeAlgorithmNames.map((algorithmName) => {
    if (algorithmName === "dark") {
      return theme.darkAlgorithm;
    }
    if (algorithmName === "compact") {
      return theme.compactAlgorithm;
    }
    return theme.defaultAlgorithm;
  });
}

export function getAlgorithmNames(themeData) {
  const algorithms = [themeData?.themeType !== "dark" ? "default" : "dark"];
  if (themeData?.isCompact === true) {
    algorithms.push("compact");
  }

  return algorithms;
}

export const OtherProviderInfo = {
  SMS: {
    "Aliyun SMS": {
      logo: `${StaticBaseUrl}/img/social_aliyun.png`,
      url: "https://aliyun.com/product/sms",
    },
    "Amazon SNS": {
      logo: `${StaticBaseUrl}/img/social_aws.png`,
      url: "https://aws.amazon.com/cn/sns/",
    },
    "Azure ACS": {
      logo: `${StaticBaseUrl}/img/social_azure.png`,
      url: "https://azure.microsoft.com/en-us/products/communication-services",
    },
    "Infobip SMS": {
      logo: `${StaticBaseUrl}/img/social_infobip.png`,
      url: "https://portal.infobip.com/homepage/",
    },
    "Tencent Cloud SMS": {
      logo: `${StaticBaseUrl}/img/social_tencent_cloud.jpg`,
      url: "https://cloud.tencent.com/product/sms",
    },
    "Baidu Cloud SMS": {
      logo: `${StaticBaseUrl}/img/social_baidu_cloud.png`,
      url: "https://cloud.baidu.com/product/sms.html",
    },
    "Volc Engine SMS": {
      logo: `${StaticBaseUrl}/img/social_volc_engine.jpg`,
      url: "https://www.volcengine.com/products/cloud-sms",
    },
    "Huawei Cloud SMS": {
      logo: `${StaticBaseUrl}/img/social_huawei.png`,
      url: "https://www.huaweicloud.com/product/msgsms.html",
    },
    "UCloud SMS": {
      logo: `${StaticBaseUrl}/img/social_ucloud.png`,
      url: "https://www.ucloud.cn/site/product/usms.html",
    },
    "Twilio SMS": {
      logo: `${StaticBaseUrl}/img/social_twilio.svg`,
      url: "https://www.twilio.com/messaging",
    },
    "SmsBao SMS": {
      logo: `${StaticBaseUrl}/img/social_smsbao.png`,
      url: "https://www.smsbao.com/",
    },
    "SUBMAIL SMS": {
      logo: `${StaticBaseUrl}/img/social_submail.svg`,
      url: "https://www.mysubmail.com",
    },
    "Msg91 SMS": {
      logo: `${StaticBaseUrl}/img/social_msg91.ico`,
      url: "https://control.msg91.com/app/",
    },
    "Mock SMS": {
      logo: `${StaticBaseUrl}/img/social_default.png`,
      url: "",
    },
  },
  Email: {
    "Default": {
      logo: `${StaticBaseUrl}/img/email_default.png`,
      url: "",
    },
    "SUBMAIL": {
      logo: `${StaticBaseUrl}/img/social_submail.svg`,
      url: "https://www.mysubmail.com",
    },
    "Mailtrap": {
      logo: `${StaticBaseUrl}/img/email_mailtrap.png`,
      url: "https://mailtrap.io",
    },
    "Azure ACS": {
      logo: `${StaticBaseUrl}/img/social_azure.png`,
      url: "https://learn.microsoft.com/zh-cn/azure/communication-services",
    },
  },
  Storage: {
    "Local File System": {
      logo: `${StaticBaseUrl}/img/social_file.png`,
      url: "",
    },
    "AWS S3": {
      logo: `${StaticBaseUrl}/img/social_aws.png`,
      url: "https://aws.amazon.com/s3",
    },
    "MinIO": {
      logo: "https://min.io/resources/img/logo.svg",
      url: "https://min.io/",
    },
    "Aliyun OSS": {
      logo: `${StaticBaseUrl}/img/social_aliyun.png`,
      url: "https://aliyun.com/product/oss",
    },
    "Tencent Cloud COS": {
      logo: `${StaticBaseUrl}/img/social_tencent_cloud.jpg`,
      url: "https://cloud.tencent.com/product/cos",
    },
    "Azure Blob": {
      logo: `${StaticBaseUrl}/img/social_azure.png`,
      url: "https://azure.microsoft.com/en-us/services/storage/blobs/",
    },
    "Qiniu Cloud Kodo": {
      logo: `${StaticBaseUrl}/img/social_qiniu_cloud.png`,
      url: "https://www.qiniu.com/solutions/storage",
    },
    "Google Cloud Storage": {
      logo: `${StaticBaseUrl}/img/social_google_cloud.png`,
      url: "https://cloud.google.com/storage",
    },
  },
  SAML: {
    "Aliyun IDaaS": {
      logo: `${StaticBaseUrl}/img/social_aliyun.png`,
      url: "https://aliyun.com/product/idaas",
    },
    "Keycloak": {
      logo: `${StaticBaseUrl}/img/social_keycloak.png`,
      url: "https://www.keycloak.org/",
    },
  },
  Payment: {
    "Dummy": {
      logo: `${StaticBaseUrl}/img/payment_paypal.png`,
      url: "",
    },
    "Alipay": {
      logo: `${StaticBaseUrl}/img/payment_alipay.png`,
      url: "https://www.alipay.com/",
    },
    "WeChat Pay": {
      logo: `${StaticBaseUrl}/img/payment_wechat_pay.png`,
      url: "https://pay.weixin.qq.com/",
    },
    "PayPal": {
      logo: `${StaticBaseUrl}/img/payment_paypal.png`,
      url: "https://www.paypal.com/",
    },
    "Stripe": {
      logo: `${StaticBaseUrl}/img/social_stripe.png`,
      url: "https://stripe.com/",
    },
    "GC": {
      logo: `${StaticBaseUrl}/img/payment_gc.png`,
      url: "https://gc.org",
    },
  },
  Captcha: {
    "Default": {
      logo: `${StaticBaseUrl}/img/captcha_default.png`,
      url: "https://pkg.go.dev/github.com/dchest/captcha",
    },
    "reCAPTCHA": {
      logo: `${StaticBaseUrl}/img/social_recaptcha.png`,
      url: "https://www.google.com/recaptcha",
    },
    "hCaptcha": {
      logo: `${StaticBaseUrl}/img/social_hcaptcha.png`,
      url: "https://www.hcaptcha.com",
    },
    "Aliyun Captcha": {
      logo: `${StaticBaseUrl}/img/social_aliyun.png`,
      url: "https://help.aliyun.com/product/28308.html",
    },
    "GEETEST": {
      logo: `${StaticBaseUrl}/img/social_geetest.png`,
      url: "https://www.geetest.com",
    },
    "Cloudflare Turnstile": {
      logo: `${StaticBaseUrl}/img/social_cloudflare.png`,
      url: "https://www.cloudflare.com/products/turnstile/",
    },
  },
  AI: {
    "OpenAI API - GPT": {
      logo: `${StaticBaseUrl}/img/social_openai.svg`,
      url: "https://platform.openai.com",
    },
  },
  Web3: {
    "MetaMask": {
      logo: `${StaticBaseUrl}/img/social_metamask.svg`,
      url: "https://metamask.io/",
    },
    "Web3Onboard": {
      logo: `${StaticBaseUrl}/img/social_web3onboard.svg`,
      url: "https://onboard.blocknative.com/",
    },
  },
  Notification: {
    "Telegram": {
      logo: `${StaticBaseUrl}/img/social_telegram.png`,
      url: "https://telegram.org/",
    },
    "Custom HTTP": {
      logo: `${StaticBaseUrl}/img/email_default.png`,
      url: "https://casdoor.org/docs/provider/notification/overview",
    },
    "DingTalk": {
      logo: `${StaticBaseUrl}/img/social_dingtalk.png`,
      url: "https://www.dingtalk.com/",
    },
    "Lark": {
      logo: `${StaticBaseUrl}/img/social_lark.png`,
      url: "https://www.larksuite.com/",
    },
    "Microsoft Teams": {
      logo: `${StaticBaseUrl}/img/social_teams.png`,
      url: "https://www.microsoft.com/microsoft-teams",
    },
    "Bark": {
      logo: `${StaticBaseUrl}/img/social_bark.png`,
      url: "https://apps.apple.com/us/app/bark-customed-notifications/id1403753865",
    },
    "Pushover": {
      logo: `${StaticBaseUrl}/img/social_pushover.png`,
      url: "https://pushover.net/",
    },
    "Pushbullet": {
      logo: `${StaticBaseUrl}/img/social_pushbullet.png`,
      url: "https://www.pushbullet.com/",
    },
    "Slack": {
      logo: `${StaticBaseUrl}/img/social_slack.png`,
      url: "https://slack.com/",
    },
    "Webpush": {
      logo: `${StaticBaseUrl}/img/email_default.png`,
      url: "https://developer.mozilla.org/en-US/docs/Web/API/Push_API",
    },
    "Discord": {
      logo: `${StaticBaseUrl}/img/social_discord.png`,
      url: "https://discord.com/",
    },
    "Google Chat": {
      logo: `${StaticBaseUrl}/img/social_google_chat.png`,
      url: "https://workspace.google.com/intl/en/products/chat/",
    },
    "Line": {
      logo: `${StaticBaseUrl}/img/social_line.png`,
      url: "https://line.me/",
    },
    "Matrix": {
      logo: `${StaticBaseUrl}/img/social_matrix.png`,
      url: "https://www.matrix.org/",
    },
    "Twitter": {
      logo: `${StaticBaseUrl}/img/social_twitter.png`,
      url: "https://twitter.com/",
    },
    "Reddit": {
      logo: `${StaticBaseUrl}/img/social_reddit.png`,
      url: "https://www.reddit.com/",
    },
    "Rocket Chat": {
      logo: `${StaticBaseUrl}/img/social_rocket_chat.png`,
      url: "https://rocket.chat/",
    },
    "Viber": {
      logo: `${StaticBaseUrl}/img/social_viber.png`,
      url: "https://www.viber.com/",
    },
  },
};

export function initCountries() {
  const countries = require("i18n-iso-countries");
  countries.registerLocale(require("i18n-iso-countries/langs/" + getLanguage() + ".json"));
  return countries;
}

export function getCountryCode(country) {
  if (phoneNumber.isSupportedCountry(country)) {
    return phoneNumber.getCountryCallingCode(country);
  }
  return "";
}

export function getCountryCodeData(countryCodes = phoneNumber.getCountries()) {
  return countryCodes?.map((countryCode) => {
    if (phoneNumber.isSupportedCountry(countryCode)) {
      const name = initCountries().getName(countryCode, getLanguage());
      return {
        code: countryCode,
        name: name || "",
        phone: phoneNumber.getCountryCallingCode(countryCode),
      };
    }
  }).filter(item => item.name !== "")
    .sort((a, b) => a.phone - b.phone);
}

export function getCountryCodeOption(country) {
  return (
    <Option key={country.code} value={country.code} label={`+${country.phone}`} text={`${country.name}, ${country.code}, ${country.phone}`} >
      <div style={{display: "flex", justifyContent: "space-between", marginRight: "10px"}}>
        <div>
          {getCountryImage(country)}
          {`${country.name}`}
        </div>
        {`+${country.phone}`}
      </div>
    </Option>
  );
}

export function getCountryImage(country) {
  return <img src={`${StaticBaseUrl}/flag-icons/${country.code}.svg`} alt={country.name} height={20} style={{marginRight: 10}} />;
}

export function initServerUrl(serverUrl) {
  ServerUrl = serverUrl;
}

export function isLocalhost() {
  const hostname = window.location.hostname;
  return hostname === "localhost";
}

export function getFullServerUrl() {
  let fullServerUrl = window.location.origin;
  if (fullServerUrl === "http://localhost:7001") {
    fullServerUrl = "http://localhost:8000";
  }
  return fullServerUrl;
}

export function isProviderVisible(providerItem) {
  if (providerItem.provider === undefined || providerItem.provider === null) {
    return false;
  }

  if (!["OAuth", "SAML", "Web3"].includes(providerItem.provider.category)) {
    return false;
  }

  if (providerItem.provider.type === "WeChatMiniProgram") {
    return false;
  }

  return true;
}

export function isResponseDenied(data) {
  if (data.msg === "Unauthorized operation" || data.msg === "未授权的操作") {
    return true;
  }
  return false;
}

export function isProviderVisibleForSignUp(providerItem) {
  if (providerItem.canSignUp === false) {
    return false;
  }

  return isProviderVisible(providerItem);
}

export function isProviderVisibleForSignIn(providerItem) {
  if (providerItem.canSignIn === false) {
    return false;
  }

  return isProviderVisible(providerItem);
}

export function isProviderPrompted(providerItem) {
  return isProviderVisible(providerItem) && providerItem.prompted;
}

export function isSignupItemPrompted(signupItem) {
  return signupItem.visible && signupItem.prompted;
}

export function getAllPromptedProviderItems(application) {
  return application.providers?.filter(providerItem => isProviderPrompted(providerItem));
}

export function getAllPromptedSignupItems(application) {
  return application.signupItems?.filter(signupItem => isSignupItemPrompted(signupItem));
}

export function getSignupItem(application, itemName) {
  const signupItems = application.signupItems?.filter(signupItem => signupItem.name === itemName);
  if (signupItems?.length > 0) {
    return signupItems[0];
  }
  return null;
}

export function isValidPersonName(personName) {
  return personName !== "";

  // // https://blog.css8.cn/post/14210975.html
  // const personNameRegex = /^[\u4e00-\u9fa5]{2,6}$/;
  // return personNameRegex.test(personName);
}

export function isValidIdCard(idCard) {
  return idCard !== "";

  // const idCardRegex = /^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9X]$/;
  // return idCardRegex.test(idCard);
}

export function isValidEmail(email) {
  // https://github.com/yiminghe/async-validator/blob/057b0b047f88fac65457bae691d6cb7c6fe48ce1/src/rule/type.ts#L9
  const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return emailRegex.test(email);
}

export function isValidPhone(phone, countryCode = "") {
  if (countryCode !== "" && countryCode !== "CN") {
    return phoneNumber.isValidPhoneNumber(phone, countryCode);
  }

  // https://learnku.com/articles/31543, `^s*$` filter empty email individually.
  const phoneCnRegex = /^1(3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}$/;
  const phoneRegex = /[0-9]{4,15}$/;

  return countryCode === "CN" ? phoneCnRegex.test(phone) : phoneRegex.test(phone);
}

export function isValidInvoiceTitle(invoiceTitle) {
  return invoiceTitle !== "";

  // if (invoiceTitle === "") {
  //   return false;
  // }
  //
  // // https://blog.css8.cn/post/14210975.html
  // const invoiceTitleRegex = /^[()（）\u4e00-\u9fa5]{0,50}$/;
  // return invoiceTitleRegex.test(invoiceTitle);
}

export function isValidTaxId(taxId) {
  return taxId !== "";

  // // https://www.codetd.com/article/8592083
  // const regArr = [/^[\da-z]{10,15}$/i, /^\d{6}[\da-z]{10,12}$/i, /^[a-z]\d{6}[\da-z]{9,11}$/i, /^[a-z]{2}\d{6}[\da-z]{8,10}$/i, /^\d{14}[\dx][\da-z]{4,5}$/i, /^\d{17}[\dx][\da-z]{1,2}$/i, /^[a-z]\d{14}[\dx][\da-z]{3,4}$/i, /^[a-z]\d{17}[\dx][\da-z]{0,1}$/i, /^[\d]{6}[\da-z]{13,14}$/i];
  // for (let i = 0; i < regArr.length; i++) {
  //   if (regArr[i].test(taxId)) {
  //     return true;
  //   }
  // }
  // return false;
}

export function isAffiliationPrompted(application) {
  const signupItem = getSignupItem(application, "Affiliation");
  if (signupItem === null) {
    return false;
  }

  return signupItem.prompted;
}

export function hasPromptPage(application) {
  const providerItems = getAllPromptedProviderItems(application);
  if (providerItems?.length > 0) {
    return true;
  }

  const signupItems = getAllPromptedSignupItems(application);
  if (signupItems?.length > 0) {
    return true;
  }

  return isAffiliationPrompted(application);
}

function isAffiliationAnswered(user, application) {
  if (!isAffiliationPrompted(application)) {
    return true;
  }

  if (user === null) {
    return false;
  }
  return user.affiliation !== "";
}

function isProviderItemAnswered(user, application, providerItem) {
  if (user === null) {
    return false;
  }

  const provider = providerItem.provider;
  const linkedValue = user[provider.type.toLowerCase()];
  return linkedValue !== undefined && linkedValue !== "";
}

function isSignupItemAnswered(user, signupItem) {
  if (user === null) {
    return false;
  }

  if (signupItem.name !== "Country/Region") {
    return true;
  }

  const value = user["region"];
  return value !== undefined && value !== "";
}

export function isPromptAnswered(user, application) {
  if (!isAffiliationAnswered(user, application)) {
    return false;
  }

  const providerItems = getAllPromptedProviderItems(application);
  for (let i = 0; i < providerItems.length; i++) {
    if (!isProviderItemAnswered(user, application, providerItems[i])) {
      return false;
    }
  }

  const signupItems = getAllPromptedSignupItems(application);
  for (let i = 0; i < signupItems.length; i++) {
    if (!isSignupItemAnswered(user, signupItems[i])) {
      return false;
    }
  }
  return true;
}

export const MfaRuleRequired = "Required";
export const MfaRulePrompted = "Prompted";
export const MfaRuleOptional = "Optional";

export function isRequiredEnableMfa(user, organization) {
  if (!user || !organization || !organization.mfaItems) {
    return false;
  }
  return getMfaItemsByRules(user, organization, [MfaRuleRequired]).length > 0;
}

export function getMfaItemsByRules(user, organization, mfaRules = []) {
  if (!user || !organization || !organization.mfaItems) {
    return [];
  }

  return organization.mfaItems.filter((mfaItem) => mfaRules.includes(mfaItem.rule))
    .filter((mfaItem) => user.multiFactorAuths.some((mfa) => mfa.mfaType === mfaItem.name && !mfa.enabled));
}

export function parseObject(s) {
  try {
    return eval("(" + s + ")");
  } catch (e) {
    return null;
  }
}

export function parseJson(s) {
  if (s === "") {
    return null;
  } else {
    return JSON.parse(s);
  }
}

export function myParseInt(i) {
  const res = parseInt(i);
  return isNaN(res) ? 0 : res;
}

export function openLink(link) {
  // this.props.history.push(link);
  const w = window.open("about:blank");
  w.location.href = link;
}

export function openLinkSafe(link) {
  // Javascript window.open issue in safari
  // https://stackoverflow.com/questions/45569893/javascript-window-open-issue-in-safari
  const a = document.createElement("a");
  a.href = link;
  a.setAttribute("target", "_blank");
  a.click();
}

export function goToLink(link) {
  window.location.href = link;
}

export function goToLinkSoft(ths, link) {
  if (link.startsWith("http")) {
    openLink(link);
    return;
  }

  ths.props.history.push(link);
}

export function showMessage(type, text) {
  if (type === "success") {
    message.success(text);
  } else if (type === "error") {
    message.error(text);
  } else if (type === "info") {
    message.info(text);
  }
}

export function isAdminUser(account) {
  if (account === undefined || account === null) {
    return false;
  }
  return account.owner === "built-in";
}

export function isLocalAdminUser(account) {
  if (account === undefined || account === null) {
    return false;
  }
  return account.isAdmin === true || isAdminUser(account);
}

export function deepCopy(obj) {
  return Object.assign({}, obj);
}

export function addRow(array, row, position = "end") {
  return position === "end" ? [...array, row] : [row, ...array];
}

export function deleteRow(array, i) {
  // return array = array.slice(0, i).concat(array.slice(i + 1));
  return [...array.slice(0, i), ...array.slice(i + 1)];
}

export function swapRow(array, i, j) {
  return [...array.slice(0, i), array[j], ...array.slice(i + 1, j), array[i], ...array.slice(j + 1)];
}

export function trim(str, ch) {
  if (str === undefined) {
    return undefined;
  }

  let start = 0;
  let end = str.length;

  while (start < end && str[start] === ch) {++start;}

  while (end > start && str[end - 1] === ch) {--end;}

  return (start > 0 || end < str.length) ? str.substring(start, end) : str;
}

export function isMobile() {
  // return getIsMobileView();
  return isMobileDevice;
}

export function getFormattedDate(date) {
  if (!date) {
    return null;
  }

  const m = moment(date).local();
  return m.format("YYYY-MM-DD HH:mm:ss");
}

export function getFormattedDateShort(date) {
  return date.slice(0, 10);
}

export function getShortName(s) {
  return s.split("/").slice(-1)[0];
}

export function getNameAtLeast(s) {
  s = getShortName(s);
  if (s.length >= 6) {
    return s;
  }

  return (
    <React.Fragment>
      &nbsp;
      {s}
      &nbsp;
      &nbsp;
    </React.Fragment>
  );
}

export function getShortText(s, maxLength = 35) {
  if (s.length > maxLength) {
    return `${s.slice(0, maxLength)}...`;
  } else {
    return s;
  }
}

export function getFriendlyFileSize(size) {
  if (size < 1024) {
    return size + " B";
  }

  const i = Math.floor(Math.log(size) / Math.log(1024));
  let num = (size / Math.pow(1024, i));
  const round = Math.round(num);
  num = round < 10 ? num.toFixed(2) : round < 100 ? num.toFixed(1) : round;
  return `${num} ${"KMGTPEZY"[i - 1]}B`;
}

function getHashInt(s) {
  let hash = 0;
  if (s.length !== 0) {
    for (let i = 0; i < s.length; i++) {
      const char = s.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
  }

  if (hash < 0) {
    hash = -hash;
  }
  return hash;
}

export function getAvatarColor(s) {
  const colorList = ["#f56a00", "#7265e6", "#ffbf00", "#00a2ae"];
  const hash = getHashInt(s);
  return colorList[hash % 4];
}

export function getLanguageText(text) {
  if (!text.includes("|")) {
    return text;
  }

  let res;
  const tokens = text.split("|");
  if (getLanguage() !== "zh") {
    res = trim(tokens[0], "");
  } else {
    res = trim(tokens[1], "");
  }
  return res;
}

export function getLanguage() {
  return (i18next.language !== undefined && i18next.language !== null && i18next.language !== "" && i18next.language !== "null") ? i18next.language : Conf.DefaultLanguage;
}

export function setLanguage(language) {
  localStorage.setItem("language", language);
  i18next.changeLanguage(language);
}

export function getAcceptLanguage() {
  if (i18next.language === null || i18next.language === "") {
    return "en;q=0.9,en;q=0.8";
  }
  return i18next.language + ";q=0.9,en;q=0.8";
}

export function getClickable(text) {
  return (
    <a onClick={() => {
      copy(text);
      showMessage("success", "Copied to clipboard");
    }}>
      {text}
    </a>
  );
}

export function getProviderLogoURL(provider) {
  if (provider.category === "OAuth") {
    if (provider.type === "Custom" && provider.customLogo) {
      return provider.customLogo;
    }
    return `${StaticBaseUrl}/img/social_${provider.type.toLowerCase()}.png`;
  } else {
    const info = OtherProviderInfo[provider.category][provider.type];
    // avoid crash when provider is not found
    if (info) {
      return info.logo;
    }
    return "";
  }
}

export function getProviderLogo(provider) {
  const idp = provider.type.toLowerCase().trim().split(" ")[0];
  const url = getProviderLogoURL(provider);
  return (
    <img width={30} height={30} src={url} alt={idp} />
  );
}

export function getProviderTypeOptions(category) {
  if (category === "OAuth") {
    return (
      [
        {id: "Google", name: "Google"},
        {id: "GitHub", name: "GitHub"},
        {id: "QQ", name: "QQ"},
        {id: "WeChat", name: "WeChat"},
        {id: "WeChatMiniProgram", name: "WeChat Mini Program"},
        {id: "Facebook", name: "Facebook"},
        {id: "DingTalk", name: "DingTalk"},
        {id: "Weibo", name: "Weibo"},
        {id: "Gitee", name: "Gitee"},
        {id: "LinkedIn", name: "LinkedIn"},
        {id: "WeCom", name: "WeCom"},
        {id: "Lark", name: "Lark"},
        {id: "GitLab", name: "GitLab"},
        {id: "ADFS", name: "ADFS"},
        {id: "Baidu", name: "Baidu"},
        {id: "Alipay", name: "Alipay"},
        {id: "Casdoor", name: "Casdoor"},
        {id: "Infoflow", name: "Infoflow"},
        {id: "Apple", name: "Apple"},
        {id: "AzureAD", name: "AzureAD"},
        {id: "Slack", name: "Slack"},
        {id: "Steam", name: "Steam"},
        {id: "Bilibili", name: "Bilibili"},
        {id: "Okta", name: "Okta"},
        {id: "Douyin", name: "Douyin"},
        {id: "Line", name: "Line"},
        {id: "Amazon", name: "Amazon"},
        {id: "Auth0", name: "Auth0"},
        {id: "BattleNet", name: "Battle.net"},
        {id: "Bitbucket", name: "Bitbucket"},
        {id: "Box", name: "Box"},
        {id: "CloudFoundry", name: "Cloud Foundry"},
        {id: "Dailymotion", name: "Dailymotion"},
        {id: "Deezer", name: "Deezer"},
        {id: "DigitalOcean", name: "DigitalOcean"},
        {id: "Discord", name: "Discord"},
        {id: "Dropbox", name: "Dropbox"},
        {id: "EveOnline", name: "Eve Online"},
        {id: "Fitbit", name: "Fitbit"},
        {id: "Gitea", name: "Gitea"},
        {id: "Heroku", name: "Heroku"},
        {id: "InfluxCloud", name: "InfluxCloud"},
        {id: "Instagram", name: "Instagram"},
        {id: "Intercom", name: "Intercom"},
        {id: "Kakao", name: "Kakao"},
        {id: "Lastfm", name: "Lastfm"},
        {id: "Mailru", name: "Mailru"},
        {id: "Meetup", name: "Meetup"},
        {id: "MicrosoftOnline", name: "MicrosoftOnline"},
        {id: "Naver", name: "Naver"},
        {id: "Nextcloud", name: "Nextcloud"},
        {id: "OneDrive", name: "OneDrive"},
        {id: "Oura", name: "Oura"},
        {id: "Patreon", name: "Patreon"},
        {id: "PayPal", name: "PayPal"},
        {id: "SalesForce", name: "SalesForce"},
        {id: "Shopify", name: "Shopify"},
        {id: "Soundcloud", name: "Soundcloud"},
        {id: "Spotify", name: "Spotify"},
        {id: "Strava", name: "Strava"},
        {id: "Stripe", name: "Stripe"},
        {id: "TikTok", name: "TikTok"},
        {id: "Tumblr", name: "Tumblr"},
        {id: "Twitch", name: "Twitch"},
        {id: "Twitter", name: "Twitter"},
        {id: "Typetalk", name: "Typetalk"},
        {id: "Uber", name: "Uber"},
        {id: "VK", name: "VK"},
        {id: "Wepay", name: "Wepay"},
        {id: "Xero", name: "Xero"},
        {id: "Yahoo", name: "Yahoo"},
        {id: "Yammer", name: "Yammer"},
        {id: "Yandex", name: "Yandex"},
        {id: "Zoom", name: "Zoom"},
        {id: "Custom", name: "Custom"},
      ]
    );
  } else if (category === "Email") {
    return (
      [
        {id: "Default", name: "Default"},
        {id: "SUBMAIL", name: "SUBMAIL"},
        {id: "Mailtrap", name: "Mailtrap"},
        {id: "Azure ACS", name: "Azure ACS"},
      ]
    );
  } else if (category === "SMS") {
    return (
      [
        {id: "Aliyun SMS", name: "Alibaba Cloud SMS"},
        {id: "Amazon SNS", name: "Amazon SNS"},
        {id: "Azure ACS", name: "Azure ACS"},
        {id: "Infobip SMS", name: "Infobip SMS"},
        {id: "Tencent Cloud SMS", name: "Tencent Cloud SMS"},
        {id: "Baidu Cloud SMS", name: "Baidu Cloud SMS"},
        {id: "Volc Engine SMS", name: "Volc Engine SMS"},
        {id: "Huawei Cloud SMS", name: "Huawei Cloud SMS"},
        {id: "UCloud SMS", name: "UCloud SMS"},
        {id: "Twilio SMS", name: "Twilio SMS"},
        {id: "SmsBao SMS", name: "SmsBao SMS"},
        {id: "SUBMAIL SMS", name: "SUBMAIL SMS"},
        {id: "Msg91 SMS", name: "Msg91 SMS"},
      ]
    );
  } else if (category === "Storage") {
    return (
      [
        {id: "Local File System", name: "Local File System"},
        {id: "AWS S3", name: "AWS S3"},
        {id: "MinIO", name: "MinIO"},
        {id: "Aliyun OSS", name: "Alibaba Cloud OSS"},
        {id: "Tencent Cloud COS", name: "Tencent Cloud COS"},
        {id: "Azure Blob", name: "Azure Blob"},
        {id: "Qiniu Cloud Kodo", name: "Qiniu Cloud Kodo"},
        {id: "Google Cloud Storage", name: "Google Cloud Storage"},
      ]
    );
  } else if (category === "SAML") {
    return ([
      {id: "Aliyun IDaaS", name: "Aliyun IDaaS"},
      {id: "Keycloak", name: "Keycloak"},
    ]);
  } else if (category === "Payment") {
    return ([
      {id: "Dummy", name: "Dummy"},
      {id: "Alipay", name: "Alipay"},
      {id: "WeChat Pay", name: "WeChat Pay"},
      {id: "PayPal", name: "PayPal"},
      {id: "Stripe", name: "Stripe"},
      {id: "GC", name: "GC"},
    ]);
  } else if (category === "Captcha") {
    return ([
      {id: "Default", name: "Default"},
      {id: "reCAPTCHA", name: "reCAPTCHA"},
      {id: "hCaptcha", name: "hCaptcha"},
      {id: "Aliyun Captcha", name: "Aliyun Captcha"},
      {id: "GEETEST", name: "GEETEST"},
      {id: "Cloudflare Turnstile", name: "Cloudflare Turnstile"},
    ]);
  } else if (category === "Web3") {
    return ([
      {id: "MetaMask", name: "MetaMask"},
      {id: "Web3Onboard", name: "Web3-Onboard"},
    ]);
  } else if (category === "Notification") {
    return ([
      {id: "Telegram", name: "Telegram"},
      {id: "Custom HTTP", name: "Custom HTTP"},
      {id: "DingTalk", name: "DingTalk"},
      {id: "Lark", name: "Lark"},
      {id: "Microsoft Teams", name: "Microsoft Teams"},
      {id: "Bark", name: "Bark"},
      {id: "Pushover", name: "Pushover"},
      {id: "Pushbullet", name: "Pushbullet"},
      {id: "Slack", name: "Slack"},
      {id: "Webpush", name: "Webpush"},
      {id: "Discord", name: "Discord"},
      {id: "Google Chat", name: "Google Chat"},
      {id: "Line", name: "Line"},
      {id: "Matrix", name: "Matrix"},
      {id: "Twitter", name: "Twitter"},
      {id: "Reddit", name: "Reddit"},
      {id: "Rocket Chat", name: "Rocket Chat"},
      {id: "Viber", name: "Viber"},
    ]);
  } else {
    return [];
  }
}

export function renderLogo(application) {
  if (application === null) {
    return null;
  }

  const defaultLogoSvg = <svg className="panel-logo" width="74" height="30" viewBox="0 0 74 30" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M67.0173 20.2C64.4173 20.2 62.2773 18.06 62.2773 14.9C62.2773 11.74 64.4173 9.6 67.0173 9.6C68.3773 9.6 69.3773 10.22 69.7373 10.68H69.8373V6H72.8573V20H70.2573L70.0573 19H69.9573C69.4773 19.64 68.4773 20.2 67.0173 20.2ZM67.5773 17.42C68.8573 17.42 69.8373 16.46 69.8373 14.9C69.8373 13.34 68.8573 12.4 67.5773 12.4C66.2973 12.4 65.3173 13.34 65.3173 14.9C65.3173 16.46 66.2973 17.42 67.5773 17.42Z" fill="#2E3A52" /><path d="M54.6094 20.2008C52.2694 20.2008 50.6094 18.5408 50.6094 15.9408V9.80078H53.6294V15.4408C53.6294 16.5408 54.3694 17.3408 55.4894 17.3408C56.6094 17.3408 57.3494 16.5408 57.3494 15.4408V9.80078H60.3694V20.0008H57.7694L57.5694 19.1008H57.4694C56.9894 19.6608 55.9494 20.2008 54.6094 20.2008Z" fill="#2E3A52" /><path d="M43.3791 20.1996C40.2991 20.1996 38.0391 17.9196 38.0391 14.8996C38.0391 11.8796 40.2991 9.59961 43.3791 9.59961C46.4591 9.59961 48.7191 11.8796 48.7191 14.8996C48.7191 17.9196 46.4591 20.1996 43.3791 20.1996ZM43.3791 17.3996C44.6591 17.3996 45.6991 16.3996 45.6991 14.8996C45.6991 13.3996 44.6591 12.3996 43.3791 12.3996C42.0991 12.3996 41.0591 13.3996 41.0591 14.8996C41.0591 16.3996 42.0991 17.3996 43.3791 17.3996Z" fill="#2E3A52" /><path d="M36.0342 20H33.0142V6H36.0342V20Z" fill="#2E3A52" /><path d="M26.0553 20.1996C22.9753 20.1996 20.6953 17.9196 20.6953 14.8996C20.6953 11.8796 22.9753 9.59961 26.0553 9.59961C29.2153 9.59961 30.7753 11.8596 31.1153 13.7796H28.0553C27.8553 13.1796 27.3353 12.3996 26.0553 12.3996C24.7753 12.3996 23.7353 13.3996 23.7353 14.8996C23.7353 16.3996 24.7753 17.4196 26.0553 17.4196C27.3353 17.4196 27.8553 16.6396 28.0553 15.9796H31.1153C30.7753 17.9396 29.2153 20.1996 26.0553 20.1996Z" fill="#2E3A52" /><path d="M19.4854 20.0006H17.1454C15.1854 20.0006 14.1654 18.9806 14.1654 17.2206V12.6606H12.5654V9.80062H14.1654V6.64062H17.1854V9.80062H19.4854V12.6606H17.1854V16.5806C17.1854 17.0806 17.3854 17.2806 17.8854 17.2806H19.4854V20.0006Z" fill="#2E3A52" /><path d="M4.02 23.9996H1V9.79961H3.6L3.8 10.7996H3.9C4.38 10.1596 5.4 9.59961 6.82 9.59961C9.42 9.59961 11.56 11.7396 11.56 14.8996C11.56 18.0596 9.42 20.1996 6.82 20.1996C5.44 20.1996 4.46 19.6196 4.12 19.1796H4.02V23.9996ZM6.28 17.4196C7.56 17.4196 8.54 16.4596 8.54 14.8996C8.54 13.3396 7.56 12.3996 6.28 12.3996C5 12.3996 4.02 13.3396 4.02 14.8996C4.02 16.4596 5 17.4196 6.28 17.4196Z" fill="#2E3A52" /></svg>;
  const logoImg = <img className="panel-logo" height={30} src={application.logo} alt={application.displayName} />;

  if (application.homepageUrl !== "") {
    return (
      <a target="_blank" rel="noreferrer" href={application.homepageUrl}>
        {application.logo ? logoImg : defaultLogoSvg}
      </a>
    );
  } else {
    return application.logo ? logoImg : defaultLogoSvg;
  }
}

export function getLoginLink(application) {
  let url;
  if (application === null) {
    url = null;
  } else if (!application.enablePassword && window.location.pathname.includes("/auto-signup/oauth/authorize")) {
    url = window.location.href.replace("/auto-signup/oauth/authorize", "/login/oauth/authorize");
  } else if (authConfig.appName === application.name) {
    url = "/login";
  } else if (application.signinUrl === "") {
    url = trim(application.homepageUrl, "/") + "/login";
  } else {
    url = application.signinUrl;
  }
  return url;
}

export function renderLoginLink(application, text) {
  const url = getLoginLink(application);
  return renderLink(url, text, null);
}

export function redirectToLoginPage(application, history) {
  const loginLink = getLoginLink(application);
  if (loginLink.startsWith("http://") || loginLink.startsWith("https://")) {
    goToLink(loginLink);
  } else {
    history.push(loginLink);
  }
}

function renderLink(url, text, onClick) {
  if (url === null) {
    return null;
  }

  if (url.startsWith("/")) {
    return (
      <Link to={url} onClick={() => {
        if (onClick !== null) {
          onClick();
        }
      }}>{text}</Link>
    );
  } else if (url.startsWith("http")) {
    return (
      <a target="_blank" rel="noopener noreferrer" style={{float: "right"}} href={url} onClick={() => {
        if (onClick !== null) {
          onClick();
        }
      }}>{text}</a>
    );
  } else {
    return null;
  }
}

export function renderSignupLink(application, text) {
  let url;
  if (application === null) {
    url = null;
  } else if (!application.enablePassword && window.location.pathname.includes("/login/oauth/authorize")) {
    url = window.location.href.replace("/login/oauth/authorize", "/auto-signup/oauth/authorize");
  } else if (authConfig.appName === application.name) {
    url = "/signup";
  } else {
    if (application.signupUrl === "") {
      url = `/signup/${application.name}`;
    } else {
      url = application.signupUrl;
    }
  }

  const storeSigninUrl = () => {
    sessionStorage.setItem("signinUrl", window.location.href);
  };

  return renderLink(url, text, storeSigninUrl);
}

export function renderForgetLink(application, text) {
  let url;
  if (application === null) {
    url = null;
  } else if (authConfig.appName === application.name) {
    url = "/forget";
  } else {
    if (application.forgetUrl === "") {
      url = `/forget/${application.name}`;
    } else {
      url = application.forgetUrl;
    }
  }

  return renderLink(url, text, null);
}

export function renderHelmet(application) {
  if (application === undefined || application === null || application.organizationObj === undefined || application.organizationObj === null || application.organizationObj === "") {
    return null;
  }

  return (
    <Helmet>
      <title>{application.organizationObj.displayName}</title>
      <link rel="icon" href={application.organizationObj.favicon} />
    </Helmet>
  );
}

export function getLabel(text, tooltip) {
  return (
    <React.Fragment>
      <span style={{marginRight: 4}}>{text}</span>
      <Tooltip placement="top" title={tooltip}>
        <QuestionCircleTwoTone twoToneColor="rgb(45,120,213)" />
      </Tooltip>
    </React.Fragment>
  );
}

export function getItem(label, key, icon, children, type) {
  return {label: label, key: key, icon: icon, children: children, type: type};
}

export function getOption(label, value) {
  return {
    label,
    value,
  };
}

export function getArrayItem(array, key, value) {
  const res = array.filter(item => item[key] === value)[0];
  return res;
}

export function getDeduplicatedArray(array, filterArray, key) {
  const res = array.filter(item => !filterArray.some(tableItem => tableItem[key] === item[key]));
  return res;
}

export function getNewRowNameForTable(table, rowName) {
  const emptyCount = table.filter(row => row.name.includes(rowName)).length;
  let res = rowName;
  for (let i = 0; i < emptyCount; i++) {
    res = res + " ";
  }
  return res;
}

export function getTagColor(s) {
  return "processing";
}

export function getTags(tags, urlPrefix = null) {
  const res = [];
  if (!tags) {
    return res;
  }

  tags.forEach((tag, i) => {
    if (urlPrefix === null) {
      res.push(
        <Tag color={getTagColor(tag)}>
          {tag}
        </Tag>
      );
    } else {
      res.push(
        <Link to={`/${urlPrefix}/${tag}`}>
          <Tag color={getTagColor(tag)}>
            {tag}
          </Tag>
        </Link>
      );
    }
  });
  return res;
}

export function getTag(color, text, icon) {
  return (
    <Tag color={color} icon={icon}>
      {text}
    </Tag>
  );
}

export function getApplicationName(application) {
  return `${application?.owner}/${application?.name}`;
}

export function getRandomName() {
  return Math.random().toString(36).slice(-6);
}

export function getRandomNumber() {
  return Math.random().toString(10).slice(-11);
}

export function getFromLink() {
  const from = sessionStorage.getItem("from");
  if (from === null) {
    return "/";
  }
  return from;
}

export function scrollToDiv(divId) {
  if (divId) {
    const ele = document.getElementById(divId);
    if (ele) {
      ele.scrollIntoView({behavior: "smooth"});
    }
  }
}

export function inIframe() {
  try {
    return window !== window.parent;
  } catch (e) {
    return true;
  }
}

export function getOrganization() {
  const organization = localStorage.getItem("organization");
  return organization !== null ? organization : "All";
}

export function setOrganization(organization) {
  localStorage.setItem("organization", organization);
  window.dispatchEvent(new Event("storageOrganizationChanged"));
}

export function getRequestOrganization(account) {
  if (isAdminUser(account)) {
    return getOrganization() === "All" ? account.owner : getOrganization();
  }
  return account.owner;
}

export function isDefaultOrganizationSelected(account) {
  if (isAdminUser(account)) {
    return getOrganization() === "All";
  }
  return false;
}

const BuiltInObjects = [
  "api-enforcer-built-in",
  "user-enforcer-built-in",
  "api-model-built-in",
  "user-model-built-in",
  "api-adapter-built-in",
  "user-adapter-built-in",
];

export function builtInObject(obj) {
  if (obj === undefined || obj === null) {
    return false;
  }
  return obj.owner === "built-in" && BuiltInObjects.includes(obj.name);
}

export const CertScopeJWT = "JWT";
export const CertScopeCACert = "CA Certificate";
export const CertScopeClientCert = "Client Certificate";

export const SamlNoRequestSign = "No sign";
export const SamlSignRequestWithFile = "Sign with default file";
export const SamlSignRequestWithCertificate = "Sign with certificate";

export function getCurrencySymbol(currency) {
  if (currency === "USD" || currency === "usd") {
    return "$";
  } else if (currency === "CNY" || currency === "cny") {
    return "¥";
  } else {
    return currency;
  }
}
