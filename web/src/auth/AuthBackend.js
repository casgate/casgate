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

import {authConfig} from "./Auth";
import * as Setting from "../Setting";
import {getStateFromQueryParams} from "./Util";

export function getAccount(query = "") {
  return fetch(`${authConfig.serverUrl}/api/get-account${query}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function signup(values) {
  return fetch(`${authConfig.serverUrl}/api/signup`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getEmailAndPhone(organization, applicationId, username, captchaToken, captchaCode) {
  return fetch(`${authConfig.serverUrl}/api/get-email-and-phone?organization=${organization}&applicationId=${applicationId}&username=${username}&captchaToken=${captchaToken}&captchaCode=${captchaCode}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then((res) => res.json());
}

export function casLoginParamsToQuery(casParams) {
  return `?type=${casParams?.type}&id=${casParams?.id}&redirectUri=${casParams?.service}`;
}

export function oAuthParamsToQuery(oAuthParams) {
  // login
  if (oAuthParams === null || oAuthParams === undefined) {
    return "";
  }

  // code
  return `?clientId=${oAuthParams.clientId}&responseType=${oAuthParams.responseType}&redirectUri=${encodeURIComponent(oAuthParams.redirectUri)}&type=${oAuthParams.type}&scope=${oAuthParams.scope}&state=${oAuthParams.state}&nonce=${oAuthParams.nonce}&code_challenge_method=${oAuthParams.challengeMethod}&code_challenge=${oAuthParams.codeChallenge}`;
}

export function getApplicationLogin(params) {
  const queryParams = (params?.type === "cas") ? casLoginParamsToQuery(params) : oAuthParamsToQuery(params);
  return fetch(`${authConfig.serverUrl}/api/get-app-login${queryParams}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function login(values, oAuthParams) {
  return fetch(`${authConfig.serverUrl}/api/login${oAuthParamsToQuery(oAuthParams)}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function loginCas(values, params) {
  return fetch(`${authConfig.serverUrl}/api/login?service=${params.service}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function logout() {
  return fetch(`${authConfig.serverUrl}/api/logout`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function unlink(values) {
  return fetch(`${authConfig.serverUrl}/api/unlink`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getSamlLogin(providerId, relayState) {
  return fetch(`${authConfig.serverUrl}/api/get-saml-login?id=${providerId}&relayState=${relayState}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function loginWithSaml(values, param) {
  return fetch(`${authConfig.serverUrl}/api/login${param}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getAuthURL(provider, application, method) {
  const applicationID = application.owner + "/" + application.name;
  const providerID = provider.owner + "/" + provider.name;
  const params = new URLSearchParams({
    providerID,
    applicationID,
    method,
  });
  const isShortState = provider.type === "WeChat" && navigator.userAgent.includes("MicroMessenger");
  const state = getStateFromQueryParams(application.name, provider.name, method, isShortState);
  // eslint-disable-next-line no-console
  console.log(state);
  return fetch(`${authConfig.serverUrl}/api/get-auth-url?${params.toString()}&state=${state}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getWechatMessageEvent() {
  return fetch(`${Setting.ServerUrl}/api/get-webhook-event`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getCaptchaStatus(values) {
  return fetch(`${Setting.ServerUrl}/api/get-captcha-status?organization=${values["organization"]}&user_id=${values["username"]}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}
