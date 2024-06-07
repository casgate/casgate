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

import * as Setting from "../Setting";
import i18next from "i18next";

export function sendTestEmail(provider, email) {
  testEmailProvider(provider, email)
    .then((res) => {
      if (res.status === "ok") {
        Setting.showMessage("success", i18next.t("general:Successfully sent"));
      } else {
        Setting.showMessage("error", res.msg);
      }
    })
    .catch(error => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
}

export function connectSmtpServer(provider) {
  testEmailProvider(provider)
    .then((res) => {
      if (res.status === "ok") {
        Setting.showMessage("success", "provider:SMTP connected successfully");
      } else {
        Setting.showMessage("error", res.msg);
      }
    })
    .catch(error => {
      Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
    });
}

function testEmailProvider(provider, email = "") {
  const emailForm = {
    title: provider.title,
    content: provider.content,
    sender: provider.displayName,
    receivers: email === "" ? ["TestSmtpServer"] : [email],
    provider: provider.name,
    owner: provider.owner,
  };

  return fetch(`${Setting.ServerUrl}/api/send-email`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(emailForm),
  }).then(res => res.json());
}
