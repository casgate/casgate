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

import "core-js/es";
import "react-app-polyfill/ie9";
import "react-app-polyfill/stable";
import React from "react";
import {createRoot} from "react-dom/client";
import "./index.css";
import "./App.less";
import App from "./App";
import * as serviceWorker from "./serviceWorker";
import {BrowserRouter} from "react-router-dom";
import "./backend/FetchFilter";
import * as Setting from "./Setting";

const container = document.getElementById("root");
const baseHref = document.getElementsByTagName("base")[0].getAttribute("href").slice(0, -1);
let baselink = "";
if (baseHref) {
  baselink = new URL(baseHref).pathname;
}

const app = createRoot(container);
Setting.initServerUrl(baselink);

app.render(<BrowserRouter basename={baselink}>
  <App />
</BrowserRouter>);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
