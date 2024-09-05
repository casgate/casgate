// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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

package util

import (
	"slices"
	"sort"
)

func DeleteVal(values []string, val string) []string {
	newValues := []string{}
	for _, v := range values {
		if v != val {
			newValues = append(newValues, v)
		}
	}
	return newValues
}

func ReplaceVal(values []string, oldVal string, newVal string) []string {
	newValues := []string{}
	for _, v := range values {
		if v == oldVal {
			newValues = append(newValues, newVal)
		} else {
			newValues = append(newValues, v)
		}
	}
	return newValues
}

func ContainsString(values []string, val string) bool {
	sort.Strings(values)
	_, found := slices.BinarySearch(values, val)

	return found
}

func InSlice(slice []string, elem string) bool {
	for _, val := range slice {
		if val == elem {
			return true
		}
	}
	return false
}

func ReturnAnyNotEmpty(strs ...string) string {
	for _, str := range strs {
		if str != "" {
			return str
		}
	}
	return ""
}

func MapStrings(data []string, f func(string) string) []string {

	mapped := make([]string, len(data))

	for i, e := range data {
		mapped[i] = f(e)
	}

	return mapped
}
