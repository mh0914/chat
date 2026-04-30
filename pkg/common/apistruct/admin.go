// Copyright © 2023 OpenIM open source community. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apistruct

import "github.com/openimsdk/protocol/sdkws"

type AdminLoginResp struct {
	AdminAccount string `json:"adminAccount"`
	AdminToken   string `json:"adminToken"`
	Nickname     string `json:"nickname"`
	FaceURL      string `json:"faceURL"`
	Level        int32  `json:"level"`
	AdminUserID  string `json:"adminUserID"`
	ImUserID     string `json:"imUserID"`
	ImToken      string `json:"imToken"`
}

type SearchDefaultGroupResp struct {
	Total  uint32             `json:"total"`
	Groups []*sdkws.GroupInfo `json:"groups"`
}

type NewUserCountResp struct {
	Total     int64            `json:"total"`
	DateCount map[string]int64 `json:"date_count"`
}

type PlatformOperatorUser struct {
	UserID                 string `json:"userID"`
	Account                string `json:"account"`
	PhoneNumber            string `json:"phoneNumber"`
	AreaCode               string `json:"areaCode"`
	Email                  string `json:"email"`
	Nickname               string `json:"nickname"`
	FaceURL                string `json:"faceURL"`
	Gender                 int32  `json:"gender"`
	Level                  int32  `json:"level"`
	IsPlatformOperator     bool   `json:"isPlatformOperator"`
	IsSmartCustomerService bool   `json:"isSmartCustomerService"`
}

type SearchPlatformOperatorUsersResp struct {
	Total uint32                  `json:"total"`
	Users []*PlatformOperatorUser `json:"users"`
}
