// Copyright 2017 Vector Creations Ltd
// Copyright 2017 New Vector Ltd
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

package routing

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/common/config"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
)

type authDict struct {
	Type    authtypes.LoginType         `json:"type"`
	Session string                      `json:"session"`
	Mac     gomatrixserverlib.HexString `json:"mac"`

	// Recaptcha
	Response string `json:"response"`
	// TODO: Lots of custom keys depending on the type
}

// sessionsDict keeps track of completed auth stages for each session.
type sessionsDict struct {
	sessions map[string][]authtypes.LoginType
}

// GetCompletedStages returns the completed stages for a session.
func (d sessionsDict) GetCompletedStages(sessionID string) []authtypes.LoginType {
	if completedStages, ok := d.sessions[sessionID]; ok {
		return completedStages
	}
	// Ensure that a empty slice is returned and not nil. See #399.
	return make([]authtypes.LoginType, 0)
}

// AAddCompletedStage records that a session has completed an auth stage.
func (d *sessionsDict) AddCompletedStage(sessionID string, stage authtypes.LoginType) {
	d.sessions[sessionID] = append(d.GetCompletedStages(sessionID), stage)
}

func newSessionsDict() *sessionsDict {
	return &sessionsDict{
		sessions: make(map[string][]authtypes.LoginType),
	}
}

// UserInteractiveFlowRequest is a generic flowRequest type for any auth call to UIAA handler
type UserInteractiveFlowRequest struct {
	// user-interactive auth params
	Auth authDict `json:"auth"`
}

// UserInteractiveResponse is response returned by UIAA flow handler to the client
// http://matrix.org/speculator/spec/HEAD/client_server/unstable.html#user-interactive-authentication-api
type UserInteractiveResponse struct {
	Flows     []authtypes.Flow       `json:"flows"`
	Completed []authtypes.LoginType  `json:"completed"`
	Params    map[string]interface{} `json:"params"`
	Session   string                 `json:"session"`
}

// newUserInteractiveResponse will return a struct to be sent back to the client
func newUserInteractiveResponse(
	sessionID string,
	fs []authtypes.Flow,
	params map[string]interface{},
) UserInteractiveResponse {
	return UserInteractiveResponse{
		fs, sessions.GetCompletedStages(sessionID), params, sessionID,
	}
}

// recaptchaResponse represents the HTTP response from a Google Recaptcha server
type recaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// validateRecaptcha returns an error response if the captcha response is invalid
func validateRecaptcha(
	cfg *config.Dendrite,
	response string,
	clientip string,
) *util.JSONResponse {
	if !cfg.Matrix.RecaptchaEnabled {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("Captcha registration is disabled"),
		}
	}

	if response == "" {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("Captcha response is required"),
		}
	}

	// Make a POST request to Google's API to check the captcha response
	resp, err := http.PostForm(cfg.Matrix.RecaptchaSiteVerifyAPI,
		url.Values{
			"secret":   {cfg.Matrix.RecaptchaPrivateKey},
			"response": {response},
			"remoteip": {clientip},
		},
	)

	if err != nil {
		return &util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.BadJSON("Error in requesting validation of captcha response"),
		}
	}

	// Close the request once we're finishing reading from it
	defer resp.Body.Close() // nolint: errcheck

	// Grab the body of the response from the captcha server
	var r recaptchaResponse
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.BadJSON("Error in contacting captcha server" + err.Error()),
		}
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return &util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.BadJSON("Error in unmarshaling captcha server's response: " + err.Error()),
		}
	}

	// Check that we received a "success"
	if !r.Success {
		return &util.JSONResponse{
			Code: http.StatusUnauthorized,
			JSON: jsonerror.BadJSON("Invalid captcha response. Please try again."),
		}
	}
	return nil
}

// HandleUserInteractiveFlow will direct and complete UIAA flow stages that the client has requested.
// It accepts a pointer to http request, an interface of type UserInteractiveFlowRequest, config,
// sessionID and a list of required stages to complete the flow as config.UserInteractiveAuthConfig
// and returns UserInteractiveResponse as specified in
// https://matrix.org/docs/spec/client_server/r0.3.0.html#user-interactive-authentication-api
// The function returns nil if authenticated successfully.
func HandleUserInteractiveFlow(
	req *http.Request,
	r UserInteractiveFlowRequest,
	sessionID string,
	cfg *config.Dendrite,
	res config.UserInteractiveAuthConfig,
) *util.JSONResponse {

	// TODO: email / msisdn auth types.

	switch r.Auth.Type {
	case "":
		// If no auth type is specified by the client, send back the list of available flows
		return &util.JSONResponse{
			Code: http.StatusUnauthorized,
			JSON: newUserInteractiveResponse(sessionID,
				res.Flows, res.Params),
		}

	case authtypes.LoginTypeRecaptcha:
		// Check given captcha response
		resErr := validateRecaptcha(cfg, r.Auth.Response, req.RemoteAddr)
		if resErr != nil {
			return resErr
		}

		// Add Recaptcha to the list of completed stages
		sessions.AddCompletedStage(sessionID, authtypes.LoginTypeRecaptcha)

	case authtypes.LoginTypeDummy:
		// there is nothing to do
		// Add Dummy to the list of completed stages
		sessions.AddCompletedStage(sessionID, authtypes.LoginTypeDummy)

	default:
		return &util.JSONResponse{
			Code: http.StatusNotImplemented,
			JSON: jsonerror.Unknown("unknown/unimplemented auth type"),
		}
	}

	// Check if the user's flow has been completed successfully
	// A response with current flow and remaining available methods
	// will be returned if a flow has not been successfully completed yet
	return checkAndCompleteFlow(sessions.GetCompletedStages(sessionID), sessionID, res)
}

// checkAndCompleteFlow checks if a given flow is completed given
// a set of allowed flows. If so, task is completed, otherwise a
// response with more stages to complete is returned.
func checkAndCompleteFlow(
	flow []authtypes.LoginType,
	sessionID string,
	allowedFlows config.UserInteractiveAuthConfig,
) *util.JSONResponse {
	if checkFlowCompleted(flow, allowedFlows.Flows) {
		// This flow was completed, task can continue
		return nil
	}

	// There are still more stages to complete.
	// Return the flows and those that have been completed.
	return &util.JSONResponse{
		Code: http.StatusUnauthorized,
		JSON: newUserInteractiveResponse(sessionID,
			allowedFlows.Flows, allowedFlows.Params),
	}
}

// checkFlows checks a single completed flow against another required one. If
// one contains at least all of the stages that the other does, checkFlows
// returns true.
func checkFlows(
	completedStages []authtypes.LoginType,
	requiredStages []authtypes.LoginType,
) bool {
	// Create temporary slices so they originals will not be modified on sorting
	completed := make([]authtypes.LoginType, len(completedStages))
	required := make([]authtypes.LoginType, len(requiredStages))
	copy(completed, completedStages)
	copy(required, requiredStages)

	// Sort the slices for simple comparison
	sort.Slice(completed, func(i, j int) bool { return completed[i] < completed[j] })
	sort.Slice(required, func(i, j int) bool { return required[i] < required[j] })

	// Iterate through each slice, going to the next required slice only once
	// we've found a match.
	i, j := 0, 0
	for j < len(required) {
		// Exit if we've reached the end of our input without being able to
		// match all of the required stages.
		if i >= len(completed) {
			return false
		}

		// If we've found a stage we want, move on to the next required stage.
		if completed[i] == required[j] {
			j++
		}
		i++
	}
	return true
}

// checkFlowCompleted checks if a flow complies with any allowed flow
// dictated by the server. Order of stages does not matter. A user may complete
// extra stages as long as the required stages of at least one flow is met.
func checkFlowCompleted(
	flow []authtypes.LoginType,
	allowedFlows []authtypes.Flow,
) bool {
	// Iterate through possible flows to check whether any have been fully completed.
	for _, allowedFlow := range allowedFlows {
		if checkFlows(flow, allowedFlow.Stages) {
			return true
		}
	}
	return false
}
