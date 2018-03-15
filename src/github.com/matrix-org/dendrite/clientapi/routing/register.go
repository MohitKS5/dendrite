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
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/matrix-org/dendrite/common/config"
	"net/http"
	"regexp"
	"strings"

	"github.com/matrix-org/dendrite/clientapi/auth"
	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/clientapi/auth/storage/accounts"
	"github.com/matrix-org/dendrite/clientapi/auth/storage/devices"
	"github.com/matrix-org/dendrite/clientapi/httputil"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/util"
	log "github.com/sirupsen/logrus"
)

const (
	minPasswordLength = 8   // http://matrix.org/docs/spec/client_server/r0.2.0.html#password-based
	maxPasswordLength = 512 // https://github.com/matrix-org/synapse/blob/v0.20.0/synapse/rest/client/v2_alpha/register.py#L161
	maxUsernameLength = 254 // http://matrix.org/speculator/spec/HEAD/intro.html#user-identifiers TODO account for domain
	sessionIDLength   = 24
)

var (
	// TODO: Remove old sessions. Need to do so on a session-specific timeout.
	// sessions stores the completed flow stages for all sessions. Referenced using their sessionID.
	sessions           = newSessionsDict()
	validUsernameRegex = regexp.MustCompile(`^[0-9a-z_\-./]+$`)
)

// registerRequest represents the submitted registration request.
// It can be broken down into 2 sections: the auth dictionary and registration parameters.
// Registration parameters vary depending on the request, and will need to remembered across
// sessions. If no parameters are supplied, the server should use the parameters previously
// remembered. If ANY parameters are supplied, the server should REPLACE all knowledge of
// previous parameters with the ones supplied. This mean you cannot "build up" request params.
type registerRequest struct {
	// registration parameters
	Password string `json:"password"`
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
	// user-interactive auth params
	UserInteractiveFlowRequest

	InitialDisplayName *string `json:"initial_device_display_name"`
}

// legacyRegisterRequest represents the submitted registration request for v1 API.
type legacyRegisterRequest struct {
	Password string                      `json:"password"`
	Username string                      `json:"user"`
	Admin    bool                        `json:"admin"`
	Type     authtypes.LoginType         `json:"type"`
	Mac      gomatrixserverlib.HexString `json:"mac"`
}

// http://matrix.org/speculator/spec/HEAD/client_server/unstable.html#post-matrix-client-unstable-register
type registerResponse struct {
	UserID      string                       `json:"user_id"`
	AccessToken string                       `json:"access_token"`
	HomeServer  gomatrixserverlib.ServerName `json:"home_server"`
	DeviceID    string                       `json:"device_id"`
}

func validateCredentials(username, password string) *util.JSONResponse {
	if resErr := validateUserName(username); resErr != nil {
		return resErr
	}
	if resErr := validatePassword(password); resErr != nil {
		return resErr
	}
	return nil
}

// validateUserName returns an error response if the username is invalid
func validateUserName(username string) *util.JSONResponse {
	// https://github.com/matrix-org/synapse/blob/v0.20.0/synapse/rest/client/v2_alpha/register.py#L161
	if len(username) > maxUsernameLength {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON(fmt.Sprintf("'username' >%d characters", maxUsernameLength)),
		}
	} else if !validUsernameRegex.MatchString(username) {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidUsername("User ID can only contain characters a-z, 0-9, or '_-./'"),
		}
	} else if username[0] == '_' { // Regex checks its not a zero length string
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidUsername("User ID can't start with a '_'"),
		}
	}
	return nil
}

// validatePassword returns an error response if the password is invalid
func validatePassword(password string) *util.JSONResponse {
	// https://github.com/matrix-org/synapse/blob/v0.20.0/synapse/rest/client/v2_alpha/register.py#L161
	if len(password) > maxPasswordLength {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON(fmt.Sprintf("'password' >%d characters", maxPasswordLength)),
		}
	} else if len(password) > 0 && len(password) < minPasswordLength {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.WeakPassword(fmt.Sprintf("password too weak: min %d chars", minPasswordLength)),
		}
	}
	return nil
}

// UsernameIsWithinApplicationServiceNamespace checks to see if a username falls
// within any of the namespaces of a given Application Service. If no
// Application Service is given, it will check to see if it matches any
// Application Service's namespace.
func UsernameIsWithinApplicationServiceNamespace(
	cfg *config.Dendrite,
	username string,
	appservice *config.ApplicationService,
) bool {
	if appservice != nil {
		// Loop through given Application Service's namespaces and see if any match
		for _, namespace := range appservice.NamespaceMap["users"] {
			// AS namespaces are checked for validity in config
			if namespace.RegexpObject.MatchString(username) {
				return true
			}
		}
		return false
	}

	// Loop through all known Application Service's namespaces and see if any match
	for _, knownAppservice := range cfg.Derived.ApplicationServices {
		for _, namespace := range knownAppservice.NamespaceMap["users"] {
			// AS namespaces are checked for validity in config
			if namespace.RegexpObject.MatchString(username) {
				return true
			}
		}
	}
	return false
}

// UsernameMatchesMultipleExclusiveNamespaces will check if a given username matches
// more than one exclusive namespace. More than one is not allowed
func UsernameMatchesMultipleExclusiveNamespaces(
	cfg *config.Dendrite,
	username string,
) bool {
	// Check namespaces and see if more than one match
	matchCount := 0
	for _, appservice := range cfg.Derived.ApplicationServices {
		for _, namespaceSlice := range appservice.NamespaceMap {
			for _, namespace := range namespaceSlice {
				// Check if we have a match on this username
				if namespace.RegexpObject.MatchString(username) {
					matchCount++
				}
			}
		}
	}
	return matchCount > 1
}

// Register processes a /register request.
// http://matrix.org/speculator/spec/HEAD/client_server/unstable.html#post-matrix-client-unstable-register
func Register(
	req *http.Request,
	accountDB *accounts.Database,
	deviceDB *devices.Database,
	cfg *config.Dendrite,
) util.JSONResponse {

	var r registerRequest
	resErr := httputil.UnmarshalJSONRequest(req, &r)
	if resErr != nil {
		return *resErr
	}

	// Retrieve or generate the sessionID
	sessionID := r.Auth.Session
	if sessionID == "" {
		// Generate a new, random session ID
		sessionID = util.RandomString(sessionIDLength)
	}

	if cfg.Matrix.RegistrationDisabled && r.Auth.Type != authtypes.LoginTypeSharedSecret {
		return util.MessageResponse(http.StatusForbidden, "Registration has been disabled")
	}

	// Squash username to all lowercase letters
	r.Username = strings.ToLower(r.Username)

	if resErr = validateCredentials(r.Username, r.Password); resErr != nil {
		return *resErr
	}

	if res := handleLoginTypes(req, r, cfg, sessionID); res != nil {
		return *res
	}

	// Make sure normal user isn't registering under an exclusive application
	// service namespace. Skip this check if no app services are registered.
	if r.Auth.Type != "m.login.application_service" &&
		len(cfg.Derived.ApplicationServices) != 0 &&
		cfg.Derived.ExclusiveApplicationServicesUsernameRegexp.MatchString(r.Username) {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.ASExclusive("This username is reserved by an application service."),
		}
	}

	logger := util.GetLogger(req.Context())
	logger.WithFields(log.Fields{
		"username":   r.Username,
		"auth.type":  r.Auth.Type,
		"session_id": r.Auth.Session,
	}).Info("Processing registration request")

	return handleRegistrationFlow(req, r, sessionID, cfg, accountDB, deviceDB)
}

func handleLoginTypes(req *http.Request, r registerRequest, cfg *config.Dendrite, sessionID string) *util.JSONResponse {
	if r.Auth.Type == authtypes.LoginTypeSharedSecret {
		// Check shared secret against config
		valid, err := isValidMacLogin(cfg, r.Username, r.Password, r.Admin, r.Auth.Mac)

		if err != nil {
			res := httputil.LogThenError(req, err)
			return &res
		} else if !valid {
			res := util.MessageResponse(http.StatusForbidden, "HMAC incorrect")
			return &res
		}

		// Add SharedSecret to the list of completed stages
		sessions.AddCompletedStage(sessionID, authtypes.LoginTypeSharedSecret)
	}

	return nil
}

// handleRegistrationFlow will direct and complete registration flow stages
// that the client has requested.
func handleRegistrationFlow(
	req *http.Request,
	r registerRequest,
	sessionID string,
	cfg *config.Dendrite,
	accountDB *accounts.Database,
	deviceDB *devices.Database,
) util.JSONResponse {
	appservice, jsonRes := HandleUserInteractiveFlow(req, r.UserInteractiveFlowRequest, sessionID, cfg, cfg.Derived.Registration)
	appserviceID := ""
	if appservice != nil {
		err := validateApplicationServiceNamespaces(cfg, r.Username, appservice)
		if err != nil {
			return *err
		}
		appserviceID = appservice.ID
	}

	if jsonRes == nil {
		return completeRegistration(
			req.Context(),
			accountDB,
			deviceDB,
			r.Username,
			r.Password,
			appserviceID,
			r.InitialDisplayName)
	}
	// TODO: Enable registration config flag
	// TODO: Guest account upgrading
	// TODO: Handle loading of previous session parameters from database.
	// TODO: Handle mapping registrationRequest parameters into session parameters

	return *jsonRes
}

func validateApplicationServiceNamespaces(
	cfg *config.Dendrite,
	username string,
	matchedApplicationService *config.ApplicationService,
) *util.JSONResponse {
	// Ensure the desired username is within at least one of the application service's namespaces.
	if !UsernameIsWithinApplicationServiceNamespace(cfg, username, matchedApplicationService) {
		// If we didn't find any matches, return M_EXCLUSIVE
		return &util.JSONResponse{
			Code: http.StatusUnauthorized,
			JSON: jsonerror.ASExclusive(fmt.Sprintf(
				"Supplied username %s did not match any namespaces for application service ID: %s",
				username,
				matchedApplicationService.ID)),
		}
	}

	// Check this user does not fit multiple application service namespaces
	if UsernameMatchesMultipleExclusiveNamespaces(cfg, username) {
		return &util.JSONResponse{
			Code: http.StatusUnauthorized,
			JSON: jsonerror.ASExclusive(fmt.Sprintf(
				"Supplied username %s matches multiple exclusive application service namespaces. Only 1 match allowed",
				username)),
		}
	}

	return nil
}

// LegacyRegister process register requests from the legacy v1 API
func LegacyRegister(
	req *http.Request,
	accountDB *accounts.Database,
	deviceDB *devices.Database,
	cfg *config.Dendrite,
) util.JSONResponse {
	var r legacyRegisterRequest
	resErr := parseAndValidateLegacyLogin(req, &r)
	if resErr != nil {
		return *resErr
	}

	logger := util.GetLogger(req.Context())
	logger.WithFields(log.Fields{
		"username":  r.Username,
		"auth.type": r.Type,
	}).Info("Processing registration request")

	if cfg.Matrix.RegistrationDisabled && r.Type != authtypes.LoginTypeSharedSecret {
		return util.MessageResponse(http.StatusForbidden, "Registration has been disabled")
	}

	switch r.Type {
	case authtypes.LoginTypeSharedSecret:
		if cfg.Matrix.RegistrationSharedSecret == "" {
			return util.MessageResponse(http.StatusBadRequest, "Shared secret registration is disabled")
		}

		valid, err := isValidMacLogin(cfg, r.Username, r.Password, r.Admin, r.Mac)
		if err != nil {
			return httputil.LogThenError(req, err)
		}

		if !valid {
			return util.MessageResponse(http.StatusForbidden, "HMAC incorrect")
		}

		return completeRegistration(req.Context(), accountDB, deviceDB, r.Username, r.Password, "", nil)
	case authtypes.LoginTypeDummy:
		// there is nothing to do
		return completeRegistration(req.Context(), accountDB, deviceDB, r.Username, r.Password, "", nil)
	default:
		return util.JSONResponse{
			Code: http.StatusNotImplemented,
			JSON: jsonerror.Unknown("unknown/unimplemented auth type"),
		}
	}
}

// parseAndValidateLegacyLogin parses the request into r and checks that the
// request is valid (e.g. valid user names, etc)
func parseAndValidateLegacyLogin(req *http.Request, r *legacyRegisterRequest) *util.JSONResponse {
	resErr := httputil.UnmarshalJSONRequest(req, &r)
	if resErr != nil {
		return resErr
	}

	// Squash username to all lowercase letters
	r.Username = strings.ToLower(r.Username)

	if resErr = validateUserName(r.Username); resErr != nil {
		return resErr
	}
	if resErr = validatePassword(r.Password); resErr != nil {
		return resErr
	}

	// All registration requests must specify what auth they are using to perform this request
	if r.Type == "" {
		return &util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("invalid type"),
		}
	}

	return nil
}

func completeRegistration(
	ctx context.Context,
	accountDB *accounts.Database,
	deviceDB *devices.Database,
	username, password, appserviceID string,
	displayName *string,
) util.JSONResponse {
	if username == "" {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("missing username"),
		}
	}
	// Blank passwords are only allowed by registered application services
	if password == "" && appserviceID == "" {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.BadJSON("missing password"),
		}
	}

	acc, err := accountDB.CreateAccount(ctx, username, password, appserviceID)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("failed to create account: " + err.Error()),
		}
	} else if acc == nil {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.UserInUse("Desired user ID is already taken."),
		}
	}

	token, err := auth.GenerateAccessToken()
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("Failed to generate access token"),
		}
	}

	// // TODO: Use the device ID in the request.
	dev, err := deviceDB.CreateDevice(ctx, username, nil, token, displayName)
	if err != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("failed to create device: " + err.Error()),
		}
	}

	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: registerResponse{
			UserID:      dev.UserID,
			AccessToken: dev.AccessToken,
			HomeServer:  acc.ServerName,
			DeviceID:    dev.ID,
		},
	}
}

// Used for shared secret registration.
// Checks if the username, password and isAdmin flag matches the given mac.
func isValidMacLogin(
	cfg *config.Dendrite,
	username, password string,
	isAdmin bool,
	givenMac []byte,
) (bool, error) {
	sharedSecret := cfg.Matrix.RegistrationSharedSecret

	// Check that shared secret registration isn't disabled.
	if cfg.Matrix.RegistrationSharedSecret == "" {
		return false, errors.New("Shared secret registration is disabled")
	}

	// Double check that username/password don't contain the HMAC delimiters. We should have
	// already checked this.
	if strings.Contains(username, "\x00") {
		return false, errors.New("Username contains invalid character")
	}
	if strings.Contains(password, "\x00") {
		return false, errors.New("Password contains invalid character")
	}
	if sharedSecret == "" {
		return false, errors.New("Shared secret registration is disabled")
	}

	adminString := "notadmin"
	if isAdmin {
		adminString = "admin"
	}
	joined := strings.Join([]string{username, password, adminString}, "\x00")

	mac := hmac.New(sha1.New, []byte(sharedSecret))
	_, err := mac.Write([]byte(joined))
	if err != nil {
		return false, err
	}
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(givenMac, expectedMAC), nil
}

type availableResponse struct {
	Available bool `json:"available"`
}

// RegisterAvailable checks if the username is already taken or invalid.
func RegisterAvailable(
	req *http.Request,
	accountDB *accounts.Database,
) util.JSONResponse {
	username := req.URL.Query().Get("username")

	// Squash username to all lowercase letters
	username = strings.ToLower(username)

	if err := validateUserName(username); err != nil {
		return *err
	}

	availability, availabilityErr := accountDB.CheckAccountAvailability(req.Context(), username)
	if availabilityErr != nil {
		return util.JSONResponse{
			Code: http.StatusInternalServerError,
			JSON: jsonerror.Unknown("failed to check availability: " + availabilityErr.Error()),
		}
	}
	if !availability {
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: jsonerror.InvalidUsername("A different user ID has already been registered for this session"),
		}
	}

	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: availableResponse{
			Available: true,
		},
	}
}
