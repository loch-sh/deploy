package handlers

import (
	"fmt"
	"net/http"

	"deploy-server/middleware"
)

// stack is the identity of a deployment, derived entirely from the verified
// GitLab ID-token claims — never from client-supplied request fields.
type stack struct {
	Namespace    string // gitlabSlug(project_path)
	Environment  string // gitlabSlug(environment)
	ProjectID    string // numeric GitLab project id — the ownership key
	RefProtected bool
	Key          string // "{namespace}-{environment}"
}

// stackFromClaims extracts and validates the deployment identity from the
// request's verified claims. It returns an HTTP status code and message on
// failure so callers can respond directly.
func stackFromClaims(r *http.Request) (stack, int, string) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		return stack{}, http.StatusUnauthorized, "missing verified claims"
	}

	if claims.ProjectPath == "" || claims.ProjectID == "" {
		return stack{}, http.StatusBadRequest, "token is missing project_path/project_id claims"
	}
	if claims.Environment == "" {
		return stack{}, http.StatusBadRequest, "token is missing the environment claim (the job needs an environment: block)"
	}

	namespace := gitlabSlug(claims.ProjectPath)
	environment := gitlabSlug(claims.Environment)

	if err := validateSlug("namespace", namespace); err != nil {
		return stack{}, http.StatusBadRequest, err.Error()
	}
	if err := validateSlug("environment", environment); err != nil {
		return stack{}, http.StatusBadRequest, err.Error()
	}

	return stack{
		Namespace:    namespace,
		Environment:  environment,
		ProjectID:    claims.ProjectID,
		RefProtected: claims.RefProtected,
		Key:          namespace + "-" + environment,
	}, 0, ""
}

// requireProtectedRef enforces that a deployment targeting a protected
// environment originates from a protected branch/tag. Returns an error message
// when the rule is violated, or "" when allowed.
//
// Note: the rule is now also enforced for every protected endpoint (deploy,
// exec, stop, directories) by middleware.RequireProtectedRef, wired in
// main.go's newMux, which also honours the environment_protected claim. This
// check is kept as a redundant, harmless second line of defence in Deploy.
func requireProtectedRef(s stack, protectedEnvs map[string]bool) string {
	if protectedEnvs[s.Environment] && !s.RefProtected {
		return fmt.Sprintf("environment %q may only be deployed from a protected branch/tag", s.Environment)
	}
	return ""
}
