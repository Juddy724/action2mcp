package app

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
)

// Test-local shorthands for feature-package types used by App integration tests.
type Candidate = execution.Candidate
type ToolConfig = execution.ToolConfig
type SQLGuardConfig = execution.SQLGuardConfig
type WSCollectConfig = execution.WSCollectConfig
type WSAuthConfig = execution.WSAuthConfig
type PreparedCall = execution.PreparedCall
type LoginErr = execution.LoginErr
type RecordingLoginResult = domain.RecordingLoginResult
