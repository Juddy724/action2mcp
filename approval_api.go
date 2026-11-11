package main

import (
	"errors"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// approvalOnly requires an explicit console origin even for read-only polling.
// Other console routes keep localOnly's existing behavior.
func (a *App) approvalOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		port := strconv.Itoa(a.cfg.Port)
		origins := r.Header.Values("Origin")
		if len(origins) != 1 || (origins[0] != "http://localhost:"+port &&
			origins[0] != "http://127.0.0.1:"+port && origins[0] != "http://[::1]:"+port) {
			writeErr(w, 403, errors.New("forbidden origin"))
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "[::1]" {
			writeErr(w, 403, errors.New("forbidden host"))
			return
		}
		contentTypes := r.Header.Values("Content-Type")
		if len(contentTypes) != 1 {
			writeErr(w, 415, errors.New("Content-Type 必须是 application/json"))
			return
		}
		mediaType, params, err := mime.ParseMediaType(contentTypes[0])
		if err != nil || mediaType != "application/json" || len(params) > 1 ||
			(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
			writeErr(w, 415, errors.New("Content-Type 必须是 application/json"))
			return
		}
		next(w, r)
	})
}

func writeApprovalErr(w http.ResponseWriter, err error) {
	status := 500
	var ae *ApprovalError
	if errors.As(err, &ae) {
		status = ae.Status
	}
	writeErr(w, status, err)
}

func (a *App) registerApprovals(mux *http.ServeMux) {
	mux.Handle("POST /api/approvals/list", a.approvalOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Status string `json:"status"`
			Limit  int    `json:"limit"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		rows, err := a.ListApprovals(in.Status, in.Limit)
		if err != nil {
			writeApprovalErr(w, err)
			return
		}
		writeJSON(w, 200, rows)
	}))
	mux.Handle("POST /api/approvals/{id}/preview", a.approvalOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Args  map[string]any `json:"args"`
			Nonce string         `json:"nonce"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		preview, err := a.PreviewApproval(pathID(r), in.Nonce, in.Args)
		if err != nil {
			writeApprovalErr(w, err)
			return
		}
		writeJSON(w, 200, preview)
	}))
	mux.Handle("POST /api/approvals/{id}/decide", a.approvalOnly(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Action      string         `json:"action"`
			Args        map[string]any `json:"args"`
			Feedback    string         `json:"feedback"`
			Nonce       string         `json:"nonce"`
			PreviewHash string         `json:"preview_hash"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := a.DecideApproval(pathID(r), in.Nonce, in.Action, in.Args, in.Feedback, in.PreviewHash); err != nil {
			writeApprovalErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
}
