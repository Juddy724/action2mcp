// Package execution owns tool models, template and credential binding, frozen
// preparation, sensitivity and display policy, and complete HTTP/WebSocket sends.
// Login/browser state, cookie/header acquisition and generated-console refresh
// enter through explicit ports. No App or shared runtime state is accepted.
// SQL repositories, browser lifecycle, approval exposure gates and MCP/console
// adapters remain outside this package.
package execution
