// Package approval owns approval pending state, nonces, deadlines, durable transitions, argument edit rules and bounded history/results. Execution-owned typed Operation ports prepare and scrub previews without sending; notifications and shutdown are injected. No mutable App, browser or vault instance is passed into the service.
package approval
