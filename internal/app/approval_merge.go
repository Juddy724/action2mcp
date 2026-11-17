package app

import "strings"

// Edits replace whole parameters. Only a wholly masked secret retains its value.
func mergeApprovalValue(original, edit any, secret bool) (any, error) {
	if secret {
		text := argString(edit)
		if text == secretMask || text == ApprovalSecretUnchanged {
			return original, nil
		}
		if strings.Contains(text, secretMask) {
			return nil, approvalErr(400, "提交值内部夹带 ******，请输入完整的新秘密参数值，未执行")
		}
	}
	return edit, nil
}
