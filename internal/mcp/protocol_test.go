package mcp

import "testing"

func TestApplyWritePrefixIsIdempotent(t *testing.T) {
	once := ApplyWritePrefix("  删除订单 ")
	if once != writeOpPrefix+" 删除订单" || ApplyWritePrefix(once) != once {
		t.Fatalf("prefix = %q", once)
	}
	if ApplyWritePrefix("") != writeOpPrefix {
		t.Fatal("empty description must become the bare marker")
	}
}
