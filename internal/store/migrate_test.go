package store

import (
	"testing"
)

func TestSQLConsoleNameFromTool(t *testing.T) {
	if sqlConsoleNameFromTool("demo_sql_query") != "demo_sql" {
		t.Fatal(sqlConsoleNameFromTool("demo_sql_query"))
	}
	if sqlConsoleNameFromTool("other") != "other" {
		t.Fatal(sqlConsoleNameFromTool("other"))
	}
}
