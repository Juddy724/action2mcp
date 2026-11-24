package execution

import (
	"strings"
	"testing"
)

func TestCheckOceanBasePlanPrimaryKeyAndRowThreshold(t *testing.T) {
	obCols := []explainColumn{{ID: "C_1", Name: "Query Plan"}}

	t.Run("TABLE GET on primary key passes", func(t *testing.T) {
		plan := `===============================================
|ID|OPERATOR       |NAME        |EST.ROWS|EST.TIME(us)|
-----------------------------------------------
|0 |TABLE GET      |t_employee|1       |4           |
===============================================
Outputs & filters:
-------------------------------------
  0 - output([t_employee.id]), filter(nil), rowset=16
      access([t_employee.id]), partitions(p0)
      is_index_back=false, is_global_index=false,
      range_key([t_employee.id]), range[1000200030001 ; 1000200030001]`
		if err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil); err != nil {
			t.Fatalf("expected TABLE GET to pass, got: %v", err)
		}
	})

	t.Run("TABLE SCAN with bounded PK range in Outputs & filters passes", func(t *testing.T) {
		plan := `==========================================================
|ID|OPERATOR            |NAME       |EST.ROWS|EST.TIME(us)|
----------------------------------------------------------
|0 |LIMIT               |           |10      |42          |
|1 |└─TABLE RANGE SCAN  |t_emp_rel|25000   |600000      |
==========================================================
Outputs & filters:
-------------------------------------
  0 - output([t_emp_rel.id]), filter(nil), limit(10), offset(nil)
  1 - output([t_emp_rel.id]), filter(nil), rowset=16
      access([t_emp_rel.id]), partitions(p0)
      range_key([t_emp_rel.customer_id], [t_emp_rel.id]), range(1000200030001,MIN ; 1000200030001,MAX)`
		if err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil); err != nil {
			t.Fatalf("expected bounded PK range scan to pass, got: %v", err)
		}
	})

	t.Run("TABLE SCAN with inclusive bracket PK range passes", func(t *testing.T) {
		plan := `==========================================================
|ID|OPERATOR   |NAME       |EST.ROWS|EST.TIME(us)|
----------------------------------------------------------
|0 |TABLE SCAN |t_orders |50000   |800000      |
==========================================================
Outputs & filters:
-------------------------------------
  0 - output([t_orders.id]), filter(nil)
      range_key([t_orders.id]), range[100 ; 200]`
		if err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil); err != nil {
			t.Fatalf("expected inclusive PK range scan to pass, got: %v", err)
		}
	})

	t.Run("Full table scan within 20000 rows and 500ms passes", func(t *testing.T) {
		plan := `==========================================================
|ID|OPERATOR        |NAME       |EST.ROWS|EST.TIME(us)|
----------------------------------------------------------
|0 |TABLE FULL SCAN |small_dict |1200    |1500        |
==========================================================
Outputs & filters:
-------------------------------------
  0 - output([small_dict.id]), filter(nil)
      range_key([small_dict.id]), range(MIN ; MAX)always true`
		if err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil); err != nil {
			t.Fatalf("expected small full scan (<=20000 rows) to pass, got: %v", err)
		}
	})

	t.Run("Full table scan over 20000 rows is rejected with table hint", func(t *testing.T) {
		plan := `==========================================================
|ID|OPERATOR        |NAME       |EST.ROWS|EST.TIME(us)|
----------------------------------------------------------
|0 |TABLE FULL SCAN |huge_logs  |50000   |120000      |
==========================================================
Outputs & filters:
-------------------------------------
  0 - output([huge_logs.id]), filter(nil)
      range_key([huge_logs.id]), range(MIN ; MAX)always true`
		err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil)
		if err == nil {
			t.Fatal("expected >20000 full scan to be rejected")
		}
		if !strings.Contains(err.Error(), "huge_logs") || !strings.Contains(err.Error(), "SHOW INDEX FROM huge_logs") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Full table scan with low EST.ROWS but high EST.TIME (>500ms) is rejected", func(t *testing.T) {
		plan := `==========================================================
|ID|OPERATOR        |NAME       |EST.ROWS|EST.TIME(us)|
----------------------------------------------------------
|0 |TABLE FULL SCAN |huge_table |10      |2000000     |
==========================================================
Outputs & filters:
-------------------------------------
  0 - output([huge_table.id]), filter([huge_table.remark = 'abc'])
      range_key([huge_table.id]), range(MIN ; MAX)always true`
		err := checkExplainResult(obCols, []explainRow{{"C_1": plan}}, nil)
		if err == nil {
			t.Fatal("expected high-cost full scan to be rejected")
		}
	})

	t.Run("Multi-column OceanBase format keeps OPERATOR and NAME on same line", func(t *testing.T) {
		multiCols := []explainColumn{
			{ID: "C_1", Name: "ID"},
			{ID: "C_2", Name: "OPERATOR"},
			{ID: "C_3", Name: "NAME"},
			{ID: "C_4", Name: "EST.ROWS"},
			{ID: "C_5", Name: "EST.TIME(us)"},
		}
		rows := []explainRow{
			{"C_1": "0", "C_2": "TABLE SCAN", "C_3": "orders(idx_customer)", "C_4": "50000", "C_5": "900000"},
		}
		if err := checkExplainResult(multiCols, rows, nil); err != nil {
			t.Fatalf("expected multi-column secondary index scan to pass, got: %v", err)
		}
		badRows := []explainRow{
			{"C_1": "0", "C_2": "TABLE FULL SCAN", "C_3": "orders", "C_4": "50000", "C_5": "900000"},
		}
		if err := checkExplainResult(multiCols, badRows, nil); err == nil {
			t.Fatal("expected multi-column unindexed >20000 scan to fail")
		}
		smallRows := []explainRow{
			{"C_1": "0", "C_2": "TABLE FULL SCAN", "C_3": "tiny_cfg", "C_4": "200", "C_5": "100"},
		}
		if err := checkExplainResult(multiCols, smallRows, nil); err != nil {
			t.Fatalf("expected multi-column <=20000 scan to pass, got: %v", err)
		}
	})
}

func TestCheckMySQLExplainRowThreshold(t *testing.T) {
	colsWithRows := []explainColumn{
		{ID: "id", Name: "id"},
		{ID: "select_type", Name: "select_type"},
		{ID: "table", Name: "table"},
		{ID: "type", Name: "type"},
		{ID: "key", Name: "key"},
		{ID: "rows", Name: "rows"},
	}
	colsNoRows := colsWithRows[:5]

	if err := checkExplainResult(colsWithRows, []explainRow{
		{"id": "1", "select_type": "SIMPLE", "table": "dict_t", "type": "ALL", "key": "", "rows": "20000"},
	}, nil); err != nil {
		t.Fatalf("expected type=ALL with rows=20000 to pass, got: %v", err)
	}

	if err := checkExplainResult(colsWithRows, []explainRow{
		{"id": "1", "select_type": "SIMPLE", "table": "empty_t", "type": "ALL", "key": "", "rows": "0"},
	}, nil); err != nil {
		t.Fatalf("expected type=ALL with rows=0 to pass, got: %v", err)
	}

	err := checkExplainResult(colsWithRows, []explainRow{
		{"id": "1", "select_type": "SIMPLE", "table": "big_t", "type": "ALL", "key": "", "rows": "20001"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "big_t") || !strings.Contains(err.Error(), "SHOW INDEX FROM big_t") {
		t.Fatalf("expected type=ALL with rows=20001 to be rejected with hint, got: %v", err)
	}

	if err := checkExplainResult(colsNoRows, []explainRow{
		{"id": "1", "select_type": "SIMPLE", "table": "unknown_t", "type": "ALL", "key": ""},
	}, nil); err == nil {
		t.Fatal("expected type=ALL without rows estimate column to stay rejected")
	}
}
