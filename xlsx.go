package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Minimal .xlsx writer: inline strings, numbers, a bold header row, frozen header and
// sane column widths. Enough for reports; no external library.

type sheet struct {
	name   string
	header []string
	rows   [][]any
	widths []int
}

func xmlEsc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func colName(i int) string {
	s := ""
	for i++; i > 0; i = (i - 1) / 26 {
		s = string(rune('A'+(i-1)%26)) + s
	}
	return s
}

func writeXLSX(w io.Writer, sheets []sheet) error {
	z := zip.NewWriter(w)
	add := func(name, body string) {
		f, _ := z.Create(name)
		io.WriteString(f, body)
	}
	var ct, wbs, rels strings.Builder
	ct.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	for i, s := range sheets {
		fmt.Fprintf(&ct, `<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i+1)
		name := s.name
		if len(name) > 31 {
			name = name[:31]
		}
		fmt.Fprintf(&wbs, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xmlEsc(name), i+1, i+1)
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i+1, i+1)
	}
	ct.WriteString(`</Types>`)
	add("[Content_Types].xml", ct.String())
	add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`)
	add("xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`+wbs.String()+`</sheets></workbook>`)
	fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, len(sheets)+1)
	add("xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+rels.String()+`</Relationships>`)
	add("xl/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf/></cellStyleXfs><cellXfs count="4"><xf/><xf fontId="1" applyFont="1"/><xf numFmtId="3" applyNumberFormat="1"/><xf numFmtId="164" applyNumberFormat="1"/></cellXfs></styleSheet>`)
	for i, s := range sheets {
		f, _ := z.Create(fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1))
		bw := &strings.Builder{}
		bw.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>`)
		for c := range s.header {
			wd := 18
			if c < len(s.widths) {
				wd = s.widths[c]
			}
			fmt.Fprintf(bw, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, c+1, c+1, wd)
		}
		bw.WriteString(`</cols><sheetData><row r="1">`)
		for c, h := range s.header {
			fmt.Fprintf(bw, `<c r="%s1" t="inlineStr" s="1"><is><t>%s</t></is></c>`, colName(c), xmlEsc(h))
		}
		bw.WriteString(`</row>`)
		io.WriteString(f, bw.String())
		for r, row := range s.rows {
			bw.Reset()
			fmt.Fprintf(bw, `<row r="%d">`, r+2)
			for c, v := range row {
				ref := colName(c) + strconv.Itoa(r+2)
				switch x := v.(type) {
				case int64:
					fmt.Fprintf(bw, `<c r="%s" s="2"><v>%d</v></c>`, ref, x)
				case int:
					fmt.Fprintf(bw, `<c r="%s" s="2"><v>%d</v></c>`, ref, x)
				case float64:
					fmt.Fprintf(bw, `<c r="%s"><v>%s</v></c>`, ref, strconv.FormatFloat(x, 'f', -1, 64))
				case time.Time:
					if !x.IsZero() {
						// Excel serial date: days since 1899-12-30.
						fmt.Fprintf(bw, `<c r="%s" s="3"><v>%f</v></c>`, ref, x.Sub(time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)).Hours()/24)
					}
				default:
					fmt.Fprintf(bw, `<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, ref, xmlEsc(fmt.Sprint(x)))
				}
			}
			bw.WriteString(`</row>`)
			io.WriteString(f, bw.String())
		}
		io.WriteString(f, `</sheetData></worksheet>`)
	}
	return z.Close()
}

func tsTime(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0).UTC()
}

func xlsxStart(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
}

// queryRows runs a query and returns generic rows, for building sheets.
func (a *App) queryRows(q string, args ...any) [][]any {
	rows, err := a.st.db.Query(q, args...)
	if err != nil {
		return [][]any{}
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	out := [][]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		rows.Scan(ptrs...)
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			} else if v == nil {
				vals[i] = ""
			}
		}
		out = append(out, vals)
	}
	return out
}

// exportDashboard writes the whole dashboard, for the current scope, as a workbook.
func (a *App) exportDashboard(w http.ResponseWriter, r *http.Request) {
	sc := scopeFrom(r)
	cond, args := sc.scans("c.id")
	w2, a2 := sc.where()
	var sheets []sheet

	sum := sheet{name: "Summary", header: []string{"Device", "Share", "Path", "Files", "Folders", "Bytes", "GB", "Indexed at (UTC)", "Status"}, widths: []int{20, 22, 40, 14, 12, 18, 12, 20, 14}}
	for _, rw := range a.queryRows(`SELECT d.name, s.name, s.path, COALESCE(c.files,0), COALESCE(c.dirs,0), COALESCE(c.bytes,0), c.finished, COALESCE(c.status,'never scanned')
	  FROM (SELECT * FROM shares`+w2+`) s JOIN devices d ON d.id=s.device_id LEFT JOIN scans c ON c.id=s.current_scan ORDER BY d.name, s.name`, a2...) {
		b, _ := rw[5].(int64)
		fin, _ := rw[6].(int64)
		sum.rows = append(sum.rows, []any{rw[0], rw[1], rw[2], rw[3], rw[4], b, float64(b) / (1 << 30), tsTime(fin), rw[7]})
	}
	sheets = append(sheets, sum)

	hc := sheet{name: "Age (modified)", header: []string{"Day", "Bytes", "Files"}, widths: []int{14, 18, 12}}
	mrows := a.aggFor(sc, "m")
	sort.Slice(mrows, func(i, j int) bool { return mrows[i].Key < mrows[j].Key })
	for _, m := range mrows {
		hc.rows = append(hc.rows, []any{m.Key, m.Bytes, m.Files})
	}
	sheets = append(sheets, hc)

	ft := sheet{name: "File types", header: []string{"Extension", "Bytes", "Files"}, widths: []int{14, 18, 12}}
	erows := a.aggFor(sc, "e")
	sort.Slice(erows, func(i, j int) bool { return erows[i].Bytes > erows[j].Bytes })
	for _, e := range erows {
		ft.rows = append(ft.rows, []any{e.Key, e.Bytes, e.Files})
	}
	sheets = append(sheets, ft)

	dc, dargs := sc.scans("d.scan_id")
	tf := sheet{name: "Top folders", header: []string{"Device", "Share", "Depth", "Folder", "Bytes", "Files", "Owner"}, widths: []int{18, 18, 8, 60, 18, 12, 26}}
	tf.rows = append(tf.rows, a.queryRows(`SELECT dv.name, s.name, d.depth, d.path, d.bytes, d.files, d.owner FROM dirs d JOIN shares s ON s.current_scan=d.scan_id
	  JOIN devices dv ON dv.id=s.device_id WHERE d.depth BETWEEN 1 AND 3 AND `+dc+` ORDER BY d.bytes DESC LIMIT 2000`, dargs...)...)
	sheets = append(sheets, tf)

	ow := sheet{name: "Owners", header: []string{"Owner", "Department", "Bytes", "Files", "Folders"}, widths: []int{30, 24, 18, 12, 10}}
	ow.rows = append(ow.rows, a.queryRows(`SELECT d.owner, COALESCE(o.department,''), SUM(d.own_bytes) b, SUM(d.own_files), COUNT(*) FROM dirs d LEFT JOIN owner_directory o ON o.owner=d.owner
	  WHERE `+dc+` GROUP BY d.owner ORDER BY b DESC LIMIT 5000`, dargs...)...)
	sheets = append(sheets, ow)

	xc, xargs := sc.scans("x.scan_id")
	du := sheet{name: "Duplicates", header: []string{"Device", "Share", "Name", "Size", "Copies", "Reclaimable bytes", "Modified (UTC)"}, widths: []int{18, 18, 40, 14, 8, 18, 18}}
	for _, rw := range a.queryRows(`SELECT d.name, s.name, x.name, x.size, x.copies, x.size*(x.copies-1) r, x.mtime FROM dup_sets x JOIN shares s ON s.current_scan=x.scan_id
	  JOIN devices d ON d.id=s.device_id WHERE `+xc+` ORDER BY r DESC LIMIT 20000`, xargs...) {
		mt, _ := rw[6].(int64)
		rw[6] = tsTime(mt)
		du.rows = append(du.rows, rw)
	}
	sheets = append(sheets, du)

	ic, iargs := sc.scansWithFailed("i.scan_id")
	is := sheet{name: "Path issues", header: []string{"Device", "Share", "Path", "Issue", "Detail", "Length"}, widths: []int{18, 18, 70, 16, 40, 8}}
	is.rows = append(is.rows, a.queryRows(`SELECT d.name, s.name, i.path, i.kind, i.detail, i.len FROM issues i JOIN shares s ON s.id=i.share_id JOIN devices d ON d.id=s.device_id
	  WHERE `+ic+` ORDER BY i.kind, i.len DESC LIMIT 50000`, iargs...)...)
	sheets = append(sheets, is)
	_ = cond
	_ = args

	xlsxStart(w, "stratum-report-"+time.Now().Format("2006-01-02")+".xlsx")
	writeXLSX(w, sheets)
}

// searchXLSX exports a search (up to Excel's row limit).
func (a *App) searchXLSX(w http.ResponseWriter, r *http.Request) {
	fl := filterFrom(r)
	from, args := a.fileSelect(fl)
	s := sheet{name: "Search", header: []string{"Device", "Share", "Path", "Name", "Extension", "Size", "Modified (UTC)", "Accessed (UTC)", "Created (UTC)", "Folder owner"},
		widths: []int{16, 16, 70, 30, 10, 14, 18, 18, 18, 26}}
	rows, err := a.st.db.Query(searchCols+from+` ORDER BY s.id, f.path LIMIT 1048000`, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	for rows.Next() {
		var dev, share, p, name, ext, owner string
		var sid, size, mt, at, ct, flags int64
		rows.Scan(&dev, &sid, &share, &p, &name, &ext, &size, &mt, &at, &ct, &owner, &flags)
		s.rows = append(s.rows, []any{dev, share, p, name, ext, size, tsTime(mt), tsTime(at), tsTime(ct), owner})
	}
	rows.Close()
	xlsxStart(w, "search.xlsx")
	writeXLSX(w, []sheet{s})
}
