package main

import (
	"strings"
)

// Filter is the shared selection language used by Search, Auto Tag rules and
// Automation inputs. Relative ages are evaluated at query time.
type Filter struct {
	Q              string   `json:"q,omitempty"`               // name substring, case-insensitive
	Ext            []string `json:"ext,omitempty"`             // extensions without dot
	PathPrefix     string   `json:"path_prefix,omitempty"`     // share-relative, e.g. /projects
	PathContains   string   `json:"path_contains,omitempty"`   //
	ModifiedAfter  int64    `json:"modified_after,omitempty"`  // unix
	ModifiedBefore int64    `json:"modified_before,omitempty"` // unix
	OlderThanDays  int      `json:"older_than_days,omitempty"` // mtime age
	NotAccessedDay int      `json:"not_accessed_days,omitempty"`
	NewerThanDays  int      `json:"newer_than_days,omitempty"`
	MinSize        int64    `json:"min_size,omitempty"`
	MaxSize        int64    `json:"max_size,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	Tag            string   `json:"tag,omitempty"`
	DeviceID       int64    `json:"device_id,omitempty"`
	ShareID        int64    `json:"share_id,omitempty"`
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// conditions renders the filter as a WHERE clause over files f / shares s.
func (fl Filter) conditions() (string, []any) {
	var c []string
	var a []any
	c = append(c, "1=1")
	if fl.DeviceID > 0 {
		c = append(c, "s.device_id=?")
		a = append(a, fl.DeviceID)
	}
	if fl.ShareID > 0 {
		c = append(c, "s.id=?")
		a = append(a, fl.ShareID)
	}
	if fl.Q != "" {
		c = append(c, `f.name LIKE ? ESCAPE '\'`)
		a = append(a, "%"+likeEscape(fl.Q)+"%")
	}
	if len(fl.Ext) > 0 {
		ph := make([]string, 0, len(fl.Ext))
		for _, e := range fl.Ext {
			e = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(e), "."))
			if e == "" {
				continue
			}
			ph = append(ph, "?")
			a = append(a, e)
		}
		if len(ph) > 0 {
			c = append(c, "f.ext IN ("+strings.Join(ph, ",")+")")
		}
	}
	if fl.PathPrefix != "" && fl.PathPrefix != "/" {
		p := "/" + strings.Trim(strings.ReplaceAll(fl.PathPrefix, `\`, "/"), "/")
		c = append(c, `(f.dir = ? OR f.dir LIKE ? ESCAPE '\')`)
		a = append(a, p, likeEscape(p)+"/%")
	}
	if fl.PathContains != "" {
		c = append(c, `f.path LIKE ? ESCAPE '\'`)
		a = append(a, "%"+likeEscape(strings.ReplaceAll(fl.PathContains, `\`, "/"))+"%")
	}
	if fl.ModifiedAfter > 0 {
		c = append(c, "f.mtime >= ?")
		a = append(a, fl.ModifiedAfter)
	}
	if fl.ModifiedBefore > 0 {
		c = append(c, "f.mtime < ?")
		a = append(a, fl.ModifiedBefore)
	}
	if fl.OlderThanDays > 0 {
		c = append(c, "f.mtime < ?")
		a = append(a, now()-int64(fl.OlderThanDays)*86400)
	}
	if fl.NewerThanDays > 0 {
		c = append(c, "f.mtime >= ?")
		a = append(a, now()-int64(fl.NewerThanDays)*86400)
	}
	if fl.NotAccessedDay > 0 {
		c = append(c, "f.atime < ?")
		a = append(a, now()-int64(fl.NotAccessedDay)*86400)
	}
	if fl.MinSize > 0 {
		c = append(c, "f.size >= ?")
		a = append(a, fl.MinSize)
	}
	if fl.MaxSize > 0 {
		c = append(c, "f.size <= ?")
		a = append(a, fl.MaxSize)
	}
	if fl.Owner != "" {
		c = append(c, `f.owner LIKE ? ESCAPE '\'`)
		a = append(a, "%"+likeEscape(fl.Owner)+"%")
	}
	if fl.Tag != "" {
		c = append(c, "EXISTS(SELECT 1 FROM file_tags t WHERE t.share_id=s.id AND t.path=f.path AND t.tag=?)")
		a = append(a, fl.Tag)
	}
	return strings.Join(c, " AND "), a
}

func (fl Filter) empty() bool {
	return fl.Q == "" && len(fl.Ext) == 0 && fl.PathPrefix == "" && fl.PathContains == "" && fl.ModifiedAfter == 0 &&
		fl.ModifiedBefore == 0 && fl.OlderThanDays == 0 && fl.NotAccessedDay == 0 && fl.NewerThanDays == 0 &&
		fl.MinSize == 0 && fl.MaxSize == 0 && fl.Owner == "" && fl.Tag == ""
}
