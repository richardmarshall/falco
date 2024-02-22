package http

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/value"
)

// Special dealing HTTP header names
const (
	cookieHeaderName    = "Cookie"
	setCookieHeaderName = "Set-Cookie"
)

// Atomic struct for header value representation
type HeaderItem struct {
	Key   *value.LenientString
	Value *value.LenientString
}

type Header map[string][][]HeaderItem

// Implement same methods of Golang http.Header struct but arguments are different
func (h Header) Clone() Header {
	cloned := Header{}
	for key, headers := range h {
		hc := make([][]HeaderItem, len(headers))
		for i := range headers {
			items := make([]HeaderItem, len(headers[i]))
			for j := range headers[i] {
				if headers[i][j].Value != nil {
					items[j] = HeaderItem{
						Key:   headers[i][j].Key.Copy().(*value.LenientString),
						Value: headers[i][j].Value.Copy().(*value.LenientString),
					}
				} else {
					items[j] = HeaderItem{
						Key:   headers[i][j].Key.Copy().(*value.LenientString),
						Value: nil,
					}
				}
			}
			hc[i] = items
		}
		cloned[key] = hc
	}
	return cloned
}

func (h Header) Set(key string, val value.Value) {
	if pos := strings.Index(key, ":"); pos != -1 {
		h.SetObject(key[:pos], key[pos+1:], val)
		return
	}
	name := textproto.CanonicalMIMEHeaderKey(key)

	// Special treating about Set-Cookie header.
	// The Set-Cookie header value has specific format like key=value; domain=xxx; path=/; expire=x, HttpOnly; SameSite=Lax
	// Then we should split key and value by "=" character
	if name == setCookieHeaderName {
		v := copyToLenientString(val)
		kv := strings.SplitN(v.String(), "=", 2)
		h[name] = [][]HeaderItem{
			{
				HeaderItem{
					Key: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: kv[0]},
						},
					},
					Value: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: kv[1]},
						},
					},
				},
			},
		}
		return
	}

	h[name] = [][]HeaderItem{
		{
			HeaderItem{
				Key:   copyToLenientString(val),
				Value: nil,
			},
		},
	}
}

func (h Header) SetObject(name, key string, val value.Value) {
	values, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok {
		v := copyToLenientString(val)
		// Assigning a not set value to a header field key with length greater
		// than 1 results in the assignment of an empty string.
		if len(key) > 1 && v.IsNotSet {
			v.IsNotSet = false
			v.Values = append(v.Values, &value.String{Value: ""})
		}
		h[textproto.CanonicalMIMEHeaderKey(name)] = [][]HeaderItem{
			{
				HeaderItem{
					Key: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: key},
						},
					},
					Value: v,
				},
			},
		}
		return
	}

	for i, hv := range values[0] {
		// Already exists, override it
		if hv.Key.StrictString() == key {
			values[0][i] = HeaderItem{
				Key: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: key},
					},
				},
				Value: copyToLenientString(val),
			}
			return
		}
	}

	values[0] = append(values[0], HeaderItem{
		Key: &value.LenientString{
			Values: []value.Value{
				&value.String{Value: key},
			},
		},
		Value: copyToLenientString(val),
	})
}

func (h Header) Add(key string, val value.Value) {
	name := textproto.CanonicalMIMEHeaderKey(key)
	v, ok := h[name]
	if !ok {
		h.Set(key, val)
		return
	}

	// Special treating about Set-Cookie header.
	// The Set-Cookie header value has specific format like key=value; domain=xxx; path=/; expire=x, HttpOnly; SameSite=Lax
	// Then we should split key and value by "=" character
	if name == setCookieHeaderName {
		hv := copyToLenientString(val)
		kv := strings.SplitN(hv.String(), "=", 2)
		v = append(v, []HeaderItem{
			{
				Key: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: kv[0]},
					},
				},
				Value: &value.LenientString{
					Values: []value.Value{
						&value.String{Value: kv[1]},
					},
				},
			},
		})
		h[name] = v
		return
	}
	v = append(v, []HeaderItem{
		{
			Key:   copyToLenientString(val),
			Value: nil,
		},
	})
	h[name] = v
}

// Get header fields value - always returns ambiguous STRING
func (h Header) Get(key string) *value.LenientString {
	if pos := strings.Index(key, ":"); pos != -1 {
		return h.GetObject(key[:pos], key[pos+1:])
	}
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(key)]
	if !ok {
		return &value.LenientString{
			IsNotSet: true,
		}
	}
	if len(hv) == 0 {
		return &value.LenientString{
			IsNotSet: true,
		}
	}

	// Merge ambiguous strings
	var merged []value.Value
	for i, v := range hv[0] {
		if !v.Key.IsNotSet {
			cpk := v.Key.Copy().(*value.LenientString) // nolint:errcheck
			merged = append(merged, cpk.Values...)
		}
		if v.Value == nil {
			continue
		}
		if !v.Value.IsNotSet {
			if v.Value.StrictString() != "" {
				merged = append(merged, &value.String{Value: "="})
			}
			cpv := v.Value.Copy().(*value.LenientString) // nolint:errcheck
			merged = append(merged, cpv.Values...)
		}
		if i != len(hv[0])-1 {
			merged = append(merged, &value.String{Value: ", "})
		}
	}

	if len(merged) == 0 {
		return &value.LenientString{
			IsNotSet: true,
		}
	}
	return &value.LenientString{Values: merged}
}

// Get header fields value for key - always returns ambiguous STRING
func (h Header) GetObject(name, key string) *value.LenientString {
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok {
		return &value.LenientString{
			IsNotSet: true,
		}
	}
	if len(hv) == 0 {
		return &value.LenientString{
			IsNotSet: true,
		}
	}
	for _, v := range hv[0] {
		if v.Key.String() != key {
			continue
		}
		return v.Value.Copy().(*value.LenientString)
	}
	return &value.LenientString{
		IsNotSet: true,
	}
}

func (h Header) Del(key string) {
	if pos := strings.Index(key, ":"); pos != -1 {
		h.DelObject(key[:pos], key[pos+1:])
		return
	}
	if _, ok := h[textproto.CanonicalMIMEHeaderKey(key)]; !ok {
		return
	}
	delete(h, textproto.CanonicalMIMEHeaderKey(key))
}

func (h Header) DelObject(name, key string) {
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok || len(hv) == 0 {
		return
	}

	var filtered []HeaderItem
	for _, v := range hv[0] {
		if v.Key.String() == key {
			continue
		}
		filtered = append(filtered, v)
	}
	hv[0] = cleanupHeaderItem(filtered)
}

func cleanupHeaderItem(items []HeaderItem) []HeaderItem {
	var cleanup []HeaderItem
	for _, v := range items {
		if v.Key.StrictString() == "" {
			continue
		}
		cleanup = append(cleanup, v)
	}
	return cleanup
}

// Utility function - convert to Header type from Golang http.Header
func FromGoHttpHeader(h http.Header) Header {
	v := Header{}
	for key, val := range h {
		values := make([][]HeaderItem, len(val))
		for i := range val {
			hv := []HeaderItem{}

			var obj []string
			switch key {
			// If cookie header, multiple items is sparated by semicolon
			case cookieHeaderName:
				obj = strings.Split(val[i], ";")
			// If set-cookie header, value does not need to be splitted
			case setCookieHeaderName:
				obj = append(obj, val[i])
			default:
				obj = strings.Split(val[i], ",")
			}

			for _, vv := range obj {
				if pos := strings.Index(vv, "="); pos != -1 {
					hv = append(hv, HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: strings.TrimSpace(vv[:pos])},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: strings.TrimSpace(vv[pos+1:])},
							},
						},
					})
					continue
				}
				hv = append(hv, HeaderItem{
					Key: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: vv},
						},
					},
					Value: nil,
				})
			}
			values[i] = hv
		}
		v[textproto.CanonicalMIMEHeaderKey(key)] = values
	}
	return v
}

// Utility function - convert to Golang http.Header from Header type
func ToGoHttpHeader(h Header) http.Header {
	v := http.Header{}
	for key, val := range h {
		for i := range val {
			var ret []string
			for _, hv := range val[i] {
				if hv.Key.StrictString() == "" {
					continue
				}
				line := hv.Key.String()
				if hv.Value != nil {
					if hv.Value.StrictString() != "" {
						line += "=" + hv.Value.String()
					}
				}
				ret = append(ret, line)
			}
			var r string
			if key == cookieHeaderName { // Cookie string should be contatenated with semicolon
				r = strings.Join(ret, "; ")
			} else {
				r = strings.Join(ret, ",")
			}
			if r != "" {
				v.Add(key, r)
			}
		}
	}
	return v
}

// Explicitly copy value as *value.LenientString
func copyToLenientString(v value.Value) *value.LenientString {
	switch t := v.(type) {
	case *value.String:
		ls := &value.LenientString{
			IsNotSet: t.IsNotSet,
		}
		ls.Values = append(ls.Values, &value.String{Value: t.Value})
		return ls
	case *value.IP:
		ls := &value.LenientString{
			IsNotSet: t.IsNotSet,
		}
		if t.Value != nil {
			ls.Values = append(ls.Values, &value.String{Value: t.Value.String()})
		}
		return ls
	case *value.LenientString:
		return t.Copy().(*value.LenientString)
	case *value.Backend:
		return &value.LenientString{
			Values: []value.Value{
				&value.String{Value: t.Value.Name.Value},
			},
		}
	default:
		return &value.LenientString{
			Values: []value.Value{t.Copy()},
		}
	}
}
