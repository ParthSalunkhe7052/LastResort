package scanner

import (
	"encoding/json"
	"net/url"
	"strings"
)

// ParameterType defines the source of a request parameter.
type ParameterType string

const (
	ParamQuery  ParameterType = "query"
	ParamForm   ParameterType = "form"
	ParamJSON   ParameterType = "json"
	ParamCookie ParameterType = "cookie"
)

// InsertionPoint represents a place where payload injection can happen.
type InsertionPoint struct {
	Name  string
	Type  ParameterType
	Value string
}

// ExtractInsertionPoints parses a URL, body, or headers to extract parameter insertion points.
func ExtractInsertionPoints(method, urlStr string, body []byte, contentType string) ([]InsertionPoint, error) {
	var points []InsertionPoint

	// 1. Query parameters
	parsedURL, err := url.Parse(urlStr)
	if err == nil {
		query := parsedURL.Query()
		for k, vals := range query {
			for _, val := range vals {
				points = append(points, InsertionPoint{
					Name:  k,
					Type:  ParamQuery,
					Value: val,
				})
			}
		}
	}

	// 2. Form or JSON body parameters
	methodUpper := strings.ToUpper(method)
	if methodUpper == "POST" || methodUpper == "PUT" || methodUpper == "PATCH" || methodUpper == "DELETE" {
		if len(body) > 0 {
			if strings.Contains(strings.ToLower(contentType), "application/json") {
				var jsonMap map[string]interface{}
				if err := json.Unmarshal(body, &jsonMap); err == nil {
					for k, v := range jsonMap {
						if valStr, ok := v.(string); ok {
							points = append(points, InsertionPoint{
								Name:  k,
								Type:  ParamJSON,
								Value: valStr,
							})
						}
					}
				}
			} else if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
				values, err := url.ParseQuery(string(body))
				if err == nil {
					for k, vals := range values {
						for _, val := range vals {
							points = append(points, InsertionPoint{
								Name:  k,
								Type:  ParamForm,
								Value: val,
							})
						}
					}
				}
			}
		}
	}

	return points, nil
}

// BuildInjectedRequest prepares the injected URL or body payload.
func BuildInjectedRequest(method, urlStr string, body []byte, contentType string, point InsertionPoint, payload string) (string, []byte) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr, body
	}

	switch point.Type {
	case ParamQuery:
		query := parsedURL.Query()
		query.Set(point.Name, payload)
		parsedURL.RawQuery = query.Encode()
		return parsedURL.String(), body

	case ParamForm:
		if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") && len(body) > 0 {
			values, err := url.ParseQuery(string(body))
			if err == nil {
				values.Set(point.Name, payload)
				return urlStr, []byte(values.Encode())
			}
		}

	case ParamJSON:
		if strings.Contains(strings.ToLower(contentType), "application/json") && len(body) > 0 {
			var jsonMap map[string]interface{}
			if err := json.Unmarshal(body, &jsonMap); err == nil {
				jsonMap[point.Name] = payload
				newBody, err := json.Marshal(jsonMap)
				if err == nil {
					return urlStr, newBody
				}
			}
		}
	}

	return urlStr, body
}
