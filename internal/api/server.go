package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	aiv1connect "github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
	"github.com/parth/lastresort/internal/orchestrator"
	"github.com/parth/lastresort/internal/report"
	"github.com/parth/lastresort/internal/storage"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ScanServer implements scanv1connect.ScanServiceHandler.
type ScanServer struct {
	DB       *storage.DB
	AiClient aiv1connect.AiServiceClient
	Orch     *orchestrator.Orchestrator
}

// NewScanServer creates a new ScanServer instance.
func NewScanServer(db *storage.DB, aiClient aiv1connect.AiServiceClient, orch *orchestrator.Orchestrator) *ScanServer {
	return &ScanServer{
		DB:       db,
		AiClient: aiClient,
		Orch:     orch,
	}
}

// CreateScan registers a new scan target in a queued state
func (s *ScanServer) CreateScan(ctx context.Context, req *connect.Request[scanv1.CreateScanRequest]) (*connect.Response[scanv1.CreateScanResponse], error) {
	scanID := uuid.New().String()
	targetURL := req.Msg.Config.TargetUrl
	profile := req.Msg.Config.Profile

	_, err := s.DB.ExecContext(ctx,
		"INSERT INTO scans (id, target_url, status, progress, profile, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		scanID, targetURL, scanv1.ScanStatus_SCAN_STATUS_QUEUED, 0.0, profile, time.Now(),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to save scan to db: %w", err))
	}

	return connect.NewResponse(&scanv1.CreateScanResponse{ScanId: scanID}), nil
}

// StartScan triggers background execution of scan phases
func (s *ScanServer) StartScan(ctx context.Context, req *connect.Request[scanv1.StartScanRequest]) (*connect.Response[scanv1.StartScanResponse], error) {
	scanID := req.Msg.ScanId

	result, err := s.DB.ExecContext(ctx,
		"UPDATE scans SET status = ?, started_at = ? WHERE id = ? AND status = ?",
		scanv1.ScanStatus_SCAN_STATUS_RUNNING, time.Now(), scanID, scanv1.ScanStatus_SCAN_STATUS_QUEUED,
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update scan: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("scan not found or not in queued state"))
	}

	// Trigger live background scan orchestration
	s.Orch.Start(scanID)

	return connect.NewResponse(&scanv1.StartScanResponse{Success: true}), nil
}

// GetScan retrieves active status and profiling insights for a scan
func (s *ScanServer) GetScan(ctx context.Context, req *connect.Request[scanv1.GetScanRequest]) (*connect.Response[scanv1.GetScanResponse], error) {
	scanID := req.Msg.ScanId

	var targetURL string
	var status int
	var progress float64
	var profile int
	var createdAt time.Time
	var startedAtNull, finishedAtNull sql.NullTime
	var detectedTechsNull, authModelNull sql.NullString

	err := s.DB.QueryRowContext(ctx,
		"SELECT target_url, status, progress, profile, created_at, started_at, finished_at, detected_technologies, auth_model FROM scans WHERE id = ?",
		scanID,
	).Scan(&targetURL, &status, &progress, &profile, &createdAt, &startedAtNull, &finishedAtNull, &detectedTechsNull, &authModelNull)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("scan not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("database error: %w", err))
	}

	var startedAt, finishedAt *timestamppb.Timestamp
	if startedAtNull.Valid {
		startedAt = timestamppb.New(startedAtNull.Time)
	}
	if finishedAtNull.Valid {
		finishedAt = timestamppb.New(finishedAtNull.Time)
	}

	return connect.NewResponse(&scanv1.GetScanResponse{
		ScanId: scanID,
		Config: &scanv1.ScanConfig{
			TargetUrl: targetURL,
			Profile:   scanv1.ScanProfile(profile),
		},
		Status:               scanv1.ScanStatus(status),
		Progress:             float32(progress),
		CreatedAt:            timestamppb.New(createdAt),
		StartedAt:            startedAt,
		FinishedAt:           finishedAt,
		DetectedTechnologies: detectedTechsNull.String,
		AuthModel:            authModelNull.String,
	}), nil
}

// ListScans lists historical assessments from SQLite database
func (s *ScanServer) ListScans(ctx context.Context, req *connect.Request[scanv1.ListScansRequest]) (*connect.Response[scanv1.ListScansResponse], error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, target_url, status, progress, profile, created_at, started_at, finished_at, detected_technologies, auth_model FROM scans ORDER BY created_at DESC")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to query scans: %w", err))
	}
	defer rows.Close()

	var scans []*scanv1.GetScanResponse
	for rows.Next() {
		var scanID, targetURL string
		var status int
		var progress float64
		var profile int
		var createdAt time.Time
		var startedAtNull, finishedAtNull sql.NullTime
		var detectedTechsNull, authModelNull sql.NullString

		if err := rows.Scan(&scanID, &targetURL, &status, &progress, &profile, &createdAt, &startedAtNull, &finishedAtNull, &detectedTechsNull, &authModelNull); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan row: %w", err))
		}

		var startedAt, finishedAt *timestamppb.Timestamp
		if startedAtNull.Valid {
			startedAt = timestamppb.New(startedAtNull.Time)
		}
		if finishedAtNull.Valid {
			finishedAt = timestamppb.New(finishedAtNull.Time)
		}

		scans = append(scans, &scanv1.GetScanResponse{
			ScanId:               scanID,
			Config: &scanv1.ScanConfig{
				TargetUrl: targetURL,
				Profile:   scanv1.ScanProfile(profile),
			},
			Status:               scanv1.ScanStatus(status),
			Progress:             float32(progress),
			CreatedAt:            timestamppb.New(createdAt),
			StartedAt:            startedAt,
			FinishedAt:           finishedAt,
			DetectedTechnologies: detectedTechsNull.String,
			AuthModel:            authModelNull.String,
		})
	}

	return connect.NewResponse(&scanv1.ListScansResponse{Scans: scans}), nil
}

// StreamScanEvents streams real-time log messages using the EventBroker pub-sub channels
func (s *ScanServer) StreamScanEvents(ctx context.Context, req *connect.Request[scanv1.StreamScanEventsRequest], stream *connect.ServerStream[scanv1.ScanEvent]) error {
	scanID := req.Msg.ScanId

	// Verify scan exists
	var exists int
	err := s.DB.QueryRowContext(ctx, "SELECT 1 FROM scans WHERE id = ?", scanID).Scan(&exists)
	if err != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("scan not found"))
	}

	// Subscribe to live orchestrator event broker
	eventCh := orchestrator.GlobalBroker.Subscribe(scanID)
	defer orchestrator.GlobalBroker.Unsubscribe(scanID, eventCh)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-eventCh:
			if !ok {
				return nil
			}

			structPayload, err := structpb.NewStruct(ev.Data)
			if err != nil {
				return connect.NewError(connect.CodeInternal, err)
			}

			err = stream.Send(&scanv1.ScanEvent{
				ScanId:    ev.ScanID,
				EventType: string(ev.Type),
				Timestamp: timestamppb.New(ev.Timestamp),
				Data:      structPayload,
			})
			if err != nil {
				return err
			}

			if ev.Type == orchestrator.EventScanCompleted {
				return nil
			}
		}
	}
}

// ListFlows retrieves proxy history transactions from SQLite database
func (s *ScanServer) ListFlows(ctx context.Context, req *connect.Request[scanv1.ListFlowsRequest]) (*connect.Response[scanv1.ListFlowsResponse], error) {
	scanID := req.Msg.ScanId

	var rows *sql.Rows
	var err error

	if scanID != "" {
		rows, err = s.DB.QueryContext(ctx, "SELECT id, scan_id, method, url, request_headers, request_body, response_headers, response_body, response_status, created_at FROM http_flows WHERE scan_id = ? ORDER BY id DESC", scanID)
	} else {
		rows, err = s.DB.QueryContext(ctx, "SELECT id, scan_id, method, url, request_headers, request_body, response_headers, response_body, response_status, created_at FROM http_flows ORDER BY id DESC")
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to query flows: %w", err))
	}
	defer rows.Close()

	var flows []*scanv1.FlowRecord
	for rows.Next() {
		var f scanv1.FlowRecord
		var createdAt time.Time
		err := rows.Scan(&f.Id, &f.ScanId, &f.Method, &f.Url, &f.RequestHeaders, &f.RequestBody, &f.ResponseHeaders, &f.ResponseBody, &f.ResponseStatus, &createdAt)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan flow: %w", err))
		}
		f.CreatedAt = createdAt.Format(time.RFC3339)
		flows = append(flows, &f)
	}

	return connect.NewResponse(&scanv1.ListFlowsResponse{Flows: flows}), nil
}

// ListFindings retrieves passive and active security findings from SQLite database
func (s *ScanServer) ListFindings(ctx context.Context, req *connect.Request[scanv1.ListFindingsRequest]) (*connect.Response[scanv1.ListFindingsResponse], error) {
	scanID := req.Msg.ScanId

	var rows *sql.Rows
	var err error

	if scanID != "" {
		rows, err = s.DB.QueryContext(ctx, "SELECT id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive, created_at FROM findings WHERE scan_id = ? ORDER BY created_at DESC", scanID)
	} else {
		rows, err = s.DB.QueryContext(ctx, "SELECT id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive, created_at FROM findings ORDER BY created_at DESC")
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to query findings: %w", err))
	}
	defer rows.Close()

	var findings []*scanv1.FindingRecord
	for rows.Next() {
		var f scanv1.FindingRecord
		var isFP int
		var createdAt time.Time
		var category sql.NullString
		err := rows.Scan(&f.Id, &f.ScanId, &f.Title, &f.Description, &f.Severity, &f.VulnerabilityType, &f.Endpoint, &f.Payload, &f.ResponseStatus, &f.Confidence, &category, &isFP, &createdAt)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan finding: %w", err))
		}
		f.Category = category.String
		f.IsFalsePositive = (isFP == 1)
		f.CreatedAt = createdAt.Format(time.RFC3339)
		findings = append(findings, &f)
	}

	return connect.NewResponse(&scanv1.ListFindingsResponse{Findings: findings}), nil
}

// ListEndpoints retrieves discovered endpoints from SQLite database
func (s *ScanServer) ListEndpoints(ctx context.Context, req *connect.Request[scanv1.ListEndpointsRequest]) (*connect.Response[scanv1.ListEndpointsResponse], error) {
	scanID := req.Msg.ScanId

	endpoints, err := s.DB.ListEndpoints(ctx, scanID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list endpoints: %w", err))
	}

	var records []*scanv1.EndpointRecord
	for _, ep := range endpoints {
		records = append(records, &scanv1.EndpointRecord{
			Id:          ep.ID,
			ScanId:      ep.ScanID,
			Method:      ep.Method,
			Url:         ep.URL,
			Source:      ep.Source,
			StatusCode:  int32(ep.StatusCode),
			ContentType: ep.ContentType,
			FirstSeenAt: ep.FirstSeenAt,
			LastSeenAt:  ep.LastSeenAt,
		})
	}

	return connect.NewResponse(&scanv1.ListEndpointsResponse{Endpoints: records}), nil
}

// SendRepeaterRequest establishes a direct socket connection to forward a custom HTTP request
func (s *ScanServer) SendRepeaterRequest(ctx context.Context, req *connect.Request[scanv1.SendRepeaterRequestRequest]) (*connect.Response[scanv1.SendRepeaterRequestResponse], error) {
	rawRequest := req.Msg.RawRequest
	targetHost := req.Msg.TargetHost
	useTLS := req.Msg.UseTls

	// Normalize hostname
	targetHost = strings.TrimPrefix(targetHost, "http://")
	targetHost = strings.TrimPrefix(targetHost, "https://")

	if !strings.Contains(targetHost, ":") {
		if useTLS {
			targetHost += ":443"
		} else {
			targetHost += ":80"
		}
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	var err error

	if useTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", targetHost, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", targetHost)
	}

	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to connect to %s: %w", targetHost, err))
	}
	defer conn.Close()

	// Forward raw payload bytes
	_, err = conn.Write([]byte(rawRequest))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send raw request bytes: %w", err))
	}

	// Ensure we set read deadline to prevent lockups on keep-alive
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var responseBuf bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			responseBuf.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	return connect.NewResponse(&scanv1.SendRepeaterRequestResponse{
		RawResponse: responseBuf.String(),
	}), nil
}

// GenerateReport invokes report generator to build assessment exports
func (s *ScanServer) GenerateReport(ctx context.Context, req *connect.Request[scanv1.GenerateReportRequest]) (*connect.Response[scanv1.GenerateReportResponse], error) {
	scanID := req.Msg.ScanId

	gen := report.NewGenerator(s.DB, s.AiClient)
	_, htmlPath, err := gen.GenerateScanReport(ctx, scanID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate report: %w", err))
	}

	reports, err := s.DB.ListReports(ctx, scanID)
	var reportID string
	if err == nil && len(reports) > 0 {
		reportID = reports[0].ID
	}

	return connect.NewResponse(&scanv1.GenerateReportResponse{
		ReportId: reportID,
		Path:     htmlPath,
	}), nil
}

// ListReports retrieves historical report records from SQLite
func (s *ScanServer) ListReports(ctx context.Context, req *connect.Request[scanv1.ListReportsRequest]) (*connect.Response[scanv1.ListReportsResponse], error) {
	scanID := req.Msg.ScanId

	reports, err := s.DB.ListReports(ctx, scanID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list reports: %w", err))
	}

	var records []*scanv1.ReportRecord
	for _, r := range reports {
		records = append(records, &scanv1.ReportRecord{
			Id:        r.ID,
			ScanId:    r.ScanID,
			Format:    r.Format,
			Path:      r.Path,
			Title:     r.Title,
			CreatedAt: r.CreatedAt,
		})
	}

	return connect.NewResponse(&scanv1.ListReportsResponse{Reports: records}), nil
}
