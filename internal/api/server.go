package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// ListFlows is deprecated and returns an empty list.
func (s *ScanServer) ListFlows(ctx context.Context, req *connect.Request[scanv1.ListFlowsRequest]) (*connect.Response[scanv1.ListFlowsResponse], error) {
	return connect.NewResponse(&scanv1.ListFlowsResponse{}), nil
}

// ListFindings retrieves passive and active security findings from SQLite database
func (s *ScanServer) ListFindings(ctx context.Context, req *connect.Request[scanv1.ListFindingsRequest]) (*connect.Response[scanv1.ListFindingsResponse], error) {
	scanID := req.Msg.ScanId

	var rows *sql.Rows
	var err error

	// Filter and prioritize high severity / verified findings and cap at 10.
	queryStr := `
		SELECT id, scan_id, title, description, severity, vulnerability_type, endpoint, payload, response_status, confidence, category, is_false_positive, created_at 
		FROM findings 
		WHERE is_false_positive = 0 %s
		ORDER BY 
			CASE category
				WHEN 'VERIFIED_FINDING' THEN 1
				WHEN 'POTENTIAL_FINDING' THEN 2
				WHEN 'NEEDS_REVIEW' THEN 3
				WHEN 'OBSERVATION' THEN 4
				ELSE 5
			END ASC,
			CASE severity 
				WHEN 'CRITICAL' THEN 1 
				WHEN 'HIGH' THEN 2 
				WHEN 'MEDIUM' THEN 3 
				WHEN 'LOW' THEN 4 
				ELSE 5 
			END ASC, 
			confidence DESC, 
			created_at DESC 
		LIMIT 10`

	if scanID != "" {
		rows, err = s.DB.QueryContext(ctx, fmt.Sprintf(queryStr, "AND scan_id = ?"), scanID)
	} else {
		rows, err = s.DB.QueryContext(ctx, fmt.Sprintf(queryStr, ""))
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
		catStr := category.String
		switch catStr {
		case "VERIFIED_FINDING":
			catStr = "VERIFIED_ATTACK"
		case "POTENTIAL_FINDING":
			catStr = "HYPOTHESIS"
		case "FALSE_POSITIVE":
			catStr = "ATTEMPT"
		case "OBSERVATION":
			catStr = "OBSERVATION"
		case "":
			catStr = "OBSERVATION"
		}
		f.Category = catStr
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

// SendRepeaterRequest is deprecated.
func (s *ScanServer) SendRepeaterRequest(ctx context.Context, req *connect.Request[scanv1.SendRepeaterRequestRequest]) (*connect.Response[scanv1.SendRepeaterRequestResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("Repeater functionality is removed"))
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
