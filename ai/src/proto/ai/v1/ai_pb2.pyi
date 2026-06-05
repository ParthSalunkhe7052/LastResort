from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("status", "provider", "model", "initialized")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    status: str
    provider: str
    model: str
    initialized: bool
    def __init__(self, status: _Optional[str] = ..., provider: _Optional[str] = ..., model: _Optional[str] = ..., initialized: bool = ...) -> None: ...

class FindingSummary(_message.Message):
    __slots__ = ("title", "severity", "vulnerability_type", "endpoint", "confidence")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    VULNERABILITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    title: str
    severity: str
    vulnerability_type: str
    endpoint: str
    confidence: float
    def __init__(self, title: _Optional[str] = ..., severity: _Optional[str] = ..., vulnerability_type: _Optional[str] = ..., endpoint: _Optional[str] = ..., confidence: _Optional[float] = ...) -> None: ...

class GenerateExecutiveSummaryRequest(_message.Message):
    __slots__ = ("target_url", "high_count", "medium_count", "low_count", "info_count", "findings", "duration", "detected_technologies")
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    HIGH_COUNT_FIELD_NUMBER: _ClassVar[int]
    MEDIUM_COUNT_FIELD_NUMBER: _ClassVar[int]
    LOW_COUNT_FIELD_NUMBER: _ClassVar[int]
    INFO_COUNT_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_TECHNOLOGIES_FIELD_NUMBER: _ClassVar[int]
    target_url: str
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    findings: _containers.RepeatedCompositeFieldContainer[FindingSummary]
    duration: str
    detected_technologies: str
    def __init__(self, target_url: _Optional[str] = ..., high_count: _Optional[int] = ..., medium_count: _Optional[int] = ..., low_count: _Optional[int] = ..., info_count: _Optional[int] = ..., findings: _Optional[_Iterable[_Union[FindingSummary, _Mapping]]] = ..., duration: _Optional[str] = ..., detected_technologies: _Optional[str] = ...) -> None: ...

class GenerateExecutiveSummaryResponse(_message.Message):
    __slots__ = ("summary", "risk_rating", "key_recommendations")
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    RISK_RATING_FIELD_NUMBER: _ClassVar[int]
    KEY_RECOMMENDATIONS_FIELD_NUMBER: _ClassVar[int]
    summary: str
    risk_rating: str
    key_recommendations: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, summary: _Optional[str] = ..., risk_rating: _Optional[str] = ..., key_recommendations: _Optional[_Iterable[str]] = ...) -> None: ...
