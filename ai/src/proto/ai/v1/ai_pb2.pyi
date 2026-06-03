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

class AnalyzeReconRequest(_message.Message):
    __slots__ = ("target_url", "headers", "cookie_names")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    COOKIE_NAMES_FIELD_NUMBER: _ClassVar[int]
    target_url: str
    headers: _containers.ScalarMap[str, str]
    cookie_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, target_url: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., cookie_names: _Optional[_Iterable[str]] = ...) -> None: ...

class AnalyzeReconResponse(_message.Message):
    __slots__ = ("detected_technologies", "authentication_model", "recommended_tests")
    DETECTED_TECHNOLOGIES_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_MODEL_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDED_TESTS_FIELD_NUMBER: _ClassVar[int]
    detected_technologies: _containers.RepeatedScalarFieldContainer[str]
    authentication_model: str
    recommended_tests: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, detected_technologies: _Optional[_Iterable[str]] = ..., authentication_model: _Optional[str] = ..., recommended_tests: _Optional[_Iterable[str]] = ...) -> None: ...

class GenerateHypothesesRequest(_message.Message):
    __slots__ = ("target_url", "endpoints")
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    target_url: str
    endpoints: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, target_url: _Optional[str] = ..., endpoints: _Optional[_Iterable[str]] = ...) -> None: ...

class Hypothesis(_message.Message):
    __slots__ = ("id", "title", "description", "confidence", "vulnerability_type")
    ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    VULNERABILITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    id: str
    title: str
    description: str
    confidence: float
    vulnerability_type: str
    def __init__(self, id: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., confidence: _Optional[float] = ..., vulnerability_type: _Optional[str] = ...) -> None: ...

class GenerateHypothesesResponse(_message.Message):
    __slots__ = ("hypotheses",)
    HYPOTHESES_FIELD_NUMBER: _ClassVar[int]
    hypotheses: _containers.RepeatedCompositeFieldContainer[Hypothesis]
    def __init__(self, hypotheses: _Optional[_Iterable[_Union[Hypothesis, _Mapping]]] = ...) -> None: ...

class ScoreConfidenceRequest(_message.Message):
    __slots__ = ("vulnerability_type", "endpoint", "payload", "response_body", "response_status")
    VULNERABILITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_STATUS_FIELD_NUMBER: _ClassVar[int]
    vulnerability_type: str
    endpoint: str
    payload: str
    response_body: str
    response_status: int
    def __init__(self, vulnerability_type: _Optional[str] = ..., endpoint: _Optional[str] = ..., payload: _Optional[str] = ..., response_body: _Optional[str] = ..., response_status: _Optional[int] = ...) -> None: ...

class ScoreConfidenceResponse(_message.Message):
    __slots__ = ("confidence", "explanation", "is_false_positive")
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    IS_FALSE_POSITIVE_FIELD_NUMBER: _ClassVar[int]
    confidence: float
    explanation: str
    is_false_positive: bool
    def __init__(self, confidence: _Optional[float] = ..., explanation: _Optional[str] = ..., is_false_positive: bool = ...) -> None: ...

class GenerateFindingNarrativeRequest(_message.Message):
    __slots__ = ("vulnerability_type", "title", "endpoint", "evidence", "confidence")
    VULNERABILITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    vulnerability_type: str
    title: str
    endpoint: str
    evidence: str
    confidence: float
    def __init__(self, vulnerability_type: _Optional[str] = ..., title: _Optional[str] = ..., endpoint: _Optional[str] = ..., evidence: _Optional[str] = ..., confidence: _Optional[float] = ...) -> None: ...

class GenerateFindingNarrativeResponse(_message.Message):
    __slots__ = ("description", "remediation")
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    REMEDIATION_FIELD_NUMBER: _ClassVar[int]
    description: str
    remediation: str
    def __init__(self, description: _Optional[str] = ..., remediation: _Optional[str] = ...) -> None: ...

class GenerateAttackPayloadRequest(_message.Message):
    __slots__ = ("hypothesis_title", "hypothesis_description", "endpoint", "method")
    HYPOTHESIS_TITLE_FIELD_NUMBER: _ClassVar[int]
    HYPOTHESIS_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    hypothesis_title: str
    hypothesis_description: str
    endpoint: str
    method: str
    def __init__(self, hypothesis_title: _Optional[str] = ..., hypothesis_description: _Optional[str] = ..., endpoint: _Optional[str] = ..., method: _Optional[str] = ...) -> None: ...

class GenerateAttackPayloadResponse(_message.Message):
    __slots__ = ("method", "url", "body", "headers", "explanation")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METHOD_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    method: str
    url: str
    body: str
    headers: _containers.ScalarMap[str, str]
    explanation: str
    def __init__(self, method: _Optional[str] = ..., url: _Optional[str] = ..., body: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., explanation: _Optional[str] = ...) -> None: ...

class DecideBrowserActionRequest(_message.Message):
    __slots__ = ("url", "page_source", "current_goal")
    URL_FIELD_NUMBER: _ClassVar[int]
    PAGE_SOURCE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_GOAL_FIELD_NUMBER: _ClassVar[int]
    url: str
    page_source: str
    current_goal: str
    def __init__(self, url: _Optional[str] = ..., page_source: _Optional[str] = ..., current_goal: _Optional[str] = ...) -> None: ...

class DecideBrowserActionResponse(_message.Message):
    __slots__ = ("action", "selector", "value", "explanation")
    ACTION_FIELD_NUMBER: _ClassVar[int]
    SELECTOR_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    action: str
    selector: str
    value: str
    explanation: str
    def __init__(self, action: _Optional[str] = ..., selector: _Optional[str] = ..., value: _Optional[str] = ..., explanation: _Optional[str] = ...) -> None: ...
