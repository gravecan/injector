package injector

import (
	"fmt"
	"runtime"
	"strings"
)

type ErrorType int

const (

	ErrorTypeUnknown ErrorType = iota
	ErrorTypeInvalidInput
	ErrorTypePermission
	ErrorTypeMemoryAllocation
	ErrorTypeProcessAccess
	ErrorTypeArchitectureMismatch
	ErrorTypePEParsing
	ErrorTypeInjectionFailed
	ErrorTypeTimeout
	ErrorTypeSystemCall
	ErrorTypeResourceExhausted
	ErrorTypeNotSupported
)

type ErrorSeverity int

const (

	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

type InjectorError struct {
	Type        ErrorType
	Severity    ErrorSeverity
	Message     string
	Cause       error
	Context     map[string]interface{}
	Recoverable bool
	Suggestions []string
	StackTrace  string
}

func (e *InjectorError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] %s: %s", e.severityString(), e.typeString(), e.Message))

	if e.Cause != nil {
		sb.WriteString(fmt.Sprintf(" (caused by: %v)", e.Cause))
	}

	if len(e.Suggestions) > 0 {
		sb.WriteString("\nSuggestions:")
		for i, suggestion := range e.Suggestions {
			sb.WriteString(fmt.Sprintf("\n  %d. %s", i+1, suggestion))
		}
	}

	return sb.String()
}

func (e *InjectorError) Unwrap() error {
	return e.Cause
}

func (e *InjectorError) IsRecoverable() bool {
	return e.Recoverable
}

func (e *InjectorError) AddContext(key string, value interface{}) *InjectorError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

func (e *InjectorError) AddSuggestion(suggestion string) *InjectorError {
	e.Suggestions = append(e.Suggestions, suggestion)
	return e
}

func (e *InjectorError) typeString() string {
	switch e.Type {
	case ErrorTypeInvalidInput:
		return "InvalidInput"
	case ErrorTypePermission:
		return "Permission"
	case ErrorTypeMemoryAllocation:
		return "MemoryAllocation"
	case ErrorTypeProcessAccess:
		return "ProcessAccess"
	case ErrorTypeArchitectureMismatch:
		return "ArchitectureMismatch"
	case ErrorTypePEParsing:
		return "PEParsing"
	case ErrorTypeInjectionFailed:
		return "InjectionFailed"
	case ErrorTypeTimeout:
		return "Timeout"
	case ErrorTypeSystemCall:
		return "SystemCall"
	case ErrorTypeResourceExhausted:
		return "ResourceExhausted"
	case ErrorTypeNotSupported:
		return "NotSupported"
	default:
		return "Unknown"
	}
}

func (e *InjectorError) severityString() string {
	switch e.Severity {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func NewError(errType ErrorType, message string, cause error) *InjectorError {

	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)

	return &InjectorError{
		Type:        errType,
		Severity:    SeverityError,
		Message:     message,
		Cause:       cause,
		Context:     make(map[string]interface{}),
		Recoverable: false,
		StackTrace:  string(buf[:n]),
	}
}

func NewRecoverableError(errType ErrorType, message string, cause error) *InjectorError {
	err := NewError(errType, message, cause)
	err.Recoverable = true
	err.Severity = SeverityWarning
	return err
}

func NewCriticalError(errType ErrorType, message string, cause error) *InjectorError {
	err := NewError(errType, message, cause)
	err.Severity = SeverityCritical
	err.Recoverable = false
	return err
}


func ErrInvalidInput(message string, input interface{}) *InjectorError {
	return NewError(ErrorTypeInvalidInput, message, nil).
		AddContext("input", input).
		AddSuggestion("Verify the input parameters are correct")
}

func ErrPermissionDenied(operation string) *InjectorError {
	return NewError(ErrorTypePermission,
		fmt.Sprintf("Permission denied for operation: %s", operation), nil).
		AddContext("operation", operation).
		AddSuggestion("Run the application as Administrator").
		AddSuggestion("Check if the target process is protected")
}

func ErrMemoryAllocation(size uintptr, err error) *InjectorError {
	return NewError(ErrorTypeMemoryAllocation,
		fmt.Sprintf("Failed to allocate %d bytes of memory", size), err).
		AddContext("size", size).
		AddSuggestion("Close other applications to free memory").
		AddSuggestion("Try a smaller DLL or different injection method")
}

func ErrProcessAccess(pid uint32, err error) *InjectorError {
	return NewError(ErrorTypeProcessAccess,
		fmt.Sprintf("Cannot access process %d", pid), err).
		AddContext("pid", pid).
		AddSuggestion("Verify the process ID is correct").
		AddSuggestion("Check if the process is still running").
		AddSuggestion("Run with elevated privileges")
}

func ErrArchitectureMismatch(processArch, dllArch string) *InjectorError {
	return NewError(ErrorTypeArchitectureMismatch,
		fmt.Sprintf("Architecture mismatch: process is %s but DLL is %s", processArch, dllArch), nil).
		AddContext("process_arch", processArch).
		AddContext("dll_arch", dllArch).
		AddSuggestion(fmt.Sprintf("Use a %s version of the DLL", processArch)).
		AddSuggestion("Recompile the DLL for the target architecture")
}

func ErrPEParsing(reason string, err error) *InjectorError {
	return NewError(ErrorTypePEParsing,
		fmt.Sprintf("Failed to parse PE file: %s", reason), err).
		AddSuggestion("Verify the file is a valid Windows PE file").
		AddSuggestion("Check if the file is corrupted")
}

func ErrInjectionFailed(method string, reason string, err error) *InjectorError {
	return NewError(ErrorTypeInjectionFailed,
		fmt.Sprintf("Injection failed using %s: %s", method, reason), err).
		AddContext("method", method).
		AddSuggestion("Try a different injection method").
		AddSuggestion("Check if anti-virus is blocking the injection")
}

func ErrTimeout(operation string, timeout int) *InjectorError {
	return NewRecoverableError(ErrorTypeTimeout,
		fmt.Sprintf("Operation '%s' timed out after %d seconds", operation, timeout), nil).
		AddContext("operation", operation).
		AddContext("timeout", timeout).
		AddSuggestion("Increase the timeout duration").
		AddSuggestion("Check if the target process is responding")
}

func IsRecoverableError(err error) bool {
	if injErr, ok := err.(*InjectorError); ok {
		return injErr.IsRecoverable()
	}
	return false
}

func GetErrorType(err error) ErrorType {
	if injErr, ok := err.(*InjectorError); ok {
		return injErr.Type
	}
	return ErrorTypeUnknown
}

func WrapError(err error, errType ErrorType, message string) *InjectorError {
	if err == nil {
		return nil
	}

	if injErr, ok := err.(*InjectorError); ok {
		newErr := &InjectorError{
			Type:        errType,
			Severity:    injErr.Severity,
			Message:     message,
			Cause:       injErr,
			Context:     injErr.Context,
			Recoverable: injErr.Recoverable,
			Suggestions: injErr.Suggestions,
			StackTrace:  injErr.StackTrace,
		}
		return newErr
	}

	return NewError(errType, message, err)
}
