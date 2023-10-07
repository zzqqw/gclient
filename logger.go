package gclient

import (
	"fmt"
	"github.com/gookit/color"
	"log"
	"os"
)

var LoggerPrefixName = Name

const (
	LevelError = "ERROR"
	LevelDebug = "DEBUG"
	LevelWarn  = "WARN"
	LevelInfo  = "INFO"
)

type LoggerInterface interface {
	Errorf(format string, v ...any)
	Warnf(format string, v ...any)
	Debugf(format string, v ...any)
	Infof(format string, v ...any)
}

var _ LoggerInterface = (*logger)(nil)

type logger struct {
	l *log.Logger
}

func NewLogger() LoggerInterface {
	l := &logger{l: log.New(os.Stdout, "", log.Lmsgprefix|log.Lshortfile|log.Ldate|log.Lmicroseconds)}
	return l
}

func (e *logger) Errorf(format string, v ...any) {
	e.Output(LevelError, format, v...)
}

func (e *logger) Warnf(format string, v ...any) {
	e.Output(LevelWarn, format, v...)
}

func (e *logger) Debugf(format string, v ...any) {
	e.Output(LevelDebug, format, v...)
}
func (e *logger) Infof(format string, v ...any) {
	e.Output(LevelInfo, format, v...)
}

func (e *logger) Output(level string, format string, v ...any) {
	e.l.SetPrefix(fmt.Sprintf("%s [%s] >> ", LoggerPrefixName, level))
	var s string
	switch level {
	case LevelError:
		s = color.Red.Text(fmt.Sprintf(format, v...))
	case LevelDebug:
		s = color.Cyan.Text(fmt.Sprintf(format, v...))
	case LevelWarn:
		s = color.Yellow.Text(fmt.Sprintf(format, v...))
	default:
		s = fmt.Sprintf(format, v...)
	}
	_ = e.l.Output(3, s)
	return
}
