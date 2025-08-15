package logger

import (
	"fmt"
	"strings"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type Direction string

const (
	Outgoing Direction = "→"
	Incoming Direction = "←"
)

type LogEntry struct {
	Timestamp   time.Time
	Direction   Direction
	Source      string
	Destination string
	MessageType string
	Payload     map[string]interface{}
	Headers     map[string]string
}

func LogOAuthMessage(entry LogEntry) {
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
	
	var color string
	switch entry.Source {
	case "CLIENT":
		color = ColorBlue
	case "AUTH-SERVER":
		color = ColorGreen
	case "RESOURCE-SERVER":
		color = ColorYellow
	default:
		color = ColorWhite
	}

	fmt.Printf("\n%s[%s] %s %s %s%s\n", 
		color, timestamp, entry.Source, entry.Direction, entry.Destination, ColorReset)
	
	fmt.Printf("%s%s:%s\n", color, entry.MessageType, ColorReset)
	
	if len(entry.Payload) > 0 {
		for key, value := range entry.Payload {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}
	
	if len(entry.Headers) > 0 {
		fmt.Printf("  Headers:\n")
		for key, value := range entry.Headers {
			if strings.ToLower(key) == "authorization" && len(value) > 20 {
				fmt.Printf("    %s: %s...\n", key, value[:20])
			} else {
				fmt.Printf("    %s: %s\n", key, value)
			}
		}
	}
	
	fmt.Printf("%s%s%s\n", color, strings.Repeat("-", 50), ColorReset)
}

func LogInfo(component string, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s%s%s: %s\n", timestamp, ColorCyan, component, ColorReset, message)
}

func LogError(component string, err error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] %s%s ERROR%s: %v\n", timestamp, ColorRed, component, ColorReset, err)
}