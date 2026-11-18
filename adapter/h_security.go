package adapter

// InsecureReasoner is an outbound or endpoint manager that remembers, from the options each
// outbound was created with, why it is not secure (option.InsecureReason). //H
type InsecureReasoner interface {
	// InsecureReason is one of the C.Insecure* reasons, or "" for a secure proxy, a group or a tag
	// it does not know.
	InsecureReason(tag string) string
}

// InsecureReason is why the outbound or endpoint tagged tag is not secure, or "" when it is.
func InsecureReason(manager OutboundManager, tag string) string {
	if reasoner, ok := manager.(InsecureReasoner); ok {
		return reasoner.InsecureReason(tag)
	}
	return ""
}
