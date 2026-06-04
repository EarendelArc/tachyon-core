package pipeline

import (
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/routing"
)

type Action string

const (
	ActionXray   Action = "xray"
	ActionTGP    Action = "tgp"
	ActionDirect Action = "direct"
	ActionDrop   Action = "drop"
)

type Decision struct {
	Action    Action
	Reason    string
	RuleIndex int
	Process   pidtrack.ProcessInfo
	Flow      pidtrack.FlowKey
}

type Router struct {
	mu            sync.RWMutex
	rules         []indexedRule
	defaultAction Action
	gameEngine    routing.Engine
}

type indexedRule struct {
	index int
	rule  config.RouteRule
}

func NewRouter(cfg config.RoutingConfig, gameEngine routing.Engine) *Router {
	rules := make([]indexedRule, 0, len(cfg.Rules))
	for idx, rule := range cfg.Rules {
		rules = append(rules, indexedRule{index: idx, rule: rule})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].rule.Priority > rules[j].rule.Priority
	})

	return &Router{
		rules:         rules,
		defaultAction: normalizeAction(cfg.DefaultAction, ActionXray),
		gameEngine:    gameEngine,
	}
}

func (r *Router) SetGameEngine(gameEngine routing.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gameEngine = gameEngine
}

func (r *Router) Decide(flow pidtrack.FlowKey, proc pidtrack.ProcessInfo) Decision {
	r.mu.RLock()
	gameEngine := r.gameEngine
	r.mu.RUnlock()

	if game := gameEngine.Decide(proc, flow); game.Kind == routing.DecisionGame {
		action := actionFromPolicies(flow.Transport, game)
		if action != "" {
			return Decision{
				Action:  action,
				Reason:  game.Reason,
				Process: proc,
				Flow:    flow,
			}
		}
	}

	for _, indexed := range r.rules {
		if routeRuleMatches(indexed.rule, flow, proc) {
			return Decision{
				Action:    normalizeAction(indexed.rule.Action, r.defaultAction),
				Reason:    "config route rule matched",
				RuleIndex: indexed.index,
				Process:   proc,
				Flow:      flow,
			}
		}
	}

	return Decision{
		Action:  r.defaultAction,
		Reason:  "default action",
		Process: proc,
		Flow:    flow,
	}
}

func routeRuleMatches(rule config.RouteRule, flow pidtrack.FlowKey, proc pidtrack.ProcessInfo) bool {
	if rule.Protocol != "" && !strings.EqualFold(rule.Protocol, string(flow.Transport)) {
		return false
	}
	if rule.ProcessName != "" && !strings.EqualFold(rule.ProcessName, proc.Name) {
		return false
	}
	if rule.CIDR != "" && !cidrContains(rule.CIDR, flow.RemoteIP) {
		return false
	}
	if rule.Domain != "" {
		return false
	}
	if rule.GeoIPCountry != "" {
		return false
	}

	return rule.Protocol != "" || rule.ProcessName != "" || rule.CIDR != ""
}

func cidrContains(cidr string, ip string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

func actionFromPolicies(transport pidtrack.Transport, decision routing.Decision) Action {
	if transport == pidtrack.TransportUDP {
		switch decision.UDPPolicy {
		case routing.UDPPolicyTGP:
			return ActionTGP
		case routing.UDPPolicyDirect:
			return ActionDirect
		case routing.UDPPolicyBlock:
			return ActionDrop
		}
	}

	if transport == pidtrack.TransportTCP {
		switch decision.TCPPolicy {
		case routing.TCPPolicyXray:
			return ActionXray
		case routing.TCPPolicyDirect:
			return ActionDirect
		case routing.TCPPolicyBlock:
			return ActionDrop
		}
	}

	return ""
}

func normalizeAction(raw string, fallback Action) Action {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "xray":
		return ActionXray
	case "tgp":
		return ActionTGP
	case "direct":
		return ActionDirect
	case "drop", "block":
		return ActionDrop
	default:
		return fallback
	}
}
