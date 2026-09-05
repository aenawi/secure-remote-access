// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hashem Aldhaheri

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Lab is the only thing in this program that talks to Docker. Everything above
// it deals in machines and commands; everything below it is the daemon.
type Lab struct {
	cli *client.Client
	// Compose prefixes container names with the project. Resolved once at
	// startup so the rest of the code can say "lab-vps" and mean it.
	prefix string
}

func NewLab() (*Lab, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Lab{cli: cli}, nil
}

func (l *Lab) Close() error { return l.cli.Close() }

// Result is what every command in this lab returns, and it is deliberately the
// same shape the sandbox page returns for its modelled probes: never a bare
// true/false, always the rung that decided it and the rule that did the
// deciding. The two extra fields — Cmd and Raw — are the only thing a real
// stack can add: the command that ran, and what it actually said.
type Result struct {
	OK          bool    `json:"ok"`
	Rung        int     `json:"rung"`
	Rule        string  `json:"rule"`
	Why         string  `json:"why"`
	RTTMs       float64 `json:"rttMs"`
	LossPct     float64 `json:"lossPct"`
	Packets     int     `json:"packets"`
	Retransmits int     `json:"retransmits"`
	Bytes       int     `json:"bytes"`
	Danger      bool    `json:"danger"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Port string `json:"port,omitempty"`
	Path string `json:"path,omitempty"` // direct | relay | lan | public

	Cmds []string `json:"cmds,omitempty"`
	Raw  string   `json:"raw,omitempty"`
	Hex  string   `json:"hex,omitempty"`

	// Evidence is the handful of counts an action measured, kept as numbers so
	// a caller does not have to read Why to find out what happened. Why stays
	// prose for humans; anything a drawing needs to be true belongs here, where
	// it cannot be lost to a rewording. Most actions measure nothing countable
	// and omit it.
	Evidence map[string]int `json:"evidence,omitempty"`

	// Detail is Evidence's other half: the handful of short strings an action
	// measured, for the things that are facts rather than counts. An address a
	// machine moved to is one of those, and a drawing that needs it has only
	// two other places to get it — Raw or Cmds — which means regexing English
	// for something the Go side already had in a variable. Same rule as
	// Evidence: prose is for humans, and anything a drawing has to be true
	// about belongs in here, where a rewording cannot lose it.
	Detail map[string]string `json:"detail,omitempty"`
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

type ExecResult struct {
	Stdout string
	Stderr string
	Code   int
}

func (e ExecResult) Out() string {
	s := strings.TrimRight(e.Stdout, "\n")
	if t := strings.TrimRight(e.Stderr, "\n"); t != "" {
		if s != "" {
			s += "\n"
		}
		s += t
	}
	return s
}

// Exec runs a command inside a lab container and waits for it. Almost every
// action in this program is one of these; the interesting part is always what
// the command was, which is why callers pass argv rather than a shell string
// unless they need a pipeline.
func (l *Lab) Exec(ctx context.Context, name string, argv ...string) (ExecResult, error) {
	var res ExecResult

	create, err := l.cli.ContainerExecCreate(ctx, l.name(name), container.ExecOptions{
		Cmd:          argv,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return res, fmt.Errorf("exec create on %s: %w", name, err)
	}

	att, err := l.cli.ContainerExecAttach(ctx, create.ID, container.ExecAttachOptions{})
	if err != nil {
		return res, fmt.Errorf("exec attach on %s: %w", name, err)
	}
	defer att.Close()

	var out, errb bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &errb, att.Reader); err != nil && !errors.Is(err, io.EOF) {
		return res, fmt.Errorf("exec read on %s: %w", name, err)
	}
	res.Stdout, res.Stderr = out.String(), errb.String()

	insp, err := l.cli.ContainerExecInspect(ctx, create.ID)
	if err != nil {
		return res, fmt.Errorf("exec inspect on %s: %w", name, err)
	}
	res.Code = insp.ExitCode
	return res, nil
}

// Sh runs a shell pipeline. Used only where a pipeline is genuinely the
// clearest thing — tcpdump into xxd, mostly.
func (l *Lab) Sh(ctx context.Context, name, script string) (ExecResult, error) {
	return l.Exec(ctx, name, "sh", "-c", script)
}

// ExecStream runs a long-lived command and calls fn for each line it writes.
// It returns when the command exits or the context is cancelled — which is how
// the tcpdump pane stops when you close the tab.
func (l *Lab) ExecStream(ctx context.Context, name string, argv []string, fn func(string)) error {
	create, err := l.cli.ContainerExecCreate(ctx, l.name(name), container.ExecOptions{
		Cmd:          argv,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return err
	}
	att, err := l.cli.ContainerExecAttach(ctx, create.ID, container.ExecAttachOptions{})
	if err != nil {
		return err
	}
	defer att.Close()

	// Demultiplex Docker's framed stream into lines without buffering the whole
	// capture: a tcpdump left running all afternoon should not grow in memory.
	pr, pw := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(pw, pw, att.Reader)
		pw.CloseWithError(err)
	}()
	go func() {
		<-ctx.Done()
		att.Close()
		pr.CloseWithError(ctx.Err())
	}()

	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fn(sc.Text())
	}
	return ctx.Err()
}

// ---------------------------------------------------------------------------
// inspection
// ---------------------------------------------------------------------------

func (l *Lab) name(short string) string {
	if l.prefix == "" {
		return short
	}
	return l.prefix + short
}

// Running reports whether a lab container exists and is running. A stopped
// machine is rung 1, and rung 1 is a real answer.
func (l *Lab) Running(ctx context.Context, name string) bool {
	ok, _ := l.RunningErr(ctx, name)
	return ok
}

// RunningErr is the same question with the reason attached, for the few callers
// that are diagnosing the lab rather than probing it.
func (l *Lab) RunningErr(ctx context.Context, name string) (bool, error) {
	insp, err := l.cli.ContainerInspect(ctx, l.name(name))
	if err != nil {
		return false, err
	}
	return insp.State != nil && insp.State.Running, nil
}

func (l *Lab) Exists(ctx context.Context, name string) bool {
	_, err := l.cli.ContainerInspect(ctx, l.name(name))
	return err == nil
}

func (l *Lab) Start(ctx context.Context, name string) error {
	return l.cli.ContainerStart(ctx, l.name(name), container.StartOptions{})
}

func (l *Lab) Stop(ctx context.Context, name string) error {
	t := 5
	return l.cli.ContainerStop(ctx, l.name(name), container.StopOptions{Timeout: &t})
}

// IPOn returns the container's address on a given compose network, matched by
// suffix because compose prefixes network names with the project too.
func (l *Lab) IPOn(ctx context.Context, name, netSuffix string) string {
	insp, err := l.cli.ContainerInspect(ctx, l.name(name))
	if err != nil || insp.NetworkSettings == nil {
		return ""
	}
	for n, ep := range insp.NetworkSettings.Networks {
		if strings.HasSuffix(n, netSuffix) {
			return ep.IPAddress
		}
	}
	return ""
}

func (l *Lab) Networks(ctx context.Context, name string) map[string]*network.EndpointSettings {
	insp, err := l.cli.ContainerInspect(ctx, l.name(name))
	if err != nil || insp.NetworkSettings == nil {
		return nil
	}
	return insp.NetworkSettings.Networks
}

// Stats reads one sample of a container's CPU, memory and interface counters.
type Stats struct {
	Name    string  `json:"name"`
	CPUPct  float64 `json:"cpuPct"`
	MemMB   float64 `json:"memMB"`
	RxBytes uint64  `json:"rxBytes"`
	TxBytes uint64  `json:"txBytes"`
}

func (l *Lab) Stats(ctx context.Context, name string) (Stats, error) {
	s := Stats{Name: name}
	resp, err := l.cli.ContainerStatsOneShot(ctx, l.name(name))
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()

	var v container.StatsResponse
	if err := decodeJSON(resp.Body, &v); err != nil {
		return s, err
	}
	cpuDelta := float64(v.CPUStats.CPUUsage.TotalUsage) - float64(v.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(v.CPUStats.SystemUsage) - float64(v.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta > 0 {
		s.CPUPct = (cpuDelta / sysDelta) * float64(v.CPUStats.OnlineCPUs) * 100
	}
	s.MemMB = float64(v.MemoryStats.Usage) / (1024 * 1024)
	for _, n := range v.Networks {
		s.RxBytes += n.RxBytes
		s.TxBytes += n.TxBytes
	}
	return s, nil
}

// PublishedBindings returns every host binding for this control container, so
// main.go can refuse to run if the lab has been published off loopback.
func (l *Lab) PublishedBindings(ctx context.Context, self string) ([]string, error) {
	insp, err := l.cli.ContainerInspect(ctx, self)
	if err != nil {
		return nil, err
	}
	var out []string
	if insp.HostConfig == nil {
		return out, nil
	}
	for port, binds := range insp.HostConfig.PortBindings {
		for _, b := range binds {
			out = append(out, fmt.Sprintf("%s -> %s:%s", port, b.HostIP, b.HostPort))
		}
	}
	return out, nil
}

// WaitFor polls fn until it returns true, or the deadline passes. Used for the
// handful of "is the coordination server answering yet" waits at startup.
func WaitFor(ctx context.Context, d time.Duration, every time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
	return false
}
