package output

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mgriffiths/ipintel/internal/config"
	"github.com/mgriffiths/ipintel/internal/lookup"
)

// RunWithSpinner runs the lookup engine with an animated spinner UI.
func RunWithSpinner(ctx context.Context, cfg *config.Config, ip string) (*lookup.Result, error) {
	engine := lookup.NewEngine(cfg)

	m := newSpinnerModel(engine, ctx, ip)
	p := tea.NewProgram(m, tea.WithContext(ctx))
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("UI error: %w", err)
	}

	final := finalModel.(spinnerModel)
	if final.err != nil {
		return nil, final.err
	}
	return final.result, nil
}

// Messages
type lookupDoneMsg struct {
	result *lookup.Result
	err    error
}

type spinnerModel struct {
	spinner  spinner.Model
	engine   *lookup.Engine
	ctx      context.Context
	ip       string
	result   *lookup.Result
	err      error
	done     bool
	quitting bool
}

func newSpinnerModel(engine *lookup.Engine, ctx context.Context, ip string) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorPrimary)

	return spinnerModel{
		spinner: s,
		engine:  engine,
		ctx:     ctx,
		ip:      ip,
	}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.runLookup(),
	)
}

func (m spinnerModel) runLookup() tea.Cmd {
	return func() tea.Msg {
		result, err := m.engine.Run(m.ctx, m.ip)
		return lookupDoneMsg{result: result, err: err}
	}
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	case lookupDoneMsg:
		m.result = msg.result
		m.err = msg.err
		m.done = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m spinnerModel) View() string {
	if m.done || m.quitting {
		return ""
	}

	providers := m.engine.ProviderNames()
	providerList := strings.Join(providers, ", ")

	return fmt.Sprintf("\n %s Querying %d sources for %s\n   %s\n\n",
		m.spinner.View(),
		len(providers),
		lipgloss.NewStyle().Bold(true).Foreground(colorValue).Render(m.ip),
		dimStyle.Render(providerList),
	)
}
