package tui

import (
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

type styles struct {
	noColor     bool
	brand       lipgloss.Style
	title       lipgloss.Style
	subtitle    lipgloss.Style
	help        lipgloss.Style
	muted       lipgloss.Style
	accent      lipgloss.Style
	success     lipgloss.Style
	warning     lipgloss.Style
	error       lipgloss.Style
	status      lipgloss.Style
	panel       lipgloss.Style
	panelStrong lipgloss.Style
	key         lipgloss.Style
	keyLabel    lipgloss.Style
	badge       lipgloss.Style
	fieldLabel  lipgloss.Style
	fieldValue  lipgloss.Style
	cursor      lipgloss.Style
	code        lipgloss.Style
}

type themePalette struct {
	accent         lipgloss.AdaptiveColor
	accentSoft     lipgloss.AdaptiveColor
	text           lipgloss.AdaptiveColor
	muted          lipgloss.AdaptiveColor
	border         lipgloss.AdaptiveColor
	success        lipgloss.AdaptiveColor
	warning        lipgloss.AdaptiveColor
	error          lipgloss.AdaptiveColor
	codeBackground lipgloss.AdaptiveColor
}

func adaptiveThemePalette() themePalette {
	return themePalette{
		// A restrained terracotta accent gives opssh a warm, Claude Code-inspired
		// character without assuming a particular terminal background.
		accent:         lipgloss.AdaptiveColor{Light: "#B84F2B", Dark: "#D97757"},
		accentSoft:     lipgloss.AdaptiveColor{Light: "#F7E7E1", Dark: "#3B2923"},
		text:           lipgloss.AdaptiveColor{Light: "#292622", Dark: "#ECE9E3"},
		muted:          lipgloss.AdaptiveColor{Light: "#66615B", Dark: "#AAA49B"},
		border:         lipgloss.AdaptiveColor{Light: "#D2CCC4", Dark: "#4C4842"},
		success:        lipgloss.AdaptiveColor{Light: "#18724A", Dark: "#67C091"},
		warning:        lipgloss.AdaptiveColor{Light: "#855B00", Dark: "#E3B341"},
		error:          lipgloss.AdaptiveColor{Light: "#B42318", Dark: "#F97066"},
		codeBackground: lipgloss.AdaptiveColor{Light: "#F3F0EB", Dark: "#272522"},
	}
}

func newStyles(noColor bool) styles {
	styleSet := styles{
		noColor:     noColor,
		brand:       lipgloss.NewStyle().Bold(true),
		title:       lipgloss.NewStyle().Bold(true),
		subtitle:    lipgloss.NewStyle(),
		help:        lipgloss.NewStyle().Faint(true),
		muted:       lipgloss.NewStyle().Faint(true),
		accent:      lipgloss.NewStyle().Bold(true),
		success:     lipgloss.NewStyle().Bold(true),
		warning:     lipgloss.NewStyle().Bold(true),
		error:       lipgloss.NewStyle().Bold(true),
		status:      lipgloss.NewStyle().Bold(true),
		panel:       lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		panelStrong: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		key:         lipgloss.NewStyle().Bold(true).Padding(0, 1),
		keyLabel:    lipgloss.NewStyle(),
		badge:       lipgloss.NewStyle().Bold(true).Padding(0, 1),
		fieldLabel:  lipgloss.NewStyle().Bold(true),
		fieldValue:  lipgloss.NewStyle(),
		cursor:      lipgloss.NewStyle(),
		code:        lipgloss.NewStyle(),
	}
	if noColor {
		return styleSet
	}

	palette := adaptiveThemePalette()

	styleSet.brand = styleSet.brand.Foreground(palette.accent)
	styleSet.title = styleSet.title.Foreground(palette.text)
	styleSet.subtitle = styleSet.subtitle.Foreground(palette.muted)
	styleSet.help = styleSet.help.Foreground(palette.muted)
	styleSet.muted = styleSet.muted.Foreground(palette.muted)
	styleSet.accent = styleSet.accent.Foreground(palette.accent)
	styleSet.success = styleSet.success.Foreground(palette.success)
	styleSet.warning = styleSet.warning.Foreground(palette.warning)
	styleSet.error = styleSet.error.Foreground(palette.error)
	styleSet.status = styleSet.status.Foreground(palette.success)
	styleSet.panel = styleSet.panel.BorderForeground(palette.border)
	styleSet.panelStrong = styleSet.panelStrong.BorderForeground(palette.accent)
	styleSet.key = styleSet.key.Foreground(palette.accent).Background(palette.accentSoft)
	styleSet.keyLabel = styleSet.keyLabel.Foreground(palette.muted)
	styleSet.badge = styleSet.badge.Foreground(palette.accent).Background(palette.accentSoft)
	styleSet.fieldLabel = styleSet.fieldLabel.Foreground(palette.accent)
	styleSet.fieldValue = styleSet.fieldValue.Foreground(palette.text)
	styleSet.cursor = styleSet.cursor.Foreground(palette.accent)
	styleSet.code = styleSet.code.Foreground(palette.text).Background(palette.codeBackground)
	return styleSet
}

func newListDelegate(styleSet styles) list.DefaultDelegate {
	delegate := list.NewDefaultDelegate()
	delegate.SetSpacing(1)
	delegate.Styles.NormalTitle = lipgloss.NewStyle().PaddingLeft(1)
	delegate.Styles.NormalDesc = lipgloss.NewStyle().PaddingLeft(1).Faint(true)
	delegate.Styles.DimmedTitle = delegate.Styles.NormalTitle.Faint(true)
	delegate.Styles.DimmedDesc = delegate.Styles.NormalDesc
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().Bold(true).Border(lipgloss.ThickBorder(), false, false, false, true).PaddingLeft(1)
	delegate.Styles.SelectedDesc = lipgloss.NewStyle().Border(lipgloss.ThickBorder(), false, false, false, true).PaddingLeft(1)
	delegate.Styles.FilterMatch = lipgloss.NewStyle().Bold(true).Underline(true)
	if !styleSet.noColor {
		palette := adaptiveThemePalette()
		delegate.Styles.NormalTitle = delegate.Styles.NormalTitle.Foreground(palette.text)
		delegate.Styles.NormalDesc = delegate.Styles.NormalDesc.Foreground(palette.muted)
		delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.Foreground(palette.accent).BorderForeground(palette.accent)
		delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.Foreground(palette.muted).BorderForeground(palette.accent)
		delegate.Styles.FilterMatch = delegate.Styles.FilterMatch.Foreground(palette.accent)
	}
	return delegate
}

func configureList(model *list.Model, singular, plural string, styleSet styles) {
	model.SetShowTitle(false)
	model.SetShowStatusBar(false)
	model.SetShowHelp(false)
	model.SetShowPagination(true)
	model.SetStatusBarItemName(singular, plural)
	model.DisableQuitKeybindings()
	model.FilterInput.Prompt = "Search  "
	model.FilterInput.KeyMap.Paste.SetEnabled(false)
	model.FilterInput.PromptStyle = styleSet.fieldLabel
	model.FilterInput.Cursor.Style = styleSet.cursor
	model.Styles.PaginationStyle = styleSet.muted.PaddingLeft(1)
	model.Styles.ActivePaginationDot = styleSet.accent.SetString("●")
	model.Styles.InactivePaginationDot = styleSet.muted.SetString("•")
	model.Styles.NoItems = styleSet.muted.PaddingLeft(1)
}

func newTableStyles(styleSet styles) table.Styles {
	return table.Styles{
		Header:   styleSet.title.Padding(0, 1),
		Cell:     styleSet.subtitle.Padding(0, 1),
		Selected: styleSet.accent.Bold(true).Padding(0, 1),
	}
}
