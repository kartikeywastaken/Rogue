# Rogue

A terminal agent harness. This is the TUI only for now; it runs against a mock
engine until the real harness is wired in.

```sh
go run .            # or: go build -o rogue . && ./rogue
go test ./...       # ROGUE_DUMP=1 go test -v ./internal/tui  prints rendered frames
```

## Layout

```
main.go                  picks the engine and starts the program
internal/engine/         the contract between UI and harness
  engine.go              Engine interface, Event stream, Mode, Request
  mock.go                fake streaming engine (text + one tool call)
internal/tui/            Bubble Tea v2 UI, knows only engine.Engine
  model.go               state, keys, turn lifecycle
  view.go                landing, session, transcript, footer
  commands.go            slash commands
  theme.go               palette and wordmark
```

## Plugging in the harness

Implement `engine.Engine` and pass it to `tui.New` in `main.go`. `Run` returns
a channel immediately and emits `KindText`, `KindToolStart`/`KindToolEnd`
(matched by `Tool.ID`), `KindUsage`, `KindNotice`, then exactly one `KindDone`
or `KindError`, and closes. Stop when `ctx` is cancelled (esc interrupts).

## Keys

| key | action |
| --- | --- |
| enter | send |
| shift+enter · alt+enter · ctrl+j | newline |
| / | command palette (tab completes) |
| shift+tab | cycle mode: default · auto · plan |
| esc | interrupt the running turn |
| ↑ ↓ | prompt history |
| pgup pgdn · wheel | scroll transcript |
| ctrl+c | quit |

Commands: `/help` `/model` `/mode` `/clear` `/new` `/quit`
