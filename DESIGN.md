# CTI Monitor — Design System

## Style: Cyberpunk UI

Dark, terminal-aesthetic, HUD-like interface for internal security analyst use. Information-dense with precise data presentation.

---

## Color Palette

| Token | Value | Usage |
|---|---|---|
| `--bg` | `#020202` | Page background |
| `--surface` | `#080808` | Panel/card backgrounds |
| `--surface2` | `#0e0e0e` | Hover states, inputs |
| `--surface3` | `#151515` | Pressed states, inner fills |
| `--border` | `#1c1c1c` | Default borders |
| `--border-hi` | `#2e2e2e` | Elevated borders, scrollbars |
| `--text` | `#d0d0d0` | Body text |
| `--text-hi` | `#f4f4f4` | High-emphasis values |
| `--text-dim` | `#808080` | Secondary labels |
| `--text-muted` | `#484848` | Tertiary / decorative |
| `--green` | `#00ff41` | Primary accent — active, success, IOC |
| `--green-dim` | `rgba(0,255,65,.07)` | Active backgrounds |
| `--green-glow` | `rgba(0,255,65,.18)` | Glow effects |
| `--amber` | `#ff9500` | Warning — quiet sites, APT chips |
| `--red` | `#ff3b30` | Danger — failing sites, destructive |
| `--cyan` | `#00d4ff` | Informational accent |
| `--purple` | `#bf5fff` | Reserved |

---

## Typography

**Google Fonts:**
```
https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap
```

| Variable | Font | Usage |
|---|---|---|
| `--font-mono` | Fira Code → JetBrains Mono → ui-monospace | Data values, IOC indicators, stat numbers, code |
| `--font-ui` | Fira Sans → system-ui | Labels, badges, nav, buttons, section headers |

**Scale:**

| Element | Size | Weight | Font | Notes |
|---|---|---|---|---|
| Body | 12px | 400 | mono | `line-height: 1.5` |
| Stat numbers | 32px | 700 | mono | `letter-spacing: -.02em`, tabular-nums |
| TTP summary numbers | 22px | 700 | mono | |
| Drawer name | 14px | 700 | mono | `letter-spacing: .06em`, uppercase |
| Site name | 11px | 500 | mono | |
| Section title | 9px | 700 | ui | `letter-spacing: .16em`, uppercase |
| Nav label | 8px | 400 | ui | `letter-spacing: .06em`, uppercase |
| Badge / pill | 9px | 600 | ui | `letter-spacing: .08em`, uppercase |
| Table header | 8px | 600 | ui | `letter-spacing: .12em`, uppercase |

---

## Layout

| Token | Value |
|---|---|
| `--sidebar-w` | `64px` |
| `--topbar-h` | `48px` |
| Tab pane padding | `22px 28px 40px` |

**Grid patterns:**
- Sources tab: `1fr 360px` (main + sticky right panel)
- IOC tab: `240px 1fr` (sticky left filters + table)
- TTP tab: `280px 1fr` (sticky left + heatmap)
- KPI row: `repeat(4, 1fr)` with `8px` gap

---

## Motion

| Token | Value | Usage |
|---|---|---|
| `--ease` | `cubic-bezier(.23,1,.32,1)` | Default ease-out |
| `--ease-drawer` | `cubic-bezier(.32,.72,0,1)` | Drawer slide |
| Row enter | `translateX(-4px)` + opacity, 300ms, staggered `45ms` | Panel rows |
| Tab enter | `translateY(5px)` + opacity, 160ms | Tab switch |
| Drawer | `translateX(100%)` → 0, spring via JS | Side panel |
| KPI bar fill | `scaleX(0→1)`, 700ms `cubic-bezier(.16,1,.3,1)` | Bar animations |

---

## Component Patterns

### KPI Cards
- `border-top: 2px solid var(--border-hi)` base; overrides to green/amber/red when expanded
- `box-shadow: 0 0 20px var(--*-glow)` when expanded
- `transform: translateY(-2px)` on hover

### Sidebar Nav Button
- Active state: `border-left: 2px solid var(--green)` + `box-shadow: inset 2px 0 8px var(--green-glow)` + `background: var(--green-dim)`
- No border box (removed in favour of left accent lane)

### Site Rows
- `border-left: 2px solid transparent` base
- On hover: `border-left-color` takes panel accent color (green/amber/red)
- Staggered `rowIn` animation on panel open

### Badges
- `.badge-amber`: `color: var(--amber)` + `background: var(--amber-dim)` + amber border
- `.badge-red`: `color: var(--red)` + `background: var(--red-dim)` + red border

### Reliability Badge
- `.rel-green` ≥70, `.rel-amber` 40–69, `.rel-red` <40, `.rel-none` unrated
- Score = Availability (0–40) + Content Quality (0–40) + User Feedback (0–20)

### Drawer
- `backdrop-filter: blur(20px) saturate(160%)`
- Width: `min(480px, 94vw)`
- Animated via JS Web Animations API

### TTP Heatmap Cells
- Heat 0: base surface
- Heat 1: amber tint `rgba(255,149,0,.09)`
- Heat 2: amber strong `rgba(255,149,0,.22)`
- Heat 3: red `rgba(255,59,48,.22)`

---

## Effects

- **Scanlines**: `body::after` — `repeating-linear-gradient` at 4% opacity, 3px pitch
- **Neon glow**: `text-shadow` / `drop-shadow` / `box-shadow` on green elements
- **Pulse animation**: status dot, 2s ease-in-out infinite
- **Spinner**: 1px border, top-color green, 0.65s linear spin

---

## Accessibility

- Keyboard navigable drawer (close on Escape)
- Focus states: `border-color: var(--green)` on inputs
- `prefers-reduced-motion`: tab/row animations use `animation: none` fallback
- Contrast: primary text `#d0d0d0` on `#020202` ≈ 12:1

---

## Anti-Patterns

- No light mode
- No emojis as icons (SVG only)
- No mixing flat and skeuomorphic styles
- No fixed-px layout widths (uses grid + min/max)
