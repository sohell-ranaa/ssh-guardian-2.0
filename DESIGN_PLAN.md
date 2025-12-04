# SSH Guardian Dashboard - Professional Design Plan

## Design Goals
1. **Professional & Clean** - Enterprise security dashboard look
2. **Easy on Eyes** - Comfortable for long monitoring sessions
3. **Information Dense** - Show lots of data without clutter
4. **Action Oriented** - Quick access to important actions
5. **Modern** - Contemporary design patterns

## Proposed Design System

### Color Palette (Light Theme with Depth)

**Background Colors:**
- Main Background: `#f0f2f5` (soft gray - not pure white, easier on eyes)
- Sidebar: `#ffffff` (white with subtle shadow)
- Panel/Card: `#ffffff` (white)
- Header: `#fafbfc` (very light gray)

**Primary Colors:**
- Primary Blue: `#0066cc` (professional blue - not too bright)
- Primary Hover: `#0052a3`
- Success: `#0a8754` (forest green)
- Warning: `#f5a623` (amber)
- Danger: `#d32f2f` (crimson red)
- Info: `#0088cc` (sky blue)

**Text Colors:**
- Primary Text: `#2c3e50` (dark blue-gray, easy to read)
- Secondary Text: `#64748b` (medium gray)
- Muted Text: `#94a3b8` (light gray)

**Borders:**
- Border Color: `#e1e4e8` (subtle gray)
- Hover Border: `#cbd5e1`

### Typography

**Font Family:**
```
'Inter', 'Segoe UI', 'Roboto', system-ui, sans-serif
```

**Font Sizes:**
- Page Title: 24px (bold)
- Section Title: 16px (semi-bold)
- Body: 14px (regular)
- Small: 12px (labels, captions)
- Tiny: 11px (meta info)

**Font Weights:**
- Bold: 600
- Semi-bold: 500
- Regular: 400

### Layout Structure

```
┌─────────────────────────────────────────────────┐
│  Sidebar (240px)  │    Main Content Area        │
│  ┌──────────────┐ │  ┌──────────────────────┐  │
│  │ Logo         │ │  │  Page Header         │  │
│  │──────────────│ │  │──────────────────────│  │
│  │ Navigation   │ │  │  KPI Cards (4)       │  │
│  │   - Overview │ │  │  ┌─┐ ┌─┐ ┌─┐ ┌─┐    │  │
│  │   - Live     │ │  │  └─┘ └─┘ └─┘ └─┘    │  │
│  │   - IPs      │ │  │──────────────────────│  │
│  │   - Analytics│ │  │  Main Content Panels │  │
│  │   - ML       │ │  │  ┌──────────────────┐│  │
│  │   - Simulate │ │  │  │ Charts/Tables    ││  │
│  │   - Settings │ │  │  └──────────────────┘│  │
│  │   - Users    │ │  └──────────────────────┘  │
│  └──────────────┘ │                             │
└─────────────────────────────────────────────────┘
```

### Component Styles

#### 1. Sidebar
- Width: 240px
- Background: #ffffff
- Shadow: `0 0 15px rgba(0,0,0,0.05)`
- Border: none (shadow provides separation)

**Navigation Items:**
- Padding: 12px 20px
- Font: 14px
- Icon Size: 16px
- Inactive: #64748b
- Hover: background #f8fafc, text #0066cc
- Active: background #e3f2fd, text #0066cc, left border 3px #0066cc

#### 2. KPI Cards
- Background: #ffffff
- Border: 1px solid #e1e4e8
- Border-radius: 8px
- Padding: 20px
- Shadow: `0 2px 4px rgba(0,0,0,0.04)`
- Hover: Shadow increases to `0 4px 12px rgba(0,0,0,0.08)`

**Card Structure:**
```
┌─────────────────┐
│ 🔵 Icon (40px)  │
│                 │
│ 1,234           │ <- Value (28px, bold)
│ TOTAL EVENTS    │ <- Label (11px, uppercase)
│ +12% from last  │ <- Change (12px, green/red)
└─────────────────┘
```

**Icon Background:**
- Primary: #e3f2fd with #0066cc icon
- Success: #e8f5e9 with #0a8754 icon
- Warning: #fff8e1 with #f5a623 icon
- Danger: #ffebee with #d32f2f icon

#### 3. Data Panels
- Background: #ffffff
- Border: 1px solid #e1e4e8
- Border-radius: 8px
- Padding: 24px
- Shadow: `0 2px 4px rgba(0,0,0,0.04)`

**Panel Header:**
- Border-bottom: 1px solid #f0f2f5
- Padding-bottom: 16px
- Margin-bottom: 20px
- Title: 16px, #2c3e50, semi-bold
- Icon before title: 14px, #64748b

#### 4. Tables
- Background: transparent
- Border: none on table
- Row separator: 1px solid #f0f2f5
- Header: background #fafbfc, text #2c3e50, font-weight 600
- Cell padding: 12px 16px
- Font: 14px
- Hover row: background #f8fafc

#### 5. Buttons

**Primary Button:**
```css
background: #0066cc
color: #ffffff
padding: 10px 20px
border-radius: 6px
font-weight: 500
shadow: 0 2px 4px rgba(0,102,204,0.2)
hover: background #0052a3, shadow increase
```

**Secondary Button:**
```css
background: #ffffff
color: #0066cc
border: 1px solid #e1e4e8
padding: 10px 20px
border-radius: 6px
hover: background #f8fafc
```

#### 6. Badges
- Padding: 4px 10px
- Border-radius: 12px
- Font: 12px, weight 500

**Status Badges:**
- Critical: background #ffebee, text #d32f2f
- High: background #fff3e0, text #f57c00
- Medium: background #fff8e1, text #f5a623
- Low: background #e8f5e9, text #0a8754
- Info: background #e3f2fd, text #0066cc

#### 7. Charts
- Use subtle colors
- Grid lines: #f0f2f5
- Axes: #94a3b8
- Tooltips: white with shadow
- Primary line/bar: #0066cc
- Secondary: #0a8754

### Spacing System
- xs: 4px
- sm: 8px
- md: 16px
- lg: 24px
- xl: 32px
- 2xl: 48px

### Shadow System
```css
--shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
--shadow-md: 0 2px 4px rgba(0,0,0,0.04);
--shadow-lg: 0 4px 12px rgba(0,0,0,0.08);
--shadow-xl: 0 8px 24px rgba(0,0,0,0.12);
```

### Border Radius
- Small: 4px (inputs)
- Medium: 6px (buttons)
- Large: 8px (cards)
- Full: 9999px (badges, pills)

## Implementation Priority

1. **Core Colors & Typography** - Set all CSS variables
2. **Sidebar** - Clean navigation
3. **KPI Cards** - Eye-catching metrics
4. **Data Panels** - Tables and content
5. **Forms & Inputs** - Clean, consistent
6. **Responsive** - Mobile/tablet support

## Why This Design Works

✓ **Professional** - Enterprise-grade appearance
✓ **Readable** - High contrast, good spacing
✓ **Organized** - Clear hierarchy
✓ **Scannable** - Easy to find information
✓ **Actionable** - Buttons and actions clear
✓ **Consistent** - Unified design system
✓ **Modern** - Contemporary patterns
✓ **Eye-friendly** - Soft colors, not harsh

This design combines the best of:
- **Splunk** - Data density and professionalism
- **Grafana** - Clean metrics visualization
- **Datadog** - Modern card-based layout
- **GitHub** - Clean, accessible UI

Ready to implement?
