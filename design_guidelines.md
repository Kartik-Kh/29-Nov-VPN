# Proxy & VPN Detector - Design Guidelines

## Design Approach
**Selected System:** Material Design with security-focused customizations
**Rationale:** This is a utility-focused security application where clarity, trust, and efficiency are paramount. Material Design provides robust patterns for data-dense interfaces while maintaining professional aesthetics.

## Core Design Elements

### Typography
- **Primary Font:** Inter or Roboto from Google Fonts
- **Hierarchy:**
  - Page Titles: 2.5rem (40px), font-weight 700
  - Section Headers: 1.75rem (28px), font-weight 600
  - Card Titles: 1.25rem (20px), font-weight 600
  - Body Text: 1rem (16px), font-weight 400
  - Metadata/Labels: 0.875rem (14px), font-weight 500
  - Risk Scores: 3rem (48px), font-weight 700, tabular-nums

### Layout System
**Spacing Primitives:** Use Tailwind units of 2, 4, 6, 8, 12, 16
- Component padding: p-6 to p-8
- Section spacing: mb-8 to mb-12
- Card gaps: gap-6
- Form field spacing: space-y-4

**Container Strategy:**
- Max-width: max-w-7xl for main content
- Asymmetric dashboard layout: 70/30 split for main analysis vs. sidebar

### Page Structure

**Header:**
- Fixed top navigation with logo, "Proxy & VPN Detector" wordmark
- Quick action: "New Analysis" button (prominent, right-aligned)
- Subtle status indicator showing API health

**Main Dashboard Layout:**
Left Panel (70%):
- IP Input Section: Large text field with IPv4/IPv6 toggle, "Analyze" button below
- Results Card: Prominent risk score (large numerical display with descriptive label), VPN/Proxy detection status with icon, IP metadata grid (2-column)
- Geographic Map: react-leaflet integration showing IP location, full-width within panel
- WHOIS Details: Expandable accordion sections for registration data, ISP info, organization details

Right Panel (30%):
- Recent Scans List: Compact vertical list showing timestamp, IP, risk score badge
- Quick Stats Cards: Total scans today, detected threats, clean IPs (stacked vertically)

**Analysis History Section:**
Below main dashboard:
- Searchable data table with columns: Timestamp, IP Address, Risk Score, Status, Location, Actions
- Pagination controls below table
- Export functionality (CSV/JSON) in table header
- 10 rows per page minimum

### Component Library

**IP Input Component:**
- Large monospace text field (min-height 56px)
- Inline validation with instant feedback
- Format helper text below field
- Analysis button spans full width on mobile, inline on desktop

**Risk Score Display:**
- Circular or arc gauge visualization
- Large central number (risk score)
- Descriptive ring segments indicating threat levels
- Supporting text below: "Low Risk" / "Medium Risk" / "High Risk" / "VPN Detected"

**Detection Status Card:**
- Icon-first design (shield icon for status)
- Primary status text (large, bold)
- Secondary metadata in grid: ISP, Country, Organization, AS Number
- Each metadata item: label above, value below

**Map Component:**
- Full-width within container
- Height: 400px on desktop, 300px on mobile
- Marker with popup showing IP details
- Zoom controls positioned top-right

**WHOIS Accordion:**
- Grouped sections: Registration, Network, Contact
- Each section header: left-aligned title, right-aligned expand icon
- Content: two-column key-value pairs with consistent spacing

**History Table:**
- Alternating row treatment for readability
- Risk score as badge component (inline, right-aligned in cell)
- Action icons: View details, Re-scan, Delete (icon-only, tooltips on hover)
- Responsive: Stack to cards on mobile

**Quick Stats Cards:**
- Vertical orientation for sidebar
- Large number (32px) at top
- Descriptive label below
- Subtle icon in corner
- Minimal padding (p-4)

### Responsive Behavior
- Desktop (lg): Side-by-side layout as described
- Tablet (md): Stack panels vertically, maintain two-column grids
- Mobile: Single column, compress metadata to single column, reduce map height

### Professional Security Aesthetics
- Subtle depth through elevation changes (cards raised above background)
- Monospace fonts for IP addresses, technical data
- Badge components for status indicators (rounded, compact)
- Minimal borders, rely on spacing and elevation for separation
- Icon usage: Shield (security), Alert (threats), Check (verified), Globe (location)

### Critical UX Patterns
- Loading states: Skeleton screens for API calls, spinner for analysis in progress
- Empty states: Helpful prompts with example IPs to analyze
- Error handling: Inline error messages below input, toast notifications for system errors
- Confirmation dialogs: For bulk operations or deletion

### Accessibility
- ARIA labels on all interactive elements
- Keyboard navigation for table and forms
- Focus indicators visible and clear
- Screen reader announcements for analysis results
- Sufficient contrast ratios throughout

**No animations** beyond standard Material transitions (drawer open/close, accordion expand).