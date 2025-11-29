import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { type IpAnalysis, type ThreatLevel } from "@shared/schema";
import {
  Globe,
  Building2,
  Server,
  MapPin,
  Clock,
  Network,
  Shield,
} from "lucide-react";

interface DetectionStatusCardProps {
  analysis: IpAnalysis;
}

function getThreatBadgeVariant(level: ThreatLevel): "default" | "secondary" | "destructive" | "outline" {
  switch (level) {
    case "low":
      return "secondary";
    case "medium":
      return "outline";
    case "high":
    case "critical":
      return "destructive";
  }
}

export function DetectionStatusCard({ analysis }: DetectionStatusCardProps) {
  const metadataItems = [
    {
      icon: Building2,
      label: "ISP",
      value: analysis.isp || "Unknown",
    },
    {
      icon: Globe,
      label: "Country",
      value: analysis.country || "Unknown",
    },
    {
      icon: MapPin,
      label: "City",
      value: analysis.city || "Unknown",
    },
    {
      icon: Server,
      label: "Organization",
      value: analysis.organization || "Unknown",
    },
    {
      icon: Network,
      label: "AS Number",
      value: analysis.asn || "Unknown",
    },
    {
      icon: Clock,
      label: "Timezone",
      value: analysis.timezone || "Unknown",
    },
  ];

  const detectionBadges = [
    { label: "VPN", active: analysis.isVpn, provider: analysis.vpnProvider },
    { label: "Proxy", active: analysis.isProxy },
    { label: "Tor", active: analysis.isTor },
    { label: "Datacenter", active: analysis.isDatacenter },
  ];

  return (
    <Card>
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="flex items-center gap-2 text-xl font-semibold">
            <Shield className="h-5 w-5 text-primary" />
            Detection Status
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="font-mono text-sm" data-testid="badge-ip-address">
              {analysis.ipAddress}
            </Badge>
            <Badge variant="secondary" className="text-xs" data-testid="badge-ip-version">
              {analysis.ipVersion}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex flex-wrap gap-2">
          {detectionBadges.map(({ label, active, provider }) => (
            <Badge
              key={label}
              size="sm"
              variant={active ? "destructive" : "secondary"}
              data-testid={`badge-${label.toLowerCase()}-status`}
            >
              {active ? (provider ? `${provider} (${label})` : `${label} Detected`) : `No ${label}`}
            </Badge>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-4">
          {metadataItems.map(({ icon: Icon, label, value }) => (
            <div key={label} className="space-y-1">
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
                <Icon className="h-3.5 w-3.5" />
                {label}
              </div>
              <p
                className="text-sm font-medium truncate"
                title={value}
                data-testid={`text-${label.toLowerCase().replace(/\s/g, "-")}`}
              >
                {value}
              </p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
