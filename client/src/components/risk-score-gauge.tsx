import { useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { getThreatLevelLabel, type ThreatLevel } from "@shared/schema";
import { Shield, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";

interface RiskScoreGaugeProps {
  score: number;
  threatLevel: ThreatLevel;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
}

export function RiskScoreGauge({
  score,
  threatLevel,
  isVpn,
  isProxy,
  isTor,
}: RiskScoreGaugeProps) {
  const { color, bgColor, Icon, ringColor } = useMemo(() => {
    switch (threatLevel) {
      case "low":
        return {
          color: "text-threat-low",
          bgColor: "bg-threat-low/10",
          ringColor: "stroke-threat-low",
          Icon: ShieldCheck,
        };
      case "medium":
        return {
          color: "text-threat-medium",
          bgColor: "bg-threat-medium/10",
          ringColor: "stroke-threat-medium",
          Icon: Shield,
        };
      case "high":
        return {
          color: "text-threat-high",
          bgColor: "bg-threat-high/10",
          ringColor: "stroke-threat-high",
          Icon: ShieldAlert,
        };
      case "critical":
        return {
          color: "text-threat-critical",
          bgColor: "bg-threat-critical/10",
          ringColor: "stroke-threat-critical",
          Icon: ShieldX,
        };
    }
  }, [threatLevel]);

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const detectionFlags = [
    { label: "VPN", active: isVpn },
    { label: "Proxy", active: isProxy },
    { label: "Tor", active: isTor },
  ].filter((f) => f.active);

  return (
    <Card className={bgColor}>
      <CardContent className="pt-6 pb-6">
        <div className="flex flex-col items-center">
          <div className="relative w-40 h-40">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="45"
                fill="none"
                strokeWidth="8"
                className="stroke-muted"
              />
              <circle
                cx="50"
                cy="50"
                r="45"
                fill="none"
                strokeWidth="8"
                strokeLinecap="round"
                className={ringColor}
                style={{
                  strokeDasharray: circumference,
                  strokeDashoffset: strokeDashoffset,
                  transition: "stroke-dashoffset 0.5s ease-in-out",
                }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span
                className={`text-4xl font-bold tabular-nums ${color}`}
                data-testid="text-risk-score"
              >
                {score}
              </span>
              <span className="text-xs text-muted-foreground font-medium uppercase tracking-wide">
                Risk Score
              </span>
            </div>
          </div>

          <div className="mt-4 flex items-center gap-2">
            <Icon className={`h-5 w-5 ${color}`} />
            <span className={`text-lg font-semibold ${color}`} data-testid="text-threat-level">
              {getThreatLevelLabel(threatLevel)}
            </span>
          </div>

          {detectionFlags.length > 0 && (
            <div className="mt-3 flex flex-wrap justify-center gap-2">
              {detectionFlags.map(({ label }) => (
                <span
                  key={label}
                  className="px-2 py-1 text-xs font-medium rounded bg-threat-critical/20 text-threat-critical"
                  data-testid={`badge-detection-${label.toLowerCase()}`}
                >
                  {label} Detected
                </span>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
