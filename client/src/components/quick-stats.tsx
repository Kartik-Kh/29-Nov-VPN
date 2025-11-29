import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { type ScanStats } from "@shared/schema";
import { Activity, ShieldAlert, ShieldCheck, Wifi } from "lucide-react";

interface QuickStatsProps {
  stats: ScanStats | null;
  isLoading?: boolean;
}

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
}

function StatCard({ label, value, icon: Icon, color }: StatCardProps) {
  return (
    <Card className="relative overflow-visible">
      <CardContent className="pt-4 pb-4">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1">
            <p
              className="text-3xl font-bold tabular-nums"
              data-testid={`text-stat-${label.toLowerCase().replace(/\s/g, "-")}`}
            >
              {value}
            </p>
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wide">
              {label}
            </p>
          </div>
          <div className={`p-2 rounded-md ${color}`}>
            <Icon className="h-4 w-4" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatCardSkeleton() {
  return (
    <Card className="relative overflow-visible">
      <CardContent className="pt-4 pb-4">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-2">
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-3 w-20" />
          </div>
          <Skeleton className="h-8 w-8 rounded-md" />
        </div>
      </CardContent>
    </Card>
  );
}

export function QuickStats({ stats, isLoading = false }: QuickStatsProps) {
  if (isLoading) {
    return (
      <div className="space-y-4">
        <StatCardSkeleton />
        <StatCardSkeleton />
        <StatCardSkeleton />
        <StatCardSkeleton />
      </div>
    );
  }

  const statItems: StatCardProps[] = [
    {
      label: "Total Scans",
      value: stats?.totalScans ?? 0,
      icon: Activity,
      color: "bg-primary/10 text-primary",
    },
    {
      label: "Threats Detected",
      value: stats?.threatsDetected ?? 0,
      icon: ShieldAlert,
      color: "bg-threat-critical/10 text-threat-critical",
    },
    {
      label: "Clean IPs",
      value: stats?.cleanIps ?? 0,
      icon: ShieldCheck,
      color: "bg-threat-low/10 text-threat-low",
    },
    {
      label: "VPNs Detected",
      value: stats?.vpnsDetected ?? 0,
      icon: Wifi,
      color: "bg-threat-high/10 text-threat-high",
    },
  ];

  return (
    <div className="space-y-4">
      {statItems.map((item) => (
        <StatCard key={item.label} {...item} />
      ))}
    </div>
  );
}
