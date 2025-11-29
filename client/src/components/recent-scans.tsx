import { format } from "date-fns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { type IpAnalysis, type ThreatLevel } from "@shared/schema";
import { Clock, ArrowRight } from "lucide-react";

interface RecentScansProps {
  analyses: IpAnalysis[];
  isLoading?: boolean;
  onSelect?: (analysis: IpAnalysis) => void;
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

function ScanItemSkeleton() {
  return (
    <div className="p-3 rounded-md border bg-card">
      <div className="flex items-center justify-between gap-2">
        <div className="space-y-2 flex-1">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-3 w-16" />
        </div>
        <Skeleton className="h-5 w-10" />
      </div>
    </div>
  );
}

export function RecentScans({ analyses, isLoading = false, onSelect }: RecentScansProps) {
  const recentAnalyses = analyses.slice(0, 10);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base font-semibold">
          <Clock className="h-4 w-4 text-primary" />
          Recent Scans
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[280px] px-4 pb-4">
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <ScanItemSkeleton key={i} />
              ))}
            </div>
          ) : recentAnalyses.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
              <Clock className="h-8 w-8 mb-2 opacity-50" />
              <p className="text-xs">No recent scans</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentAnalyses.map((analysis) => (
                <button
                  key={analysis.id}
                  onClick={() => onSelect?.(analysis)}
                  className="w-full p-3 rounded-md border bg-card hover-elevate active-elevate-2 text-left transition-colors"
                  data-testid={`button-recent-scan-${analysis.id}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-sm font-medium truncate">
                        {analysis.ipAddress}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {format(new Date(analysis.analyzedAt), "MMM d, HH:mm")}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={getThreatBadgeVariant(analysis.threatLevel as ThreatLevel)}
                        size="sm"
                      >
                        {analysis.riskScore}
                      </Badge>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
