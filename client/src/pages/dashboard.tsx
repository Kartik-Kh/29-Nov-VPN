import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { IpInputForm } from "@/components/ip-input-form";
import { RiskScoreGauge } from "@/components/risk-score-gauge";
import { DetectionStatusCard } from "@/components/detection-status-card";
import { IpMap } from "@/components/ip-map";
import { WhoisAccordion } from "@/components/whois-accordion";
import { HistoryTable } from "@/components/history-table";
import { QuickStats } from "@/components/quick-stats";
import { RecentScans } from "@/components/recent-scans";
import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  type IpAnalysis,
  type WhoisRecord,
  type ScanStats,
  type ThreatLevel,
} from "@shared/schema";
import { Shield, Search, AlertTriangle } from "lucide-react";

interface AnalyzeResponse {
  analysis: IpAnalysis;
  whois: WhoisRecord | null;
  cached: boolean;
}

export default function Dashboard() {
  const { toast } = useToast();
  const [selectedAnalysis, setSelectedAnalysis] = useState<IpAnalysis | null>(null);
  const [selectedWhois, setSelectedWhois] = useState<WhoisRecord | null>(null);

  const { data: history = [], isLoading: isLoadingHistory } = useQuery<IpAnalysis[]>({
    queryKey: ["/api/analyses"],
  });

  const { data: stats, isLoading: isLoadingStats } = useQuery<ScanStats>({
    queryKey: ["/api/stats"],
  });

  const analyzeMutation = useMutation({
    mutationFn: async (ipAddress: string): Promise<AnalyzeResponse> => {
      const response = await apiRequest("POST", "/api/analyze", { ipAddress });
      return response.json();
    },
    onSuccess: (data) => {
      setSelectedAnalysis(data.analysis);
      setSelectedWhois(data.whois);
      queryClient.invalidateQueries({ queryKey: ["/api/analyses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });

      if (data.cached) {
        toast({
          title: "Analysis Retrieved",
          description: "Results loaded from cache for faster response.",
        });
      } else {
        toast({
          title: "Analysis Complete",
          description: `IP ${data.analysis.ipAddress} has been analyzed.`,
        });
      }
    },
    onError: (error: Error) => {
      toast({
        title: "Analysis Failed",
        description: error.message || "Failed to analyze IP address. Please try again.",
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/analyses/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/analyses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      toast({
        title: "Record Deleted",
        description: "The analysis record has been removed.",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Delete Failed",
        description: error.message || "Failed to delete the record.",
        variant: "destructive",
      });
    },
  });

  const handleAnalyze = useCallback((ipAddress: string) => {
    analyzeMutation.mutate(ipAddress);
  }, [analyzeMutation]);

  const handleViewAnalysis = useCallback((analysis: IpAnalysis) => {
    setSelectedAnalysis(analysis);
    setSelectedWhois(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const handleRescan = useCallback((ipAddress: string) => {
    analyzeMutation.mutate(ipAddress);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [analyzeMutation]);

  const handleDelete = useCallback((id: string) => {
    if (selectedAnalysis?.id === id) {
      setSelectedAnalysis(null);
      setSelectedWhois(null);
    }
    deleteMutation.mutate(id);
  }, [deleteMutation, selectedAnalysis]);

  const handleExport = useCallback((format: "csv" | "json") => {
    if (history.length === 0) {
      toast({
        title: "No Data",
        description: "There is no analysis history to export.",
        variant: "destructive",
      });
      return;
    }

    let content: string;
    let filename: string;
    let mimeType: string;

    if (format === "json") {
      content = JSON.stringify(history, null, 2);
      filename = `ip-analysis-export-${Date.now()}.json`;
      mimeType = "application/json";
    } else {
      const headers = ["IP Address", "Risk Score", "Threat Level", "VPN", "Proxy", "Country", "City", "ISP", "Analyzed At"];
      const rows = history.map((a) => [
        a.ipAddress,
        a.riskScore.toString(),
        a.threatLevel,
        a.isVpn ? "Yes" : "No",
        a.isProxy ? "Yes" : "No",
        a.country || "",
        a.city || "",
        a.isp || "",
        new Date(a.analyzedAt).toISOString(),
      ]);
      content = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
      filename = `ip-analysis-export-${Date.now()}.csv`;
      mimeType = "text/csv";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    toast({
      title: "Export Complete",
      description: `Analysis history exported as ${format.toUpperCase()}.`,
    });
  }, [history, toast]);

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6 lg:gap-8">
          <div className="space-y-6">
            <IpInputForm
              onAnalyze={handleAnalyze}
              isLoading={analyzeMutation.isPending}
            />

            {analyzeMutation.isPending && (
              <Card>
                <CardContent className="pt-6 pb-6">
                  <div className="flex flex-col items-center justify-center py-8">
                    <div className="relative">
                      <div className="w-20 h-20 rounded-full border-4 border-muted animate-pulse" />
                      <Shield className="absolute inset-0 m-auto h-8 w-8 text-primary animate-pulse" />
                    </div>
                    <p className="mt-4 text-sm text-muted-foreground font-medium">
                      Analyzing IP address...
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Checking VPN, Proxy, and threat databases
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {!analyzeMutation.isPending && !selectedAnalysis && (
              <Card>
                <CardContent className="pt-6 pb-6">
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="p-4 rounded-full bg-muted mb-4">
                      <Search className="h-8 w-8 text-muted-foreground" />
                    </div>
                    <h3 className="text-lg font-semibold mb-2">
                      Ready to Analyze
                    </h3>
                    <p className="text-sm text-muted-foreground max-w-md">
                      Enter an IP address above to detect VPNs, proxies, and other
                      masked connections. Get comprehensive threat analysis and
                      WHOIS records.
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {selectedAnalysis && !analyzeMutation.isPending && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <RiskScoreGauge
                    score={selectedAnalysis.riskScore}
                    threatLevel={selectedAnalysis.threatLevel as ThreatLevel}
                    isVpn={selectedAnalysis.isVpn}
                    isProxy={selectedAnalysis.isProxy}
                    isTor={selectedAnalysis.isTor}
                  />
                  <DetectionStatusCard analysis={selectedAnalysis} />
                </div>

                <IpMap
                  latitude={selectedAnalysis.latitude}
                  longitude={selectedAnalysis.longitude}
                  city={selectedAnalysis.city}
                  country={selectedAnalysis.country}
                  ipAddress={selectedAnalysis.ipAddress}
                />

                <WhoisAccordion whois={selectedWhois} />
              </>
            )}

            <HistoryTable
              analyses={history}
              isLoading={isLoadingHistory}
              onView={handleViewAnalysis}
              onRescan={handleRescan}
              onDelete={handleDelete}
              onExport={handleExport}
            />
          </div>

          <aside className="space-y-6">
            <QuickStats stats={stats || null} isLoading={isLoadingStats} />
            <RecentScans
              analyses={history}
              isLoading={isLoadingHistory}
              onSelect={handleViewAnalysis}
            />
          </aside>
        </div>
      </div>
    </div>
  );
}
