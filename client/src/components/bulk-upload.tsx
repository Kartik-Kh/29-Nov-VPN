import { useState } from "react";
import { Loader2, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { IpAnalysis } from "@shared/schema";

interface BulkUploadProps {
  onComplete?: (analyses: IpAnalysis[]) => void;
  isLoading?: boolean;
}

export function BulkUpload({ onComplete, isLoading = false }: BulkUploadProps) {
  const { toast } = useToast();
  const [ipList, setIpList] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleAnalyze = async () => {
    const ips = ipList
      .split("\n")
      .map(ip => ip.trim())
      .filter(ip => ip.length > 0);

    if (ips.length === 0) {
      toast({
        title: "No IPs",
        description: "Please enter at least one IP address.",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    try {
      const response = await apiRequest("POST", "/api/bulk-analyze", { ips });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Bulk analysis failed");
      }

      queryClient.invalidateQueries({ queryKey: ["/api/analyses"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });

      toast({
        title: "Bulk Analysis Complete",
        description: `Analyzed ${data.analyses.length} IP addresses.`,
      });

      setIpList("");
      onComplete?.(data.analyses);
    } catch (error) {
      toast({
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Failed to analyze IPs",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      const ips = content
        .split(/[\n,]/)
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0)
        .join("\n");
      setIpList(ips);
    };
    reader.readAsText(file);
  };

  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-xl font-semibold">
          <Upload className="h-5 w-5 text-primary" />
          Bulk IP Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">
            Enter IP addresses (one per line or comma-separated)
          </label>
          <Textarea
            placeholder="192.168.1.1&#10;8.8.8.8&#10;1.1.1.1&#10;..."
            value={ipList}
            onChange={(e) => setIpList(e.target.value)}
            disabled={isAnalyzing || isLoading}
            className="min-h-32 font-mono text-sm"
            data-testid="textarea-bulk-ips"
          />
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handleAnalyze}
            disabled={isAnalyzing || isLoading || ipList.trim().length === 0}
            className="flex-1"
            data-testid="button-analyze-bulk"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Analyze {ipList.split("\n").filter(ip => ip.trim()).length} IPs
              </>
            )}
          </Button>
          <Button
            variant="outline"
            onClick={() => setIpList("")}
            disabled={isAnalyzing || isLoading}
            size="icon"
            data-testid="button-clear-bulk"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="border-t pt-4">
          <label className="text-sm font-medium block mb-2">Or upload CSV file</label>
          <input
            type="file"
            accept=".csv,.txt"
            onChange={handleFileUpload}
            disabled={isAnalyzing || isLoading}
            className="text-sm"
            data-testid="input-bulk-file"
          />
          <p className="text-xs text-muted-foreground mt-2">
            Upload a CSV or TXT file with one IP per line
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
