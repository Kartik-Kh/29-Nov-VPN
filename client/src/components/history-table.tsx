import { useState } from "react";
import { format } from "date-fns";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { type IpAnalysis, type ThreatLevel } from "@shared/schema";
import {
  History,
  Search,
  Eye,
  RefreshCw,
  Trash2,
  Download,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

interface HistoryTableProps {
  analyses: IpAnalysis[];
  isLoading?: boolean;
  onView?: (analysis: IpAnalysis) => void;
  onRescan?: (ipAddress: string) => void;
  onDelete?: (id: string) => void;
  onExport?: (format: "csv" | "json") => void;
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

const ITEMS_PER_PAGE = 10;

export function HistoryTable({
  analyses,
  isLoading = false,
  onView,
  onRescan,
  onDelete,
  onExport,
}: HistoryTableProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);

  const filteredAnalyses = analyses.filter(
    (a) =>
      a.ipAddress.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.country?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.isp?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const totalPages = Math.ceil(filteredAnalyses.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedAnalyses = filteredAnalyses.slice(
    startIndex,
    startIndex + ITEMS_PER_PAGE
  );

  return (
    <Card>
      <CardHeader className="pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <CardTitle className="flex items-center gap-2 text-xl font-semibold">
            <History className="h-5 w-5 text-primary" />
            Analysis History
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by IP, country, ISP..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 h-9"
                data-testid="input-search-history"
              />
            </div>
            {onExport && (
              <div className="flex gap-1">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => onExport("csv")}
                      data-testid="button-export-csv"
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export as CSV</TooltipContent>
                </Tooltip>
              </div>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : filteredAnalyses.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
            <History className="h-10 w-10 mb-3 opacity-50" />
            <p className="text-sm font-medium">
              {searchQuery ? "No matching results found" : "No analysis history yet"}
            </p>
            <p className="text-xs mt-1">
              {searchQuery
                ? "Try adjusting your search terms"
                : "Start by analyzing an IP address above"}
            </p>
          </div>
        ) : (
          <>
            <div className="rounded-md border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="font-semibold">Timestamp</TableHead>
                    <TableHead className="font-semibold">IP Address</TableHead>
                    <TableHead className="font-semibold">Risk Score</TableHead>
                    <TableHead className="font-semibold">Status</TableHead>
                    <TableHead className="font-semibold">Location</TableHead>
                    <TableHead className="font-semibold text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginatedAnalyses.map((analysis) => (
                    <TableRow key={analysis.id} data-testid={`row-analysis-${analysis.id}`}>
                      <TableCell className="text-sm text-muted-foreground">
                        {format(new Date(analysis.analyzedAt), "MMM d, yyyy HH:mm")}
                      </TableCell>
                      <TableCell className="font-mono text-sm font-medium">
                        {analysis.ipAddress}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={getThreatBadgeVariant(analysis.threatLevel as ThreatLevel)}
                          size="sm"
                        >
                          {analysis.riskScore}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 flex-wrap">
                          {analysis.isVpn && (
                            <Badge variant="destructive" size="sm">VPN</Badge>
                          )}
                          {analysis.isProxy && (
                            <Badge variant="destructive" size="sm">Proxy</Badge>
                          )}
                          {!analysis.isVpn && !analysis.isProxy && (
                            <Badge variant="secondary" size="sm">Clean</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        {[analysis.city, analysis.country].filter(Boolean).join(", ") || "Unknown"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          {onView && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => onView(analysis)}
                                  data-testid={`button-view-${analysis.id}`}
                                >
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>View Details</TooltipContent>
                            </Tooltip>
                          )}
                          {onRescan && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => onRescan(analysis.ipAddress)}
                                  data-testid={`button-rescan-${analysis.id}`}
                                >
                                  <RefreshCw className="h-4 w-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>Re-scan</TooltipContent>
                            </Tooltip>
                          )}
                          {onDelete && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => onDelete(analysis.id)}
                                  data-testid={`button-delete-${analysis.id}`}
                                >
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>Delete</TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4">
                <p className="text-sm text-muted-foreground">
                  Showing {startIndex + 1}-{Math.min(startIndex + ITEMS_PER_PAGE, filteredAnalyses.length)} of {filteredAnalyses.length} results
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    data-testid="button-prev-page"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="text-sm font-medium px-2">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    data-testid="button-next-page"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
