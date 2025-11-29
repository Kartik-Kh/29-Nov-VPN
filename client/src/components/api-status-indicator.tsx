import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Circle } from "lucide-react";

interface ApiStatusIndicatorProps {
  isConnected: boolean;
  latency?: number;
}

export function ApiStatusIndicator({ isConnected, latency }: ApiStatusIndicatorProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className="gap-1.5 cursor-default"
          data-testid="badge-api-status"
        >
          <Circle
            className={`h-2 w-2 fill-current ${
              isConnected ? "text-threat-low" : "text-threat-critical"
            }`}
          />
          <span className="text-xs">
            {isConnected ? "API Online" : "API Offline"}
          </span>
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        <p className="text-xs">
          {isConnected
            ? `Detection API is online${latency ? ` (${latency}ms)` : ""}`
            : "Detection API is unavailable"}
        </p>
      </TooltipContent>
    </Tooltip>
  );
}
