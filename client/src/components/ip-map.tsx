import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin, ExternalLink, Locate } from "lucide-react";
import { Button } from "@/components/ui/button";

interface IpMapProps {
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  ipAddress: string;
}

export function IpMap({ latitude, longitude, city, country, ipAddress }: IpMapProps) {
  const hasLocation = latitude != null && longitude != null;
  const lat = latitude ?? 0;
  const lng = longitude ?? 0;

  const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";

  const googleMapsUrl = `https://www.google.com/maps/search/${lat},${lng}`;
  const openStreetMapUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}&zoom=12`;
  const appleMapUrl = `https://maps.apple.com/?q=${lat},${lng}`;

  if (!hasLocation) {
    return (
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2 text-xl font-semibold">
            <MapPin className="h-5 w-5 text-primary" />
            Geographic Location
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[300px] lg:h-[400px] flex items-center justify-center bg-muted rounded-md">
            <div className="text-center text-muted-foreground">
              <MapPin className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">Location data not available</p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-xl font-semibold">
          <MapPin className="h-5 w-5 text-primary" />
          Geographic Location
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="bg-muted rounded-lg p-6 space-y-4">
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">IP Address</p>
            <p className="text-lg font-mono font-semibold">{ipAddress}</p>
          </div>

          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">Location</p>
            <div className="flex items-center gap-2">
              <Locate className="h-4 w-4 text-primary" />
              <p className="text-lg font-semibold">{locationLabel}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">Latitude</p>
              <p className="text-sm font-mono font-semibold">{lat.toFixed(4)}°</p>
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">Longitude</p>
              <p className="text-sm font-mono font-semibold">{lng.toFixed(4)}°</p>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          <p className="text-sm font-medium text-muted-foreground">View on Map</p>
          <div className="flex flex-col gap-2">
            <a href={googleMapsUrl} target="_blank" rel="noopener noreferrer">
              <Button 
                variant="outline" 
                className="w-full justify-between"
                data-testid="button-google-maps"
              >
                <span>Google Maps</span>
                <ExternalLink className="h-4 w-4" />
              </Button>
            </a>
            <a href={openStreetMapUrl} target="_blank" rel="noopener noreferrer">
              <Button 
                variant="outline" 
                className="w-full justify-between"
                data-testid="button-openstreetmap"
              >
                <span>OpenStreetMap</span>
                <ExternalLink className="h-4 w-4" />
              </Button>
            </a>
            <a href={appleMapUrl} target="_blank" rel="noopener noreferrer">
              <Button 
                variant="outline" 
                className="w-full justify-between"
                data-testid="button-apple-maps"
              >
                <span>Apple Maps</span>
                <ExternalLink className="h-4 w-4" />
              </Button>
            </a>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
