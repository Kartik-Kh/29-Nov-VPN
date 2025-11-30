import { GoogleMap, Marker, InfoWindow } from "@react-google-maps/api";
import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin, AlertCircle } from "lucide-react";

interface IpMapProps {
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  ipAddress: string;
}

const mapContainerStyle = {
  width: "100%",
  height: "100%",
};

export function IpMap({ latitude, longitude, city, country, ipAddress }: IpMapProps) {
  const hasLocation = latitude != null && longitude != null;
  const [markerShown, setMarkerShown] = useState(true);
  const lat = latitude ?? 0;
  const lng = longitude ?? 0;
  const center = { lat, lng };
  const apiKey = import.meta.env.VITE_GOOGLE_MAPS_API_KEY;

  const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";

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

  if (!apiKey) {
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
            <div className="text-center text-muted-foreground space-y-2">
              <AlertCircle className="h-8 w-8 mx-auto opacity-50" />
              <p className="text-sm">Google Maps API key not configured</p>
              <p className="text-xs">Location: {locationLabel}</p>
              <p className="text-xs font-mono">{lat.toFixed(4)}, {lng.toFixed(4)}</p>
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
      <CardContent>
        <div 
          className="h-[300px] lg:h-[400px] rounded-md overflow-hidden"
          data-testid="map-container"
        >
          <GoogleMap
            mapContainerStyle={mapContainerStyle}
            center={center}
            zoom={11}
            options={{
              disableDefaultUI: false,
              zoomControl: true,
              mapTypeControl: true,
              fullscreenControl: true,
            }}
          >
            <Marker
              position={center}
              onClick={() => setMarkerShown(true)}
              title={ipAddress}
            >
              {markerShown && (
                <InfoWindow onCloseClick={() => setMarkerShown(false)}>
                  <div className="text-sm space-y-1">
                    <p className="font-semibold font-mono">{ipAddress}</p>
                    <p className="text-sm">{locationLabel}</p>
                    <p className="text-xs text-gray-600">
                      {lat.toFixed(4)}, {lng.toFixed(4)}
                    </p>
                  </div>
                </InfoWindow>
              )}
            </Marker>
          </GoogleMap>
        </div>
      </CardContent>
    </Card>
  );
}
