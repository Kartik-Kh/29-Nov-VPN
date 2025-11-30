import { useCallback, useEffect, useRef } from "react";
import { GoogleMap, Marker, InfoWindow } from "@react-google-maps/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin } from "lucide-react";
import { useScript } from "@/hooks/use-script";

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
  const mapRef = useRef<google.maps.Map | null>(null);
  const [selectedMarker, setSelectedMarker] = useCallback(() => setSelectedMarker(true), []);

  const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";
  const googleMapsApiKey = import.meta.env.VITE_GOOGLE_MAPS_API_KEY;

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
      <CardContent>
        <div 
          className="h-[300px] lg:h-[400px] rounded-md overflow-hidden"
          data-testid="map-container"
        >
          {!googleMapsApiKey ? (
            <div className="h-full flex items-center justify-center bg-muted">
              <div className="text-center text-muted-foreground">
                <MapPin className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">Google Maps API key not configured</p>
              </div>
            </div>
          ) : (
            <GoogleMap
              mapContainerStyle={{ width: "100%", height: "100%" }}
              center={{ lat, lng }}
              zoom={10}
              ref={mapRef}
              options={{
                disableDefaultUI: false,
                zoomControl: true,
                mapTypeControl: true,
              }}
            >
              <Marker
                position={{ lat, lng }}
                onClick={() => setSelectedMarker(true)}
                title={ipAddress}
              >
                {selectedMarker && (
                  <InfoWindow onCloseClick={() => setSelectedMarker(false)}>
                    <div className="text-sm">
                      <p className="font-semibold font-mono">{ipAddress}</p>
                      <p className="text-muted-foreground">{locationLabel}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {lat.toFixed(4)}, {lng.toFixed(4)}
                      </p>
                    </div>
                  </InfoWindow>
                )}
              </Marker>
            </GoogleMap>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
