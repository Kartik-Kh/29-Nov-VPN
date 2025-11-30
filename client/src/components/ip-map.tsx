import { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin } from "lucide-react";

const markerIcon = new L.Icon({
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

interface IpMapProps {
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  ipAddress: string;
}

function MapUpdater({ latitude, longitude }: { latitude: number; longitude: number }) {
  const map = useMap();
  
  useEffect(() => {
    map.setView([latitude, longitude], 10, { animate: true });
  }, [map, latitude, longitude]);
  
  return null;
}

export function IpMap({ latitude, longitude, city, country, ipAddress }: IpMapProps) {
  const hasLocation = latitude != null && longitude != null;
  const lat = latitude ?? 0;
  const lng = longitude ?? 0;

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

  const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";

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
          <MapContainer
            center={[lat, lng]}
            zoom={10}
            scrollWheelZoom={true}
            style={{ height: "100%", width: "100%" }}
          >
            <TileLayer
              attribution='&copy; <a href="https://cartodb.com/">CartoDB</a>'
              url="https://{s}.basemaps.cartocdn.com/positron/{z}/{x}/{y}{r}.png"
            />
            <Marker position={[lat, lng]} icon={markerIcon}>
              <Popup>
                <div className="text-sm">
                  <p className="font-semibold font-mono">{ipAddress}</p>
                  <p className="text-muted-foreground">{locationLabel}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {lat.toFixed(4)}, {lng.toFixed(4)}
                  </p>
                </div>
              </Popup>
            </Marker>
            <MapUpdater latitude={lat} longitude={lng} />
          </MapContainer>
        </div>
      </CardContent>
    </Card>
  );
}
