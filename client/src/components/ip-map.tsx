import { useEffect, useRef } from "react";
import L from "leaflet";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin } from "lucide-react";

interface IpMapProps {
  latitude?: number | null;
  longitude?: number | null;
  city?: string | null;
  country?: string | null;
  ipAddress: string;
}

export function IpMap({ latitude, longitude, city, country, ipAddress }: IpMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  const hasLocation = latitude != null && longitude != null;
  const lat = latitude ?? 0;
  const lng = longitude ?? 0;

  useEffect(() => {
    if (!hasLocation || !mapRef.current) return;

    // Destroy previous map instance
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
    }

    // Create new map instance
    const map = L.map(mapRef.current).setView([lat, lng], 10);

    // Add CartoDB tiles
    L.tileLayer("https://{s}.basemaps.cartocdn.com/positron/{z}/{x}/{y}{r}.png", {
      attribution: "&copy; CartoDB",
      maxZoom: 19,
    }).addTo(map);

    // Add marker
    const markerIcon = L.icon({
      iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
      iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
      shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
      iconSize: [25, 41],
      iconAnchor: [12, 41],
      popupAnchor: [1, -34],
      shadowSize: [41, 41],
    });

    const marker = L.marker([lat, lng], { icon: markerIcon }).addTo(map);
    const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";
    marker.bindPopup(
      `<div class="text-sm"><p class="font-semibold">${ipAddress}</p><p>${locationLabel}</p><p class="text-xs mt-1">${lat.toFixed(4)}, ${lng.toFixed(4)}</p></div>`
    );

    mapInstanceRef.current = map;

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [lat, lng, hasLocation, ipAddress, city, country]);

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
          ref={mapRef}
          className="h-[300px] lg:h-[400px] rounded-md overflow-hidden bg-muted"
          data-testid="map-container"
        />
      </CardContent>
    </Card>
  );
}
