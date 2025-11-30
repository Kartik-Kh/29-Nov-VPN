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
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);

  const hasLocation = latitude != null && longitude != null;
  const lat = latitude ?? 0;
  const lng = longitude ?? 0;
  const locationLabel = [city, country].filter(Boolean).join(", ") || "Unknown Location";

  useEffect(() => {
    if (!hasLocation || !containerRef.current) return;

    // Clean up previous map
    if (mapRef.current) {
      mapRef.current.off();
      mapRef.current.remove();
      mapRef.current = null;
    }

    // Create new map
    const map = L.map(containerRef.current, {
      center: [lat, lng],
      zoom: 11,
      scrollWheelZoom: true,
    });

    // Add free OpenStreetMap tiles
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap contributors",
      maxZoom: 19,
    }).addTo(map);

    // Add marker with custom icon
    const markerHtml = `
      <div style="
        width: 32px;
        height: 32px;
        background: #ef4444;
        border: 3px solid white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      ">
        <div style="
          width: 8px;
          height: 8px;
          background: white;
          border-radius: 50%;
        "></div>
      </div>
    `;

    const customIcon = L.divIcon({
      html: markerHtml,
      iconSize: [32, 32],
      iconAnchor: [16, 16],
      popupAnchor: [0, -16],
    });

    const marker = L.marker([lat, lng], { icon: customIcon })
      .addTo(map)
      .bindPopup(
        `<div style="font-size: 12px; line-height: 1.6;">
          <strong>${ipAddress}</strong><br/>
          ${locationLabel}<br/>
          <code>${lat.toFixed(4)}, ${lng.toFixed(4)}</code>
        </div>`,
        { maxWidth: 250 }
      )
      .openPopup();

    mapRef.current = map;

    // Cleanup
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [lat, lng, hasLocation, ipAddress, locationLabel]);

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
          Geographic Location: {locationLabel}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div
          ref={containerRef}
          className="h-[300px] lg:h-[400px] rounded-md overflow-hidden border border-border bg-muted"
          data-testid="map-container"
          style={{ width: "100%" }}
        />
      </CardContent>
    </Card>
  );
}
