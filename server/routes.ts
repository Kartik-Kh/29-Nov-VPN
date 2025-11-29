import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import {
  analyzeIpRequestSchema,
  isValidIpAddress,
  getIpVersion,
  getThreatLevelFromScore,
  type InsertIpAnalysis,
  type InsertWhoisRecord,
} from "@shared/schema";

const IPINFO_TOKEN = process.env.IPINFO_API_KEY;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;

async function fetchIpInfoData(ipAddress: string) {
  if (!IPINFO_TOKEN) {
    console.log('No IPINFO_API_KEY configured');
    return null;
  }
  try {
    const response = await fetch(`https://ipinfo.io/${ipAddress}?token=${IPINFO_TOKEN}`);
    if (!response.ok) {
      console.log(`IPInfo API error for ${ipAddress}: ${response.status}`);
      return null;
    }
    const data = await response.json();
    console.log(`IPInfo data for ${ipAddress}:`, data);
    return data;
  } catch (error) {
    console.error(`IPInfo fetch error for ${ipAddress}:`, error);
    return null;
  }
}

async function fetchAbuseIPDBData(ipAddress: string) {
  if (!ABUSEIPDB_API_KEY) {
    console.log('No ABUSEIPDB_API_KEY configured');
    return null;
  }
  try {
    const response = await fetch('https://api.abuseipdb.com/api/v2/check', {
      method: 'POST',
      headers: {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        ipAddress,
        maxAgeInDays: '90',
        verbose: '',
      }),
    });
    if (!response.ok) {
      console.log(`AbuseIPDB API error for ${ipAddress}: ${response.status}`);
      return null;
    }
    const data = await response.json();
    console.log(`AbuseIPDB data for ${ipAddress}:`, data);
    return data.data || null;
  } catch (error) {
    console.error(`AbuseIPDB fetch error for ${ipAddress}:`, error);
    return null;
  }
}

async function generateRealAnalysis(ipAddress: string, ipinfoData: any, abuseipdbData: any): Promise<InsertIpAnalysis> {
  const ipVersion = getIpVersion(ipAddress) || "IPv4";
  
  const country = ipinfoData?.country || "Unknown";
  const countryCode = ipinfoData?.country_code || "XX";
  const city = ipinfoData?.city || "Unknown";
  const region = ipinfoData?.region || city;
  const [latStr, lngStr] = (ipinfoData?.loc || "0,0").split(",");
  const latitude = parseFloat(latStr) || 0;
  const longitude = parseFloat(lngStr) || 0;
  const organization = ipinfoData?.org || "Unknown";
  const isp = organization.split(" ").slice(1).join(" ") || organization;
  const asn = ipinfoData?.asn?.split(" ")[0] || "Unknown";
  const timezone = ipinfoData?.timezone || "UTC";
  
  const abuseScore = abuseipdbData?.abuseConfidenceScore || 0;
  const totalReports = abuseipdbData?.totalReports || 0;
  const usageType = abuseipdbData?.usageType || "unknown";
  const isp_abusedb = abuseipdbData?.isp || isp;
  
  let riskScore = Math.round(abuseScore * 0.8);
  const isVpn = usageType === "Data Center" || organization.toLowerCase().includes("vpn");
  const isProxy = usageType === "Data Center" && totalReports > 0;
  const isTor = false;
  const isDatacenter = usageType === "Data Center" || usageType === "Content Delivery Network";
  
  if (isVpn) riskScore = Math.min(100, riskScore + 20);
  if (isProxy) riskScore = Math.min(100, riskScore + 15);
  if (isDatacenter && riskScore < 30) riskScore = Math.max(30, riskScore);
  if (totalReports > 0) riskScore = Math.min(100, riskScore + Math.min(totalReports * 5, 25));
  
  const threatLevel = getThreatLevelFromScore(riskScore);
  
  return {
    ipAddress,
    ipVersion,
    riskScore,
    isVpn,
    isProxy,
    isTor,
    isDatacenter,
    threatLevel,
    isp: isp_abusedb,
    organization,
    asn,
    country,
    countryCode,
    city,
    region,
    latitude,
    longitude,
    timezone,
    analyzedAt: new Date(),
  };
}

const knownVpnProviders = [
  "NordVPN", "ExpressVPN", "Surfshark", "CyberGhost", "Private Internet Access",
  "ProtonVPN", "Mullvad", "IPVanish", "TunnelBear", "Windscribe",
];

const knownDatacenters = [
  "Amazon", "AWS", "Google Cloud", "Microsoft Azure", "DigitalOcean",
  "Linode", "Vultr", "OVH", "Hetzner", "Cloudflare",
];

const suspiciousIsps = [
  "M247", "Choopa", "QuadraNet", "LeaseWeb", "ColoCrossing",
];

function generateMockAnalysis(ipAddress: string): InsertIpAnalysis {
  const ipVersion = getIpVersion(ipAddress) || "IPv4";
  
  const octets = ipAddress.split(".");
  const firstOctet = parseInt(octets[0] || "0", 10);
  const lastOctet = parseInt(octets[octets.length - 1] || "0", 10);
  
  const seed = firstOctet * 1000 + lastOctet;
  const random = (max: number) => Math.floor((seed * 9301 + 49297) % 233280 / 233280 * max);
  
  const isVpn = random(100) < 30;
  const isProxy = !isVpn && random(100) < 15;
  const isTor = !isVpn && !isProxy && random(100) < 5;
  const isDatacenter = random(100) < 25;
  
  let riskScore = 0;
  if (isVpn) riskScore += 35 + random(30);
  if (isProxy) riskScore += 25 + random(25);
  if (isTor) riskScore += 40 + random(20);
  if (isDatacenter) riskScore += 15 + random(15);
  
  riskScore = Math.min(100, Math.max(0, riskScore + random(15)));
  
  const threatLevel = getThreatLevelFromScore(riskScore);
  
  const countries = [
    { name: "United States", code: "US", lat: 37.7749, lng: -122.4194 },
    { name: "Germany", code: "DE", lat: 52.5200, lng: 13.4050 },
    { name: "Netherlands", code: "NL", lat: 52.3676, lng: 4.9041 },
    { name: "United Kingdom", code: "GB", lat: 51.5074, lng: -0.1278 },
    { name: "Canada", code: "CA", lat: 43.6532, lng: -79.3832 },
    { name: "France", code: "FR", lat: 48.8566, lng: 2.3522 },
    { name: "Japan", code: "JP", lat: 35.6762, lng: 139.6503 },
    { name: "Australia", code: "AU", lat: -33.8688, lng: 151.2093 },
    { name: "Singapore", code: "SG", lat: 1.3521, lng: 103.8198 },
    { name: "Sweden", code: "SE", lat: 59.3293, lng: 18.0686 },
  ];
  
  const cities = [
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
    "Berlin", "Amsterdam", "London", "Toronto", "Paris",
    "Tokyo", "Sydney", "Singapore", "Stockholm", "Frankfurt",
  ];
  
  const isps = [
    "Comcast Cable Communications", "AT&T Services", "Verizon FiOS",
    "Deutsche Telekom AG", "British Telecom", "Orange SA",
    "NTT Communications", "Telstra Corporation", "SingTel",
    ...knownDatacenters, ...suspiciousIsps,
  ];
  
  const organizations = [
    "Residential Network", "Corporate Network", "Educational Institution",
    ...knownVpnProviders, ...knownDatacenters,
  ];
  
  const countryIndex = random(countries.length);
  const country = countries[countryIndex];
  const city = cities[random(cities.length)];
  const isp = isVpn 
    ? knownVpnProviders[random(knownVpnProviders.length)]
    : isDatacenter 
      ? knownDatacenters[random(knownDatacenters.length)]
      : isps[random(isps.length)];
  const organization = isVpn 
    ? knownVpnProviders[random(knownVpnProviders.length)]
    : isDatacenter 
      ? knownDatacenters[random(knownDatacenters.length)]
      : organizations[random(organizations.length)];
  
  const latOffset = (random(100) - 50) / 100;
  const lngOffset = (random(100) - 50) / 100;
  
  return {
    ipAddress,
    ipVersion,
    riskScore,
    isVpn,
    isProxy,
    isTor,
    isDatacenter,
    threatLevel,
    isp,
    organization,
    asn: `AS${10000 + random(90000)}`,
    country: country.name,
    countryCode: country.code,
    city,
    region: city,
    latitude: country.lat + latOffset,
    longitude: country.lng + lngOffset,
    timezone: "UTC",
    analyzedAt: new Date(),
  };
}

function generateMockWhois(ipAddress: string): InsertWhoisRecord {
  const seed = ipAddress.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const random = (max: number) => Math.floor((seed * 9301 + 49297) % 233280 / 233280 * max);
  
  const registrars = [
    "ARIN", "RIPE NCC", "APNIC", "LACNIC", "AFRINIC",
    "American Registry for Internet Numbers", "Reseaux IP Europeens",
  ];
  
  const orgs = [
    "Internet Assigned Numbers Authority", "Cloud Services LLC",
    "Data Center Operations", "Network Solutions Inc", "Hosting Provider Corp",
  ];
  
  const contacts = [
    "abuse@network.com", "noc@provider.net", "admin@hosting.org",
    "security@datacenter.io", "support@isp.com",
  ];
  
  const nameServers = [
    ["ns1.provider.net", "ns2.provider.net"],
    ["dns1.hosting.com", "dns2.hosting.com"],
    ["a.ns.cloud.io", "b.ns.cloud.io", "c.ns.cloud.io"],
  ];
  
  const now = new Date();
  const createdYear = 2010 + random(10);
  const createdDate = new Date(createdYear, random(12), random(28) + 1);
  const updatedDate = new Date(now.getFullYear() - random(2), random(12), random(28) + 1);
  
  return {
    ipAddress,
    domain: null,
    registrar: registrars[random(registrars.length)],
    registrantName: "Network Administrator",
    registrantOrg: orgs[random(orgs.length)],
    registrantCountry: "US",
    createdDate: createdDate.toISOString().split("T")[0],
    updatedDate: updatedDate.toISOString().split("T")[0],
    expiresDate: null,
    nameServers: nameServers[random(nameServers.length)],
    netRange: `${ipAddress}/24`,
    netName: `NET-${ipAddress.split(".").slice(0, 2).join("-")}`,
    netHandle: `NET-${random(10000)}-${random(10000)}`,
    originAs: `AS${10000 + random(90000)}`,
    abuseContact: contacts[random(contacts.length)],
    techContact: contacts[random(contacts.length)],
    fetchedAt: now,
  };
}

function validateRequest(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: "Validation failed",
          details: error.errors,
        });
      } else {
        next(error);
      }
    }
  };
}

const requestCounts = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT = 50;
const RATE_WINDOW = 60 * 1000;

function rateLimit(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  
  const record = requestCounts.get(ip);
  
  if (!record || now > record.resetAt) {
    requestCounts.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return next();
  }
  
  if (record.count >= RATE_LIMIT) {
    return res.status(429).json({
      error: "Rate limit exceeded",
      retryAfter: Math.ceil((record.resetAt - now) / 1000),
    });
  }
  
  record.count++;
  next();
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.use("/api", rateLimit);
  
  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });
  
  app.post(
    "/api/analyze",
    validateRequest(analyzeIpRequestSchema),
    async (req: Request, res: Response) => {
      try {
        const { ipAddress } = req.body;
        
        if (!isValidIpAddress(ipAddress)) {
          return res.status(400).json({ error: "Invalid IP address format" });
        }
        
        const cached = await storage.getCachedResult(ipAddress);
        if (cached) {
          return res.json({
            analysis: cached.analysis,
            whois: cached.whois,
            cached: true,
          });
        }
        
        const [ipinfoData, abuseipdbData] = await Promise.all([
          fetchIpInfoData(ipAddress),
          fetchAbuseIPDBData(ipAddress),
        ]);
        
        let analysisData: InsertIpAnalysis;
        if (ipinfoData || abuseipdbData) {
          analysisData = await generateRealAnalysis(ipAddress, ipinfoData, abuseipdbData);
        } else {
          analysisData = generateMockAnalysis(ipAddress);
        }
        
        const analysis = await storage.createAnalysis(analysisData);
        
        const whoisData = generateMockWhois(ipAddress);
        const whois = await storage.createWhoisRecord(whoisData);
        
        storage.setCachedResult(ipAddress, analysis, whois);
        
        res.json({
          analysis,
          whois,
          cached: false,
          realData: !!(ipinfoData || abuseipdbData),
        });
      } catch (error) {
        console.error("Analysis error:", error);
        res.status(500).json({ error: "Failed to analyze IP address" });
      }
    }
  );
  
  app.get("/api/analyses", async (_req: Request, res: Response) => {
    try {
      const analyses = await storage.getAllAnalyses();
      res.json(analyses);
    } catch (error) {
      console.error("Get analyses error:", error);
      res.status(500).json({ error: "Failed to retrieve analyses" });
    }
  });
  
  app.get("/api/analyses/:id", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const analysis = await storage.getAnalysis(id);
      
      if (!analysis) {
        return res.status(404).json({ error: "Analysis not found" });
      }
      
      const whois = await storage.getWhoisByIp(analysis.ipAddress);
      
      res.json({ analysis, whois });
    } catch (error) {
      console.error("Get analysis error:", error);
      res.status(500).json({ error: "Failed to retrieve analysis" });
    }
  });
  
  app.delete("/api/analyses/:id", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const deleted = await storage.deleteAnalysis(id);
      
      if (!deleted) {
        return res.status(404).json({ error: "Analysis not found" });
      }
      
      res.json({ success: true });
    } catch (error) {
      console.error("Delete analysis error:", error);
      res.status(500).json({ error: "Failed to delete analysis" });
    }
  });
  
  app.get("/api/stats", async (_req: Request, res: Response) => {
    try {
      const stats = await storage.getStats();
      res.json(stats);
    } catch (error) {
      console.error("Get stats error:", error);
      res.status(500).json({ error: "Failed to retrieve statistics" });
    }
  });
  
  app.get("/api/whois/:ipAddress", async (req: Request, res: Response) => {
    try {
      const { ipAddress } = req.params;
      
      if (!isValidIpAddress(ipAddress)) {
        return res.status(400).json({ error: "Invalid IP address format" });
      }
      
      let whois = await storage.getWhoisByIp(ipAddress);
      
      if (!whois) {
        const whoisData = generateMockWhois(ipAddress);
        whois = await storage.createWhoisRecord(whoisData);
      }
      
      res.json(whois);
    } catch (error) {
      console.error("WHOIS lookup error:", error);
      res.status(500).json({ error: "Failed to retrieve WHOIS records" });
    }
  });

  return httpServer;
}
