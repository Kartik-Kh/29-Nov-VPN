import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import Redis from "ioredis";
import { z } from "zod";
import {
  analyzeIpRequestSchema,
  isValidIpAddress,
  getIpVersion,
  getThreatLevelFromScore,
  type InsertIpAnalysis,
  type InsertWhoisRecord,
} from "@shared/schema";

// API Keys from environment
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;
const MAXMIND_KEY = process.env.MAXMIND_API_KEY;
const IPINFO_KEY = process.env.IPINFO_API_KEY;
const WHOISXML_KEY = process.env.WHOISXML_API_KEY;

console.log("API Keys loaded:", {
  abuseipdb: !!ABUSEIPDB_KEY,
  maxmind: !!MAXMIND_KEY,
  ipinfo: !!IPINFO_KEY,
  whoisxml: !!WHOISXML_KEY,
});

// Redis for caching (optional)
let redis: Redis | null = null;
try {
  redis = new Redis({
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: parseInt(process.env.REDIS_PORT || "6379"),
    retryStrategy: () => null,
    maxRetriesPerRequest: 3,
  });
  redis.on("error", () => {
    redis = null;
    console.log("⚠ Redis unavailable");
  });
  redis.on("connect", () => console.log("✓ Connected to Redis"));
} catch {
  console.log("⚠ Redis unavailable");
}

const CACHE_TTL = 3600; // 1 hour

// Free IP API - no key needed
async function fetchIPAPI(ip: string) {
  try {
    const res = await fetch(`https://ip-api.com/json/${ip}?fields=status,country,countryCode,city,region,lat,lon,isp,org,as,timezone,mobile,proxy,hosting`);
    if (!res.ok) {
      console.log(`IP-API HTTP ${res.status}`);
      return null;
    }
    const data = await res.json();
    if (data.status === "success") {
      console.log(`✓ IP-API found for ${ip}: org=${data.org}, isp=${data.isp}, proxy=${data.proxy}`);
      return data;
    } else {
      console.log(`IP-API failed: ${data.message}`);
    }
    return null;
  } catch (e) {
    console.error("IP-API error:", e);
    return null;
  }
}

// AbuseIPDB with correct format
async function fetchAbuseIPDB(ip: string) {
  if (!ABUSEIPDB_KEY) return null;
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check`, {
      method: "GET",
      headers: {
        Key: ABUSEIPDB_KEY,
        Accept: "application/json",
      },
      body: new URLSearchParams({ ipAddress: ip, maxAgeInDays: "90" }),
    });
    if (!res.ok) {
      console.log(`AbuseIPDB ${res.status}`);
      return null;
    }
    const data = await res.json();
    console.log(`✓ AbuseIPDB for ${ip}:`, data.data);
    return data.data || null;
  } catch (e) {
    return null;
  }
}

// List of known VPN/proxy providers and datacenters
const VPN_PROVIDERS = [
  "NordVPN", "ExpressVPN", "Surfshark", "ProtonVPN", "CyberGhost",
  "IPVanish", "Private Internet Access", "PIA", "Windscribe", "TunnelBear",
  "Turbo VPN", "HotspotShield", "VyprVPN", "StrongVPN", "Mullvad", "turbo",
  "IVPN", "PureVPN", "SaferVPN", "VPN Gate", "Astrill", "Bitdefender VPN",
  "Avast VPN", "AVG VPN", "McAfee VPN", "Norton VPN", "Perfect Privacy",
  "Freedome", "Hotspot Shield", "Hide My Ass", "HMA", "VPNBook",
  "VPNGate", "Psiphon", "UltraVPN", "VPNArea", "ibVPN", "SlickVPN"
];

// Generate analysis from real IP-API data
async function generateRealAnalysis(ip: string, ipApiData: any, abuseData: any): Promise<InsertIpAnalysis> {
  const ipVersion = getIpVersion(ip) || "IPv4";
  
  const country = ipApiData?.country || "Unknown";
  const countryCode = ipApiData?.countryCode || "XX";
  const city = ipApiData?.city || "Unknown";
  const region = ipApiData?.region || city;
  const latitude = ipApiData?.lat || 0;
  const longitude = ipApiData?.lon || 0;
  const organization = ipApiData?.org || "Unknown";
  const isp = ipApiData?.isp || "Unknown";
  const asn = ipApiData?.as?.split(" ")?.[0] || "Unknown";
  const timezone = ipApiData?.timezone || "UTC";
  
  // VPN detection from organization, ISP and IP-API flags
  const orgLower = organization.toLowerCase();
  const ispLower = isp.toLowerCase();
  const isVpnProvider = VPN_PROVIDERS.some(v => orgLower.includes(v.toLowerCase()) || ispLower.includes(v.toLowerCase()));
  const isVpn = isVpnProvider || ipApiData?.proxy === true || orgLower.includes("vpn") || ispLower.includes("vpn") || orgLower.includes("datacenter") || ispLower.includes("datacenter");
  const isProxy = ipApiData?.proxy === true || (abuseData?.usageType === "Data Center") || ispLower.includes("proxy");
  const isTor = abuseData?.isTor || false;
  const isDatacenter = ipApiData?.hosting === true || orgLower.includes("aws") || orgLower.includes("azure") || orgLower.includes("google") || orgLower.includes("digitalocean");
  
  let riskScore = 0;
  if (isVpn) riskScore = 65;
  if (isProxy) riskScore = Math.max(riskScore, 60);
  if (isTor) riskScore = 95;
  if (isDatacenter && !isVpn && !isProxy) riskScore = 35;
  if (abuseData?.abuseConfidenceScore) riskScore = Math.max(riskScore, Math.round(abuseData.abuseConfidenceScore * 0.9));
  if (abuseData?.totalReports > 3) riskScore = Math.min(100, riskScore + 15);
  
  riskScore = Math.min(100, Math.max(0, riskScore));
  const threatLevel = getThreatLevelFromScore(riskScore);
  
  return {
    ipAddress: ip,
    ipVersion,
    riskScore,
    isVpn,
    isProxy,
    isTor,
    isDatacenter,
    threatLevel,
    isp,
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

function validateRequest(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Validation failed", details: error.errors });
      } else {
        next(error);
      }
    }
  };
}

const requestCounts = new Map<string, { count: number; resetAt: number }>();
function rateLimit(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const record = requestCounts.get(ip);
  
  if (!record || now > record.resetAt) {
    requestCounts.set(ip, { count: 1, resetAt: now + 60000 });
    return next();
  }
  
  if (record.count >= 50) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }
  
  record.count++;
  next();
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  await storage.connect();
  
  app.use("/api", rateLimit);
  
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });
  
  app.post("/api/analyze", validateRequest(analyzeIpRequestSchema), async (req, res) => {
    try {
      const { ipAddress } = req.body;
      if (!isValidIpAddress(ipAddress)) {
        return res.status(400).json({ error: "Invalid IP address" });
      }
      
      // Check Redis cache first
      if (redis) {
        const cacheKey = `analysis:${ipAddress}`;
        try {
          const cached = await redis.get(cacheKey);
          if (cached) {
            return res.json({ ...JSON.parse(cached), cached: true, source: "redis" });
          }
        } catch {
          // Continue if cache fails
        }
      }
      
      // Fetch from free IP-API and optional AbuseIPDB
      const [ipApiData, abuseData] = await Promise.all([
        fetchIPAPI(ipAddress),
        fetchAbuseIPDB(ipAddress),
      ]);
      
      const hasRealData = !!ipApiData;
      
      let analysisData: InsertIpAnalysis;
      if (hasRealData) {
        analysisData = await generateRealAnalysis(ipAddress, ipApiData, abuseData);
      } else {
        // Fallback to mock
        analysisData = {
          ipAddress,
          ipVersion: "IPv4",
          riskScore: 15,
          isVpn: false,
          isProxy: false,
          isTor: false,
          isDatacenter: false,
          threatLevel: "low",
          isp: "Unknown ISP",
          organization: "Unknown Organization",
          asn: "AS0000",
          country: "Unknown",
          countryCode: "XX",
          city: "Unknown",
          region: "Unknown",
          latitude: 0,
          longitude: 0,
          timezone: "UTC",
          analyzedAt: new Date(),
        };
      }
      
      const analysis = await storage.createAnalysis(analysisData);
      const whois = await storage.createWhoisRecord({
        ipAddress,
        domain: null,
        registrar: whoisData?.result?.registrar || "Unknown",
        registrantName: "Network Administrator",
        registrantOrg: whoisData?.result?.organization || "Unknown",
        registrantCountry: whoisData?.result?.countryCode || "XX",
        createdDate: whoisData?.result?.createdDate || "",
        updatedDate: whoisData?.result?.updatedDate || "",
        expiresDate: null,
        nameServers: whoisData?.result?.nameServers || [],
        netRange: `${ipAddress}/24`,
        netName: `NET-${ipAddress.split(".").slice(0, 2).join("-")}`,
        netHandle: "HANDLE-0000",
        originAs: "",
        abuseContact: "",
        techContact: "",
        fetchedAt: new Date(),
      });
      
      // Cache result in Redis if available
      const result = { analysis, whois, cached: false, source: hasRealData ? "real" : "mock" };
      if (redis) {
        try {
          const cacheKey = `analysis:${ipAddress}`;
          await redis.setex(cacheKey, CACHE_TTL, JSON.stringify(result));
        } catch {
          // Continue if cache fails
        }
      }
      
      res.json(result);
    } catch (error) {
      console.error("Analysis error:", error);
      res.status(500).json({ error: "Failed to analyze IP" });
    }
  });
  
  app.get("/api/analyses", async (_req, res) => {
    try {
      const analyses = await storage.getAllAnalyses();
      res.json(analyses);
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve analyses" });
    }
  });
  
  app.get("/api/analyses/:id", async (req, res) => {
    try {
      const analysis = await storage.getAnalysis(req.params.id);
      if (!analysis) return res.status(404).json({ error: "Not found" });
      const whois = await storage.getWhoisByIp(analysis.ipAddress);
      res.json({ analysis, whois });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve analysis" });
    }
  });
  
  app.delete("/api/analyses/:id", async (req, res) => {
    try {
      const deleted = await storage.deleteAnalysis(req.params.id);
      if (!deleted) return res.status(404).json({ error: "Not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete analysis" });
    }
  });
  
  app.get("/api/stats", async (_req, res) => {
    try {
      const stats = await storage.getStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve stats" });
    }
  });
  
  app.get("/api/whois/:ipAddress", async (req, res) => {
    try {
      const { ipAddress } = req.params;
      if (!isValidIpAddress(ipAddress)) {
        return res.status(400).json({ error: "Invalid IP" });
      }
      const whois = await storage.getWhoisByIp(ipAddress);
      res.json(whois || { ipAddress, message: "No WHOIS data found" });
    } catch (error) {
      res.status(500).json({ error: "Failed to retrieve WHOIS" });
    }
  });

  return httpServer;
}
