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

// Fetch real data from 4 APIs
async function fetchAbuseIPDB(ip: string) {
  if (!ABUSEIPDB_KEY) {
    console.log("AbuseIPDB: No API key");
    return null;
  }
  try {
    const params = new URLSearchParams();
    params.append("ipAddress", ip);
    params.append("maxAgeInDays", "90");
    
    const res = await fetch("https://api.abuseipdb.com/api/v2/check", {
      method: "POST",
      headers: {
        Key: ABUSEIPDB_KEY,
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });
    if (!res.ok) {
      console.log(`AbuseIPDB error: ${res.status} - ${res.statusText}`);
      return null;
    }
    const data = await res.json();
    console.log(`AbuseIPDB success for ${ip}:`, data.data);
    return data.data || null;
  } catch (e) {
    console.error("AbuseIPDB fetch error:", e);
    return null;
  }
}

async function fetchMaxMind(ip: string) {
  if (!MAXMIND_KEY) {
    console.log("MaxMind: No API key");
    return null;
  }
  try {
    const res = await fetch(`https://geoip.maxmind.com/geoip/v2.1/city/${ip}`, {
      headers: { Authorization: `Basic ${Buffer.from(`account_id:${MAXMIND_KEY}`).toString("base64")}` },
    });
    if (!res.ok) {
      console.log(`MaxMind error: ${res.status} - ${res.statusText}`);
      return null;
    }
    const data = await res.json();
    console.log(`MaxMind success for ${ip}:`, data);
    return data;
  } catch (e) {
    console.error("MaxMind fetch error:", e);
    return null;
  }
}

async function fetchIPInfo(ip: string) {
  if (!IPINFO_KEY) {
    console.log("IPInfo: No API key");
    return null;
  }
  try {
    const res = await fetch(`https://ipinfo.io/${ip}?token=${IPINFO_KEY}`);
    if (!res.ok) {
      console.log(`IPInfo error: ${res.status} - ${res.statusText}`);
      return null;
    }
    const data = await res.json();
    console.log(`IPInfo success for ${ip}:`, data);
    return data;
  } catch (e) {
    console.error("IPInfo fetch error:", e);
    return null;
  }
}

async function fetchWhoisXML(ip: string) {
  if (!WHOISXML_KEY) {
    console.log("WhoisXML: No API key");
    return null;
  }
  try {
    const res = await fetch(
      `https://ip-whois-api.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_KEY}&ipv4=${ip}`
    );
    if (!res.ok) {
      console.log(`WhoisXML error: ${res.status} - ${res.statusText}`);
      return null;
    }
    const data = await res.json();
    console.log(`WhoisXML success for ${ip}:`, data);
    return data;
  } catch (e) {
    console.error("WhoisXML fetch error:", e);
    return null;
  }
}

// Generate analysis from real API data
async function generateRealAnalysis(
  ip: string,
  abuseData: any,
  maxmindData: any,
  ipinfoData: any,
  whoisData: any
): Promise<InsertIpAnalysis> {
  const ipVersion = getIpVersion(ip) || "IPv4";
  
  // Primary source: MaxMind, fallback to IPInfo
  const country = maxmindData?.country?.iso_code || ipinfoData?.country || "Unknown";
  const countryCode = country;
  const city = maxmindData?.city?.names?.en || ipinfoData?.city || "Unknown";
  const region = maxmindData?.subdivisions?.[0]?.names?.en || ipinfoData?.region || city;
  const latitude = maxmindData?.location?.latitude || parseFloat(ipinfoData?.loc?.split(",")?.[0]) || 0;
  const longitude = maxmindData?.location?.longitude || parseFloat(ipinfoData?.loc?.split(",")?.[1]) || 0;
  
  const organization = ipinfoData?.org?.split(" ").slice(1).join(" ") || whoisData?.result?.registrar || "Unknown";
  const isp = organization;
  const asn = maxmindData?.traits?.autonomous_system_number?.toString() || ipinfoData?.asn?.split(" ")?.[0] || "Unknown";
  const timezone = maxmindData?.location?.time_zone || ipinfoData?.timezone || "UTC";
  
  // Threat calculation from AbuseIPDB
  const abuseScore = abuseData?.abuseConfidenceScore || 0;
  const totalReports = abuseData?.totalReports || 0;
  const usageType = abuseData?.usageType || "unknown";
  
  let riskScore = Math.round(abuseScore);
  const isVpn = usageType === "Data Center" || organization.toLowerCase().includes("vpn");
  const isProxy = usageType === "Data Center" && totalReports > 0;
  const isTor = abuseData?.isTor || false;
  const isDatacenter = usageType === "Data Center" || usageType === "Content Delivery Network";
  
  if (isVpn) riskScore = Math.min(100, riskScore + 25);
  if (isProxy) riskScore = Math.min(100, riskScore + 20);
  if (isTor) riskScore = 100;
  if (totalReports > 5) riskScore = Math.min(100, riskScore + 30);
  
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
      
      // Fetch from all APIs in parallel
      const [abuseData, maxmindData, ipinfoData, whoisData] = await Promise.all([
        fetchAbuseIPDB(ipAddress),
        fetchMaxMind(ipAddress),
        fetchIPInfo(ipAddress),
        fetchWhoisXML(ipAddress),
      ]);
      
      const hasRealData = !!(abuseData || maxmindData || ipinfoData);
      
      let analysisData: InsertIpAnalysis;
      if (hasRealData) {
        analysisData = await generateRealAnalysis(
          ipAddress,
          abuseData,
          maxmindData,
          ipinfoData,
          whoisData
        );
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
