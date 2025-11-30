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
const MAXMIND_KEY = process.env.MAXMIND_LICENSE_KEY;
const IPINFO_KEY = process.env.IPINFO_API_KEY;
const WHOISXML_KEY = process.env.WHOISXML_API_KEY;
const APIIP_KEY = process.env.APIIP_API_KEY;
const PYPROXY_ACCESS_KEY = process.env.PYPROXY_ACCESS_KEY;
const PYPROXY_ACCESS_SECRET = process.env.PYPROXY_ACCESS_SECRET;

console.log("API Keys loaded:", {
  abuseipdb: !!ABUSEIPDB_KEY,
  maxmind: !!MAXMIND_KEY,
  ipinfo: !!IPINFO_KEY,
  whoisxml: !!WHOISXML_KEY,
  apiip: !!APIIP_KEY,
  pyproxy: !!PYPROXY_ACCESS_KEY,
});

// Redis for caching
let redis: Redis | null = null;
try {
  const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
  redis = new Redis(REDIS_URL, {
    retryStrategy: (times) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    enableReadyCheck: false,
    enableOfflineQueue: false,
  });
  redis.on("error", (err) => {
    redis = null;
    console.log("⚠ Redis unavailable:", err.message);
  });
  redis.on("connect", () => console.log("✓ Connected to Redis"));
} catch (err) {
  console.log("⚠ Redis unavailable:", err);
}

const CACHE_TTL = 3600; // 1 hour

// IPInfo - Free geolocation
async function fetchIPGeolocation(ip: string) {
  try {
    const res = await fetch(`https://ipinfo.io/${ip}?token=a91115dbbe7daf`);
    if (!res.ok) return null;
    const data = await res.json();
    console.log(`✓ IPInfo for ${ip}:`, { country: data.country, city: data.city, org: data.org });
    return data;
  } catch (e) {
    return null;
  }
}

// PyProxy - VPN/Proxy detection
async function fetchPyProxy(ip: string) {
  if (!PYPROXY_ACCESS_KEY || !PYPROXY_ACCESS_SECRET) return null;
  try {
    const res = await fetch(`https://api.pyproxy.io/v1/ip_info`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${PYPROXY_ACCESS_KEY}`,
      },
      body: JSON.stringify({ ip, secret: PYPROXY_ACCESS_SECRET }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    console.log(`✓ PyProxy for ${ip}:`, { isVpn: data.is_vpn, isProxy: data.is_proxy });
    return data;
  } catch (e) {
    return null;
  }
}

// APIIP - Geolocation and VPN detection
async function fetchAPIIP(ip: string) {
  if (!APIIP_KEY) return null;
  try {
    const res = await fetch(`https://apiip.net/api/check?ip=${ip}&apiKey=${APIIP_KEY}`);
    if (!res.ok) return null;
    const data = await res.json();
    console.log(`✓ APIIP for ${ip}:`, { country: data.country_name, city: data.city, isVpn: data.is_vpn });
    return data;
  } catch (e) {
    return null;
  }
}

// WhoisXML API
async function fetchWhoisXML(ip: string) {
  if (!WHOISXML_KEY) return null;
  try {
    const res = await fetch(`https://ip-whois-api.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_KEY}&ipv4=${ip}`);
    if (!res.ok) return null;
    const data = await res.json();
    console.log(`✓ WhoisXML for ${ip}:`, { org: data.result?.organization });
    return data.result || null;
  } catch (e) {
    return null;
  }
}

// AbuseIPDB
async function fetchAbuseIPDB(ip: string) {
  if (!ABUSEIPDB_KEY) return null;
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
      headers: {
        Key: ABUSEIPDB_KEY,
        Accept: "application/json",
      },
    });
    if (!res.ok) return null;
    const data = await res.json();
    console.log(`✓ AbuseIPDB for ${ip}:`, { score: data.data?.abuseConfidenceScore, isTor: data.data?.isTor });
    return data.data || null;
  } catch (e) {
    return null;
  }
}

// List of known VPN/proxy providers
const VPN_PROVIDERS = [
  "NordVPN", "ExpressVPN", "Surfshark", "ProtonVPN", "CyberGhost",
  "IPVanish", "Private Internet Access", "PIA", "Windscribe", "TunnelBear",
  "Turbo VPN", "TurboVPN", "HotspotShield", "VyprVPN", "StrongVPN", "Mullvad", "turbo",
  "IVPN", "PureVPN", "SaferVPN", "VPN Gate", "Astrill", "Bitdefender VPN",
  "Avast VPN", "AVG VPN", "McAfee VPN", "Norton VPN", "Perfect Privacy",
  "Freedome", "Hotspot Shield", "Hide My Ass", "HMA", "VPNBook",
  "VPNGate", "Psiphon", "UltraVPN", "VPNArea", "ibVPN", "SlickVPN",
  "CyberVPN", "VPN.com", "FastVPN", "VPNSecure", "BTGuard",
  "SecureVPN", "VPNUnlimited", "IronSocket", "ZenMate", "VPNMaster", "KeepSolid",
  "Betternet", "Touch VPN", "Thunder VPN", "Snap VPN", "Free VPN", "ProxyMaster",
  "VPN Master", "Unblock", "Browsec", "ZenVPN", "UFO VPN"
];

// Hosting/datacenter providers
const HOSTING_PROVIDERS = [
  "AWS", "Azure", "Google Cloud", "DigitalOcean", "Linode", "Vultr",
  "Zenlayer", "Softlayer", "Equinix", "Rackspace", "OVH", "Hetzner",
  "Scaleway", "Packet", "UpCloud", "Brightbox", "Joyent", "ProfitBricks",
  "Heroku", "Openshift", "EC2", "Compute Engine", "App Service"
];

// Hosting providers commonly used by VPN services
const VPN_HOSTING_PROVIDERS = [
  "Zenlayer", "Softlayer", "Equinix", "Packet", "Vultr", "DigitalOcean", "OVH",
  "Datacamp", "Contabo", "M247", "BudgetVM", "Nocix", "Ryukish", "VPS.ag",
  "ColoCrossing", "Leaseweb", "Cogent", "Voxility", "VHoster",
  "The Constant Company", "ConstantCompany", "Constant Company", "AS20473"
];

// Generate analysis from real data
async function generateRealAnalysis(ip: string, geoData: any, abuseData: any, pyProxyData: any, apiipData: any): Promise<InsertIpAnalysis> {
  const ipVersion = getIpVersion(ip) || "IPv4";
  
  // Parse location data from multiple sources
  let locStr = "0,0";
  if (geoData?.loc) {
    locStr = geoData.loc;
  } else if (apiipData?.latitude && apiipData?.longitude) {
    locStr = `${apiipData.latitude},${apiipData.longitude}`;
  }
  const loc = locStr.split(",");
  const country = geoData?.country || apiipData?.country_name || "Unknown";
  const countryCode = country;
  const city = geoData?.city || apiipData?.city || "Unknown";
  const region = geoData?.region || city;
  const latitude = parseFloat(loc[0]) || 0;
  const longitude = parseFloat(loc[1]) || 0;
  const organization = geoData?.org || "Unknown";
  const isp = geoData?.isp || organization.split(" ").slice(1).join(" ") || "Unknown";
  const asn = geoData?.asn || "Unknown";
  const timezone = geoData?.timezone || "UTC";
  
  // VPN/Proxy detection from multiple sources
  const orgLower = organization.toLowerCase();
  const ispLower = isp.toLowerCase();
  
  // Detect which VPN provider was matched
  let vpnProvider: string | null = null;
  const matchedVpnProvider = VPN_PROVIDERS.find(v => orgLower.includes(v.toLowerCase()) || ispLower.includes(v.toLowerCase()));
  const matchedVpnHosting = VPN_HOSTING_PROVIDERS.find(h => orgLower.includes(h.toLowerCase()) || ispLower.includes(h.toLowerCase()));
  
  if (matchedVpnProvider) {
    vpnProvider = matchedVpnProvider;
  } else if (matchedVpnHosting) {
    vpnProvider = matchedVpnHosting;
  }
  
  const isVpnProvider = !!matchedVpnProvider;
  const isVpnHosting = !!matchedVpnHosting;
  const isHosting = HOSTING_PROVIDERS.some(h => orgLower.includes(h.toLowerCase()) || ispLower.includes(h.toLowerCase()));
  
  // Combine detection from PyProxy, APIIP, AbuseIPDB and provider lists
  const isVpn = isVpnProvider || isVpnHosting || pyProxyData?.is_vpn === true || apiipData?.is_vpn === "true" || orgLower.includes("vpn") || ispLower.includes("vpn");
  const isProxy = pyProxyData?.is_proxy === true || apiipData?.is_proxy === "true" || ispLower.includes("proxy") || (abuseData?.usageType === "Data Center");
  const isTor = abuseData?.isTor === true || false;
  const isDatacenter = isHosting || orgLower.includes("datacenter") || orgLower.includes("hosting");
  
  let riskScore = 0;
  if (isVpn) riskScore = 75;
  if (isProxy) riskScore = Math.max(riskScore, 70);
  if (isTor) riskScore = 95;
  if (isDatacenter && !isVpn && !isProxy) riskScore = 45;
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
    vpnProvider,
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
      
      // Check Redis cache first (skip if fresh=true)
      const isFresh = req.query.fresh === "true";
      if (!isFresh && redis) {
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
      
      // Fetch from all available APIs
      const [geoData, abuseData, pyProxyData, apiipData, whoisData] = await Promise.all([
        fetchIPGeolocation(ipAddress),
        fetchAbuseIPDB(ipAddress),
        fetchPyProxy(ipAddress),
        fetchAPIIP(ipAddress),
        fetchWhoisXML(ipAddress),
      ]);
      
      const hasRealData = !!geoData || !!apiipData;
      
      let analysisData: InsertIpAnalysis;
      if (hasRealData) {
        analysisData = await generateRealAnalysis(ipAddress, geoData, abuseData, pyProxyData, apiipData);
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
          vpnProvider: null,
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
        registrar: "Unknown",
        registrantName: "Network Administrator",
        registrantOrg: analysisData.organization,
        registrantCountry: analysisData.countryCode,
        createdDate: "",
        updatedDate: "",
        expiresDate: null,
        nameServers: [],
        netRange: `${ipAddress}/24`,
        netName: `NET-${ipAddress.split(".").slice(0, 2).join("-")}`,
        netHandle: "HANDLE-0000",
        originAs: analysisData.asn,
        abuseContact: "",
        techContact: "",
        fetchedAt: new Date(),
      });
      
      // Cache the result in Redis
      const result = { analysis, whois, cached: false, source: "real" };
      if (redis) {
        const cacheKey = `analysis:${ipAddress}`;
        try {
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

  // Clear Redis cache endpoint
  app.post("/api/clear-cache", async (_req, res) => {
    try {
      if (redis) {
        await redis.flushdb();
        console.log("✓ Redis cache cleared");
      }
      res.json({ success: true, message: "Cache cleared" });
    } catch (error) {
      res.status(500).json({ error: "Failed to clear cache" });
    }
  });

  // Clear Redis cache on server startup (after connection ready)
  if (redis) {
    redis.on("ready", async () => {
      try {
        await redis!.flushdb();
        console.log("✓ Redis cache cleared on startup");
      } catch (e) {
        console.log("⚠ Failed to clear Redis on startup:", e);
      }
    });
  }
  
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

  // Bulk IP analysis
  app.post("/api/bulk-analyze", validateRequest(z.object({
    ips: z.array(z.string()).min(1).max(100),
  })), async (req, res) => {
    try {
      const { ips } = req.body;
      const validIps = ips.filter(ip => isValidIpAddress(ip));
      
      if (validIps.length === 0) {
        return res.status(400).json({ error: "No valid IP addresses provided" });
      }

      const analyses: any[] = [];
      
      for (const ip of validIps as string[]) {
        try {
          // Check cache first
          let cacheKey = `analysis:${ip}`;
          let cached = null;
          if (redis) {
            try {
              cached = await redis.get(cacheKey);
            } catch (e) {
              // Continue if cache fails
            }
          }
          
          if (cached) {
            analyses.push(JSON.parse(cached));
            continue;
          }

          // Fetch from APIs
          const [geoData, abuseData, pyProxyData, apiipData] = await Promise.all([
            fetchIPGeolocation(ip),
            fetchAbuseIPDB(ip),
            fetchPyProxy(ip),
            fetchAPIIP(ip),
          ]);

          const analysisData = await generateRealAnalysis(ip, geoData, abuseData, pyProxyData, apiipData);
          const analysis = await storage.createAnalysis(analysisData);
          const whois = await storage.createWhoisRecord({
            ipAddress: ip,
            domain: null,
            registrar: "Unknown",
            registrantName: "Network Administrator",
            registrantOrg: analysisData.organization,
            registrantCountry: analysisData.countryCode,
            createdDate: "",
            updatedDate: "",
            expiresDate: null,
            nameServers: [],
            netRange: `${ip}/24`,
            netName: `NET-${ip.split(".").slice(0, 2).join("-")}`,
            netHandle: "HANDLE-0000",
            originAs: analysisData.asn,
            abuseContact: "",
            techContact: "",
            fetchedAt: new Date(),
          });

          const result = { analysis, whois, cached: false, source: "real" };
          if (redis) {
            try {
              await redis.setex(cacheKey, CACHE_TTL, JSON.stringify(result));
            } catch (e) {
              // Continue if cache fails
            }
          }
          
          analyses.push(result);
        } catch (ipError) {
          console.error(`Error analyzing ${ip}:`, ipError);
          // Continue with next IP
        }
      }

      res.json({ analyses, total: validIps.length, completed: analyses.length });
    } catch (error) {
      console.error("Bulk analysis error:", error);
      res.status(500).json({ error: "Failed to perform bulk analysis" });
    }
  });

  return httpServer;
}
