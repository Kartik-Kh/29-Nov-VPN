import { pgTable, text, varchar, integer, boolean, timestamp, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// IP Analysis Result schema
export const ipAnalyses = pgTable("ip_analyses", {
  id: varchar("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  ipVersion: text("ip_version").notNull(), // "IPv4" or "IPv6"
  riskScore: integer("risk_score").notNull(), // 0-100
  isVpn: boolean("is_vpn").notNull(),
  isProxy: boolean("is_proxy").notNull(),
  isTor: boolean("is_tor").notNull(),
  isDatacenter: boolean("is_datacenter").notNull(),
  threatLevel: text("threat_level").notNull(), // "low", "medium", "high", "critical"
  vpnProvider: text("vpn_provider"), // Name of detected VPN provider (e.g., "Zenlayer", "TurboVPN")
  isp: text("isp"),
  organization: text("organization"),
  asn: text("asn"),
  country: text("country"),
  countryCode: text("country_code"),
  city: text("city"),
  region: text("region"),
  latitude: real("latitude"),
  longitude: real("longitude"),
  timezone: text("timezone"),
  analyzedAt: timestamp("analyzed_at").notNull(),
});

// WHOIS Record schema
export const whoisRecords = pgTable("whois_records", {
  id: varchar("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  domain: text("domain"),
  registrar: text("registrar"),
  registrantName: text("registrant_name"),
  registrantOrg: text("registrant_org"),
  registrantCountry: text("registrant_country"),
  createdDate: text("created_date"),
  updatedDate: text("updated_date"),
  expiresDate: text("expires_date"),
  nameServers: text("name_servers").array(),
  netRange: text("net_range"),
  netName: text("net_name"),
  netHandle: text("net_handle"),
  originAs: text("origin_as"),
  abuseContact: text("abuse_contact"),
  techContact: text("tech_contact"),
  fetchedAt: timestamp("fetched_at").notNull(),
});

// Insert schemas
export const insertIpAnalysisSchema = createInsertSchema(ipAnalyses).omit({ id: true });
export const insertWhoisRecordSchema = createInsertSchema(whoisRecords).omit({ id: true });

// Types
export type IpAnalysis = typeof ipAnalyses.$inferSelect;
export type InsertIpAnalysis = z.infer<typeof insertIpAnalysisSchema>;
export type WhoisRecord = typeof whoisRecords.$inferSelect;
export type InsertWhoisRecord = z.infer<typeof insertWhoisRecordSchema>;

// API Request/Response types
export const analyzeIpRequestSchema = z.object({
  ipAddress: z.string().min(1, "IP address is required"),
});

export type AnalyzeIpRequest = z.infer<typeof analyzeIpRequestSchema>;

export interface AnalyzeIpResponse {
  analysis: IpAnalysis;
  whois: WhoisRecord | null;
  cached: boolean;
}

export interface ScanStats {
  totalScans: number;
  threatsDetected: number;
  cleanIps: number;
  vpnsDetected: number;
}

// Threat level helpers
export type ThreatLevel = "low" | "medium" | "high" | "critical";

export function getThreatLevelFromScore(score: number): ThreatLevel {
  if (score < 25) return "low";
  if (score < 50) return "medium";
  if (score < 75) return "high";
  return "critical";
}

export function getThreatLevelLabel(level: ThreatLevel): string {
  switch (level) {
    case "low": return "Low Risk";
    case "medium": return "Medium Risk";
    case "high": return "High Risk";
    case "critical": return "VPN/Proxy Detected";
  }
}

// IP validation helpers
export const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
export const ipv6Regex = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}$|^[a-fA-F0-9]{1,4}::(?:[a-fA-F0-9]{1,4}:){0,5}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,2}:(?:[a-fA-F0-9]{1,4}:){0,4}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,3}:(?:[a-fA-F0-9]{1,4}:){0,3}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,4}:(?:[a-fA-F0-9]{1,4}:){0,2}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,5}:(?:[a-fA-F0-9]{1,4}:)?[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}$/;

export function isValidIpAddress(ip: string): boolean {
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

export function getIpVersion(ip: string): "IPv4" | "IPv6" | null {
  if (ipv4Regex.test(ip)) return "IPv4";
  if (ipv6Regex.test(ip)) return "IPv6";
  return null;
}
