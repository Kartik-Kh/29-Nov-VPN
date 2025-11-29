import {
  type IpAnalysis,
  type InsertIpAnalysis,
  type WhoisRecord,
  type InsertWhoisRecord,
  type ScanStats,
} from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  createAnalysis(analysis: InsertIpAnalysis): Promise<IpAnalysis>;
  getAnalysis(id: string): Promise<IpAnalysis | undefined>;
  getAnalysisByIp(ipAddress: string): Promise<IpAnalysis | undefined>;
  getAllAnalyses(): Promise<IpAnalysis[]>;
  deleteAnalysis(id: string): Promise<boolean>;
  
  createWhoisRecord(record: InsertWhoisRecord): Promise<WhoisRecord>;
  getWhoisByIp(ipAddress: string): Promise<WhoisRecord | undefined>;
  
  getStats(): Promise<ScanStats>;
  
  getCachedResult(ipAddress: string): Promise<{ analysis: IpAnalysis; whois: WhoisRecord | null } | null>;
  setCachedResult(ipAddress: string, analysis: IpAnalysis, whois: WhoisRecord | null): void;
}

export class MemStorage implements IStorage {
  private analyses: Map<string, IpAnalysis>;
  private whoisRecords: Map<string, WhoisRecord>;
  private cache: Map<string, { analysis: IpAnalysis; whois: WhoisRecord | null; timestamp: number }>;
  private readonly CACHE_TTL = 5 * 60 * 1000;

  constructor() {
    this.analyses = new Map();
    this.whoisRecords = new Map();
    this.cache = new Map();
  }

  async createAnalysis(insertAnalysis: InsertIpAnalysis): Promise<IpAnalysis> {
    const id = randomUUID();
    const analysis: IpAnalysis = { ...insertAnalysis, id };
    this.analyses.set(id, analysis);
    return analysis;
  }

  async getAnalysis(id: string): Promise<IpAnalysis | undefined> {
    return this.analyses.get(id);
  }

  async getAnalysisByIp(ipAddress: string): Promise<IpAnalysis | undefined> {
    return Array.from(this.analyses.values())
      .sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime())
      .find((analysis) => analysis.ipAddress === ipAddress);
  }

  async getAllAnalyses(): Promise<IpAnalysis[]> {
    return Array.from(this.analyses.values()).sort(
      (a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime()
    );
  }

  async deleteAnalysis(id: string): Promise<boolean> {
    return this.analyses.delete(id);
  }

  async createWhoisRecord(insertRecord: InsertWhoisRecord): Promise<WhoisRecord> {
    const id = randomUUID();
    const record: WhoisRecord = { ...insertRecord, id };
    this.whoisRecords.set(id, record);
    return record;
  }

  async getWhoisByIp(ipAddress: string): Promise<WhoisRecord | undefined> {
    return Array.from(this.whoisRecords.values())
      .sort((a, b) => new Date(b.fetchedAt).getTime() - new Date(a.fetchedAt).getTime())
      .find((record) => record.ipAddress === ipAddress);
  }

  async getStats(): Promise<ScanStats> {
    const allAnalyses = Array.from(this.analyses.values());
    const threatsDetected = allAnalyses.filter(
      (a) => a.isVpn || a.isProxy || a.isTor
    ).length;
    const cleanIps = allAnalyses.filter(
      (a) => !a.isVpn && !a.isProxy && !a.isTor
    ).length;
    const vpnsDetected = allAnalyses.filter((a) => a.isVpn).length;

    return {
      totalScans: allAnalyses.length,
      threatsDetected,
      cleanIps,
      vpnsDetected,
    };
  }

  async getCachedResult(ipAddress: string): Promise<{ analysis: IpAnalysis; whois: WhoisRecord | null } | null> {
    const cached = this.cache.get(ipAddress);
    if (!cached) return null;
    
    if (Date.now() - cached.timestamp > this.CACHE_TTL) {
      this.cache.delete(ipAddress);
      return null;
    }
    
    return { analysis: cached.analysis, whois: cached.whois };
  }

  setCachedResult(ipAddress: string, analysis: IpAnalysis, whois: WhoisRecord | null): void {
    this.cache.set(ipAddress, { analysis, whois, timestamp: Date.now() });
  }
}

export const storage = new MemStorage();
